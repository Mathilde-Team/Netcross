"""Mesures par étape du pipeline (issue #1016)."""

from __future__ import annotations

import json
import shutil
import socket
import struct
import sys
import tracemalloc

import pytest
from pcap_builders import write_pcap

import cross_capture_analyzer_cli as analyzer_cli
from netcross_core import profiling
from netcross_core.profiling import ETAPES_STANDARD, MesuresPipeline, creer_mesures, marquer


class Horloge:
    """Horloge factice : chaque lecture avance du pas suivant."""

    def __init__(self, *pas):
        self.t = 100.0
        self.pas = list(pas)

    def __call__(self):
        valeur = self.t
        if self.pas:
            self.t += self.pas.pop(0)
        return valeur


# -- unité ---------------------------------------------------------------------


def test_etapes_contigues_somme_egale_total():
    m = MesuresPipeline(horloge=Horloge(1.0, 0.25, 2.0, 0.5))
    for nom in ETAPES_STANDARD:
        m.etape(nom)
    donnees = m.terminer()
    durees = {nom: v["secondes"] for nom, v in donnees["etapes"].items()}
    assert durees == {"lecture": 1.0, "correlation": 0.25, "detecteurs": 2.0, "rapport": 0.5}
    assert donnees["total_s"] == pytest.approx(sum(durees.values()))
    assert list(donnees["etapes"]) == list(ETAPES_STANDARD)


def test_etape_rouverte_cumule_ses_passages():
    m = MesuresPipeline(horloge=Horloge(1, 1, 1, 1, 1))
    for nom in ("lecture", "detecteurs", "rapport", "detecteurs", "rapport"):
        m.etape(nom)
    etapes = m.terminer()["etapes"]
    assert etapes["detecteurs"]["passages"] == 2
    assert etapes["detecteurs"]["secondes"] == 2
    assert etapes["rapport"]["passages"] == 2
    assert m.total_s == 5


def test_memoire_relevee_par_etape():
    m = MesuresPipeline()
    m.etape("lecture")
    tampon = bytearray(4 * 1024 * 1024)
    m.etape("rapport")
    donnees = m.terminer()
    del tampon
    assert donnees["etapes"]["lecture"]["rss_max_ko"] > 0
    assert donnees["etapes"]["rapport"]["rss_max_ko"] >= donnees["etapes"]["lecture"]["rss_max_ko"]
    assert donnees["rss_max_ko"] >= donnees["etapes"]["rapport"]["rss_max_ko"]
    assert "pic_tracemalloc_ko" not in donnees["etapes"]["lecture"]
    assert donnees["tracemalloc"] is False


def test_tracemalloc_pic_par_etape_et_arret():
    assert not tracemalloc.is_tracing()
    m = MesuresPipeline(tracemalloc_actif=True)
    assert tracemalloc.is_tracing()
    m.etape("lecture")
    tampon = [bytes(1024) for _ in range(4096)]  # ~4 Mio d'allocations Python
    del tampon  # libéré avant la fin de l'étape : seul le pic de « lecture » le voit
    m.etape("rapport")
    donnees = m.terminer()
    assert not tracemalloc.is_tracing()
    assert donnees["etapes"]["lecture"]["pic_tracemalloc_ko"] >= 4000
    assert donnees["etapes"]["rapport"]["pic_tracemalloc_ko"] < donnees["etapes"]["lecture"]["pic_tracemalloc_ko"]
    assert "pic Python" in m.resume()


def test_tracemalloc_deja_actif_n_est_pas_arrete():
    tracemalloc.start()
    try:
        m = MesuresPipeline(tracemalloc_actif=True)
        m.etape("lecture")
        m.terminer()
        assert tracemalloc.is_tracing()
    finally:
        tracemalloc.stop()


def test_terminer_idempotent_et_etape_apres_terminer_ignoree():
    m = MesuresPipeline(horloge=Horloge(1, 1, 1))
    m.etape("lecture")
    premier = m.terminer()
    m.etape("rapport")
    assert m.terminer() == premier
    assert list(m.etapes) == ["lecture"]


def test_terminer_sans_etape():
    m = MesuresPipeline()
    donnees = m.terminer()
    assert donnees["total_s"] == 0.0
    assert donnees["etapes"] == {}
    assert "total 0.000 s" in m.resume()


def test_ecrire_json_et_resume(tmp_path):
    m = MesuresPipeline(horloge=Horloge(3.0, 1.0))
    m.etape("lecture")
    m.etape("rapport")
    chemin = tmp_path / "mesures.json"
    donnees = m.ecrire_json(chemin)
    assert json.loads(chemin.read_text(encoding="utf-8")) == donnees
    resume = m.resume()
    assert "lecture" in resume
    assert "75.0 %" in resume
    assert "25.0 %" in resume


def test_desactive_aucun_objet(monkeypatch):
    def interdit(*_a, **_k):
        raise AssertionError("aucun objet de mesures ne doit être créé")

    monkeypatch.setattr(profiling, "MesuresPipeline", interdit)
    assert creer_mesures(False) is None
    marquer(None, "lecture")  # ne lève pas, ne fait rien


def test_active_cree_et_marque():
    m = creer_mesures(True)
    assert isinstance(m, MesuresPipeline)
    marquer(m, "lecture")
    assert m._courante == "lecture"


# -- intégration CLI ---------------------------------------------------------------


def _trame(seq):
    tcp = struct.pack("!HHIIBBHHH", 40000, 80, seq, 1, 5 << 4, 0x18, 65535, 0, 0) + b"x" * 40
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        1,
        0x4000,
        64,
        6,
        0,
        socket.inet_aton("10.0.0.1"),
        socket.inet_aton("10.0.0.2"),
    )
    return b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00" + ip + tcp


@pytest.fixture
def captures(tmp_path):
    for nom, n in (("amont", 20), ("aval", 18)):
        write_pcap(
            tmp_path / f"{nom}.pcap", [(1_700_000_000_000_000 + i * 10_000, _trame(1000 + i * 10)) for i in range(n)]
        )
    return tmp_path


def _lancer(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", *[str(a) for a in args]])
    analyzer_cli.main()
    return capsys.readouterr()


def _base(dossier, rapport):
    return [
        "--capture",
        f"A={dossier / 'amont.pcap'}",
        "--capture",
        f"B={dossier / 'aval.pcap'}",
        "--order",
        "A,B",
        "--json-report",
        rapport,
    ]


def _sans_horodatage(chemin):
    donnees = json.loads(chemin.read_text(encoding="utf-8"))
    donnees.pop("generated_at", None)
    donnees.get("meta", {}).pop("generated_at", None)
    return donnees


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent du PATH")
def test_cli_profile_steps_etapes_et_resultats_inchanges(captures, monkeypatch, capsys):
    mesures_json = captures / "mesures.json"
    sortie = _lancer(monkeypatch, capsys, *_base(captures, captures / "avec.json"), "--profile-steps", mesures_json)
    assert "Mesures par étape" in sortie.out
    donnees = json.loads(mesures_json.read_text(encoding="utf-8"))
    assert list(donnees["etapes"]) == list(ETAPES_STANDARD)
    somme = sum(v["secondes"] for v in donnees["etapes"].values())
    assert somme == pytest.approx(donnees["total_s"], abs=1e-5)
    assert donnees["etapes"]["detecteurs"]["passages"] == 2
    assert donnees["etapes"]["lecture"]["rss_max_enfants_ko"] > 0  # tshark compté

    def interdit(*_a, **_k):
        raise AssertionError("aucun objet de mesures sans --profile-steps")

    monkeypatch.setattr(profiling, "MesuresPipeline", interdit)
    sortie = _lancer(monkeypatch, capsys, *_base(captures, captures / "sans.json"))
    assert "Mesures par étape" not in sortie.out
    assert _sans_horodatage(captures / "avec.json") == _sans_horodatage(captures / "sans.json")


@pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent du PATH")
def test_cli_profile_tracemalloc(captures, monkeypatch, capsys):
    mesures_json = captures / "mesures.json"
    _lancer(
        monkeypatch,
        capsys,
        *_base(captures, captures / "r.json"),
        "--profile-steps",
        mesures_json,
        "--profile-tracemalloc",
    )
    donnees = json.loads(mesures_json.read_text(encoding="utf-8"))
    assert donnees["tracemalloc"] is True
    assert all("pic_tracemalloc_ko" in v for v in donnees["etapes"].values())
    assert not tracemalloc.is_tracing()


def test_cli_tracemalloc_sans_profile_steps(monkeypatch, capsys):
    monkeypatch.setattr(
        sys, "argv", ["cross_capture_analyzer_cli.py", "--capture", "A=x.pcap", "--profile-tracemalloc"]
    )
    with pytest.raises(SystemExit) as exc:
        analyzer_cli.main()
    assert exc.value.code == 2
    assert "--profile-tracemalloc necessite --profile-steps" in capsys.readouterr().err
