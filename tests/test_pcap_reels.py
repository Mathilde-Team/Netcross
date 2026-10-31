"""Tests du harnais de tests réels scripts/pcap_reels.py (issue #1008).

La vraie banque (/app/pcaps) n'existe que sur la VM du runner : ici, une
banque factice est construite dans tmp_path à partir des exemples du guide.
Le point le plus important est vérifié explicitement : sans --noms, rien de
la banque (nom de fichier, de dossier, de point, adresse, texte de constat)
n'apparaît dans la sortie du harnais.
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EXEMPLES = ROOT / "docs" / "guide" / "exemples"


def _charger():
    chemin = ROOT / "scripts" / "pcap_reels.py"
    spec = importlib.util.spec_from_file_location("pcap_reels", chemin)
    module = importlib.util.module_from_spec(spec)
    sys.modules["pcap_reels"] = module
    spec.loader.exec_module(module)
    return module


pr = _charger()

requires_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark non installe")

MANIFESTE_OK = """
cas:
  - nom: policing-wan
    captures: {LAN-SECRET: lan.pcap, WAN-SECRET: wan.pcap}
    ordre: [LAN-SECRET, WAN-SECRET]
    attendu:
      score_sante: {min: 0, max: 100}
      constats:
        - {rule_id: saturation}
      constats_absents:
        - {rule_id: syn_flood}
"""


def _banque(tmp_path: Path, manifeste: str | None = MANIFESTE_OK) -> Path:
    banque = tmp_path / "banque"
    dossier = banque / "client-confidentiel" / "incident"
    dossier.mkdir(parents=True)
    for nom in ("lan.pcap", "wan.pcap"):
        shutil.copy(EXEMPLES / nom, dossier / nom)
    (banque / "divers").mkdir()
    shutil.copy(EXEMPLES / "lan_apres.pcap", banque / "divers" / "capture-privee.pcap")
    if manifeste is not None:
        (dossier / pr.NOM_MANIFESTE).write_text(manifeste, encoding="utf-8")
    return banque


# --- découverte et manifestes ---------------------------------------------


def test_decouverte_scenarios_puis_fumee(tmp_path):
    cas = pr.decouvrir(_banque(tmp_path))
    assert [c.type for c in cas] == ["scénario", "fumée"]
    # les captures citées par un manifeste ne sont pas rejouées en fumée
    assert cas[1].nom_reel == "divers/capture-privee.pcap"
    assert list(cas[0].captures) == ["LAN-SECRET", "WAN-SECRET"]


def test_identifiants_opaques_et_stables(tmp_path):
    a = pr.decouvrir(_banque(tmp_path))
    b = pr.decouvrir(tmp_path / "banque")
    assert [c.ident for c in a] == [c.ident for c in b]
    for c in a:
        assert "client" not in c.ident and "pcap" not in c.ident


def test_banque_absente(tmp_path):
    with pytest.raises(pr.BanqueError):
        pr.decouvrir(tmp_path / "rien")


def test_banque_vide(tmp_path):
    (tmp_path / "vide").mkdir()
    with pytest.raises(pr.BanqueError):
        pr.decouvrir(tmp_path / "vide")


def test_ignorer(tmp_path):
    banque = _banque(tmp_path)
    (banque / "divers" / pr.NOM_MANIFESTE).write_text("ignorer: ['capture-*.pcap']\n", encoding="utf-8")
    assert [c.type for c in pr.decouvrir(banque)] == ["scénario"]


INTERDITES = ["--notify-webhook=http://x", "--pdf-report", "--live", "--plugin-path", "--ai-endpoint"]


@pytest.mark.parametrize("option", INTERDITES)
def test_option_non_permise(tmp_path, option):
    manifeste = MANIFESTE_OK.replace("    ordre:", f"    options: ['{option}']\n    ordre:")
    with pytest.raises(pr.BanqueError, match="non permise"):
        pr.decouvrir(_banque(tmp_path, manifeste))


def test_option_permise(tmp_path):
    manifeste = MANIFESTE_OK.replace("    ordre:", "    options: ['--bucket-ms', '100', '--redact']\n    ordre:")
    cas = pr.decouvrir(_banque(tmp_path, manifeste))
    assert cas[0].options == ["--bucket-ms", "100", "--redact"]


def test_cle_inconnue_refusee(tmp_path):
    manifeste = MANIFESTE_OK.replace("constats_absents:", "constat_absent:")
    with pytest.raises(pr.BanqueError, match="inconnue"):
        pr.decouvrir(_banque(tmp_path, manifeste))


def test_capture_hors_banque_refusee(tmp_path):
    manifeste = MANIFESTE_OK.replace("wan.pcap", "../../../dehors.pcap")
    (tmp_path / "dehors.pcap").write_bytes(b"")
    with pytest.raises(pr.BanqueError, match="hors de la banque"):
        pr.decouvrir(_banque(tmp_path, manifeste))


def test_capture_citee_absente(tmp_path):
    with pytest.raises(pr.BanqueError, match="absente"):
        pr.decouvrir(_banque(tmp_path, MANIFESTE_OK.replace("wan.pcap", "manque.pcap")))


# --- vérification du rapport -----------------------------------------------

RAPPORT = {
    "points": ["A", "B"],
    "health_score": 72,
    "health_label": "a_surveiller",
    "findings": [
        {"rule_id": "saturation", "severity": "anomalie", "segment": "A -> B", "message": "10.1.2.3 sature"},
        {"rule_id": "loss_per_segment", "severity": "a_surveiller", "segment": "B", "message": "5 paquets"},
    ],
}


def test_rapport_conforme():
    attendu = {
        "score_sante": {"min": 60, "max": 80},
        "label_sante": ["a_surveiller", "degrade"],
        "constats": [{"rule_id": "saturation", "segment": "A -> B", "message_contient": "sature"}],
        "constats_absents": [{"rule_id": "syn_flood"}],
    }
    assert pr.verifier_rapport(RAPPORT, attendu) == []


def test_rapport_ecarts_sans_donnees():
    attendu = {
        "score_sante": {"min": 90},
        "constats": [{"rule_id": "saturation", "nombre_min": 2}],
        "constats_absents": [{"segment": "B"}],
    }
    ecarts = pr.verifier_rapport(RAPPORT, attendu)
    assert len(ecarts) == 3
    texte = " ".join(ecarts)
    # ni segment, ni point, ni adresse, ni message de constat
    for secret in ("A -> B", "10.1.2.3", "sature", "paquets"):
        assert secret not in texte


def test_rapport_incomplet():
    assert any("incomplet" in e for e in pr.verifier_rapport({}, {}))


def test_resume_exception_sans_message():
    stderr = (
        "Traceback (most recent call last):\n"
        '  File "/__w/Netcross/Netcross/src/cross_capture_analyzer_cli.py", line 10, in main\n'
        "    analyse()\n"
        '  File "/__w/Netcross/Netcross/src/netcross_core/analysis.py", line 1402, in _analyse_handshake\n'
        "    x = d[k]\n"
        "KeyError: '192.168.12.34'\n"
    )
    resume = pr.resumer_exception(stderr)
    assert resume == "KeyError dans netcross_core/analysis.py:1402 (_analyse_handshake)"
    assert pr.resumer_exception("rien de grave") is None


# --- exécution réelle (tshark) ---------------------------------------------


@requires_tshark
def test_execution_et_absence_de_fuite(tmp_path, capsys):
    banque = _banque(tmp_path)
    resume = tmp_path / "resume.md"
    code = pr.main(["--banque", str(banque), "--resume", str(resume)])
    sortie = capsys.readouterr()
    assert code == 0, sortie.out
    texte = sortie.out + sortie.err + resume.read_text(encoding="utf-8")
    assert "2 cas, 2 conformes, 0 en échec" in texte
    for secret in ("client-confidentiel", "capture-privee", "lan.pcap", "LAN-SECRET", "policing", str(tmp_path)):
        assert secret not in texte


@requires_tshark
def test_execution_echec_signale(tmp_path, capsys):
    manifeste = MANIFESTE_OK.replace("syn_flood", "saturation")
    code = pr.main(["--banque", str(_banque(tmp_path, manifeste))])
    sortie = capsys.readouterr().out
    assert code == 1
    assert "constat interdit n°1 (rule_id=saturation)" in sortie


@requires_tshark
def test_noms_en_local(tmp_path, capsys):
    pr.main(["--banque", str(_banque(tmp_path)), "--noms", "--lister"])
    assert "divers/capture-privee.pcap" in capsys.readouterr().out


def test_main_banque_absente(tmp_path, capsys):
    assert pr.main(["--banque", str(tmp_path / "rien")]) == 2
