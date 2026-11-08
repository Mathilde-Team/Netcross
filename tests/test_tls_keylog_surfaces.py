"""--tls-keylog sur les quatre surfaces (issue #1040) : CLI d'analyse, CLI de
différentiel, API et GUI. Capture TLS 1.3 réelle (tests/tls13_keylog_capture.py)
quand tshark est présent, doubles sinon.
"""

from __future__ import annotations

import importlib
import os
import shutil
import stat
import sys
from pathlib import Path

import pytest
from conftest import make_pkt

import cross_capture_analyzer_cli as cli
import cross_capture_diff_cli as diff_cli
import netcross_gtk4.analysis_pipeline as pipeline_mod
from netcross_core.tls_keylog import MESSAGE_REDACT, MESSAGE_SANS_CAPTURE
from netcross_gtk4.advanced_options import AdvancedSettings, settings_from_values, validate
from netcross_gtk4.analysis_pipeline import AnalysisOptions, run_analysis_pipeline

sys.path.insert(0, str(Path(__file__).parent))
from tls13_keylog_capture import URI, ecrire_capture  # noqa: E402

avec_tshark = pytest.mark.skipif(shutil.which("tshark") is None, reason="tshark absent")


@pytest.fixture(scope="module")
def session_tls13(tmp_path_factory):
    pytest.importorskip("cryptography")
    return ecrire_capture(tmp_path_factory.mktemp("tls13-surfaces"))


@pytest.fixture
def cles(tmp_path):
    chemin = tmp_path / "keys.txt"
    chemin.write_text("CLIENT_RANDOM 00 11\n")
    return str(chemin)


def _main(module, monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["prog", *map(str, argv)])
    try:
        module.main()
    except SystemExit as exc:
        return exc.code
    return 0


# --- CLI d'analyse -------------------------------------------------------------


@avec_tshark
@pytest.mark.parametrize("parallele", [[], ["--parallel"]])
def test_cli_analyse_dechiffre_avec_cle(session_tls13, monkeypatch, capsys, parallele):
    capture, keys = session_tls13
    assert _main(cli, monkeypatch, ["--capture", f"P1={capture}", *parallele]) == 0
    assert URI not in capsys.readouterr().out
    code = _main(cli, monkeypatch, ["--capture", f"P1={capture}", "--tls-keylog", f"P1={keys}", *parallele])
    sortie = capsys.readouterr()
    assert code == 0
    assert URI in sortie.out
    assert "Fichier(s) de cles TLS transmis a tshark pour : P1" in sortie.err
    assert str(keys) not in sortie.err


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["--capture", "P1=a.pcap", "--tls-keylog", "{k}", "--redact"], MESSAGE_REDACT),
        (["--capture", "P1=a.pcap", "--tls-keylog", "X={k}"], "point inconnu « X »"),
        (["--capture", "P1=a.pcap", "--tls-keylog", "{k}.absent"], "fichier introuvable"),
        (["--live", "P1=lo", "--tls-keylog", "{k}"], MESSAGE_SANS_CAPTURE),
    ],
)
def test_cli_analyse_refus_avant_lecture(monkeypatch, capsys, cles, argv, message):
    monkeypatch.setattr(cli, "parse_capture", lambda *a, **k: pytest.fail("capture lue malgre le refus"))
    assert _main(cli, monkeypatch, [a.format(k=cles) for a in argv]) == 1
    assert message in capsys.readouterr().err


def test_cli_analyse_split_interfaces_herite(monkeypatch, cles):
    vus = []
    monkeypatch.setattr(cli, "_expand_split_interfaces", lambda caps: [("P1:eth0", "a0"), ("P1:eth1", "a1")])

    def lecture(label, path, raise_on_error=False, **options):
        vus.append((label, options))
        return [make_pkt(point=label, ts=1.0)]

    monkeypatch.setattr(cli, "parse_capture", lecture)
    _main(cli, monkeypatch, ["--capture", "P1=a.pcapng", "--split-interfaces", "--tls-keylog", f"P1={cles}"])
    assert vus == [("P1:eth0", {"tls_keylog": cles}), ("P1:eth1", {"tls_keylog": cles})]


# --- CLI de différentiel -------------------------------------------------------


def test_diff_cli_transmet_le_fichier(monkeypatch, cles):
    vus = []

    def lecture(label, path, raise_on_error=False, **options):
        vus.append((label, path, options))
        return [make_pkt(point=label, ts=1.0)]

    monkeypatch.setattr(diff_cli, "parse_capture", lecture)
    argv = ["--baseline", "P1=b.pcap", "--current", "P1=c.pcap", "--current", "P2=d.pcap"]
    _main(diff_cli, monkeypatch, [*argv, "--tls-keylog", f"P2={cles}"])
    assert ("P2", "d.pcap", {"tls_keylog": cles}) in vus
    assert ("P1", "b.pcap", {}) in vus


def test_diff_cli_parallele(monkeypatch, cles):
    vus = []

    def lecture(captures, workers=None, **options):
        vus.append(options)
        return [make_pkt(point=label, ts=1.0) for label, _ in captures], [
            {"label": label, "path": path, "count": 1, "seconds": 0.0, "error": None} for label, path in captures
        ]

    monkeypatch.setattr(diff_cli, "parse_captures_parallel", lecture)
    _main(diff_cli, monkeypatch, ["--baseline", "P1=b", "--current", "P1=c", "--parallel", "--tls-keylog", cles])
    assert vus == [{"tls_keylogs": {"P1": cles}}, {"tls_keylogs": {"P1": cles}}]
    vus.clear()
    _main(diff_cli, monkeypatch, ["--baseline", "P1=b", "--current", "P1=c", "--parallel"])
    assert vus == [{}, {}]


@pytest.mark.parametrize(
    ("extra", "message"),
    [(["--tls-keylog", "{k}", "--redact"], MESSAGE_REDACT), (["--tls-keylog", "X={k}"], "point inconnu")],
)
def test_diff_cli_refus(monkeypatch, capsys, cles, extra, message):
    monkeypatch.setattr(diff_cli, "parse_capture", lambda *a, **k: pytest.fail("capture lue malgre le refus"))
    argv = ["--baseline", "P1=b.pcap", "--current", "P1=c.pcap", *[e.format(k=cles) for e in extra]]
    assert _main(diff_cli, monkeypatch, argv) == 1
    assert message in capsys.readouterr().err


# --- API -----------------------------------------------------------------------


@pytest.fixture
def api():
    pytest.importorskip("fastapi", reason="extra [api] non installé")
    pytest.importorskip("multipart", reason="python-multipart non installé")
    from fastapi.testclient import TestClient

    module = importlib.import_module("netcross_api.app")
    return module, TestClient(module.app)


@avec_tshark
def test_api_capture_dechiffree_puis_cle_supprimee(api, session_tls13, monkeypatch):
    module, client = api
    capture, keys = session_tls13
    copies = []
    origine = module._save_tls_keylogs

    async def espion(*args):
        resultat = await origine(*args)
        copies.extend((c, stat.S_IMODE(os.stat(c).st_mode)) for c in resultat[1])
        return resultat

    monkeypatch.setattr(module, "_save_tls_keylogs", espion)
    fichiers = [("file", ("a.pcap", capture.read_bytes())), ("tls_keylog", ("keys.txt", keys.read_bytes()))]
    reponse = client.post("/captures?wait=true", data={"label": "P1"}, files=fichiers)
    assert reponse.status_code == 201, reponse.text
    rapport = client.get(f"/analyses/{reponse.json()['analysis_id']}/report").text
    assert URI in rapport
    assert [mode for _, mode in copies] == [0o600]
    assert not os.path.exists(copies[0][0])
    sans = client.post("/captures?wait=true", data={"label": "P1"}, files=fichiers[:1])
    assert URI not in client.get(f"/analyses/{sans.json()['analysis_id']}/report").text


@avec_tshark
def test_api_multi_par_point(api, session_tls13):
    module, client = api
    capture, keys = session_tls13
    donnees = capture.read_bytes()
    fichiers = [
        ("files", ("a.pcap", donnees)),
        ("files", ("b.pcap", donnees)),
        ("tls_keylog", ("keys.txt", keys.read_bytes())),
    ]
    reponse = client.post(
        "/captures/multi?wait=true", data={"labels": "P1,P2", "tls_keylog_labels": "P2"}, files=fichiers
    )
    assert reponse.status_code == 201, reponse.text
    entree = module.store.get(reponse.json()["analysis_id"])
    assert entree["metadata"]["options"]["tls_keylogs"] == ["P2"]
    assert str(keys) not in str(entree["metadata"])


@pytest.mark.parametrize(
    ("data", "avec_cle", "message"),
    [
        ({"redact": "true"}, True, "redact=true"),
        ({"tls_keylog_labels": "X"}, True, "point inconnu « X »"),
        ({"tls_keylog_labels": "P1,P1"}, True, "2 point(s) pour 1 fichier(s)"),
        ({"tls_keylog_labels": "P1"}, False, "sans fichier tls_keylog"),
    ],
)
def test_api_refus(api, monkeypatch, data, avec_cle, message):
    module, client = api
    sauvegardes = []
    origine = module._save_upload

    async def espion(fichier, label):
        chemin = await origine(fichier, label)
        sauvegardes.append(chemin)
        return chemin

    monkeypatch.setattr(module, "_save_upload", espion)
    fichiers = [("file", ("a.pcap", b"\xd4\xc3\xb2\xa1" + b"\x00" * 20))]
    if avec_cle:
        fichiers.append(("tls_keylog", ("keys.txt", b"CLIENT_RANDOM 00 11\n")))
    reponse = client.post("/captures?wait=true", data={"label": "P1", **data}, files=fichiers)
    assert reponse.status_code == 400
    assert message in reponse.json()["detail"]
    assert "--tls-keylog" not in reponse.json()["detail"]
    assert all(not os.path.exists(c) for c in sauvegardes)


def test_api_refus_multi(api):
    _, client = api
    fichiers = [
        ("files", ("a.pcap", b"x")),
        ("files", ("b.pcap", b"x")),
        ("tls_keylog", ("keys.txt", b"k")),
    ]
    reponse = client.post("/captures/multi", data={"labels": "P1,P2", "tls_keylog_labels": "P3"}, files=fichiers)
    assert reponse.status_code == 400
    assert "point inconnu « P3 »" in reponse.json()["detail"]


def test_api_appel_direct_sans_fichier(api):
    module, _ = api
    assert module._fichiers_tls_keylog(object()) == []
    assert module._fichiers_tls_keylog([]) == []


def test_api_lecture_transmet_le_fichier(api, monkeypatch):
    module, _ = api
    vus = []
    monkeypatch.setattr(
        module, "parse_capture", lambda label, path, **o: vus.append((label, o)) or [make_pkt(point=label)]
    )
    module._read_captures([("P1", "a"), ("P2", "b")], None, (("P2", "/k"),))
    assert vus == [("P1", {}), ("P2", {"tls_keylog": "/k"})]


# --- GUI -----------------------------------------------------------------------


def test_gui_reglages_et_refus(cles):
    assert settings_from_values(0, 1, 0, tls_keylog="") == AdvancedSettings()
    reglages = settings_from_values(0, 1, 0, tls_keylog=cles)
    assert reglages == AdvancedSettings(tls_keylog=cles)
    assert validate(reglages, security=False) == []
    assert validate(reglages, security=False, redact=True) == [MESSAGE_REDACT]
    assert validate(AdvancedSettings(tls_keylog=cles + ".absent"), security=False) == [
        f"--tls-keylog : fichier introuvable : {cles}.absent"
    ]


def test_gui_lecture_transmet_le_fichier(monkeypatch, cles):
    import pcap_parser.capture as capture

    vus = []
    monkeypatch.setattr(
        pipeline_mod, "parse_capture", lambda label, path, **o: vus.append((label, o)) or [make_pkt(point=label)]
    )
    pipeline_mod.load_packets([("A", "a"), ("B", "b")], False, tls_keylog=cles)
    assert vus == [("A", {"tls_keylog": cles}), ("B", {"tls_keylog": cles})]
    paralleles = []
    monkeypatch.setattr(
        capture, "parse_captures_parallel", lambda caps, max_workers=None, **o: paralleles.append(o) or ([], [])
    )
    pipeline_mod.load_packets([("A", "a")], True, tls_keylog=cles)
    assert paralleles == [{"tls_keylogs": {"A": cles}}]


def test_gui_pipeline_transmet_et_refuse(monkeypatch, cles):
    vus = []
    monkeypatch.setattr(
        pipeline_mod, "parse_capture", lambda label, path, **o: vus.append(o) or [make_pkt(point=label, ts=1.0)]
    )
    journal = []
    options = AnalysisOptions(parallel=False, advanced=AdvancedSettings(tls_keylog=cles))
    run_analysis_pipeline([("A", "a")], options, on_progress=journal.append)
    assert vus == [{"tls_keylog": cles}]
    assert any("--tls-keylog" in ligne for ligne in journal)
    with pytest.raises(ValueError, match="--redact"):
        run_analysis_pipeline(
            [("A", "a")], AnalysisOptions(parallel=False, redact=True, advanced=AdvancedSettings(tls_keylog=cles))
        )


@avec_tshark
def test_gui_pipeline_capture_reelle(session_tls13):
    capture, keys = session_tls13
    resultat = run_analysis_pipeline(
        [("P1", str(capture))], AnalysisOptions(parallel=False, advanced=AdvancedSettings(tls_keylog=str(keys)))
    )
    assert URI in resultat.text


def test_gui_fenetre(cles):
    from gtk4_display import exiger_gtk4_avec_affichage

    gtk = exiger_gtk4_avec_affichage()
    from netcross_gtk4.app import MainWindow

    app = gtk.Application(application_id="org.netcross.test1040")
    app.register(None)
    window = MainWindow(app)
    assert window.advanced_settings().tls_keylog is None
    window.tls_keylog_option.set_path(cles)
    assert window.advanced_settings().tls_keylog == cles
    window.close()


def test_api_echec_de_copie_nettoie_et_relance(api, monkeypatch):
    import asyncio

    from fastapi import HTTPException

    module, _ = api
    copies = []
    origine = module._save_upload

    async def copie_puis_echec(fichier, label):
        if copies:
            raise HTTPException(status_code=413, detail="trop volumineux")
        chemin = await origine(fichier, label)
        copies.append(chemin)
        return chemin

    class Fichier:
        def __init__(self, nom):
            self.filename = nom
            self._donnees = [b"CLIENT_RANDOM 00 11\n", b""]

        async def read(self, _taille):
            return self._donnees.pop(0)

    monkeypatch.setattr(module, "_save_upload", copie_puis_echec)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(module._save_tls_keylogs([Fichier("a"), Fichier("b")], "P1,P2", ["P1", "P2"]))
    assert exc.value.status_code == 413
    assert copies and not os.path.exists(copies[0])
