# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #1047 : les secrets de déchiffrement ne sortent jamais de l'analyse.

Un run complet est lancé avec un fichier de clés (``--tls-keylog``) puis avec
les mêmes secrets embarqués dans la capture (bloc DSB, ``editcap
--inject-secrets``). Toutes les sorties produites sont ensuite relues octet
par octet à la recherche des secrets : rapports texte, Markdown, JSON, PDF
(brut et texte extrait), HTML de sécurité, export SIEM, journal Zeek, base
d'historique SQLite, ticket de support, contenus extraits, sortie standard,
sortie d'erreur et tous les messages loguru, TRACE compris. Le même contrôle
est fait sur l'API (réponses et entrée du magasin d'analyses).

Les exports de CAPTURE (``--export-pcap``, ``--merge``, ``--split``...) sont
hors de ce périmètre : ce sont des copies de la capture d'entrée, qui gardent
ses blocs DSB comme le fait Wireshark (voir docs/couverture-dechiffrement.md).
"""

from __future__ import annotations

import base64
import contextlib
import importlib
import io
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from loguru import logger

import cross_capture_analyzer_cli as cli

sys.path.insert(0, str(Path(__file__).parent))
from tls13_keylog_capture import URI, ecrire_capture  # noqa: E402

pytestmark = pytest.mark.skipif(
    shutil.which("tshark") is None or shutil.which("editcap") is None, reason="tshark/editcap absents"
)


def formes_des_secrets(keylog: Path) -> set[bytes]:
    """Toutes les formes sous lesquelles un secret du fichier de clés pourrait
    fuir : hexadécimal (minuscules, majuscules, séparé par « : »), octets
    bruts et base64 -- pour le client_random comme pour le secret."""
    formes: set[bytes] = set()
    for ligne in keylog.read_text().splitlines():
        champs = ligne.split()
        if len(champs) != 3:
            continue
        for valeur in champs[1:]:
            brut = bytes.fromhex(valeur)
            deux_points = ":".join(valeur[i : i + 2] for i in range(0, len(valeur), 2))
            formes |= {valeur.lower().encode(), valeur.upper().encode(), deux_points.encode()}
            formes |= {brut, base64.b64encode(brut)}
    return formes


def fuites(contenus: dict[str, bytes], formes: set[bytes]) -> dict[str, int]:
    """``{sortie: nombre de formes de secret trouvées}`` des sorties fautives."""
    return {nom: n for nom, data in contenus.items() if (n := sum(1 for f in formes if f in data))}


def relire(dossier: Path) -> dict[str, bytes]:
    """Contenu de chaque fichier produit sous ``dossier`` ; un PDF est aussi
    relu en texte (ses flux sont compressés)."""
    contenus = {}
    for chemin in sorted(p for p in dossier.rglob("*") if p.is_file()):
        data = chemin.read_bytes()
        if chemin.suffix == ".pdf" and shutil.which("pdftotext"):
            data += subprocess.run(["pdftotext", str(chemin), "-"], capture_output=True, check=False).stdout
        contenus[str(chemin.relative_to(dossier))] = data
    return contenus


@pytest.fixture(scope="module")
def session(tmp_path_factory):
    pytest.importorskip("cryptography")
    dossier = tmp_path_factory.mktemp("non-fuite")
    capture, keylog = ecrire_capture(dossier / "entree")
    dsb = dossier / "entree" / "dsb.pcapng"
    subprocess.run(["editcap", "--inject-secrets", f"tls,{keylog}", str(capture), str(dsb)], check=True)
    return capture, keylog, dsb


def _run_complet(argv_capture: list[str], sorties: Path, monkeypatch) -> dict[str, bytes]:
    sorties.mkdir()
    argv = [
        "prog",
        *argv_capture,
        "--tls",
        "--quic",
        "--security-report",
        "--security-html",
        str(sorties / "securite.html"),
        "--pdf-report",
        str(sorties / "rapport.pdf"),
        "--json-report",
        str(sorties / "rapport.json"),
        "--md-report",
        str(sorties / "rapport.md"),
        "--siem-export",
        "cef",
        "--siem-output",
        str(sorties / "siem.cef"),
        "--zeek-conn",
        str(sorties / "conn.log"),
        "--history-db",
        str(sorties / "historique.db"),
        "--support-ticket",
        str(sorties / "ticket.json"),
        "--support-consent",
        "--extract-contents",
        str(sorties / "contenus"),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    journal = io.StringIO()
    sink = logger.add(journal, level=0, format="{message} {extra} {exception}")
    try:
        with (
            contextlib.redirect_stdout(io.StringIO()) as sortie,
            contextlib.redirect_stderr(io.StringIO()) as erreurs,
            contextlib.suppress(SystemExit),
        ):
            cli.main()
    finally:
        logger.remove(sink)
    contenus = relire(sorties)
    contenus |= {"stdout": sortie.getvalue().encode(), "stderr": erreurs.getvalue().encode()}
    contenus["loguru"] = journal.getvalue().encode()
    return contenus


ATTENDUES = {"securite.html", "rapport.pdf", "rapport.json", "rapport.md", "siem.cef", "conn.log"}
ATTENDUES |= {"historique.db", "ticket.json", "contenus/manifest.json"}


def test_formes_et_detection(session):
    assert fuites({"a": b"xx 0a0b yy", "b": b"rien"}, {b"0a0b"}) == {"a": 1}
    _, keylog, dsb = session
    formes = formes_des_secrets(keylog)
    assert len(formes) >= 5 * 4  # client_random + 4 secrets TLS 1.3, au moins 4 formes distinctes chacun
    # témoin : la recherche trouve bien les secrets là où ils sont
    temoin = fuites({"cles": keylog.read_bytes(), "dsb": dsb.read_bytes(), "rien": b"netcross"}, formes)
    assert set(temoin) == {"cles", "dsb"}


def test_run_avec_fichier_de_cles(session, tmp_path, monkeypatch):
    capture, keylog, _ = session
    contenus = _run_complet(["--capture", f"A={capture}", "--tls-keylog", f"A={keylog}"], tmp_path / "s", monkeypatch)
    assert set(contenus) >= ATTENDUES
    assert URI.encode() in contenus["stdout"] + contenus["rapport.json"]  # le déchiffrement a bien eu lieu
    assert b"main: fin" in contenus["loguru"]  # journal loguru capturé, niveau debug compris
    assert fuites(contenus, formes_des_secrets(keylog)) == {}


def test_run_avec_bloc_dsb(session, tmp_path, monkeypatch):
    _, keylog, dsb = session
    contenus = _run_complet(["--capture", f"A={dsb}"], tmp_path / "s", monkeypatch)
    assert set(contenus) >= ATTENDUES
    assert b"bloc(s) DSB" in contenus["stdout"]
    assert any(name.startswith("contenus/documents/") for name in contenus)  # contenu HTTP déchiffré extrait
    assert fuites(contenus, formes_des_secrets(keylog)) == {}


def test_api_sans_fuite(session, monkeypatch):
    pytest.importorskip("fastapi", reason="extra [api] non installé")
    pytest.importorskip("multipart", reason="python-multipart non installé")
    from fastapi.testclient import TestClient

    module = importlib.import_module("netcross_api.app")
    client = TestClient(module.app)
    capture, keylog, _ = session
    journal = io.StringIO()
    sink = logger.add(journal, level=0, format="{message} {extra}")
    try:
        fichiers = [("file", ("a.pcap", capture.read_bytes())), ("tls_keylog", ("keys.txt", keylog.read_bytes()))]
        reponse = client.post("/captures?wait=true", data={"label": "P1", "tls": "true"}, files=fichiers)
        assert reponse.status_code == 201, reponse.text
        identifiant = reponse.json()["analysis_id"]
        contenus = {
            "creation": reponse.content,
            "analyse": client.get(f"/analyses/{identifiant}").content,
            "rapport": client.get(f"/analyses/{identifiant}/report").content,
            "magasin": repr(module.store.get(identifiant)).encode(),
        }
    finally:
        logger.remove(sink)
    contenus["loguru"] = journal.getvalue().encode()
    assert URI.encode() in contenus["rapport"]
    assert fuites(contenus, formes_des_secrets(keylog)) == {}
