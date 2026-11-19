# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests app.py -- export HTML et extraits pcap de preuve (issue #1083).

Methodes couvertes : `on_export_html`, `_on_html_path_chosen`,
`export_html_to`, `on_extraire_pcaps_preuve`, `_on_evidence_dir_chosen`,
`extraire_pcaps_preuve_dans`.

Même garde-fou GTK4/CI que `tests/test_app_gtk4_lot9.py` : GTK4 n'est pas
installable partout, tout le module est ignoré dans ce cas ; aucun test
n'exige GTK4 en CI. Le pipeline HTML est pur Python
(voir `netcross_report.html_report`) : le vrai `generate_html_report`
est utilisé, seul le sélecteur de fichiers est doublé (pas de portail
D-Bus en CI). L'extraction des preuves pcap utilise un vrai fichier
pcap synthétique (même esprit que `tests/test_evidence_pcaps.py`).
"""

from __future__ import annotations

import pathlib
import struct

import pytest
from conftest import make_pkt
from gtk4_display import exiger_gtk4_avec_affichage

Gtk = exiger_gtk4_avec_affichage()
from gi.repository import GLib  # noqa: E402

import netcross_gtk4.app as app_module  # noqa: E402
from netcross_core.analysis import analyse  # noqa: E402
from netcross_core.correlate import correlate  # noqa: E402
from netcross_gtk4.app import MainWindow  # noqa: E402
from netcross_report import build_findings  # noqa: E402


@pytest.fixture(scope="module")
def window():
    app = Gtk.Application(application_id="org.netcross.test1083")
    app.register(None)
    return MainWindow(app)


def _analysis_result():
    """Report + flows minimaux mais réels, comme test_app_gtk4_lot9."""
    pkts = [
        make_pkt(point="A", src="10.0.0.1", dst="10.0.0.2", proto="TCP", sport=1111, dport=443, frame_number=1),
        make_pkt(point="B", src="10.0.0.1", dst="10.0.0.2", proto="TCP", sport=1111, dport=443, frame_number=1),
        make_pkt(point="A", src="10.0.0.1", dst="10.0.0.3", proto="UDP", sport=2222, dport=53, frame_number=2),
        make_pkt(point="B", src="10.0.0.1", dst="10.0.0.3", proto="UDP", sport=2222, dport=53, frame_number=2),
    ]
    flows = correlate(pkts)
    report = analyse(flows, ["A", "B"], pkts)
    return report, flows


def _appliquer_run_single(window, report, flows):
    """État minimal d'un run "single" terminé (comme test_app_gtk4_lot9)."""
    window.last_mode = "single"
    window.last_report = report
    window.last_flows = flows
    window.last_findings = None
    window.last_tls_findings = None
    window.last_quic_findings = None
    window.last_wireshark_expert_events = None
    window.last_security_report = None


class _FakeSaveDialog:
    """Remplace `Gtk.FileDialog` : `save()` appelle la callback
    immédiatement avec un chemin fixe, `save_finish()` le restitue."""

    def __init__(self, path):
        self._path = path
        self.initial_name = None

    def set_initial_name(self, name):
        self.initial_name = name

    def save(self, parent, cancellable, callback):
        callback(self, None)

    def save_finish(self, result):
        return _FakeGFile(self._path)


class _FakeFolderDialog:
    """Doublure minimale pour `select_folder()` (issue #1083)."""

    def __init__(self, path):
        self._path = path

    def select_folder(self, parent, cancellable, callback):
        callback(self, None)

    def select_folder_finish(self, result):
        return _FakeGFile(self._path)


class _FakeGFile:
    def __init__(self, path):
        self._path = path

    def get_path(self):
        return self._path


def _trame_ethernet_ipv4(numero: int) -> bytes:
    """Trame Ethernet/IPv4 minimale et déterministe (adresse dans le
    pseudo-random du test, pas de dépendance au contenu)."""
    src = bytes.fromhex("f81e34abcd01") + struct.pack("!B", numero)
    dst = bytes.fromhex("f81e34abcd02")
    entete_ip = struct.pack("!BBHHHBBH", 0x45, 0, 40, numero, 0x4000, 64, 6, 0)
    return dst + src + b"\x08\x00" + entete_ip + b"\x00" * 20


def _ecrire_pcap(chemin: pathlib.Path, trames: list[bytes]) -> None:
    """Écrit un pcap classique (lien Ethernet) avec une trame par numéro."""
    with open(chemin, "wb") as sortie:
        sortie.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for numero, trame in enumerate(trames, 1):
            sortie.write(struct.pack("<IIII", numero * 1_000_000, 0, len(trame), len(trame)))
            sortie.write(trame)


# -- Export HTML ------------------------------------------------------------


def test_on_export_html_sans_analyse_ne_fait_rien(window, monkeypatch):
    """Sans analyse simple (last_mode None), aucun dialogue n'est ouvert."""
    window.last_mode = None
    appels = {"n": 0}

    def _fake_dialog():
        appels["n"] += 1
        return _FakeSaveDialog("/tmp/inutilise.html")

    monkeypatch.setattr(app_module.Gtk, "FileDialog", _fake_dialog)

    window.on_export_html(None)

    assert appels["n"] == 0


def test_on_export_html_declenche_lexport_reel(window, monkeypatch, tmp_path):
    """Chaîne complète : on_export_html -> _on_html_path_chosen ->
    export_html_to. Le pipeline HTML est pur Python : le vrai
    `generate_html_report` est utilisé."""
    report, flows = _analysis_result()
    _appliquer_run_single(window, report, flows)

    dest = str(tmp_path / "rapport_analyse.html")
    monkeypatch.setattr(app_module.Gtk, "FileDialog", lambda: _FakeSaveDialog(dest))

    window.on_export_html(None)

    assert f"Rapport HTML ecrit dans {dest}" == window.status_label.get_text()
    assert pathlib.Path(dest).exists()
    contenu = pathlib.Path(dest).read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in contenu
    # Rapport autonome : aucune ressource externe chargée (src/href)
    assert 'src="http' not in contenu
    assert 'href="http' not in contenu


def test_export_html_inclut_constats_et_preuves(window, monkeypatch, tmp_path):
    """export_html_to embarque les constats (build_findings) et, si les
    extraits pcap de preuve ont été produits, leur nom de fichier (lien
    relatif, jamais d'URL absolue)."""
    report, flows = _analysis_result()
    _appliquer_run_single(window, report, flows)
    window.last_findings = build_findings(report)

    source = tmp_path / "A.pcap"
    _ecrire_pcap(source, [_trame_ethernet_ipv4(1), _trame_ethernet_ipv4(2)])
    window._annotation_captures = [("A", str(source))]
    window._last_redactor = None
    from netcross_core.expert_model import EvidenceLink, PacketEvidence
    from netcross_report.synthesis import Finding

    window.last_findings = [
        Finding(
            severity="P1",
            category="TCP",
            segment="A->B",
            message="retransmission en rafale",
            evidence=[EvidenceLink("A", "trame 2", packet=PacketEvidence("A", 2))],
        )
    ]

    extraits = window.extraire_pcaps_preuve_dans(str(tmp_path))
    assert extraits, "l'extraction doit produire au moins un extrait"
    nom_extrait = extraits[0]["fichier"]
    assert pathlib.Path(tmp_path / nom_extrait).exists()

    dest = str(tmp_path / "rapport.html")
    monkeypatch.setattr(app_module.Gtk, "FileDialog", lambda: _FakeSaveDialog(dest))
    window.on_export_html(None)

    contenu = pathlib.Path(dest).read_text(encoding="utf-8")
    assert nom_extrait in contenu  # lien relatif vers l'extrait
    assert 'href="http' not in contenu


def test_export_html_erreur_os_statut(window, monkeypatch, tmp_path):
    """Une OSError pendant l'écrit pose le statut d'erreur sans lever."""
    report, flows = _analysis_result()
    _appliquer_run_single(window, report, flows)

    def _lever(*a, **k):
        raise OSError("disque plein")

    monkeypatch.setattr("netcross_report.html_report.generate_html_report", _lever)
    assert window.export_html_to(str(tmp_path / "x.html")) is None
    assert "Erreur HTML" in window.status_label.get_text()


# -- Extraits pcap de preuve --------------------------------------------------


def test_extraire_pcaps_preuve_dans_ecrit_les_extraits(window, tmp_path):
    """extraire_pcaps_preuve_dans écrit un pcapng par constat (vrai
    fichier pcap source), garde les refs pour le rapport HTML et pose le
    statut avec le nombre d'extraits."""
    report, flows = _analysis_result()
    _appliquer_run_single(window, report, flows)

    source = tmp_path / "A.pcap"
    _ecrire_pcap(source, [_trame_ethernet_ipv4(i) for i in range(1, 6)])
    window._annotation_captures = [("A", str(source))]
    window._last_redactor = None

    from netcross_core.expert_model import EvidenceLink, PacketEvidence
    from netcross_report.synthesis import Finding

    window.last_findings = [
        Finding(
            severity="P1",
            category="TCP",
            segment="A->B",
            message="retransmission en rafale",
            evidence=[EvidenceLink("A", "trame 3", packet=PacketEvidence("A", 3))],
        )
    ]

    dossier = tmp_path / "preuves"
    dossier.mkdir()
    window.last_evidence_pcaps = None
    extraits = window.extraire_pcaps_preuve_dans(str(dossier))

    assert extraits
    assert window.last_evidence_pcaps is extraits
    fichiers = {e["fichier"] for e in extraits}
    for nom in fichiers:
        assert (dossier / nom).is_file()
    assert "extrait(s) pcap de preuve" in window.status_label.get_text()


def test_on_evidence_dir_chosen_erreur_glib_ne_leve_pas(window, monkeypatch):
    """`select_folder_finish` peut lever GLib.Error (annulation) :
    `_on_evidence_dir_chosen` l'avale sans appeler l'extraction."""
    report, flows = _analysis_result()
    _appliquer_run_single(window, report, flows)
    appele = {"n": 0}
    monkeypatch.setattr(window, "extraire_pcaps_preuve_dans", lambda _d: appele.__setitem__("n", appele["n"] + 1))

    class _DialogEnErreur:
        def select_folder_finish(self, result):
            raise GLib.Error("annule par l'utilisateur")

    window._on_evidence_dir_chosen(_DialogEnErreur(), None)

    assert appele["n"] == 0
