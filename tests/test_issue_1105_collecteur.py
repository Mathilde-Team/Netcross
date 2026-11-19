# SPDX-License-Identifier: GPL-3.0-or-later
"""Collecteur : inventaire, santé des sondes et schéma ``probe://`` (#1105).

Cinq niveaux, tous bout à bout dès que les outils sont présents :

- ``netcross_probe.serveur`` : l'agent sert santé, métadonnées et
  fenêtres en mTLS (stdlib ``http.server`` + contextes TLS #1101) ;
- ``netcross_probe.client`` : la moitié collecteur des mêmes appels --
  reprise unique des ``GET``/``DELETE``, ``POST`` jamais rejoué ;
- ``netcross_core.probe_capture`` : le point ``probe://`` -- la fenêtre
  est tirée à la fin de session puis lue par le pipeline habituel ;
- ``netcross_api.probe_routes`` : inventaire (``GET /probes``) et santé
  actuelle (``GET /probes/{id}/health``) côté collecteur, clé API ;
- ``cross_capture_analyzer_cli`` : le point ``probe://`` en ``--live``.

Les tests « réels » (tshark, editcap, capinfos, libpcap) sont sautés si
l'outil est absent du PATH, comme le reste du dépôt.
"""

from __future__ import annotations

import ctypes.util
import json
import shutil
import socket
import ssl
import struct

import pytest

fastapi = pytest.importorskip("fastapi", reason="extra [api] non installé")
from fastapi.testclient import TestClient  # noqa: E402 -- après importorskip
from pcap_builders import write_pcap  # noqa: E402

from netcross_api import probe_routes  # noqa: E402
from netcross_api.app import app  # noqa: E402
from netcross_core.probe_capture import (  # noqa: E402
    collecter_fenetre_sonde,
    est_source_sonde,
    url_sonde,
)
from netcross_probe import AgentProbe, ReglagesCapture  # noqa: E402
from netcross_probe.client import (  # noqa: E402
    ClientSonde,
    SondeInjoignableError,
    SondeRefusError,
    client_depuis_env,
)
from netcross_probe.securite import (  # noqa: E402
    creer_autorite,
    generer_cle_privee,
    generer_csr_sonde,
    signer_csr_sonde,
)
from netcross_probe.serveur import ServeurSonde  # noqa: E402
from pcap_parser.remote import CaptureSourceError, parse_source  # noqa: E402

LIBPCAP = ctypes.util.find_library("pcap")
TSHARK = shutil.which("tshark")
EDITCAP = shutil.which("editcap")
CAPINFOS = shutil.which("capinfos")

T0 = 1_791_000_000.0  # epoch arbitraire, seconde entière


def _trame(proto: int, sport: int, dport: int) -> bytes:
    """Trame Ethernet/IPv4 minimale mais décodable (TCP si proto=6, UDP si proto=17)."""
    if proto == 17:  # UDP : longueur 8 + charge 4, checksum 0
        segment = struct.pack("!HHHH", sport, dport, 8 + 4, 0) + b"\x00\x00\x00\x01"
    else:  # TCP : en-tête de 20 octets, drapeaux ACK
        segment = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, 0x10, 65535, 0, 0)
    total = 20 + len(segment)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total,
        1,
        0,
        64,
        proto,
        0,
        b"\x0a\x00\x00\x01",
        b"\x0a\x00\x00\x02",
    )
    return b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00" + ip + segment


def _paquets_tampon():
    """10 paquets de T0 à T0+9 : UDP sur les rangs pairs, TCP sur les impairs."""
    return [(int((T0 + i) * 1_000_000), _trame(17 if i % 2 == 0 else 6, 40000, 443)) for i in range(10)]


requis_reels = pytest.mark.skipif(
    TSHARK is None or EDITCAP is None or CAPINFOS is None,
    reason="tshark/editcap/capinfos absent du PATH",
)


# -- fabrique : autorité, sonde complète (serveur mTLS) --------------------------------------


def _faux_tampon(dossier, prefixe="probe"):
    """Un fichier de tampon circulaire, nommage tshark."""
    chemin = dossier / f"{prefixe}_00001_20261109120000.pcap"
    write_pcap(chemin, _paquets_tampon())
    return dossier


class _AgentSansCapture(AgentProbe):
    """AgentProbe sans enregistreur (les tests écrivent le tampon eux-mêmes)."""

    def __init__(self, dossier):
        reglages = ReglagesCapture(interface="eth0", dossier=str(dossier), prefixe="probe")
        super().__init__(reglages, dossier_fenetres=str(dossier))


@pytest.fixture()
def autorite():
    return creer_autorite(nom="CA test #1105")


@pytest.fixture()
def identite_sonde(autorite):
    """Certificat client de sonde + chaîne de l'autorité (mTLS)."""
    cle = generer_cle_privee()
    csr = generer_csr_sonde("SONDE-TEST", cle)
    certificat = signer_csr_sonde(csr, "prb_test1105sonde000001", autorite)
    return certificat, cle, autorite.certificat_pem


@pytest.fixture()
def serveur_sonde(tmp_path, identite_sonde):
    """La sonde en service : tampon écrit, ServeurSonde écoutant sur 127.0.0.1:0."""
    _faux_tampon(tmp_path)
    agent = _AgentSansCapture(tmp_path)
    serveur = ServeurSonde(agent, identite_sonde, "prb_test1105sonde000001", "SONDE-TEST", demarrer_capture=False)
    url = serveur.demarrer("127.0.0.1", 0)
    yield serveur, url
    serveur.arreter()


@pytest.fixture()
def client_sonde(serveur_sonde, identite_sonde):
    """Client mTLS du collecteur vers la sonde en service."""
    _serveur, url = serveur_sonde
    certificat, cle, ca = identite_sonde
    return ClientSonde(url, certificat, cle, ca, delai=5.0)


# -- 1. serveur : santé, métadonnées, cycle de vie d'une fenêtre ------------------------------


def test_sante_et_metadonnees_servies_en_mtls(client_sonde):
    sante = client_sonde.sante()
    assert sante["status"] in {"ok", "degraded", "failing"}
    assert sante["capturing"] is False  # aucun enregistreur dans le test
    assert sante["buffer"]["files"] == 1
    meta = client_sonde.metadonnees()
    assert meta["probe_id"] == "prb_test1105sonde000001"
    assert meta["probe_name"] == "SONDE-TEST"
    assert meta["api_version"] == "1.0"


@requis_reels
def test_fenetre_cycle_de_vie_complet(client_sonde, tmp_path):
    """POST -> description, GET -> pcapng avec Digest, DELETE -> 404 ensuite."""
    fenetre = client_sonde.demander_fenetre(T0 + 3, T0 + 6)
    assert fenetre["packet_count"] == 4
    assert fenetre["probe_id"] == "prb_test1105sonde000001"
    assert fenetre["covered"] == {"start": T0 + 3, "end": T0 + 6}
    assert fenetre["expires_at"] > 0
    identifiant = fenetre["window_id"]
    # description servie seule (GET /windows/{id})
    _statut, entetes, donnees = client_sonde._requete(f"/probe/v1/windows/{identifiant}", "GET")
    assert json.loads(donnees)["window_id"] == identifiant
    # pcapng : octets servis + en-tête Digest sha-256 conforme
    _statut, entetes, donnees = client_sonde._requete(f"/probe/v1/windows/{identifiant}/pcapng", "GET")
    assert donnees[:4] == b"\x0a\x0d\x0d\x0a"  # magie pcapng
    assert entetes["Digest"].startswith("sha-256=")
    # libération : 204 puis 404 window_unknown
    _statut, _entetes, _donnees = client_sonde._requete(f"/probe/v1/windows/{identifiant}", "DELETE")
    assert _statut == 204
    with pytest.raises(SondeRefusError, match="window_unknown"):
        client_sonde.telecharger_fenetre(identifiant)


@requis_reels
def test_fenetre_refus_explicites(client_sonde):
    """Bornes hors tampon : 404 window_not_buffered ; fenêtre trop
    grande : 413 window_too_large."""
    with pytest.raises(SondeRefusError) as refus:
        client_sonde.demander_fenetre(T0 + 100, T0 + 110)
    assert refus.value.statut == 404
    assert refus.value.code == "window_not_buffered"
    with pytest.raises(SondeRefusError) as refus:
        client_sonde.demander_fenetre(T0, T0 + 9, max_octets=10)
    assert refus.value.statut == 413
    assert refus.value.code == "window_too_large"


@pytest.mark.skipif(LIBPCAP is None, reason="libpcap absente")
@requis_reels
def test_fenetre_filtre_bpf_invalide_400(client_sonde):
    with pytest.raises(SondeRefusError) as refus:
        client_sonde.demander_fenetre(T0, T0 + 9, bpf="expression-invalide")
    assert refus.value.statut == 400
    assert refus.value.code == "invalid_bpf"


def test_fenetre_inconnue_404(client_sonde):
    with pytest.raises(SondeRefusError) as refus:
        client_sonde.telecharger_fenetre("win_inexistante")
    assert refus.value.statut == 404
    assert refus.value.code == "window_unknown"


def test_route_inconnue_404(client_sonde):
    with pytest.raises(SondeRefusError) as refus:
        client_sonde._requete("/probe/v1/autre-chose", "GET")
    assert refus.value.statut == 404
    assert refus.value.code == "not_found"


def test_mtls_sans_certificat_client_refuse(serveur_sonde):
    """Critère d'acceptation #1101 : aucune route sans certificat client --
    le refus a lieu pendant la poignée de main, pas par une route."""
    _serveur, url = serveur_sonde
    hote, port = url.partition("//")[2].split(":")
    contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    contexte.check_hostname = False
    contexte.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hote, int(port)), timeout=5) as brut:
        tls = contexte.wrap_socket(brut)
        # Refus de poignée de main : erreur TLS, ou fermeture d'autorité par
        # le serveur selon le timing -- les deux traduisent le même refus.
        with pytest.raises((ssl.SSLError, ConnectionResetError)):
            tls.send(b"x")
            tls.recv(1)


# -- 2. client : coupures réseau (reprise GET, POST jamais rejoué) ----------------------------


def test_client_sonde_injoignable():
    """Port fermé : erreur explicite, sans secret dans le message."""
    client = ClientSonde("https://127.0.0.1:1", "cert", "cle", "ca", delai=0.5)
    with pytest.raises(SondeInjoignableError):
        client.sante()


def test_get_reprise_apres_coupure_reseau(serveur_sonde, identite_sonde):
    """Première ouverture interrompue (``URLError``), seconde : succès."""
    _serveur, url = serveur_sonde
    certificat, cle, ca = identite_sonde
    client = ClientSonde(url, certificat, cle, ca, delai=5.0)
    ouvertures = []

    def _ouvrir_instable(requete, delai):
        if len(ouvertures) == 0:
            ouvertures.append("coupure")
            raise OSError("coupure simulée entre le collecteur et la sonde")
        ouvertures.append("ok")
        return ClientSonde._ouvrir(client, requete, delai)

    client._ouvrir = _ouvrir_instable
    sante = client.sante()
    assert sante["capturing"] is False
    assert ouvertures == ["coupure", "ok"]


def test_post_jamais_rejoue_apres_coupure(serveur_sonde, identite_sonde):
    """Une coupure pendant le POST ne crée pas une seconde fenêtre :
    l'échec est explicite dès le premier échec, un seul passage."""
    _serveur, url = serveur_sonde
    certificat, cle, ca = identite_sonde
    client = ClientSonde(url, certificat, cle, ca, delai=5.0)
    ouvertures = []

    def _ouvrir_toujours_coupe(requete, delai):
        ouvertures.append("coupure")
        raise OSError("coupure simulée pendant le POST")

    client._ouvrir = _ouvrir_toujours_coupe
    with pytest.raises(SondeInjoignableError):
        client.demander_fenetre(T0, T0 + 1)
    assert ouvertures == ["coupure"]  # un seul passage : jamais de second POST


def test_client_depuis_env_exige_les_trois_identites():
    """Identités manquantes : refus explicite, sans certificat la poignée
    de main serait refusée de toute façon (« aucune écoute sans mTLS »)."""
    with pytest.raises(SondeInjoignableError, match="NETCROSS_PROBE_CERT_PEM"):
        client_depuis_env("https://sonde:9443", env={})


# -- 3. collecteur : inventaire et santé (clé API) -------------------------------------------


@pytest.fixture()
def client_collecteur():
    probe_routes.registre_sondes = probe_routes.RegistreSondes()
    return TestClient(app), probe_routes.registre_sondes


def _inscrire(client, registre, nom="SONDE-TEST", **extra):
    cle = generer_cle_privee()
    csr = generer_csr_sonde(nom, cle)
    corps = {
        "probe_name": nom,
        "csr_pem": csr,
        "agent_version": "1.0",
        "api_versions": ["1.0", "1.1"],
        **extra,
    }
    reponse = client.post(
        "/probe/v1/enrollments",
        headers={"Authorization": f"Bearer {registre.creer_jeton()}"},
        json=corps,
    )
    return reponse


def test_inventaire_liste_les_sondes_inscrites(client_collecteur):
    client, registre = client_collecteur
    reponse = _inscrire(client, registre, listen_base_url="https://sonde.example.net:9443")
    assert reponse.status_code == 201
    inventaire = client.get("/probes")
    assert inventaire.status_code == 200
    fiches = inventaire.json()["probes"]
    assert [f["probe_name"] for f in fiches] == ["SONDE-TEST"]
    fiche = fiches[0]
    assert fiche["listen_base_url"] == "https://sonde.example.net:9443"
    assert fiche["revoked"] is False
    assert fiche["certificate_expires_at"] > 0


def test_enrolement_listen_base_url_non_https_refuse(client_collecteur):
    client, registre = client_collecteur
    reponse = _inscrire(client, registre, listen_base_url="http://sonde.example.net:9443")
    assert reponse.status_code == 400
    assert reponse.json()["error"] == "invalid_request"


def test_sante_sonde_inconnue_404(client_collecteur):
    client, _registre = client_collecteur
    reponse = client.get("/probes/prb_nimporte/health")
    assert reponse.status_code == 404
    assert reponse.json()["error"] == "probe_unknown"


def test_sante_sonde_sans_adresse_annoncee_409(client_collecteur):
    """Une sonde 1.0 (sans ``listen_base_url``) est inscrite mais pas
    interrogeable en direct : refus explicite, jamais une santé inventée."""
    client, registre = client_collecteur
    reponse = _inscrire(client, registre, nom="SONDE-SANS-ADRESSE")
    assert reponse.status_code == 201
    probe_id = reponse.json()["probe_id"]
    sante = client.get(f"/probes/{probe_id}/health")
    assert sante.status_code == 409
    assert sante.json()["error"] == "probe_address_unknown"


def test_sante_sonde_muette_502(client_collecteur):
    """Adresse annoncée mais sonde muette : 502 explicite (le port est fermé)."""
    client, registre = client_collecteur
    reponse = _inscrire(client, registre, listen_base_url="https://127.0.0.1:1")
    assert reponse.status_code == 201
    probe_id = reponse.json()["probe_id"]
    sante = client.get(f"/probes/{probe_id}/health")
    assert sante.status_code == 502
    assert sante.json()["error"] == "sonde_injoignable"


def test_sante_sonde_revoquee_401(client_collecteur):
    client, registre = client_collecteur
    reponse = _inscrire(client, registre, listen_base_url="https://127.0.0.1:1")
    probe_id = reponse.json()["probe_id"]
    registre.revoquer(probe_id)
    sante = client.get(f"/probes/{probe_id}/health")
    assert sante.status_code == 401
    assert sante.json()["error"] == "probe_revoked"


def test_inventaire_et_sante_bout_en_bout(client_collecteur, tmp_path):
    """La boucle complète : enrôlement réel (certificat signé par
    l'autorité du collecteur), sonde en service avec cette identité,
    inventaire, puis santé actuelle lue en mTLS par le collecteur."""
    client, registre = client_collecteur
    # un port libre pour la sonde : l'adresse est annoncée à l'enrôlement
    reserve = socket.socket()
    reserve.bind(("127.0.0.1", 0))
    port = reserve.getsockname()[1]
    reserve.close()
    cle = generer_cle_privee()
    csr = generer_csr_sonde("SONDE-E2E", cle)
    reponse = client.post(
        "/probe/v1/enrollments",
        headers={"Authorization": f"Bearer {registre.creer_jeton()}"},
        json={
            "probe_name": "SONDE-E2E",
            "csr_pem": csr,
            "agent_version": "1.0",
            "api_versions": ["1.0", "1.1"],
            "listen_base_url": f"https://127.0.0.1:{port}",
        },
    )
    assert reponse.status_code == 201
    corps = reponse.json()
    probe_id = corps["probe_id"]
    # la sonde sert avec l'identité signée par l'autorité du collecteur
    _faux_tampon(tmp_path)
    agent = _AgentSansCapture(tmp_path)
    serveur = ServeurSonde(
        agent,
        (corps["client_certificate_pem"], cle, corps["ca_chain_pem"]),
        probe_id,
        "SONDE-E2E",
        demarrer_capture=False,
    )
    url = serveur.demarrer("127.0.0.1", port)
    try:
        inventaire = client.get("/probes").json()["probes"]
        assert [f["probe_id"] for f in inventaire] == [probe_id]
        assert inventaire[0]["listen_base_url"] == url
        sante = client.get(f"/probes/{probe_id}/health")
        assert sante.status_code == 200
        assert sante.json()["capturing"] is False
        assert sante.json()["status"] in {"ok", "degraded", "failing"}
        # la santé lue est mémorisée pour l'inventaire (dernière connue)
        inventaire = client.get("/probes").json()["probes"]
        assert inventaire[0]["health"]["status"] in {"ok", "degraded", "failing"}
    finally:
        serveur.arreter()


# -- 4. schéma probe:// (analyse d'URL, refus explicites) ------------------------------------


def test_probe_url_est_une_source_sonde():
    assert est_source_sonde("probe://sonde.lan:9443/ROUTEUR")
    assert est_source_sonde("probe://sonde.lan/ROUTEUR")
    assert est_source_sonde("probe://sonde.lan")
    assert not est_source_sonde("eth0")
    assert not est_source_sonde("rpcap://hote/eth0")
    assert not est_source_sonde("probe://")  # URL invalide : faux, pas une exception


def test_probe_url_hote_port_et_nom_de_sonde():
    source = parse_source("probe://sonde.lan:9443/ROUTEUR")
    assert source.kind == "probe"
    assert url_sonde("probe://sonde.lan:9443/ROUTEUR") == "https://sonde.lan:9443"
    assert url_sonde("probe://sonde.lan") == "https://sonde.lan:9443"


def test_probe_url_refuse_utilisateur():
    """Le schéma probe:// n'embarque pas d'identifiants : refus explicite."""
    with pytest.raises(CaptureSourceError):
        parse_source("probe://utilisateur@sonde.lan/")


def test_collecter_fenetre_sonde_via_point_probe(serveur_sonde, identite_sonde, monkeypatch):
    """Le point probe:// complet : fenêtre tirée puis lue par le même
    pipeline que --capture (parse_capture)."""
    if TSHARK is None or EDITCAP is None or CAPINFOS is None or LIBPCAP is None:
        pytest.skip("tshark/editcap/capinfos ou libpcap absent du PATH")
    _serveur, url = serveur_sonde
    certificat, cle, ca = identite_sonde
    hote, port = url.partition("//")[2].split(":")
    point = f"probe://{hote}:{port}/SONDE-TEST"
    monkeypatch.setenv("NETCROSS_PROBE_CERT_PEM", certificat)
    monkeypatch.setenv("NETCROSS_PROBE_KEY_PEM", cle)
    monkeypatch.setenv("NETCROSS_PROBE_CA_PEM", ca)
    # le tampon couvre [T0, T0+9] : la fenêtre demandée est celle-là
    pkts = collecter_fenetre_sonde("SONDE-TEST", point, T0, T0 + 9)
    assert len(pkts) == 10


# -- 5. CLI --live : le point probe:// tire sa fenêtre à l'arrêt -------------------------------


def test_cli_point_probe_tire_sa_fenetre_a_l_arret(monkeypatch, capsys):
    """--live DMZ:probe://… : rien pendant la session, la fenêtre est
    tirée à l'arrêt (durée atteinte) puis rejoint les autres paquets."""
    import cross_capture_analyzer_cli as analyzer_cli
    from tests.conftest import make_pkt

    appels = {}

    def _fausse_collecte(label, iface, debut, fin, bpf=None, **_kwargs):
        appels.update({"label": label, "iface": iface, "bpf": bpf, "fenetre": (debut, fin)})
        return [make_pkt(src="10.0.0.1", dst="10.0.0.2", dport=443, ts=1000.0, point=label)]

    monkeypatch.setattr(analyzer_cli, "collecter_fenetre_sonde", _fausse_collecte)
    paquets = analyzer_cli._run_live_captures(["DMZ:probe://sonde.lan:9443/ROUTEUR"], duration=0.05)
    assert appels["label"] == "DMZ"
    assert appels["iface"] == "probe://sonde.lan:9443/ROUTEUR"
    assert appels["bpf"] is None
    assert appels["fenetre"][1] > appels["fenetre"][0]  # [début de session, arrêt]
    assert [p.point for p in paquets] == ["DMZ"]
    assert "fenêtre de sonde lue" in capsys.readouterr().out


def test_cli_point_probe_erreur_ne_tue_pas_la_session(monkeypatch, capsys):
    """Une sonde injoignable est rapportée sur ce point ; la session se
    termine (les autres points, s'il y en a, ne sont pas privés d'analyse)."""
    import cross_capture_analyzer_cli as analyzer_cli

    def _collecte_impossible(*_args, **_kwargs):
        raise OSError("sonde injoignable (test CLI)")

    monkeypatch.setattr(analyzer_cli, "collecter_fenetre_sonde", _collecte_impossible)
    paquets = analyzer_cli._run_live_captures(["DMZ:probe://sonde.lan:9443/ROUTEUR"], duration=0.05)
    assert paquets == []
    sortie = capsys.readouterr()
    assert "ERREUR : sonde injoignable ou refus" in sortie.err


def test_cli_parse_live_spec_probe():
    """Le point probe:// se spécifie comme toute source distante : label,
    URL (nom de sonde dans le chemin pour accoler un filtre BPF)."""
    import cross_capture_analyzer_cli as analyzer_cli

    assert analyzer_cli._parse_live_spec("DMZ:probe://sonde.lan:9443/ROUTEUR") == (
        "DMZ",
        "probe://sonde.lan:9443/ROUTEUR",
        None,
    )
    assert analyzer_cli._parse_live_spec("DMZ:probe://sonde.lan:9443/ROUTEUR:tcp port 443") == (
        "DMZ",
        "probe://sonde.lan:9443/ROUTEUR",
        "tcp port 443",
    )
