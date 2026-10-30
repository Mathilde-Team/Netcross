"""Tests du générateur de jeux synthétiques multi-points (issue #1015).

La relecture des fichiers passe par ``tests/pcap_builders.read_pcapng``,
indépendant du générateur : un bogue d'écriture ne peut pas être masqué par
le même bogue à la lecture. Les vérifications « métier » (pertes vues par
Netcross au bon segment, sommes de contrôle, SNI) passent par tshark et sont
sautées s'il est absent.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import struct
import subprocess

import pytest
from pcap_builders import read_pcapng

from netcross_core.testing import synth
from netcross_core.testing.synth import Configuration, generer

EPB = 0x6
TSHARK = shutil.which("tshark")


def _paquets(chemin):
    """[(horodatage_ns, trame), ...] des EPB du fichier, dans l'ordre."""
    sortie = []
    for type_bloc, corps, _interface, donnees in read_pcapng(chemin):
        if type_bloc == EPB:
            _if, haut, bas = struct.unpack_from("<III", corps, 0)
            sortie.append(((haut << 32) | bas, donnees))
    return sortie


def _empreintes(dossier, points):
    return [hashlib.sha256((dossier / f"P{i + 1}.pcapng").read_bytes()).hexdigest() for i in range(points)]


def _signature(trame):
    """Identité d'un paquet indépendante du point (TTL et somme IP exclus)."""
    ip = trame[14:]
    return ip[:8] + ip[12:20] + ip[20:]


# -- déterminisme -------------------------------------------------------------


def test_meme_graine_memes_octets(tmp_path):
    cfg = {"points": 3, "paquets": 2000, "graine": 42, "segment_perte": 1, "taux_perte": 0.05}
    v1 = generer(Configuration(**cfg), tmp_path / "a")
    v2 = generer(Configuration(**cfg), tmp_path / "b")
    assert _empreintes(tmp_path / "a", 3) == _empreintes(tmp_path / "b", 3)
    assert v1 == v2
    assert (tmp_path / "a" / "verite.json").read_bytes() == (tmp_path / "b" / "verite.json").read_bytes()


def test_graines_differentes_octets_differents(tmp_path):
    generer(Configuration(points=2, paquets=500, graine=1), tmp_path / "a")
    generer(Configuration(points=2, paquets=500, graine=2), tmp_path / "b")
    assert _empreintes(tmp_path / "a", 2) != _empreintes(tmp_path / "b", 2)


def test_empreintes_de_la_verite_correspondent_aux_fichiers(tmp_path):
    verite = generer(Configuration(points=2, paquets=300), tmp_path)
    assert verite["fichiers"] == {f"P{i + 1}.pcapng": h for i, h in enumerate(_empreintes(tmp_path, 2))}
    assert json.loads((tmp_path / "verite.json").read_text(encoding="utf-8")) == verite


# -- format pcapng ------------------------------------------------------------


def test_entete_nanoseconde_et_nom_du_point(tmp_path):
    generer(Configuration(points=2, paquets=50), tmp_path)
    blocs = read_pcapng(tmp_path / "P2.pcapng")
    assert blocs[0][0] == 0x0A0D0D0A
    assert blocs[1][0] == 0x1
    idb = blocs[1][1]
    assert struct.unpack_from("<H", idb, 0)[0] == 1  # LINKTYPE_ETHERNET
    assert b"P2" in idb
    assert struct.pack("<HHB", 9, 1, 9) in idb  # if_tsresol = 10^-9


def test_horodatages_monotones_et_volume(tmp_path):
    verite = generer(Configuration(points=3, paquets=3000, gigue_ms=0.5, decalages_ms=[0, -2.5, 7]), tmp_path)
    for nom in verite["points"]:
        paquets = _paquets(tmp_path / f"{nom}.pcapng")
        assert len(paquets) == verite["paquets_par_point"][nom]
        horodatages = [ts for ts, _ in paquets]
        assert horodatages == sorted(horodatages)
    assert verite["paquets_emis"] == 3000
    assert verite["decalages_horloge_ms"] == {"P1": 0.0, "P2": -2.5, "P3": 7.0}


def test_sommes_de_controle_ip_valides(tmp_path):
    generer(Configuration(points=2, paquets=200), tmp_path)
    for _ts, trame in _paquets(tmp_path / "P2.pcapng"):
        assert synth._somme_controle(trame[14:34]) == 0


def test_somme_controle_longueur_impaire():
    assert synth._somme_controle(b"\x01") == synth._somme_controle(b"\x01\x00")


# -- vérité terrain : pertes, retards, horloges ---------------------------------


def test_pertes_au_bon_segment_et_comptees_exactement(tmp_path):
    verite = generer(Configuration(points=4, paquets=5000, graine=3, segment_perte=2, taux_perte=0.1), tmp_path)
    vus = verite["paquets_par_point"]
    perdus = verite["perte"]["paquets_perdus"]
    assert perdus > 0
    assert vus["P1"] == vus["P2"] == 5000
    assert vus["P3"] == vus["P4"] == 5000 - perdus
    assert sum(verite["perte"]["par_type"].values()) == perdus
    assert verite["perte"]["par_type"]["dns"] == 0
    p2 = {_signature(t) for _, t in _paquets(tmp_path / "P2.pcapng")}
    p3 = {_signature(t) for _, t in _paquets(tmp_path / "P3.pcapng")}
    assert p3 <= p2
    assert len(p2 - p3) == perdus


def test_pertes_sens_retour(tmp_path):
    verite = generer(
        Configuration(points=3, paquets=4000, graine=5, segment_perte=1, taux_perte=0.2, sens_perte="retour"),
        tmp_path,
    )
    perdus = verite["perte"]["paquets_perdus"]
    vus = verite["paquets_par_point"]
    assert perdus > 0
    assert vus["P3"] == vus["P2"] == 4000
    assert vus["P1"] == 4000 - perdus
    assert verite["perte"]["par_type"]["udp"] == 0  # flux UDP synthétiques : sens aller seulement


def test_pertes_les_deux_sens(tmp_path):
    verite = generer(
        Configuration(points=2, paquets=4000, graine=5, segment_perte=1, taux_perte=0.2, sens_perte="les_deux"),
        tmp_path,
    )
    vus = verite["paquets_par_point"]
    assert vus["P1"] < 4000
    assert vus["P2"] < 4000
    assert 8000 - vus["P1"] - vus["P2"] == verite["perte"]["paquets_perdus"]


def test_poignee_de_main_jamais_perdue(tmp_path):
    generer(Configuration(points=2, paquets=3000, segment_perte=1, taux_perte=1.0, melange={"tcp": 1}), tmp_path)

    def aller(chemin):
        return [t for _, t in _paquets(chemin) if t[6:12] == synth._MAC_CLIENT]

    p1, p2 = aller(tmp_path / "P1.pcapng"), aller(tmp_path / "P2.pcapng")
    syn = [t for t in p1 if t[14 + 20 + 13] == 0x02]
    assert syn
    assert len([t for t in p2 if t[14 + 20 + 13] == 0x02]) == len(syn)
    assert any(len(t) > 54 for t in p1)  # des données partent de P1…
    assert all(len(t) == 54 for t in p2)  # …aucune n'arrive à P2 : seuls SYN/ACK/FIN, sans charge


def test_taux_nul_aucune_perte(tmp_path):
    verite = generer(Configuration(points=2, paquets=500, segment_perte=1, taux_perte=0.0), tmp_path)
    assert verite["perte"]["paquets_perdus"] == 0


def test_retard_sur_le_tiers_central(tmp_path):
    cfg = {"points": 3, "paquets": 6000, "graine": 9, "gigue_ms": 0.0, "melange": {"udp": 1}}
    sans = generer(Configuration(**cfg), tmp_path / "sans")
    avec = generer(Configuration(**cfg, segment_retard=2, retard_ms=50.0), tmp_path / "avec")
    assert sans["retard"]["fenetre_ns"] is None
    debut, fin = avec["retard"]["fenetre_ns"]
    assert avec["retard"]["paquets_concernes"] > 0
    # appariement par contenu : le retard réordonne les paquets à la sortie de la fenêtre
    p3 = {_signature(t): ts for ts, t in _paquets(tmp_path / "avec" / "P3.pcapng")}
    delais = [(debut <= t2 < fin, p3[_signature(t)] - t2) for t2, t in _paquets(tmp_path / "avec" / "P2.pcapng")]
    assert {d for dedans, d in delais if not dedans} == {synth.MS}
    assert {d for dedans, d in delais if dedans} == {51 * synth.MS}
    # le segment 1 n'est pas touché
    p1 = _paquets(tmp_path / "avec" / "P1.pcapng")
    p2 = _paquets(tmp_path / "avec" / "P2.pcapng")
    assert {b[0] - a[0] for a, b in zip(p1, p2)} == {synth.MS}


def test_decalage_horloge_applique(tmp_path):
    cfg = {"points": 2, "paquets": 400, "gigue_ms": 0.0, "melange": {"udp": 1}}
    generer(Configuration(**cfg), tmp_path / "a")
    generer(Configuration(**cfg, decalages_ms=[0, 12.5]), tmp_path / "b")
    a = _paquets(tmp_path / "a" / "P2.pcapng")
    b = _paquets(tmp_path / "b" / "P2.pcapng")
    assert {y[0] - x[0] for x, y in zip(a, b)} == {12_500_000}


def test_ttl_decremente_a_chaque_segment(tmp_path):
    generer(Configuration(points=5, paquets=300, melange={"udp": 1}), tmp_path)
    for i in range(5):
        assert {t[22] for _, t in _paquets(tmp_path / f"P{i + 1}.pcapng")} == {64 - i}


def test_flux_par_type_et_melange(tmp_path):
    verite = generer(Configuration(points=2, paquets=5000, melange={"dns": 1, "tls": 1}), tmp_path)
    assert verite["flux_par_type"]["tcp"] == verite["flux_par_type"]["udp"] == 0
    assert verite["flux_par_type"]["dns"] > 0
    assert verite["flux_par_type"]["tls"] > 0


def test_un_seul_paquet(tmp_path):
    verite = generer(Configuration(points=2, paquets=1), tmp_path)
    assert verite["paquets_par_point"] == {"P1": 1, "P2": 1}


# -- validation ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("champs", "message"),
    [
        ({"points": 1}, "au moins 2 points"),
        ({"paquets": 0}, "au moins 1 paquet"),
        ({"debit_pps": 0}, "debit_pps"),
        ({"retard_ms": -1}, "délais positifs"),
        ({"gigue_ms": 2.0}, "gigue_ms"),
        ({"taux_perte": 1.5}, "taux_perte"),
        ({"sens_perte": "nord"}, "sens_perte"),
        ({"segment_perte": 2}, "segment_perte entre 1 et 1"),
        ({"segment_retard": 0}, "segment_retard"),
        ({"decalages_ms": [1.0]}, "decalages_ms"),
        ({"melange": {"icmp": 1}}, "melange"),
        ({"melange": {}}, "melange"),
        ({"melange": {"tcp": -1, "udp": 2}}, "melange"),
        ({"melange": {"tcp": 0}}, "melange"),
    ],
)
def test_configuration_invalide(tmp_path, champs, message):
    with pytest.raises(ValueError, match=message):
        generer(Configuration(**champs), tmp_path)
    assert not list(tmp_path.iterdir())


# -- ligne de commande --------------------------------------------------------


def test_cli_jeu_unique(tmp_path, capsys):
    code = synth.main(
        [
            "--sortie",
            str(tmp_path),
            "--points",
            "3",
            "--paquets",
            "500",
            "--segment-perte",
            "1",
            "--taux-perte",
            "0.1",
            "--decalages-ms",
            "0,1.5,-2",
        ]
    )
    assert code == 0
    verite = json.loads((tmp_path / "verite.json").read_text(encoding="utf-8"))
    assert verite["configuration"]["decalages_ms"] == [0.0, 1.5, -2.0]
    assert "500 paquets" in capsys.readouterr().out


def test_cli_matrice(tmp_path):
    code = synth.main(["--sortie", str(tmp_path), "--matrice", "--matrice-points", "2,3", "--matrice-paquets", "100"])
    assert code == 0
    assert sorted(p.name for p in tmp_path.iterdir()) == ["p2-n100-g1", "p3-n100-g1"]
    assert (tmp_path / "p3-n100-g1" / "P3.pcapng").exists()


def test_cli_parametre_invalide(tmp_path, capsys):
    assert synth.main(["--sortie", str(tmp_path), "--points", "2", "--segment-perte", "5"]) == 2
    assert "erreur" in capsys.readouterr().out


def test_matrice_standard_par_defaut():
    args = synth.construire_parseur().parse_args(["--sortie", "x", "--matrice"])
    assert args.matrice_points == [2, 3, 5, 10]
    assert args.matrice_paquets == [10_000, 100_000, 1_000_000]


def test_script_enveloppe(tmp_path):
    resultat = subprocess.run(
        ["python3", "scripts/bench_datasets.py", "--sortie", str(tmp_path), "--paquets", "50"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert resultat.returncode == 0, resultat.stderr
    assert (tmp_path / "P2.pcapng").exists()


# -- intégration tshark / Netcross --------------------------------------------


@pytest.mark.skipif(TSHARK is None, reason="tshark absent")
def test_tshark_lit_les_jeux_sans_erreur(tmp_path):
    generer(Configuration(points=2, paquets=2000, graine=11), tmp_path)
    sortie = subprocess.run(
        [
            TSHARK,
            "-r",
            str(tmp_path / "P1.pcapng"),
            "-o",
            "ip.check_checksum:TRUE",
            "-o",
            "tcp.check_checksum:TRUE",
            "-o",
            "udp.check_checksum:TRUE",
            "-Y",
            "ip.checksum.status==2 || tcp.checksum.status==2 || udp.checksum.status==2 || tcp.analysis.flags",
            "-T",
            "fields",
            "-e",
            "frame.number",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert sortie.stdout.strip() == ""
    sni = subprocess.run(
        [
            TSHARK,
            "-r",
            str(tmp_path / "P1.pcapng"),
            "-Y",
            "tls.handshake.type==1",
            "-T",
            "fields",
            "-e",
            "tls.handshake.extensions_server_name",
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    assert sni
    assert all(nom.startswith("synth-") and nom.endswith(".example.test") for nom in sni)


@pytest.mark.skipif(TSHARK is None, reason="tshark absent")
def test_netcross_localise_la_perte_sur_le_bon_segment(tmp_path):
    from netcross_core.analysis import analyse
    from netcross_core.correlate import correlate
    from netcross_core.parsing import parse_capture

    verite = generer(
        Configuration(points=3, paquets=3000, graine=7, segment_perte=2, taux_perte=0.05, melange={"tcp": 1}),
        tmp_path,
    )
    paquets = []
    for nom in verite["points"]:
        paquets += parse_capture(nom, str(tmp_path / f"{nom}.pcapng"))
    rapport = analyse(correlate(paquets), verite["points"], paquets)
    pertes = {p: n for p, n in rapport.loss_count.items() if n}
    assert set(pertes) == {"P3"}
    # Netcross corrèle TCP par (5-tuple, numéro de séquence) : un segment de
    # données perdu dont le numéro de séquence est partagé par un ACK pur
    # (premier segment après la poignée de main) reste « vu » ; d'où un
    # compte possiblement inférieur à la vérité, jamais supérieur.
    assert 0.5 * verite["perte"]["paquets_perdus"] <= pertes["P3"] <= verite["perte"]["paquets_perdus"]
