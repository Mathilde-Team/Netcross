# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.security.beaconing -- issue #147 (SCENARIO-1) : detection de
beaconing C2. Paquets synthetiques (make_pkt) ; le trafic « legitime » imite
un poste de travail ordinaire (navigation, NTP, DNS, keepalive TCP,
sauvegarde reguliere) pour verifier le critere « aucun faux positif ».
"""

import random

import pytest
from conftest import make_pkt

from netcross_core.models import Report
from netcross_core.security.beaconing import (
    SIGNAL_ASYMMETRIC,
    SIGNAL_OFF_HOURS,
    SIGNAL_PERIODIC,
    SIGNAL_SMALL_PAYLOAD,
    SIGNAL_STABLE_SIZE,
    BeaconingThresholds,
    detect_beaconing,
)
from netcross_core.security.findings import apply_security_findings, beaconing_findings

CLIENT = "192.168.1.10"
C2 = "93.184.216.34"  # adresse routable globalement (les plages de documentation ne le sont pas)
NOON = 12 * 3600  # 12h UTC : heures de bureau
NIGHT = 2 * 3600  # 2h UTC : hors heures de bureau


def _out(ts, *, size=120, dst=C2, dport=443, sport=40000, src=CLIENT, point="A", proto="TCP", frame=None):
    """Paquet client -> serveur portant `size` octets de charge utile."""
    fields = {
        "point": point,
        "ts": ts,
        "proto": proto,
        "src": src,
        "dst": dst,
        "sport": sport,
        "dport": dport,
        "length": size + 54 if proto == "TCP" else size,
        "frame_number": frame,
    }
    if proto == "TCP":
        fields["tcp_len"] = size
    return make_pkt(**fields)


def _reply(ts, *, size=600, server=C2, server_port=443, client=CLIENT, client_port=40000, point="A"):
    """Paquet serveur -> client (reponse a un check-in)."""
    return make_pkt(
        point=point,
        ts=ts,
        proto="TCP",
        src=server,
        dst=client,
        sport=server_port,
        dport=client_port,
        length=size + 54,
        tcp_len=size,
    )


def _beacon(count=20, step=60.0, start=NOON, size=120, jitter=0.0, seed=1, **kwargs):
    """`count` check-ins regulierement espaces ; `size` peut etre une liste (cyclique)."""
    rng = random.Random(seed)
    sizes = size if isinstance(size, list) else [size]
    return [
        _out(
            start + i * step + (rng.uniform(-jitter, jitter) if jitter else 0.0),
            size=sizes[i % len(sizes)],
            frame=i + 1,
            **kwargs,
        )
        for i in range(count)
    ]


def _legit_workstation():
    """Trafic externe ordinaire : navigation irreguliere, NTP, DNS, keepalive,
    et une sauvegarde reguliere mais volumineuse."""
    rng = random.Random(7)
    servers = ["151.101.1.69", "142.250.74.110", "185.199.108.153", "93.184.216.34"]
    pkts, ts = [], NOON
    for _ in range(120):  # navigation : intervalles et tailles irreguliers
        ts += rng.uniform(0.5, 40.0)
        dst, size, sport = rng.choice(servers), rng.randrange(200, 1400), rng.randrange(40000, 60000)
        pkts.append(_out(ts, size=size, dst=dst, sport=sport))
    for i in range(30):  # NTP toutes les 64 s, DNS toutes les 30 s (UDP, petits, reguliers)
        pkts.append(_out(NOON + i * 64.0, size=90, proto="UDP", dst="162.159.200.1", dport=123, sport=45000))
        pkts.append(_out(NOON + i * 30.0, size=70, proto="UDP", dst="8.8.8.8", dport=53, sport=46000))
    # keepalive TCP : segments vides toutes les 45 s
    pkts += [_out(NOON + i * 45.0, size=0, dst="142.250.74.110", sport=50000) for i in range(30)]
    # sauvegarde : reguliere mais gros volume
    pkts += [_out(NOON + i * 10.0, size=1400, dst="185.199.108.153", dport=8443, sport=51000) for i in range(30)]
    return pkts


# --- detection de base ------------------------------------------------------


def test_beacon_periodique_petit_et_constant_leve_une_suspicion():
    result = detect_beaconing(_beacon())
    (s,) = result.suspicions
    assert s["kind"] == "beacon" and s["point"] == "A" and s["proto"] == "TCP"
    assert (s["src"], s["dst"], s["dport"]) == (CLIENT, C2, 443)
    assert s["signals"] == [SIGNAL_PERIODIC, SIGNAL_SMALL_PAYLOAD, SIGNAL_STABLE_SIZE]
    assert s["severity"] == "moyenne"
    assert s["checkins"] == 20
    assert s["mean_interval"] == 60.0 and s["interval_stddev"] == 0.0 and s["interval_cv"] == 0.0
    assert s["median_bytes"] == 120.0 and s["bytes_up"] == 20 * 120 and s["bytes_down"] == 0
    assert s["score"] == pytest.approx(0.8)
    assert s["frames"] == list(range(1, 11))  # plafonne a 10 trames de preuve


def test_beacon_udp_detecte():
    (s,) = detect_beaconing(_beacon(proto="UDP", dport=5000, size=100)).suspicions
    assert s["proto"] == "UDP" and s["dport"] == 5000


def test_gigue_moderee_detectee_et_score_plus_bas_que_cadence_exacte():
    exact = detect_beaconing(_beacon()).suspicions[0]
    (jittery,) = detect_beaconing(_beacon(jitter=3.0)).suspicions  # +/- 5 % : CV ~ 0.04
    assert 0.0 < jittery["interval_cv"] <= 0.15
    assert 0.5 < jittery["score"] < exact["score"]


def test_gigue_forte_non_detectee():
    assert detect_beaconing(_beacon(jitter=30.0)).suspicions == []  # +/- 50 % : CV ~ 0.4


def test_intervalles_irreguliers_non_detectes():
    rng = random.Random(5)
    ts, pkts = NOON, []
    for i in range(20):
        ts += rng.uniform(5.0, 120.0)
        pkts.append(_out(ts, frame=i + 1))
    assert detect_beaconing(pkts).suspicions == []


def test_rafales_fusionnees_en_un_seul_checkin():
    """Une requete suivie de segments a 0,1 s d'ecart est UN check-in."""
    pkts = [_out(NOON + i * 60.0 + k * 0.1, size=40) for i in range(20) for k in range(3)]
    (s,) = detect_beaconing(pkts).suspicions
    assert s["checkins"] == 20 and s["median_bytes"] == 120.0 and s["mean_interval"] == 60.0


# --- signaux centraux -------------------------------------------------------


def test_minimum_de_checkins():
    assert detect_beaconing(_beacon(count=9)).suspicions == []
    assert len(detect_beaconing(_beacon(count=10)).suspicions) == 1


def test_gros_volume_regulier_nest_pas_un_beacon():
    assert detect_beaconing(_beacon(size=5000)).suspicions == []


def test_taille_variable_nest_pas_un_beacon():
    assert detect_beaconing(_beacon(size=[50, 500])).suspicions == []


def test_cadence_inferieure_au_minimum_ignoree_puis_reglable():
    fast = _beacon(step=4.0)  # bursts separes (> 2 s) mais moyenne < 5 s
    assert detect_beaconing(fast).suspicions == []
    assert len(detect_beaconing(fast, BeaconingThresholds(min_interval_seconds=1.0)).suspicions) == 1


# --- signaux faibles --------------------------------------------------------


def test_ratio_asymetrique_aggrave_la_suspicion():
    pkts = _beacon() + [_reply(NOON + i * 60.0 + 0.05) for i in range(20)]
    (s,) = detect_beaconing(pkts).suspicions  # pas de constat miroir cote serveur
    assert s["src"] == CLIENT
    assert SIGNAL_ASYMMETRIC in s["signals"]
    assert s["severity"] == "elevee"
    assert s["bytes_down"] == 20 * 600
    assert s["score"] == pytest.approx(0.9)


def test_reponses_plus_petites_que_les_requetes_pas_de_signal_asymetrique():
    pkts = _beacon(size=400) + [_reply(NOON + i * 60.0 + 0.05, size=100) for i in range(20)]
    (s,) = detect_beaconing(pkts).suspicions
    assert SIGNAL_ASYMMETRIC not in s["signals"] and s["severity"] == "moyenne"


def test_heures_inhabituelles_aggravent_la_suspicion():
    (s,) = detect_beaconing(_beacon(start=NIGHT)).suspicions
    assert SIGNAL_OFF_HOURS in s["signals"] and s["severity"] == "elevee"
    (day,) = detect_beaconing(_beacon(start=NOON)).suspicions
    assert SIGNAL_OFF_HOURS not in day["signals"]


def test_plage_horaire_configurable():
    strict = BeaconingThresholds(office_hours_utc=(0, 8))
    (s,) = detect_beaconing(_beacon(start=NOON), strict).suspicions  # 12h est hors de 0h-8h
    assert SIGNAL_OFF_HOURS in s["signals"]


def test_signaux_faibles_seuls_ne_levent_rien():
    """Reponses asymetriques + nuit, mais aucune periodicite."""
    rng = random.Random(11)
    ts, pkts = NIGHT, []
    for _ in range(20):
        ts += rng.uniform(5.0, 120.0)
        pkts += [_out(ts), _reply(ts + 0.05)]
    assert detect_beaconing(pkts).suspicions == []


# --- aucun faux positif -----------------------------------------------------


@pytest.mark.parametrize("port", [53, 123])
def test_ports_ignores_dns_et_ntp(port):
    pkts = _beacon(proto="UDP", dport=port, sport=45000, size=90, step=64.0)
    assert detect_beaconing(pkts).suspicions == []


@pytest.mark.parametrize("payload", [0, 1])
def test_keepalive_tcp_nest_jamais_un_checkin(payload):
    assert detect_beaconing(_beacon(size=payload, step=45.0)).suspicions == []


def test_paquets_tcp_sans_tcp_len_ignores():
    pkts = [make_pkt(ts=NOON + i * 60.0, src=CLIENT, dst=C2, sport=40000, dport=443) for i in range(20)]
    assert detect_beaconing(pkts).suspicions == []


def test_destination_interne_ignoree_puis_reglable():
    internal = _beacon(dst="10.0.0.5")
    assert detect_beaconing(internal).suspicions == []
    assert len(detect_beaconing(internal, BeaconingThresholds(external_only=False)).suspicions) == 1


def test_trafic_de_poste_de_travail_legitime_ne_leve_aucune_suspicion():
    assert detect_beaconing(_legit_workstation()).suspicions == []


# --- groupement -------------------------------------------------------------


def test_un_flux_par_point_sans_cumul_entre_points():
    both = detect_beaconing(_beacon(point="A") + _beacon(point="B"))
    assert [s["point"] for s in both.suspicions] == ["A", "B"]
    split = detect_beaconing(_beacon(count=6, point="A") + _beacon(count=6, start=NOON + 500, point="B"))
    assert split.suspicions == []


def test_beacon_isole_du_trafic_irregulier_vers_le_meme_hote():
    rng = random.Random(3)
    noise = [_out(NOON + rng.uniform(0, 1200), size=300, dport=80, sport=41000 + i) for i in range(40)]
    (s,) = detect_beaconing(_beacon() + noise).suspicions
    assert s["dport"] == 443


# --- seuils -----------------------------------------------------------------


def test_seuils_configurables():
    pkts = _beacon(count=6)
    assert detect_beaconing(pkts).suspicions == []
    assert len(detect_beaconing(pkts, BeaconingThresholds(min_checkins=5)).suspicions) == 1
    jittery = _beacon(jitter=30.0)
    assert len(detect_beaconing(jittery, BeaconingThresholds(max_interval_cv=1.0)).suspicions) == 1


# --- integration Report / findings de securite -----------------------------


def test_beaconing_findings_format_anomalie():
    pkts = _beacon(start=NIGHT)
    (f,) = beaconing_findings(detect_beaconing(pkts).suspicions)
    assert f["category"] == "anomalie" and f["severity"] == "elevee" and f["point"] == "A"
    assert "beaconing C2" in f["detail"] and CLIENT in f["detail"] and C2 in f["detail"] and "443" in f["detail"]
    assert "trames" in f["detail"]


def test_beaconing_findings_vide():
    assert beaconing_findings([]) == []


def test_apply_security_findings_inclut_le_beaconing():
    report = Report()
    pkts = _beacon()
    apply_security_findings(report, iter(pkts))  # un iterateur : le module materialise la liste
    cats = [f["category"] for f in report.security_findings]
    assert "anomalie" in cats  # au moins le beaconing
    apply_security_findings(report, pkts)  # remplacement, pas ajout
    assert len(report.security_findings) == len(cats)  # pas d'ajout


def test_apply_security_findings_trafic_legitime_reste_vide():
    report = Report()
    apply_security_findings(report, _legit_workstation())
    # Le trafic legitime ne leve aucun constat de securite (beaconing, tunneling,
    # mouvement lateral...). flow_stats peut classer des flux (interactif,
    # transfert) -- ce ne sont pas des constats de securite, juste des stats.
    assert all("flux " in f.get("detail", "") for f in report.security_findings), (
        f"constats inattendus sur trafic legitime: {report.security_findings}"
    )
