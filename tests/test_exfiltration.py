# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests de netcross_core.security.exfiltration (issue #148, SCENARIO-2).
Detection d'exfiltration : volume anormal, ratio asymetrique,
heures ouvrables, destination nouvelle, protocole inhabituel.
"""

from __future__ import annotations

import json

import pytest
from conftest import make_pkt

from netcross_core.models import Report
from netcross_core.security.exfiltration import (
    SIGNAL_ASYMMETRIC_RATIO,
    SIGNAL_CORRELATED_BEACONING,
    SIGNAL_CORRELATED_DNS_TUNNEL,
    SIGNAL_HIGH_VOLUME,
    SIGNAL_NEW_DESTINATION,
    SIGNAL_OFF_HOURS,
    SIGNAL_UNUSUAL_PROTOCOL,
    ExfiltrationThresholds,
    correlate_exfiltration,
    detect_exfiltration,
    dns_tunnel_sources,
)
from netcross_core.security.findings import apply_security_findings, exfiltration_findings

CLIENT = "192.168.1.10"
SERVER = "10.0.0.1"
EXTERNAL = "93.184.216.34"

# Seuil de volume bas pour les tests
_VOL = 100_000  # 100 Ko


def _upload(src, dst, count=100, size=1400, ts_start=43200.0):
    """Paquets src->dst a 12h UTC (heures ouvrables)."""
    return [make_pkt(src=src, dst=dst, length=size, ts=ts_start + i, proto="TCP") for i in range(count)]


def _download(src, dst, count=5, size=100, ts_start=53200.0):
    """Paquets dst->src."""
    return [make_pkt(src=dst, dst=src, length=size, ts=ts_start + i, proto="TCP") for i in range(count)]


def _thresholds(**overrides):
    defaults = {"min_volume_bytes": _VOL, "min_packets_for_volume": 5}
    defaults.update(overrides)
    return ExfiltrationThresholds(**defaults)


# -- Tests: volume eleve ------------------------------------------------------


def test_high_volume_detected():
    """Volume total > seuil -> signal high_volume."""
    pkts = _upload(CLIENT, EXTERNAL, count=100, size=1400)  # 140 Ko > 100 Ko
    result = detect_exfiltration(pkts, thresholds=_thresholds())

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_HIGH_VOLUME in alert["signals"]
    assert alert["volume_bytes"] > _VOL


def test_low_volume_no_alert():
    """Volume faible -> pas d'alerte."""
    pkts = _upload(CLIENT, SERVER, count=3, size=100)  # 300 octets
    result = detect_exfiltration(pkts, thresholds=_thresholds())

    assert result.alerts == []


# -- Tests: ratio asymetrique -------------------------------------------------


def test_asymmetric_ratio_detected():
    """Ratio upload/download > 10:1 -> signal asymmetric_ratio."""
    upload = _upload(CLIENT, EXTERNAL, count=100, size=1400)
    download = _download(CLIENT, EXTERNAL, count=2, size=100)
    result = detect_exfiltration(upload + download, thresholds=_thresholds())

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_ASYMMETRIC_RATIO in alert["signals"]
    assert alert["ratio"] > 10.0


def test_balanced_flow_no_asymmetry():
    """Flux equilibre -> pas de signal asymmetric_ratio."""
    upload = _upload(CLIENT, SERVER, count=10, size=1000)
    download = _download(CLIENT, SERVER, count=10, size=1000)
    # Volume trop faible pour declencher high_volume
    result = detect_exfiltration(upload + download, thresholds=_thresholds(min_volume_bytes=999_999_999))

    asym = [a for a in result.alerts if SIGNAL_ASYMMETRIC_RATIO in a["signals"]]
    assert len(asym) == 0


def test_unidirectional_upload_triggers_asymmetry():
    """Upload massif unidirectionnel (download=0) -> asymmetric_ratio."""
    pkts = _upload(CLIENT, EXTERNAL, count=100, size=1400)
    result = detect_exfiltration(pkts, thresholds=_thresholds())

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_ASYMMETRIC_RATIO in alert["signals"]


# -- Tests: heures ouvrables --------------------------------------------------


def test_off_hours_detected():
    """Transfert nocturne -> signal off_hours."""
    # 2h UTC = 7200 secondes depuis minuit
    pkts = [make_pkt(src=CLIENT, dst=EXTERNAL, length=2000, ts=7200.0 + i, proto="TCP") for i in range(100)]
    result = detect_exfiltration(pkts, thresholds=_thresholds())

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_OFF_HOURS in alert["signals"]


def test_business_hours_no_off_hours_signal():
    """Transfert a midi -> pas de signal off_hours."""
    pkts = _upload(CLIENT, EXTERNAL, count=100, size=1400)  # 12h UTC
    result = detect_exfiltration(pkts, thresholds=_thresholds())

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_OFF_HOURS not in alert["signals"]


# -- Tests: destination nouvelle ----------------------------------------------


def test_new_destination_detected():
    """Destination non dans baseline -> signal new_destination."""
    pkts = _upload(CLIENT, EXTERNAL, count=100, size=1400)
    baseline = frozenset({SERVER})
    result = detect_exfiltration(pkts, thresholds=_thresholds(), known_destinations=baseline)

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_NEW_DESTINATION in alert["signals"]


def test_known_destination_no_new_signal():
    """Destination dans baseline -> pas de signal new_destination."""
    pkts = _upload(CLIENT, EXTERNAL, count=100, size=1400)
    baseline = frozenset({EXTERNAL})
    result = detect_exfiltration(pkts, thresholds=_thresholds(), known_destinations=baseline)

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_NEW_DESTINATION not in alert["signals"]


def test_no_baseline_no_new_signal():
    """Sans baseline -> signal new_destination jamais emis."""
    pkts = _upload(CLIENT, EXTERNAL, count=100, size=1400)
    result = detect_exfiltration(pkts, thresholds=_thresholds(), known_destinations=None)

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_NEW_DESTINATION not in alert["signals"]


# -- Tests: protocole inhabituel ----------------------------------------------


def test_unusual_protocol_dns_volume():
    """Gros volume DNS -> signal unusual_protocol_volume."""
    pkts = [make_pkt(src=CLIENT, dst=EXTERNAL, length=500, ts=43200.0 + i, proto="DNS") for i in range(2000)]
    result = detect_exfiltration(pkts, thresholds=_thresholds(min_bytes_for_protocol=100_000))

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_UNUSUAL_PROTOCOL in alert["signals"]


def test_tcp_not_unusual_protocol():
    """TCP n'est pas un protocole inhabituel."""
    pkts = _upload(CLIENT, EXTERNAL, count=100, size=1400)
    result = detect_exfiltration(pkts, thresholds=_thresholds())

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert SIGNAL_UNUSUAL_PROTOCOL not in alert["signals"]


# -- Tests: alertes fortes vs faibles -----------------------------------------


def test_strong_alert_flag():
    """Une alerte avec un signal fort a strong=True."""
    pkts = _upload(CLIENT, EXTERNAL, count=100, size=1400)
    result = detect_exfiltration(pkts, thresholds=_thresholds())

    alert = next(a for a in result.alerts if a["dst"] == EXTERNAL)
    assert alert["strong"] is True


def test_weak_only_alert_not_strong():
    """Une alerte avec seulement des signaux faibles a strong=False."""
    # Volume faible mais destination nouvelle + off-hours
    pkts = [make_pkt(src=CLIENT, dst=EXTERNAL, length=100, ts=7200.0, proto="TCP")]
    # Seuil volume tres haut pour ne pas declencher high_volume
    # Mais off_hours + new_destination sont des signaux faibles
    # qui ne declenchent pas d'alerte seuls (apres la correction)
    result = detect_exfiltration(
        pkts,
        thresholds=_thresholds(min_volume_bytes=999_999_999, min_packets_for_volume=999),
        known_destinations=frozenset({SERVER}),
    )
    # Pas d'alerte car pas de signal fort
    assert result.alerts == []


# -- Tests: flow_stats --------------------------------------------------------


def test_flow_stats_returned():
    """flow_stats contient tous les flux, meme sans alerte."""
    pkts = _upload(CLIENT, SERVER, count=5, size=100)
    result = detect_exfiltration(pkts, thresholds=_thresholds())

    assert len(result.flow_stats) >= 1
    stat = next(s for s in result.flow_stats if s["dst"] == SERVER)
    assert stat["upload_bytes"] == 500
    assert stat["packet_count"] == 5


# -- Tests: vide --------------------------------------------------------------


def test_empty_input():
    """Aucun paquet -> aucun flux, aucune alerte."""
    result = detect_exfiltration([])
    assert result.alerts == []
    assert result.flow_stats == []


# -- Integration #148 : sens, anti faux positifs, score, correlations -------------


def test_download_http_normal_aucun_faux_positif():
    """Gros telechargement externe -> interne : le flux serveur->client est
    tres asymetrique mais entrant -- aucune alerte."""
    pkts = _download(CLIENT, EXTERNAL, count=200, size=1400) + _upload(CLIENT, EXTERNAL, count=5, size=60)
    result = detect_exfiltration(pkts, thresholds=_thresholds())
    assert result.alerts == []


def test_transfert_interne_ignore_par_defaut():
    pkts = _upload(CLIENT, SERVER, count=100, size=1400)
    assert detect_exfiltration(pkts, thresholds=_thresholds()).alerts == []
    assert detect_exfiltration(pkts, thresholds=_thresholds(external_only=False)).alerts


def test_petit_post_sous_le_plancher_de_ratio():
    """20 Ko envoyes, 1 Ko recu : ratio 20:1 mais volume derisoire."""
    pkts = _upload(CLIENT, EXTERNAL, count=20, size=1000) + _download(CLIENT, EXTERNAL, count=10, size=100)
    assert detect_exfiltration(pkts).alerts == []


def test_multi_points_volume_non_double():
    pkts = _upload(CLIENT, EXTERNAL, count=100, size=1400)
    vu_en_b = [make_pkt(point="B", src=p.src, dst=p.dst, length=p.length, ts=p.ts) for p in pkts]
    result = detect_exfiltration(pkts + vu_en_b, thresholds=_thresholds())
    assert sorted(a["point"] for a in result.alerts) == ["A", "B"]
    assert {a["upload_bytes"] for a in result.alerts} == {140_000}


def test_off_hours_minoritaire_non_signale():
    nuit = [make_pkt(src=CLIENT, dst=EXTERNAL, length=1400, ts=7200.0 + i) for i in range(30)]
    jour = _upload(CLIENT, EXTERNAL, count=70, size=1400)
    alert = detect_exfiltration(nuit + jour, thresholds=_thresholds()).alerts[0]
    assert SIGNAL_OFF_HOURS not in alert["signals"]
    assert alert["off_hours_fraction"] == pytest.approx(0.3)


def test_score_et_severite():
    pkts = _upload(CLIENT, EXTERNAL, count=100, size=1400)
    alert = detect_exfiltration(pkts, thresholds=_thresholds()).alerts[0]
    assert alert["signals"] == [SIGNAL_HIGH_VOLUME, SIGNAL_ASYMMETRIC_RATIO]
    assert alert["score"] == 60 and alert["severity"] == "elevee"
    assert alert["ratio"] is None  # aucun retour
    json.dumps(alert)  # serialisable (pas d'inf)
    ratio_seul = detect_exfiltration(
        pkts + _download(CLIENT, EXTERNAL, count=2, size=100),
        thresholds=_thresholds(min_volume_bytes=10_000_000, min_upload_for_ratio=100_000),
    ).alerts[0]
    assert ratio_seul["signals"] == [SIGNAL_ASYMMETRIC_RATIO]
    assert ratio_seul["score"] == 25 and ratio_seul["severity"] == "moyenne"


def test_correlation_beaconing_et_dns():
    alert = detect_exfiltration(_upload(CLIENT, EXTERNAL, count=100, size=1400), thresholds=_thresholds()).alerts[0]
    dns_pkts = [
        make_pkt(src=CLIENT, dst="10.0.0.53", sport=5000, dport=53, proto="DNS", dns_qry_name="a1b2.tunnel.example"),
        make_pkt(src="192.168.1.99", dst="10.0.0.53", sport=5000, dport=53, proto="DNS", dns_qry_name="www.ok.test"),
    ]
    sources = dns_tunnel_sources(dns_pkts, [{"point": "A", "domain": "tunnel.example"}])
    assert sources == {("A", CLIENT)}
    (out,) = correlate_exfiltration([alert], [{"point": "A", "src": CLIENT, "dst": EXTERNAL}], sources)
    assert SIGNAL_CORRELATED_BEACONING in out["signals"] and SIGNAL_CORRELATED_DNS_TUNNEL in out["signals"]
    assert out["score"] == 90
    assert alert["score"] == 60  # entree non modifiee
    (autre_point,) = correlate_exfiltration([alert], [{"point": "B", "src": CLIENT, "dst": EXTERNAL}])
    assert SIGNAL_CORRELATED_BEACONING not in autre_point["signals"]
    assert dns_tunnel_sources(dns_pkts, []) == set()


def test_findings_texte():
    alert = detect_exfiltration(_upload(CLIENT, EXTERNAL, count=100, size=1400), thresholds=_thresholds()).alerts[0]
    (f,) = exfiltration_findings([alert])
    assert f["severity"] == "elevee" and f["category"] == "anomalie" and f["point"] == "A"
    assert "suspicion d'exfiltration de 192.168.1.10 vers 93.184.216.34" in f["detail"]
    assert "140.0 Ko envoyes" in f["detail"] and "aucun retour" in f["detail"] and "60/100" in f["detail"]


def test_apply_security_findings_remplit_le_rapport():
    pkts = [make_pkt(src=CLIENT, dst=EXTERNAL, length=1400, ts=43200.0 + i * 0.01) for i in range(8000)]
    r = Report(points=["A"])
    apply_security_findings(r, pkts, known_destinations=frozenset({SERVER}))
    assert len(r.exfiltration_alerts) == 1
    assert SIGNAL_NEW_DESTINATION in r.exfiltration_alerts[0]["signals"]
    assert any("suspicion d'exfiltration" in f["detail"] for f in r.security_findings)
    r2 = Report(points=["A"])
    apply_security_findings(r2, _upload(CLIENT, EXTERNAL, count=10, size=100))
    assert r2.exfiltration_alerts == []


# -- CLI : --known-destinations ---------------------------------------------------


def _analyzer(monkeypatch, *argv):
    import sys

    import cross_capture_analyzer_cli as cli

    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", *map(str, argv)])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    return exc.value.code


def test_cli_known_destinations_sans_security_report(tmp_path, monkeypatch, capsys):
    f = tmp_path / "k.json"
    f.write_text('["1.2.3.4"]')
    assert _analyzer(monkeypatch, "--capture", "A=x.pcap", "--known-destinations", f) == 1
    assert "--known-destinations necessite --security-report" in capsys.readouterr().err


def test_cli_known_destinations_fichier_absent(tmp_path, monkeypatch, capsys):
    code = _analyzer(
        monkeypatch, "--capture", "A=x.pcap", "--security-report", "--known-destinations", tmp_path / "nope.json"
    )
    assert code == 1
    assert "fichier introuvable" in capsys.readouterr().err


@pytest.mark.parametrize("contenu", ["[]", "pas du json", '{"autre": 1}'])
def test_cli_known_destinations_vide_ou_invalide(tmp_path, monkeypatch, capsys, contenu):
    f = tmp_path / "k.json"
    f.write_text(contenu)
    assert _analyzer(monkeypatch, "--capture", "A=x.pcap", "--security-report", "--known-destinations", f) == 1
    assert "aucune IP lue" in capsys.readouterr().err
