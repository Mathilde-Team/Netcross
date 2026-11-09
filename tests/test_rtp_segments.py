# SPDX-License-Identifier: GPL-3.0-or-later
"""Transport RTP par segment, y compris horloges, pertes aval et NAT/SBC."""

import json
from dataclasses import replace

import pytest
from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.clock_sync import EstimationHorloge
from netcross_core.correlate import correlate
from netcross_core.redact import redact_packets
from netcross_core.rtp_match import SEQ_MOD, TS_MOD, match_rtp_streams
from netcross_core.rtp_segments import TRANSPORT_NOTE, analyse_rtp_segments
from netcross_report.json_report import build_json_report_document
from netcross_report.synthesis import build_findings


def _rtp(point, *, delay=0.0, dropped=(), seq_offset=0, ts_offset=0, ssrc=123, src="10.1.0.1", n=40):
    return [
        make_pkt(
            point=point,
            proto="UDP",
            ts=10 + i * 0.02 + delay,
            src=src,
            is_rtp=True,
            rtp_seq=(65530 + i + seq_offset) % SEQ_MOD,
            rtp_ts=(TS_MOD - 300 + i * 160 + ts_offset) % TS_MOD,
            rtp_ssrc=ssrc,
            key_id=i,
        )
        for i in range(n)
        if i not in dropped
    ]


def _segments(packets, estimates=None, *, ordered=True, clock_rate=8000):
    matches = match_rtp_streams(packets, ["A", "B", "C"])
    return analyse_rtp_segments(packets, matches, estimates or {}, ordered=ordered, clock_rate=clock_rate)


def test_seul_le_segment_aval_est_degrade_et_exporte():
    packets = _rtp("A") + _rtp("B", delay=0.005) + _rtp("C", delay=0.01, dropped=(10, 11))
    report = analyse(
        correlate(packets),
        ["A", "B", "C"],
        packets,
        clock_offsets={("A", "B"): 0.0, ("B", "C"): 0.0},
    )
    first, second = report.rtp_segments
    assert first["lost"] == 0
    assert first["degraded"] is False
    assert second["lost"] == 2
    assert second["loss_pct"] == pytest.approx(5.0)
    assert second["transport_quality"] < first["transport_quality"]
    assert second["delay_ms"] == pytest.approx(5.0)
    findings = [f for f in build_findings(report) if "Dégradation de transport" in f.message]
    assert [f.segment for f in findings] == ["B -> C"]
    assert findings[0].sample_size == 40
    assert build_json_report_document(report)["rtp_segments"] == report.rtp_segments


def test_perte_deja_en_amont_non_recomptee():
    packets = _rtp("A", dropped=(12, 13)) + _rtp("B", delay=0.01, dropped=(12, 13))
    (segment,) = _segments(packets)
    assert segment["lost"] == 0
    assert segment["loss_pct"] == 0
    assert segment["degraded"] is False


def test_capture_aval_tronquee_aux_bords_n_est_pas_une_perte():
    packets = _rtp("A") + _rtp("B", delay=0.01, dropped=tuple(range(5)) + tuple(range(35, 40)))
    (segment,) = _segments(packets)
    assert segment["sample_count"] == 30
    assert segment["lost"] == 0


def test_nat_sbc_sequences_horodatages_recrits_et_passages_a_zero():
    packets = _rtp("A") + _rtp(
        "B", delay=0.01, dropped=(12,), seq_offset=77, ts_offset=123456, ssrc=999, src="192.0.2.20"
    )
    (segment,) = _segments(packets)
    assert segment["lost"] == 1
    assert segment["loss_pct"] == pytest.approx(2.5)
    assert segment["added_jitter_ms"] == pytest.approx(0.0, abs=1e-9)


def test_doublons_et_ordre_du_tableau_sans_effet():
    packets = _rtp("A") + _rtp("B", delay=0.01, dropped=(12,))
    expected = _segments(packets)
    packets.extend(replace(p, ts=p.ts + 0.001) for p in packets[:10])
    assert _segments(list(reversed(packets))) == expected


def test_sans_horloge_delai_physique_non_mesurable():
    (segment,) = _segments(_rtp("A") + _rtp("B", delay=0.01))
    assert segment["signed_delta_ms"] == pytest.approx(10.0)
    assert segment["delay_ms"] is None
    assert segment["clock_uncertainty_ms"] is None
    assert segment["direction_confirmed"] is False


def test_incertitude_extrapolee_trop_grande_pour_le_delai():
    estimate = EstimationHorloge(0.0, ic_decalage_ms=50.0, ic_derive_ppm=10.0)
    (segment,) = _segments(_rtp("A") + _rtp("B", delay=0.01), {("A", "B"): estimate})
    assert segment["clock_uncertainty_ms"] > 50
    assert segment["delay_ms"] is None


def test_intervalle_qui_touche_zero_ne_prouve_pas_un_delai_physique():
    estimate = EstimationHorloge(0.0, ic_decalage_ms=1000.0)
    (segment,) = _segments(_rtp("A") + _rtp("B", delay=1.0), {("A", "B"): estimate})
    assert segment["delay_ms"] is None
    assert segment["direction_confirmed"] is False


def test_correction_decalage_et_derive_au_temps_des_paquets():
    first = _rtp("A")
    second = [replace(p, point="B", ts=p.ts + 0.005 + 0.037 + p.ts * 500e-6) for p in first]
    estimate = EstimationHorloge(37.0, derive_ppm=500.0, ic_decalage_ms=0.01, ic_derive_ppm=1.0)
    (segment,) = _segments(first + second, {("A", "B"): estimate})
    assert segment["delay_ms"] == pytest.approx(5.0)
    assert segment["clock_uncertainty_ms"] == pytest.approx(0.01 + first[-1].ts / 1000)
    assert segment["direction_confirmed"] is True


def test_estimation_stockee_dans_le_sens_inverse():
    estimate = EstimationHorloge(-37.0)
    (segment,) = _segments(_rtp("A") + _rtp("B", delay=0.047), {("B", "A"): estimate})
    assert segment["delay_ms"] == pytest.approx(10.0)


def test_flux_retour_localise_la_perte_dans_le_bon_sens():
    estimate = EstimationHorloge(0.0, manuel=True)
    (segment,) = _segments(_rtp("A", delay=0.02, dropped=(12, 13)) + _rtp("B", delay=0.01), {("A", "B"): estimate})
    assert segment["segment"] == "A -> B"
    assert (segment["upstream"], segment["downstream"]) == ("B", "A")
    assert segment["lost"] == 2
    assert segment["delay_ms"] == pytest.approx(10.0)


def test_gigue_ajoutee_et_delai_long_signalent_la_degradation():
    first = _rtp("A")
    second = [replace(p, point="B", ts=p.ts + 0.2 + (0.04 if i % 2 else 0)) for i, p in enumerate(first)]
    (segment,) = _segments(first + second, {("A", "B"): EstimationHorloge(0.0)})
    assert segment["added_jitter_ms"] >= 5
    assert segment["delay_ms"] >= 150
    assert segment["degraded"] is True


def test_metriques_rtp_srtp_sans_acces_a_la_charge_utile():
    # Pkt ne porte aucune charge utile audio à déchiffrer. Exactement le même
    # calcul s'applique aux en-têtes SRTP lisibles, sans inventer le codec.
    (segment,) = _segments(_rtp("A") + _rtp("B", delay=0.01))
    assert segment["scope"] == "transport"
    assert segment["note"] == TRANSPORT_NOTE
    assert "RTP/SRTP" in segment["note"]
    assert "G.711" in segment["note"]
    assert "qualité perçue" in segment["note"]


def test_paquets_anonymises_avant_analyse_ne_fuitent_pas_dans_les_segments():
    packets = _rtp("A") + _rtp("B", delay=0.01, dropped=(12,))
    redact_packets(packets)
    report = analyse(correlate(packets), ["A", "B"], packets)
    document = build_json_report_document(report)
    assert document["rtp_segments"]
    assert "10.1.0.1" not in json.dumps(document)


def test_sans_ordre_fourni_pas_de_segment_physique():
    assert _segments(_rtp("A") + _rtp("B"), ordered=False) == []


def test_paquets_hors_rtp_et_entetes_incomplets_ignores():
    packets = _rtp("A") + _rtp("B")
    base = packets[0]
    additions = [
        replace(base, proto="TCP"),
        replace(base, is_rtp=False),
        replace(base, rtp_seq=None),
        replace(base, rtp_ts=None),
    ]
    assert _segments(packets + additions) == _segments(packets)


def test_recouvrement_inferieur_a_deux_paquets():
    packets = _rtp("A", n=1) + _rtp("B", n=1)
    assert _segments(packets) == []


@pytest.mark.parametrize("clock_rate", [0, -1, float("nan"), float("inf")])
def test_horloge_rtp_invalide_refusee(clock_rate):
    with pytest.raises(ValueError, match="strictement positive et finie"):
        _segments([], clock_rate=clock_rate)
