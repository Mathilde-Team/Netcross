# SPDX-License-Identifier: GPL-3.0-or-later
"""Les délais physiques corrigés ne s'annulent pas entre aller et retour."""

from dataclasses import replace

import pytest
from conftest import make_pkt

from netcross_core.analysis import analyse
from netcross_core.correlate import correlate


def _echange_bidirectionnel(decalage_ms, *, rtp=False):
    decalage_s = decalage_ms / 1000
    aller = make_pkt(
        point="A",
        ts=1.0,
        proto="UDP",
        sport=40000,
        dport=45000,
        key_id=1,
        payload_hash="aller",
        is_rtp=rtp,
        rtp_ssrc=100 if rtp else None,
        rtp_seq=1 if rtp else None,
        rtp_ts=8000 if rtp else None,
    )
    retour = make_pkt(
        point="B",
        ts=1.006 + decalage_s,
        proto="UDP",
        src=aller.dst,
        dst=aller.src,
        sport=aller.dport,
        dport=aller.sport,
        key_id=2,
        payload_hash="retour",
        is_rtp=rtp,
        rtp_ssrc=101 if rtp else None,
        rtp_seq=1 if rtp else None,
        rtp_ts=8000 if rtp else None,
    )
    return [
        aller,
        replace(aller, point="B", ts=1.005 + decalage_s),
        retour,
        replace(retour, point="A", ts=1.011),
    ]


@pytest.mark.parametrize("decalage_ms", [-37.0, 0.0, 37.0])
@pytest.mark.parametrize("rtp", [False, True])
def test_delais_corriges_positifs_dans_les_deux_sens(decalage_ms, rtp):
    paquets = _echange_bidirectionnel(decalage_ms, rtp=rtp)
    rapport = analyse(
        correlate(paquets),
        ["A", "B"],
        paquets,
        clock_offsets={("A", "B"): decalage_ms},
    )
    assert rapport.latency[("A", "B")] == pytest.approx([5.0, 5.0])
    assert rapport.latency_by_bucket[("A", "B")][1] == pytest.approx([5.0, 5.0])
    if rtp:
        assert [flux["delay_ms"] for flux in rapport.rtp_streams] == pytest.approx([5.0, 5.0])


def test_sans_estimation_le_delta_signe_reste_disponible():
    paquets = _echange_bidirectionnel(0.0)
    rapport = analyse(correlate(paquets), ["A", "B"], paquets)
    assert not rapport.clock_offset_estimate
    assert rapport.latency[("A", "B")] == pytest.approx([5.0, -5.0])
