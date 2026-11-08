# SPDX-License-Identifier: GPL-3.0-or-later
"""Coherence de l'API publique de pcap_parser (`__all__` vs imports reels).

Regression : apres la fusion defectueuse f1f67dc (PR #190), `__all__` listait
`CaptureRingBuffer` sans que le nom soit importe dans `pcap_parser/__init__.py`
(et omettait merge_captures, replay_capture, split_capture, TcpreplayError,
TcpreplayNotFoundError). Aucun test ne le voyait car le code interne importe
depuis `pcap_parser.capture` ; seul `from pcap_parser import ...` etait casse.
"""

import pcap_parser

CAPTURE_API = (
    "CaptureRingBuffer",
    "TcpreplayError",
    "TcpreplayNotFoundError",
    "iter_live",
    "merge_captures",
    "parse_capture",
    "parse_captures_parallel",
    "replay_capture",
    "split_capture",
)


def test_tous_les_noms_de_all_existent_dans_le_package():
    manquants = [name for name in pcap_parser.__all__ if not hasattr(pcap_parser, name)]
    assert manquants == []


def test_import_etoile_fonctionne():
    namespace: dict = {}
    exec("from pcap_parser import *", namespace)
    assert set(pcap_parser.__all__) <= set(namespace)


def test_api_publique_de_capture_est_reexportee_et_declaree():
    for name in CAPTURE_API:
        assert name in pcap_parser.__all__, name
        assert getattr(pcap_parser, name) is getattr(pcap_parser.capture, name), name


def test_all_sans_doublon():
    assert len(pcap_parser.__all__) == len(set(pcap_parser.__all__))
