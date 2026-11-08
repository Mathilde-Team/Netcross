# SPDX-License-Identifier: GPL-3.0-or-later
"""
Non-regression du CEF apres le refactoring `_to_siem_records` (issue #279) :
sortie figee capturee AVANT le refactoring, horloge figee.
"""

from __future__ import annotations

import datetime as real_dt
import types

import pytest

import netcross_report.siem_export as siem
from netcross_core.models import Report

GOLDEN = [
    "CEF:0|Netcross|Netcross|1.0|100|exploit: Log4Shell \\| a\\\\b|10|shost=LAN rt=1767323045000",
    "CEF:0|Netcross|Netcross|1.0|201|dns_tunnel: " + "x" * 243 + "|6|rt=1767323045000",
    "CEF:0|Netcross|Netcross|1.0|999|zzz: |5|shost=W\\|AN rt=1767323045000",
    "CEF:0|Netcross|Netcross|1.0|200|anomalie: |3|rt=1767323045000",
    "CEF:0|Netcross|Netcross|1.0|300|cve: CVE=1 é|3|shost=P rt=1767323045000",
]


class _FrozenDateTime:
    @staticmethod
    def now():
        return real_dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=real_dt.UTC)


@pytest.fixture
def frozen_clock(monkeypatch):
    monkeypatch.setattr(siem, "_dt", types.SimpleNamespace(datetime=_FrozenDateTime))


def _report():
    r = Report()
    r.security_findings = [
        {"severity": "critique", "category": "exploit", "detail": "Log4Shell | a\\b", "point": "LAN"},
        {"severity": "Moyenne", "category": "dns_tunnel", "detail": "x" * 300, "point": None},
        {"severity": "inconnue", "category": "zzz", "detail": "", "point": "W|AN"},
        {},
        {"severity": "faible", "category": "cve", "detail": "CVE=1 é", "point": "P", "cve_id": "CVE-1"},
    ]
    return r


def test_cef_identique_a_la_sortie_figee(frozen_clock):
    assert siem.export_cef(_report()) == GOLDEN
