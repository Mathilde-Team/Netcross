# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for the GTK4 duplicate status formatter.

The formatter is deliberately pure Python, so these tests do not require GTK.
"""

from netcross_core.models import Report
from netcross_gtk4.duplicate_view import format_duplicate_indicator


def test_duplicate_indicator_empty():
    report = Report()
    assert format_duplicate_indicator(report) == "Doublons inter-captures : aucun détecté."


def test_duplicate_indicator_lists_pairs_and_inclusion():
    report = Report()
    report.duplicate_count[("A", "B")] = 10
    report.duplicate_count[("A", "C")] = 2
    assert format_duplicate_indicator(report) == (
        "Doublons inter-captures : 12 paquet(s) (A ↔ B : 10, A ↔ C : 2) — inclus dans les statistiques"
    )


def test_duplicate_indicator_marks_exclusion():
    report = Report()
    report.duplicate_count[("A", "B")] = 10
    report.duplicates_excluded = True
    assert format_duplicate_indicator(report).endswith(" — exclus des statistiques et de la corrélation")
