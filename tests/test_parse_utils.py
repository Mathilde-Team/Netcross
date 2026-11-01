# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.tshark_stats.parse_utils -- tests des cas limites non couverts
par les tests de parsers (issue #246).

parse_utils est le socle commun des parsers tshark_stats (conversations,
endpoints, io_stat...). Les tests des parsers couvrent les chemins normaux
mais rater certaines branches edge-case : None en entree, champs vides,
colonnes introuvables. Ce fichier cible specifiquement ces branches.
"""

from __future__ import annotations

from netcross_core.tshark_stats.parse_utils import (
    data_rows,
    find_column,
    is_filter_line,
    is_separator,
    is_title_or_section,
    normalize_header,
    parse_float,
    parse_int,
    raw_fields_from,
    reconstruct_headers,
    split_fields,
)

# --- is_separator ----------------------------------------------------------


def test_is_separator_dash_line():
    assert is_separator("---") is True
    assert is_separator("------") is True


def test_is_separator_short_string():
    assert is_separator("--") is False
    assert is_separator("") is False
    assert is_separator("a") is False


def test_is_separator_mixed_chars():
    assert is_separator("====") is True
    assert is_separator("==== some text") is False


# --- is_filter_line --------------------------------------------------------


def test_is_filter_line_with_spaces():
    assert is_filter_line("   Filter: ip") is True


def test_is_filter_line_not_filter():
    assert is_filter_line("Some text") is False


# --- is_title_or_section ---------------------------------------------------


def test_is_title_or_section_empty():
    assert is_title_or_section("") is True
    assert is_title_or_section("   ") is True


def test_is_title_or_section_separator():
    assert is_title_or_section("========") is True


def test_is_title_or_section_filter():
    assert is_title_or_section("Filter: tcp") is True


def test_is_title_or_section_data_line():
    assert is_title_or_section("| 192.168.1.1 | 100 |") is False


# --- split_fields ----------------------------------------------------------


def test_split_fields_no_pipes():
    # split_fields ne retourne que les champs entre |, pas le texte brut
    assert split_fields("plain text") == []


def test_split_fields_single_field_with_borders():
    assert split_fields("| value |") == ["value"]


def test_split_fields_multiple_fields():
    result = split_fields("| addr | port | pkts |")
    assert result == ["addr", "port", "pkts"]


def test_split_fields_no_borders():
    result = split_fields("addr | port | pkts")
    assert result == ["addr", "port", "pkts"]


# --- parse_int -------------------------------------------------------------


def test_parse_int_none():
    assert parse_int(None) is None


def test_parse_int_empty():
    assert parse_int("") is None
    assert parse_int("  ") is None


def test_parse_int_dash():
    assert parse_int("-") is None
    assert parse_int("--") is None


def test_parse_int_with_commas():
    assert parse_int("1,234,567") == 1234567


def test_parse_int_with_spaces():
    assert parse_int("  42  ") == 42


def test_parse_int_invalid():
    assert parse_int("abc") is None


def test_parse_int_float_string():
    # parse_int tronque les floats vers int
    assert parse_int("3.14") == 3


# --- parse_float -----------------------------------------------------------


def test_parse_float_none():
    assert parse_float(None) is None


def test_parse_float_empty():
    assert parse_float("") is None


def test_parse_float_dash():
    assert parse_float("-") is None
    assert parse_float("--") is None


def test_parse_float_with_commas():
    assert parse_float("1,234.56") == 1234.56


def test_parse_float_with_unit():
    # parse_float extrait la valeur numerique meme avec un suffixe
    assert parse_float("3.14s") == 3.14


def test_parse_float_invalid():
    assert parse_float("abc") is None


def test_parse_float_negative():
    assert parse_float("-1.5") == -1.5


# --- normalize_header ------------------------------------------------------


def test_normalize_header_lowercase():
    assert normalize_header("Address") == "address"


def test_normalize_header_collapse_spaces():
    assert normalize_header("  Packets   Sent  ") == "packets sent"


def test_normalize_header_remove_percent():
    assert normalize_header("Loss %") == "loss"


def test_normalize_header_units():
    # bits/s et mbit/s sont normalises, mais bytes/s ne l'est pas
    assert normalize_header("Bits/s") == "bits_s"
    assert normalize_header("Mbit/s") == "bits_s"


# --- find_column -----------------------------------------------------------


def test_find_column_match():
    headers = ["Address", "Port", "Packets"]
    assert find_column(headers, "port") == 1


def test_find_column_multiple_keywords():
    headers = ["Packets Sent", "Packets Received"]
    assert find_column(headers, "packets", "sent") == 0


def test_find_column_no_match():
    headers = ["Address", "Port"]
    assert find_column(headers, "bytes") is None


def test_find_column_partial_match():
    headers = ["Packet Count", "Byte Count"]
    assert find_column(headers, "packet") == 0
    assert find_column(headers, "byte") == 1


# --- data_rows -------------------------------------------------------------


def test_data_rows_extracts_only_data():
    text = """================================================================================
| Address | Port | Packets |
| 192.168.1.1 | 80 | 100 |
| 10.0.0.1 | 443 | 200 |
Filter: tcp
================================================================================"""
    rows = data_rows(text)
    assert len(rows) == 2
    assert "192.168.1.1" in rows[0]


def test_data_rows_empty():
    assert data_rows("") == []
    assert data_rows("No data here") == []


# --- reconstruct_headers / raw_fields_from ---------------------------------


def test_reconstruct_headers_basic():
    text = """================================================================================
| Address | Port |
| Packets |
================================================================================"""
    headers = reconstruct_headers(text)
    assert len(headers) >= 1


def test_raw_fields_from():
    headers = ["address", "port"]
    fields = ["192.168.1.1", "80"]
    result = raw_fields_from(headers, fields)
    assert result["address"] == "192.168.1.1"
    assert result["port"] == "80"


def test_raw_fields_from_mismatched_lengths():
    headers = ["address", "port"]
    fields = ["192.168.1.1"]
    result = raw_fields_from(headers, fields)
    assert result["address"] == "192.168.1.1"
    assert result.get("port", "") == ""
