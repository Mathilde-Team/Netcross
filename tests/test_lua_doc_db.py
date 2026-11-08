# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests de la banque SQLite de l'API Lua Wireshark (issue #387)."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from netcross_core import lua_doc

ROOT = Path(__file__).resolve().parent.parent
JSON_PATH = ROOT / "data" / "lua_api.json"

SAMPLE = {
    "version_wireshark": "4.4.0",
    "date_generation": "2026-09-24",
    "source": "test",
    "classes": {
        "Tvb": {
            "nom": "Tvb",
            "module": "Tvb",
            "description": "Testy virtual buffer",
            "exemples": ["local t = tvb"],
            "attributs": [
                {
                    "nom": "reported_len",
                    "nom_complet": "tvb.reported_len",
                    "mode": "RO",
                    "description": "The reported length of the packet.",
                    "depuis_version": "",
                }
            ],
            "methodes": [
                {
                    "nom": "range",
                    "genre": "methode",
                    "signature": "tvb:range([offset], [length])",
                    "description": "Creates a TvbRange from this Tvb.",
                    "arguments": [
                        {"nom": "offset", "type": "", "optionnel": True, "description": "Offset (0-based)."},
                        {"nom": "length", "type": "", "optionnel": True, "description": "Length of the range."},
                    ],
                    "retours": ["The TvbRange."],
                    "erreurs": ["Offset out of bounds"],
                    "exemples": ["local r = tvb:range(0, 4)"],
                    "depuis_version": "",
                },
                {
                    "nom": "len",
                    "signature": "tvb:len()",
                    "description": "Obtain the actual (captured) length of a Tvb.",
                    "arguments": [],
                    "retours": ["The captured length of the Tvb."],
                    "exemples": [],
                    "depuis_version": "",
                },
            ],
        },
        "ByteArray": {
            "nom": "ByteArray",
            "description": "",
            "methodes": [
                {
                    "nom": "new",
                    "genre": "constructeur",
                    "signature": "ByteArray.new([hexbytes], [separator])",
                    "description": "Creates a new ByteArray object. Starting in version 1.11.3 ...",
                    "arguments": [{"nom": "hexbytes", "type": "", "optionnel": True, "description": "Hex."}],
                    "retours": ["The new ByteArray object."],
                    "exemples": [],
                    "depuis_version": "1.11.3",
                }
            ],
        },
    },
}


@pytest.fixture
def conn() -> sqlite3.Connection:
    c = lua_doc.connect(":memory:")
    lua_doc.load_json(c, SAMPLE)
    yield c
    c.close()


def test_schema_tables(conn: sqlite3.Connection) -> None:
    names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type IN ('table')")}
    for t in lua_doc._TABLES:
        assert t in names
    assert conn.execute("PRAGMA user_version").fetchone()[0] == lua_doc.SCHEMA_VERSION


def test_counts_and_meta(conn: sqlite3.Connection) -> None:
    assert lua_doc.list_classes(conn) == ["ByteArray", "Tvb"]
    meta = lua_doc.get_meta(conn)
    assert meta["version_wireshark"] == "4.4.0"
    assert meta["date_generation"] == "2026-09-24"
    assert meta["schema_version"] == str(lua_doc.SCHEMA_VERSION)


def test_load_is_idempotent(conn: sqlite3.Connection) -> None:
    counts = lua_doc.load_json(conn, SAMPLE)
    assert counts == {
        "classes": 2,
        "methodes": 3,
        "parametres": 3,
        "retours": 3,
        "erreurs": 1,
        "exemples": 1,
        "attributs": 1,
    }
    assert conn.execute("SELECT COUNT(*) FROM methodes").fetchone()[0] == 3
    assert conn.execute("SELECT COUNT(*) FROM recherche").fetchone()[0] == 4  # 3 methodes + 1 attribut


def test_old_schema_is_rebuilt(tmp_path: Path) -> None:
    db = tmp_path / "old.db"
    old = sqlite3.connect(db)
    old.execute("CREATE TABLE methodes (id INTEGER PRIMARY KEY, nom TEXT)")  # schema v1, sans genre
    old.commit()
    old.close()
    c = lua_doc.connect(db)
    lua_doc.load_json(c, SAMPLE)
    assert lua_doc.get_class(c, "Tvb") is not None
    c.close()


def test_get_class_full_sheet(conn: sqlite3.Connection) -> None:
    fiche = lua_doc.get_class(conn, "tvb")  # insensible a la casse
    assert fiche is not None
    assert fiche.nom == "Tvb" and fiche.module == "Tvb"
    assert fiche.exemples == ["local t = tvb"]
    assert [m.nom for m in fiche.methodes] == ["range", "len"]
    rng = fiche.methodes[0]
    assert rng.classe == "Tvb" and rng.genre == "methode"
    assert [p.nom for p in rng.parametres] == ["offset", "length"]  # ordre conserve
    assert all(p.optionnel for p in rng.parametres)
    assert rng.retours == ["The TvbRange."]
    assert rng.erreurs == ["Offset out of bounds"]
    assert rng.exemples == ["local r = tvb:range(0, 4)"]
    (attr,) = fiche.attributs
    assert (attr.nom_complet, attr.mode) == ("tvb.reported_len", "RO")


def test_get_class_unknown(conn: sqlite3.Connection) -> None:
    assert lua_doc.get_class(conn, "Nope") is None


def test_search_fts(conn: sqlite3.Connection) -> None:
    res = lua_doc.search(conn, "captured length")
    assert res and res[0].signature == "tvb:len()"
    assert not res[0].est_attribut
    m = lua_doc.get_methode(conn, res[0].ref_id)
    assert m is not None and m.retours == ["The captured length of the Tvb."]


def test_search_finds_attributes(conn: sqlite3.Connection) -> None:
    (res,) = lua_doc.search(conn, "reported")
    assert res.est_attribut and res.signature == "tvb.reported_len"
    attr = lua_doc.get_attribut(conn, res.ref_id)
    assert attr is not None and attr.mode == "RO"


def test_search_falls_back_to_any_word(conn: sqlite3.Connection) -> None:
    # "zzz" n'existe nulle part : repli sur OU, "captured" suffit
    assert [r.signature for r in lua_doc.search(conn, "captured zzz")] == ["tvb:len()"]


def test_search_prefix_and_class(conn: sqlite3.Connection) -> None:
    assert {r.classe for r in lua_doc.search(conn, "ByteArr")} == {"ByteArray"}


def test_search_special_chars_safe(conn: sqlite3.Connection) -> None:
    # Ne doit pas lever d'erreur de syntaxe FTS5
    assert lua_doc.search(conn, 'tvb:range( "') is not None
    assert lua_doc.search(conn, "   ") == []


def test_version_and_genre_preserved(conn: sqlite3.Connection) -> None:
    fiche = lua_doc.get_class(conn, "ByteArray")
    assert fiche is not None
    assert fiche.methodes[0].depuis_version == "1.11.3"
    assert fiche.methodes[0].genre == "constructeur"


@pytest.mark.skipif(not JSON_PATH.exists(), reason="data/lua_api.json absent")
def test_real_json_load_and_fast_search(tmp_path: Path) -> None:
    db = tmp_path / "lua.db"
    c = lua_doc.connect(db)
    counts = lua_doc.load_json_file(c, JSON_PATH)
    assert counts["classes"] >= 30 and counts["methodes"] >= 300
    t0 = time.perf_counter()
    res = lua_doc.search(c, "protofield uint32")
    assert time.perf_counter() - t0 < 0.1  # "reponse quasi instantanee" (#331)
    assert any(r.classe == "ProtoField" for r in res)
    tvb = lua_doc.get_class(c, "Tvb")
    assert tvb is not None and len(tvb.methodes) >= 5
    pinfo = lua_doc.get_class(c, "Pinfo")
    assert pinfo is not None and any(a.nom == "src" for a in pinfo.attributs)
    c.close()


@pytest.mark.skipif(not JSON_PATH.exists(), reason="data/lua_api.json absent")
def test_build_script(tmp_path: Path) -> None:
    db = tmp_path / "out.db"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "build_lua_db.py"), "--input", str(JSON_PATH), "--db", str(db)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert db.exists()
    assert "methodes" in proc.stdout


def test_build_script_missing_input(tmp_path: Path) -> None:
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "build_lua_db.py"), "--input", str(tmp_path / "x.json")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
