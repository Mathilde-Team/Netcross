# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests de l'extraction de l'API Lua Wireshark depuis l'AsciiDoc de make-wsluarm.py (issue #386)."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
JSON_PATH = ROOT / "data" / "lua_api.json"


def _load_tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("extract_lua_api", ROOT / "tools" / "extract_lua_api.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["extract_lua_api"] = mod
    spec.loader.exec_module(mod)
    return mod


ext = _load_tool()

# Extrait conforme a la sortie de tools/make-wsluarm.py (Wireshark 4.6).
ADOC = """\
// wslua_byte_array.c
[#lua_module_Tvb]
=== Functions For Handling Packet Data

// wslua_byte_array.c
[#lua_class_ByteArray]
==== ByteArray

Byte arrays, see <<lua_class_Tvb,`Tvb`>>.

==== Example

[source,lua]
----
    local ba = ByteArray.new("01 02")
----

// wslua_byte_array.c
[#lua_fn_ByteArray_new__hexbytes____separator__]
===== ByteArray.new([hexbytes], [separator])

Creates a new <<lua_class_ByteArray,`ByteArray`>> object.

Starting in version 1.11.3, if the second argument is a boolean `true`,
then the first argument is treated as a raw Lua string.

===== Example

[source,lua]
----
    local empty = ByteArray.new()
    local b1 = ByteArray.new("a1 b2 c3 d4")
----

[float]
===== Arguments

hexbytes (optional)::

A string consisting of hexadecimal bytes like "00 B1 A2".

// function_arg_footer: hexbytes (optional)
separator (optional)::

A string separator between hex bytes/words (default=" ").

// function_arg_footer: separator (optional)
// end of function_args

[float]
===== Returns

The new ByteArray object.

// function_returns_footer: ByteArray.new
// function_footer: ByteArray_new__hexbytes____separator__

// wslua_byte_array.c
[#lua_fn_bytearray___concat_first__second_]
===== bytearray:__concat(first, second)

Concatenate two <<lua_class_ByteArray,`ByteArray`>>s.

[float]
===== Arguments

first::

First array.

// function_arg_footer: first
second::

Second array.

// function_arg_footer: second
// end of function_args

[float]
===== Errors

* Both arguments must be ByteArrays

// function_errors_footer: bytearray:__concat
// function_footer: bytearray___concat_first__second_

// wslua_byte_array.c
[#lua_fn_bytearray_len__]
===== bytearray:len()

Obtain the length of a <<lua_class_ByteArray,`ByteArray`>>.

[float]
===== Returns

The length of the <<lua_class_ByteArray,`ByteArray`>>.

// function_returns_footer: bytearray:len
// function_footer: bytearray_len__

[#lua_class_attrib_bytearray_size]
===== bytearray.size

Mode: Retrieve only.

Size of the array. Since 4.2.0.

// End bytearray.size

// class_footer: ByteArray
[#global_functions_Tvb]
==== Global Functions

// wslua_byte_array.c
[#lua_fn_register_thing_name_]
===== register_thing(name)

Registers a thing, see https://www.wireshark.org/docs/[the docs].

[float]
===== Arguments

name::

The name.

// function_arg_footer: name
// end of function_args

// function_footer: register_thing_name_
// Global function
// end of module
"""


@pytest.fixture(scope="module")
def parsed() -> dict:
    return ext.parse_adoc(ADOC)


def _meth(classes: dict, cls: str, nom: str) -> dict:
    return next(m for m in classes[cls]["methodes"] if m["nom"] == nom)


# -- parseur AsciiDoc -------------------------------------------------------


def test_classes_and_module(parsed: dict) -> None:
    assert set(parsed) == {"ByteArray", "GlobalFunctions"}
    ba = parsed["ByteArray"]
    assert ba["module"] == "Tvb"
    assert ba["description"] == "Byte arrays, see `Tvb`."
    assert ba["exemples"] == ['local ba = ByteArray.new("01 02")']
    assert [m["nom"] for m in ba["methodes"]] == ["new", "__concat", "len"]


def test_constructor_full(parsed: dict) -> None:
    m = _meth(parsed, "ByteArray", "new")
    assert m["genre"] == "constructeur"
    assert m["signature"] == "ByteArray.new([hexbytes], [separator])"
    assert m["description"].startswith("Creates a new `ByteArray` object.\n\nStarting in version 1.11.3")
    assert "Example" not in m["description"] and "[float]" not in m["description"]
    assert m["depuis_version"] == "1.11.3"
    assert [(a["nom"], a["optionnel"]) for a in m["arguments"]] == [("hexbytes", True), ("separator", True)]
    assert m["arguments"][0]["description"] == 'A string consisting of hexadecimal bytes like "00 B1 A2".'
    assert m["retours"] == ["The new ByteArray object."]
    assert m["exemples"] == ['local empty = ByteArray.new()\nlocal b1 = ByteArray.new("a1 b2 c3 d4")']
    assert m["section"] == "lua_fn_ByteArray_new__hexbytes____separator__"


def test_no_bleed_between_functions(parsed: dict) -> None:
    concat = _meth(parsed, "ByteArray", "__concat")
    assert concat["genre"] == "metamethode"
    assert concat["retours"] == []  # pas ceux de len()
    assert concat["erreurs"] == ["Both arguments must be ByteArrays"]
    assert [a["optionnel"] for a in concat["arguments"]] == [False, False]
    length = _meth(parsed, "ByteArray", "len")
    assert length["genre"] == "methode"
    assert length["arguments"] == []
    assert length["retours"] == ["The length of the `ByteArray`."]


def test_attributes(parsed: dict) -> None:
    (attr,) = parsed["ByteArray"]["attributs"]
    assert attr["nom"] == "size" and attr["nom_complet"] == "bytearray.size"
    assert attr["mode"] == "RO"
    assert attr["description"] == "Size of the array. Since 4.2.0."
    assert attr["depuis_version"] == "4.2.0"


def test_global_functions_and_links(parsed: dict) -> None:
    (fn,) = parsed["GlobalFunctions"]["methodes"]
    assert fn["genre"] == "fonction" and fn["nom"] == "register_thing"
    assert fn["description"] == "Registers a thing, see the docs (https://www.wireshark.org/docs/)."
    assert fn["arguments"][0]["nom"] == "name"


def test_merge_across_files() -> None:
    classes = ext.parse_adoc(ADOC)
    ext.parse_adoc(
        ADOC.replace("bytearray:len()", "bytearray:size()").replace("[#lua_fn_bytearray_len__]", "[#x]"), classes
    )
    assert len(classes["GlobalFunctions"]["methodes"]) == 2


@pytest.mark.parametrize(
    ("texte", "attendu"),
    [
        ("Since 1.99.8", "1.99.8"),
        ("New in version 3.2", "3.2"),
        ("starting in Wireshark 4.4.0, x", "4.4.0"),
        ("Since: 4.2.0", "4.2.0"),
        ("no version here", ""),
    ],
)
def test_extract_version(texte: str, attendu: str) -> None:
    assert ext.extract_version(texte) == attendu


# -- rendu des blocs AsciiDoc ----------------------------------------------


def test_render_admonition() -> None:
    texte = ext.render_blocks(["Apply it.", "", "[WARNING]", "====", "Avoid *loops*", "here.", "====", "", "After."])
    assert texte == "Apply it.\n\nWarning: Avoid loops here.\n\nAfter."


def test_render_table_and_title() -> None:
    lignes = [
        ".Colors",
        '[cols="2",options="header"]',
        "|===",
        "|Index |Color",
        "|1 |{set:cellbgcolor:#fff} pink",
        "|===",
    ]
    texte = ext.render_blocks(lignes)
    assert texte == "Colors:\n\n  Index  Color\n  1      pink"


def test_render_unclosed_table() -> None:
    texte = ext.render_blocks(["Valid:", "", "|===", "|a |A", "|bb |B", "", "Suite."])
    assert texte == "Valid:\n\n  a   A\n  bb  B\n\nSuite."


def test_render_list_and_literal() -> None:
    texte = ext.render_blocks(
        ["Items:", "", "* one", "continued", "* menu:Analyze[] two", "", "----", "wireshark -o x", "----"]
    )
    assert texte == "Items:\n\n- one continued\n- Analyze two\n\n  wireshark -o x"


def test_example_heading_without_source() -> None:
    desc, exemples = ext.split_description(["The name.", "", "===== Example", "a = 1", "", "-- sugar", "b = 2"])
    assert desc == "The name."
    assert exemples == ["a = 1\n\n-- sugar\nb = 2"]


def test_inline_macros() -> None:
    assert ext.clean_inline("(e.g. menu:Lua Scripts[My Stats])") == "(e.g. Lua Scripts > My Stats)"
    assert ext.clean_inline("press kbd:[Ctrl+L]") == "press Ctrl+L"
    assert ext.clean_inline("The <<lua_class_Column,``Column``>>s") == "The `Column`s"


def test_identifiers_not_mangled() -> None:
    assert ext.clean_inline("use snake_case_name and a*b*c") == "use snake_case_name and a*b*c"


# -- lecture des sources Wireshark -----------------------------------------


def _fake_wireshark(tmp_path: Path) -> Path:
    src = tmp_path / "wireshark"
    (src / "epan" / "wslua").mkdir(parents=True)
    (src / "tools").mkdir()
    (src / "CMakeLists.txt").write_text(
        "set(PROJECT_MAJOR_VERSION 4)\nset(PROJECT_MINOR_VERSION 6)\nset(PROJECT_PATCH_VERSION 9)\n", encoding="utf-8"
    )
    (src / "epan" / "wslua" / "CMakeLists.txt").write_text(
        "set(WSLUA_MODULES\n\t${CMAKE_CURRENT_SOURCE_DIR}/wslua_a.c\n\t${CMAKE_CURRENT_SOURCE_DIR}/wslua_b.c\n)\n"
        "set(WSLUA_FILES\n\t${WSLUA_MODULES}\n\twslua_other.c\n)\n",
        encoding="utf-8",
    )
    # Faux make-wsluarm.py : ecrit l'extrait ADOC dans --output-directory.
    (src / "tools" / "make-wsluarm.py").write_text(
        "import sys, pathlib\n"
        "out = pathlib.Path(sys.argv[sys.argv.index('--output-directory') + 1])\n"
        "assert [pathlib.Path(a).name for a in sys.argv[3:]] == ['wslua_a.c', 'wslua_b.c']\n"
        f"(out / 'wslua_a.adoc').write_text({ADOC!r})\n",
        encoding="utf-8",
    )
    return src


def test_wireshark_version_and_modules(tmp_path: Path) -> None:
    src = _fake_wireshark(tmp_path)
    assert ext.wireshark_version(src) == "4.6.9"
    assert [p.name for p in ext.wslua_modules(src)] == ["wslua_a.c", "wslua_b.c"]


def test_main_from_wireshark_src(tmp_path: Path) -> None:
    src = _fake_wireshark(tmp_path)
    out = tmp_path / "api.json"
    assert ext.main(["--wireshark-src", str(src), "--output", str(out)]) == 0
    api = json.loads(out.read_text(encoding="utf-8"))
    assert api["version_wireshark"] == "4.6.9"
    assert "make-wsluarm.py" in api["source"]
    assert list(api["classes"]) == ["ByteArray", "GlobalFunctions"]


def test_main_from_adoc_dir(tmp_path: Path) -> None:
    (tmp_path / "wslua_x.adoc").write_text(ADOC, encoding="utf-8")
    out = tmp_path / "api.json"
    assert ext.main(["--adoc-dir", str(tmp_path), "--version", "4.6.0", "--output", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["version_wireshark"] == "4.6.0"


def test_main_empty_adoc_dir(tmp_path: Path) -> None:
    assert ext.main(["--adoc-dir", str(tmp_path), "--output", str(tmp_path / "o.json")]) == 1


# -- JSON versionne (data/lua_api.json) ------------------------------------


@pytest.fixture(scope="module")
def lua_api() -> dict:
    return json.loads(JSON_PATH.read_text(encoding="utf-8"))


def test_json_metadata(lua_api: dict) -> None:
    assert set(lua_api) == {"version_wireshark", "date_generation", "source", "classes"}
    assert lua_api["version_wireshark"].count(".") == 2
    assert "make-wsluarm.py" in lua_api["source"]


def test_json_coverage(lua_api: dict) -> None:
    classes = lua_api["classes"]
    assert len(classes) >= 35
    for nom in ("Proto", "ProtoField", "Tvb", "TvbRange", "TreeItem", "Pinfo", "Field", "Dissector", "ByteArray"):
        assert nom in classes, nom
    assert sum(len(c["methodes"]) for c in classes.values()) >= 350
    assert sum(len(c["attributs"]) for c in classes.values()) >= 100
    assert len(classes["ProtoField"]["methodes"]) >= 20
    assert len(classes["TvbRange"]["methodes"]) >= 20


def test_json_fields(lua_api: dict) -> None:
    for classe in lua_api["classes"].values():
        assert set(classe) == {"nom", "module", "description", "exemples", "methodes", "attributs"}
        for m in classe["methodes"]:
            assert {"nom", "genre", "signature", "description", "arguments", "retours", "erreurs", "exemples"} <= set(m)
            assert "(" in m["signature"]
            for a in m["arguments"]:
                assert set(a) == {"nom", "type", "optionnel", "description"}
            texte = m["description"] + " ".join(m["retours"])
            assert "<<" not in texte and "[float]" not in texte and "=====" not in texte
            assert "|===" not in texte and "[NOTE]" not in texte and "[WARNING]" not in texte and "{set:" not in texte


def test_json_pinfo_attributes(lua_api: dict) -> None:
    noms = {a["nom"] for a in lua_api["classes"]["Pinfo"]["attributs"]}
    assert {"src", "dst", "src_port", "dst_port", "number"} <= noms
