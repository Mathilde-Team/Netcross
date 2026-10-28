# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests de scripts/generate_class_diagram.py et de docs/class-diagram.md (issue #140).

Le diagramme de classes est GENERE depuis src/ et rafraichi par le hook
pre-commit `class-diagram`. Deux familles de tests :

- des tests unitaires du generateur sur un mini-`src/` factice (tmp_path) ;
- un test de fraicheur : le fichier versionne doit etre exactement ce que le
  generateur produit aujourd'hui depuis le vrai src/ (filet de securite pour
  les contributions qui n'auraient pas execute le hook pre-commit).
"""

from __future__ import annotations

import importlib.util
import re
import sys
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "generate_class_diagram.py"
GENERATED = REPO_ROOT / "docs" / "class-diagram.md"


def _load_generator():
    spec = importlib.util.spec_from_file_location("generate_class_diagram", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    # Enregistre AVANT exec_module : `dataclass` (annotations en chaines, PEP 563)
    # retrouve son module dans sys.modules.
    sys.modules["generate_class_diagram"] = module
    spec.loader.exec_module(module)
    return module


gen = _load_generator()


def _write(root: Path, rel: str, source: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(source), encoding="utf-8")


def _render(src: Path) -> str:
    return gen.render_document(gen.collect_modules(src))


def _blocks(document: str) -> list[str]:
    """Contenu de chaque bloc ```mermaid du document."""
    out: list[str] = []
    current: list[str] | None = None
    for line in document.splitlines():
        if line.strip() == "```mermaid":
            current = []
        elif line.strip() == "```" and current is not None:
            out.append("\n".join(current))
            current = None
        elif current is not None:
            current.append(line)
    return out


@pytest.fixture
def mini_src(tmp_path: Path) -> Path:
    src = tmp_path / "src"
    _write(
        src,
        "pcap_parser/__init__.py",
        '"""pcap_parser -- decodage bas niveau. Deuxieme phrase ignoree."""\n',
    )
    _write(
        src,
        "pcap_parser/packet.py",
        '''
        """pcap_parser.packet -- un paquet normalise."""
        from __future__ import annotations

        from dataclasses import dataclass


        @dataclass(slots=True)
        class RawPacket:
            ts: float
            ttl: int | None
            tags: tuple[str, ...]
            _cache: dict[str, list[int]]
            link: Optional["Link"] = None
            kind: int | str = 0

            def describe(self, verbose=False) -> str:
                return ""

            def _private(self) -> None: ...

            @staticmethod
            def parse(raw: bytes, *extra, strict=True, **opts) -> RawPacket:
                return None


        class Link:
            pass


        def read_packets(path, limit: int = 0) -> list[RawPacket]:
            return []


        def _helper():
            return None
        ''',
    )
    _write(
        src,
        "netcross_core/models.py",
        '''
        """netcross_core.models -- structures partagees. Suite de la description."""
        from __future__ import annotations

        import enum
        from dataclasses import dataclass, field

        from pcap_parser.packet import RawPacket


        class Severity(enum.Enum):
            INFO = "info"
            CRITICAL = "critical"
            _hidden = "x"


        class BaseEvent:
            pass


        class Boom(Exception):
            pass


        @dataclass
        class Finding(BaseEvent):
            severity: Severity
            packets: list[RawPacket] = field(default_factory=list)


        @dataclass
        class Report:
            findings: list[Finding]
            worst: "Finding | None"
            other: Finding
        ''',
    )
    _write(
        src,
        "netcross_report/models.py",
        """
        from dataclasses import dataclass


        @dataclass
        class Report:
            title: str
        """,
    )
    _write(
        src,
        "netcross_report/guarded.py",
        """
        try:
            import gi
        except ImportError:
            gi = None

        if gi:
            class Window(gi.Widget):
                def run(self):
                    return None
        """,
    )
    _write(
        src,
        "tool_cli.py",
        '''
        """Outil en ligne de commande."""
        import argparse

        from netcross_core.models import Report
        from netcross_report import models as report_models


        def main():
            return 0
        ''',
    )
    return src


# --------------------------------------------------------------------------- #
# Extraction et formatage                                                     #
# --------------------------------------------------------------------------- #


def test_champs_dataclass_types_et_visibilite(mini_src):
    doc = _render(mini_src)
    assert "class RawPacket {" in doc
    assert "<<dataclass, slots>>" in doc  # dataclass + option slots=True
    assert "+float ts" in doc
    assert "+int? ttl" in doc  # X | None -> X?
    assert "+tuple~str, ...~ tags" in doc  # generiques et Ellipsis
    assert "-dict~str, list~int~~ _cache" in doc  # generiques imbriques, prive -> '-'
    assert "+Link? link" in doc  # Optional["Link"] avec reference en chaine
    assert "+int or str kind" in doc  # union sans None


def test_methodes_publiques_seulement_avec_parametres_et_retour(mini_src):
    doc = _render(mini_src)
    assert "+describe(verbose) str" in doc
    assert "_private" not in doc  # methode privee absente
    # staticmethod -> `$`, *args/**kwargs et mots-cles conserves, `self`/`cls` retires
    assert "+parse(raw, extra, strict, opts)$ RawPacket" in doc


def test_fonctions_de_module_dans_un_noeud_module(mini_src):
    doc = _render(mini_src)
    assert 'class mod_pcap_parser_packet["pcap_parser.packet"] {' in doc
    assert "<<module>>" in doc
    assert "+read_packets(path, limit) list~RawPacket~" in doc
    assert "_helper" not in doc


def test_enum_liste_ses_membres_publics(mini_src):
    doc = _render(mini_src)
    assert "class Severity {" in doc
    assert "<<enum.Enum>>" in doc
    assert "+INFO" in doc
    assert "+CRITICAL" in doc
    assert "_hidden" not in doc


def test_classe_sans_membre_ni_stereotype_tient_sur_une_ligne(mini_src):
    doc = _render(mini_src)
    assert "\n    class Link\n" in doc


def test_classe_sous_try_et_if_est_detectee(mini_src):
    doc = _render(mini_src)
    assert "class Window {" in doc
    assert "<<gi.Widget>>" in doc  # base externe -> stereotype


def test_module_table_premiere_phrase_sans_prefixe_de_nom(mini_src):
    doc = _render(mini_src)
    assert "| `netcross_core.models` | structures partagees. |" in doc
    assert "| `pcap_parser` | decodage bas niveau. |" in doc
    assert "| `tool_cli` | Outil en ligne de commande. |" in doc


def test_annotation_privee_de_caracteres_dangereux_pour_mermaid():
    assert gen._safe('a "b" {c} <d> `e` | f') == "a b c d e f"


# --------------------------------------------------------------------------- #
# Relations                                                                   #
# --------------------------------------------------------------------------- #


def test_heritage_local_donne_une_fleche_et_pas_de_stereotype(mini_src):
    doc = _render(mini_src)
    assert "BaseEvent <|-- Finding" in doc
    finding = doc.split("class Finding {")[1].split("}")[0]
    assert "BaseEvent" not in finding  # base locale au bloc -> fleche, pas stereotype


def test_base_externe_va_dans_le_stereotype(mini_src):
    doc = _render(mini_src)
    boom = doc.split("class Boom {")[1].split("}")[0]
    assert "<<Exception>>" in boom


def test_association_deduite_des_annotations_avec_noms_de_champs(mini_src):
    doc = _render(mini_src)
    # `findings`, `worst` (annotation en chaine) et `other` pointent vers Finding ; `Report` existe
    # dans deux packages, son id est donc qualifie par le module.
    assert "netcross_core_models_Report --> Finding : findings, other, worst" in doc
    assert "Finding --> Severity : severity" in doc


def test_noms_de_classe_en_double_sont_qualifies_par_leur_module(mini_src):
    doc = _render(mini_src)
    assert 'class netcross_core_models_Report["netcross_core.models.Report"] {' in doc
    assert 'class netcross_report_models_Report["netcross_report.models.Report"] {' in doc


def test_pas_de_relation_entre_blocs_differents(mini_src):
    doc = _render(mini_src)
    # Finding.packets reference RawPacket, defini dans un AUTRE package : pas de fleche.
    assert "--> RawPacket" not in doc


def test_graphe_de_dependances_entre_packages(mini_src):
    graph = gen._render_package_graph(gen.collect_modules(mini_src))
    assert graph.startswith("flowchart TD")
    assert 'netcross_core -->|"1 import"| pcap_parser' in graph
    # tool_cli : `from netcross_core.models import` + `from netcross_report import` -> 1 chacun
    assert 'CLI -->|"1 import"| netcross_core' in graph
    assert 'CLI -->|"1 import"| netcross_report' in graph
    assert "argparse" not in graph  # imports stdlib ignores


# --------------------------------------------------------------------------- #
# Decoupage, determinisme, structure                                          #
# --------------------------------------------------------------------------- #


def test_decoupage_en_plusieurs_blocs_par_modules_entiers(tmp_path, monkeypatch):
    src = tmp_path / "src"
    for i in range(4):
        fields = "\n".join(f"    champ_{j}: int" for j in range(30))
        _write(
            src,
            f"netcross_core/mod{i}.py",
            f"from dataclasses import dataclass\n\n\n@dataclass\nclass C{i}:\n{fields}\n",
        )
    monkeypatch.setattr(gen, "MAX_BLOCK_CHARS", 1000)
    doc = _render(src)
    blocks = [b for b in _blocks(doc) if b.startswith("classDiagram")]
    assert len(blocks) > 1
    assert "### Diagramme (1/" in doc
    # Chaque classe apparait dans exactement un bloc (modules jamais coupes en deux).
    for i in range(4):
        assert sum(f"class C{i} " in b for b in blocks) == 1
    # Et tous les champs d'une classe restent ensemble.
    for b in blocks:
        for i in range(4):
            if f"class C{i} " in b:
                assert b.count("champ_") % 30 == 0


def test_sortie_deterministe(mini_src):
    assert _render(mini_src) == _render(mini_src)


def test_ordre_des_sections_suit_les_couches(mini_src):
    doc = _render(mini_src)
    order = [doc.index(f"## `{p}`") for p in ("pcap_parser", "netcross_core", "netcross_report")]
    assert order == sorted(order)
    assert doc.index("## CLI") > order[-1]


# --------------------------------------------------------------------------- #
# CLI (--check / ecriture)                                                    #
# --------------------------------------------------------------------------- #


def test_check_echoue_si_fichier_absent_puis_passe_apres_ecriture(mini_src, tmp_path, capsys):
    out = tmp_path / "out" / "class-diagram.md"
    assert gen.main(["--src", str(mini_src), "--output", str(out), "--check"]) == 1
    assert not out.exists()  # --check n'ecrit jamais
    assert "obsolete" in capsys.readouterr().err

    assert gen.main(["--src", str(mini_src), "--output", str(out)]) == 0
    assert out.exists()
    assert gen.main(["--src", str(mini_src), "--output", str(out), "--check"]) == 0


def test_check_detecte_un_fichier_perime_apres_changement_du_code(mini_src, tmp_path):
    out = tmp_path / "class-diagram.md"
    gen.main(["--src", str(mini_src), "--output", str(out)])
    _write(mini_src, "netcross_core/extra.py", "class Nouvelle:\n    x: int\n")
    assert gen.main(["--src", str(mini_src), "--output", str(out), "--check"]) == 1
    gen.main(["--src", str(mini_src), "--output", str(out)])
    assert "class Nouvelle {" in out.read_text(encoding="utf-8")
    assert gen.main(["--src", str(mini_src), "--output", str(out), "--check"]) == 0


def test_ecriture_idempotente_ne_touche_pas_au_fichier(mini_src, tmp_path):
    out = tmp_path / "class-diagram.md"
    gen.main(["--src", str(mini_src), "--output", str(out)])
    first = out.stat().st_mtime_ns
    gen.main(["--src", str(mini_src), "--output", str(out)])
    assert out.stat().st_mtime_ns == first  # pas de reecriture inutile -> le hook ne fait pas echouer


# --------------------------------------------------------------------------- #
# Le vrai fichier versionne                                                   #
# --------------------------------------------------------------------------- #


def test_docs_class_diagram_est_a_jour():
    """Filet de securite : le fichier versionne == ce que le generateur produit depuis src/."""
    expected = gen.render_document(gen.collect_modules(REPO_ROOT / "src"))
    actual = GENERATED.read_text(encoding="utf-8") if GENERATED.exists() else ""
    assert actual == expected, (
        "docs/class-diagram.md est obsolete : executer `python3 scripts/generate_class_diagram.py` "
        "(le hook pre-commit `class-diagram` le fait automatiquement) puis l'ajouter au commit."
    )


def test_vrai_diagramme_structure_sure_pour_mermaid():
    blocks = _blocks(GENERATED.read_text(encoding="utf-8"))
    assert len(blocks) >= 2
    for block in blocks:
        assert block.startswith(("classDiagram", "flowchart TD", "flowchart LR"))
        assert len(block) <= gen.MAX_BLOCK_CHARS + 5_000  # marge sous les 50 000 de mermaid
        assert block.count("{") == block.count("}")  # accolades de classes equilibrees
        assert "`" not in block


def test_vrai_diagramme_couvre_les_classes_cles():
    text = GENERATED.read_text(encoding="utf-8")
    for name in ("RawPacket", "Pkt", "Report", "Finding", "ExpertEvent", "MainWindow"):
        # `class Nom` si le nom est unique dans src/, sinon `class <module>_Nom["<module>.Nom"]`.
        assert re.search(rf'class (\w*_)?{name}\b(\["[\w.]*{name}"\])?', text), name


def test_vrai_diagramme_possede_section_inter_modules():
    """Le diagramme versionné doit inclure une section 'Relations inter-modules'."""
    text = GENERATED.read_text(encoding="utf-8")
    assert "## Relations inter-modules" in text
    # Au moins une relation flowchart inter-modules (syntaxe mermaid -->|label|)
    assert re.search(r"flowchart LR\n.*-->\|.*\|--", text, re.DOTALL)


def test_inter_module_relations_sur_mini_src(mini_src):
    """Les relations inter-modules sont détectées et placées dans une section dédiée."""
    doc = _render(mini_src)
    # Finding (netcross_core.models) référence RawPacket (pcap_parser.packet) via 'packets'
    assert "## Relations inter-modules" in doc
    assert "Finding -->|packets| RawPacket" in doc
    # Les nœuds sont déclarés explicitement avec leur nom complet (module.Class)
    assert 'Finding["netcross_core.models.Finding"]' in doc
    assert 'RawPacket["pcap_parser.packet.RawPacket"]' in doc
    # ET cette relation n'apparait PAS dans les blocs classDiagram par package
    blocks = [b for b in _blocks(doc) if b.startswith("classDiagram")]
    for b in blocks:
        assert "--> RawPacket" not in b


def test_inter_module_relations_aucune_relation_retourne_vide():
    """Sans relation inter-module, la section n'est pas ajoutée."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        src = gen.Path(tmp) / "src"
        _write(src, "pkg_a/__init__.py", '"""Package A."""\n')
        _write(src, "pkg_a/a.py", "class A:\n    pass\n")
        _write(src, "pkg_b/__init__.py", '"""Package B."""\n')
        _write(src, "pkg_b/b.py", "class B:\n    pass\n")
        doc = _render(src)
        assert "Relations inter-modules" not in doc
