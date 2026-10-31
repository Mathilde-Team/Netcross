"""netcross_gtk4.lua_doc_view -- logique sans GTK de la fenetre
« Documentation Lua » (issue #873), equivalent de ``netcross-lua-doc``.

Meme banque SQLite (``netcross_core.lua_doc``), meme texte que la CLI
(``netcross_report.lua_doc_text``) : liste des classes (``--classes``),
fiche d'une classe (``--class``), recherche (``TERME``, ``--limit``,
``--full``) et document JSON (``--json``). Issue #917 : catalogue des
dissecteurs Lua (``--dissectors``, ``--domain``, ``--non-native``,
``--domains``), même texte et même JSON.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from typing import Any

from netcross_core import lua_dissectors, lua_doc
from netcross_core.logging_config import get_logger
from netcross_report.lua_dissectors_text import render_dissecteurs, render_domaines
from netcross_report.lua_doc_text import render_fiche, render_resultats

logger = get_logger(__name__)

DEFAULT_LIMIT = 20


class LuaDocUnavailableError(Exception):
    """JSON de l'API Lua introuvable (meme message que la CLI)."""


class LuaDocBrowser:
    """Acces a la documentation Lua pour la GUI (une connexion, fermee par
    ``close``)."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        source: str | Path | None = None,
        find_json: Callable[[], Path | None] | None = None,
    ) -> None:
        json_path = Path(source) if source else (find_json or lua_doc.find_json)()
        if json_path is None or not json_path.is_file():
            emplacements = ", ".join(str(p) for p in lua_doc.json_candidates())
            logger.warning("LuaDocBrowser: JSON introuvable ({})", emplacements)
            raise LuaDocUnavailableError(
                f"JSON de l'API Lua introuvable ({source or emplacements}). "
                "Le generer avec : python3 tools/extract_lua_api.py --tag vX.Y.Z"
            )
        self.conn: sqlite3.Connection = lua_doc.ensure_db(db_path or lua_doc.DEFAULT_DB_PATH, json_path)
        self.version = lua_doc.get_meta(self.conn).get("version_wireshark", "")
        self.catalogue = lua_dissectors.ensure_catalogue(self.conn)
        logger.debug("LuaDocBrowser.__init__: fin")

    def close(self) -> None:
        self.conn.close()
        logger.debug("LuaDocBrowser.close: fin")

    def classes(self) -> list[str]:
        logger.debug("LuaDocBrowser.classes: retour lua_doc.list_classes(…)")
        return lua_doc.list_classes(self.conn)

    def classes_text(self) -> str:
        """Texte de ``netcross-lua-doc --classes``."""
        noms = self.classes()
        logger.debug("LuaDocBrowser.classes_text: retour '\\n'.join(…)")
        return "\n".join([f"{len(noms)} classes -- Wireshark {self.version}", "", *(f"  {n}" for n in noms)])

    def class_text(self, name: str) -> str:
        """Fiche de ``--class NOM``, ou message « Classe inconnue » de la CLI."""
        fiche = lua_doc.get_class(self.conn, name)
        if fiche is None:
            suggestion = lua_doc.suggest_classes(self.conn, name)
            logger.debug("class_text: classe inconnue {}", name)
            return f"Classe inconnue : {name}" + (f" (voir : {', '.join(suggestion)})" if suggestion else "")
        logger.debug("LuaDocBrowser.class_text: retour '\\n'.join(render_fiche(fiche, self.vers…(…)")
        return "\n".join(render_fiche(fiche, self.version)).rstrip()

    def search(self, terme: str, limit: int = DEFAULT_LIMIT, full: bool = False) -> tuple[str, list[str]]:
        """(texte de ``netcross-lua-doc [--full] --limit N TERME``, classes
        trouvees dans l'ordre, pour ouvrir leur fiche)."""
        terme = terme.strip()
        if not terme:
            logger.debug("LuaDocBrowser.search: si not terme -> retour tuple de 2")
            return "", []
        res = lua_doc.search(self.conn, terme, limit)
        if not res:
            logger.debug("LuaDocBrowser.search: si not res -> retour tuple de 2")
            return f"Aucun resultat pour « {terme} » (Wireshark {self.version}).", []
        classes = list(dict.fromkeys(r.classe for r in res))
        logger.debug("LuaDocBrowser.search: retour tuple de 2")
        return "\n".join(render_resultats(self.conn, terme, res, full)).rstrip(), classes

    # -- catalogue des dissecteurs (issue #917) -------------------------------

    def domains(self) -> list[str]:
        """Domaines du catalogue (liste de la GUI), du plus fourni au moins fourni."""
        logger.debug("LuaDocBrowser.domains: retour liste")
        return [d for d, _n in lua_dissectors.domains(self.conn)]

    def domains_text(self) -> str:
        """Texte de ``netcross-lua-doc --domains``."""
        if not self.catalogue:
            logger.debug("LuaDocBrowser.domains_text: si not self.catalogue -> retour self._catalogue_absent(…)")
            return self._catalogue_absent()
        logger.debug("LuaDocBrowser.domains_text: retour '\\n'.join(…)")
        return "\n".join(render_domaines(lua_dissectors.domains_document(self.conn)))

    def dissectors_text(
        self, terme: str = "", domaine: str | None = None, non_natif: bool = False, limit: int = DEFAULT_LIMIT
    ) -> str:
        """Texte de ``netcross-lua-doc --dissectors [TERME] [--domain] [--non-native] --limit N``."""
        if not self.catalogue:
            logger.debug("LuaDocBrowser.dissectors_text: si not self.catalogue -> retour self._catalogue_absent(…)")
            return self._catalogue_absent()
        doc = lua_dissectors.search_document(self.conn, terme.strip(), domaine, non_natif, limit)
        if not doc["total"]:
            logger.debug("LuaDocBrowser.dissectors_text: si not doc['total'] -> retour chaîne formatée")
            return f"Aucun dissecteur Lua pour « {terme.strip() or domaine or ''} »."
        logger.debug("LuaDocBrowser.dissectors_text: retour '\\n'.join(render_dissecteurs(doc)).rstr…(…)")
        return "\n".join(render_dissecteurs(doc)).rstrip()

    def dissectors_json(
        self, terme: str = "", domaine: str | None = None, non_natif: bool = False, limit: int = DEFAULT_LIMIT
    ) -> str:
        """JSON de ``--dissectors --json`` (même document que ``GET /lua-doc/dissectors``)."""
        doc = lua_dissectors.search_document(self.conn, terme.strip(), domaine, non_natif, limit)
        logger.debug("LuaDocBrowser.dissectors_json: retour json.dumps(…)")
        return json.dumps(doc, ensure_ascii=False, indent=2)

    @staticmethod
    def _catalogue_absent() -> str:
        emplacements = ", ".join(str(p) for p in lua_dissectors.csv_candidates())
        logger.debug("LuaDocBrowser: catalogue des dissecteurs absent")
        return f"Catalogue des dissecteurs Lua introuvable ({emplacements})."

    def json_text(
        self, terme: str = "", name: str | None = None, limit: int = DEFAULT_LIMIT, full: bool = False
    ) -> str:
        """JSON de ``--json`` : fiche (``name``), recherche (``terme``) ou
        liste des classes."""
        meta = lua_doc.get_meta(self.conn)
        doc: dict[str, Any]
        if name:
            fiche = lua_doc.get_class(self.conn, name)
            doc = {"meta": meta, "classe": asdict(fiche) if fiche else None}
        elif terme.strip():
            doc = lua_doc.search_document(self.conn, terme.strip(), limit, full)
        else:
            doc = {"meta": meta, "classes": self.classes()}
        logger.debug("LuaDocBrowser.json_text: retour json.dumps(…)")
        return json.dumps(doc, ensure_ascii=False, indent=2)
