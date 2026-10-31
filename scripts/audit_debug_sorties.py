#!/usr/bin/env python3
"""Contrôle AST : un logger.debug() avant chaque sortie de fonction.

Sortie = chaque ``return``, chaque ``raise`` et la fin implicite d'une
fonction (quand le corps peut « tomber » au bout sans return/raise).
Une sortie est conforme si l'instruction qui la précède immédiatement,
dans le même bloc, est un appel ``logger.debug(...)`` (pour un ``raise``,
un appel ``logger.info/warning/error/exception/critical`` est aussi
accepté). Les bouchons (corps = docstring / pass / ...) et les
``@overload`` sont ignorés.

Usage : python3 scripts/audit_debug_sorties.py [--json FICHIER]
"""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path

from loguru import logger

# Issue #954 : l'audit couvre tout le Python suivi par git, pas seulement src/.
BASES = (
    Path(__file__).resolve().parent.parent / "src",
    Path(__file__).resolve().parent.parent / "scripts",
    Path(__file__).resolve().parent.parent / "tools",
)
LOGGER_NAMES = ("logger", "_logger", "log")
RAISE_OK = {"debug", "info", "warning", "error", "exception", "critical"}


def _log_level(stmt: ast.stmt | None) -> str | None:
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) and isinstance(stmt.value.func, ast.Attribute):
        base = stmt.value.func.value
        # logger.debug(...) ou logger.opt(...).debug(...)
        while isinstance(base, ast.Call) and isinstance(base.func, ast.Attribute):
            base = base.func.value
        if isinstance(base, ast.Name) and base.id in LOGGER_NAMES:
            logger.debug(
                "_log_level: si isinstance(base, ast.Name) and base.id in LOGGER_NAMES -> retour stmt.value.func.attr"
            )
            return stmt.value.func.attr
    logger.debug("_log_level: retour None")
    return None


def _can_fall_through(body: list[ast.stmt]) -> bool:
    if not body:
        logger.debug("_can_fall_through: si not body -> retour True")
        return True
    last = body[-1]
    if isinstance(last, (ast.Return, ast.Raise)):
        logger.debug("_can_fall_through: si isinstance(last, (ast.Return, ast.Raise)) -> retour False")
        return False
    if isinstance(last, ast.If):
        logger.debug(
            "_can_fall_through: si isinstance(last, ast.If) -> retour _can_fall_through(last.body) or _can_fall_throu…"
        )
        return _can_fall_through(last.body) or _can_fall_through(last.orelse)
    if isinstance(last, (ast.With, ast.AsyncWith)):
        logger.debug("_can_fall_through: si isinstance(last, (ast.With, ast.AsyncWith)) -> retour _can_fall_through(…)")
        return _can_fall_through(last.body)
    if isinstance(last, ast.Try) or (hasattr(ast, "TryStar") and isinstance(last, ast.TryStar)):
        if last.finalbody and not _can_fall_through(last.finalbody):
            logger.debug(
                "_can_fall_through: si last.finalbody and (not _can_fall_through(last.finalbody)) -> retour False"
            )
            return False
        main = last.body + last.orelse
        logger.debug(
            "_can_fall_through: si isinstance(last, ast.Try) or (hasattr(ast, 'TryStar') and i… -> retour _can_fall_t…"
        )
        return _can_fall_through(main) or any(_can_fall_through(h.body) for h in last.handlers)
    if isinstance(last, ast.While):
        infinite = isinstance(last.test, ast.Constant) and bool(last.test.value)
        has_break = any(isinstance(n, ast.Break) for n in ast.walk(last))
        logger.debug("_can_fall_through: si isinstance(last, ast.While) -> retour not infinite or has_break")
        return not infinite or has_break
    logger.debug("_can_fall_through: retour True")
    return True


def _is_stub(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in fn.decorator_list:
        name = dec.attr if isinstance(dec, ast.Attribute) else getattr(dec, "id", None)
        if name == "overload":
            logger.debug("_is_stub: si name == 'overload' -> retour True")
            return True
    body = list(fn.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    logger.debug("_is_stub: retour all(…)")
    return all(
        isinstance(s, ast.Pass)
        or (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and s.value.value is Ellipsis)
        for s in body
    )


def _blocks(node: ast.AST):
    """Tous les blocs d'instructions de la fonction, sans descendre dans
    les fonctions/classes imbriquées (elles sont auditées à part)."""
    for field in ("body", "orelse", "finalbody"):
        block = getattr(node, field, None)
        if isinstance(block, list) and block and isinstance(block[0], ast.stmt):
            yield block
            for s in block:
                if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    yield from _blocks(s)
    for h in getattr(node, "handlers", []) or []:
        yield h.body
        for s in h.body:
            if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                yield from _blocks(s)
    for c in getattr(node, "cases", []) or []:
        yield c.body
        for s in c.body:
            if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                yield from _blocks(s)
    logger.debug("_blocks: fin")


def audit_function(fn) -> tuple[int, list[tuple[int, str]]]:
    """Renvoie (nombre de sorties, sorties non conformes [(ligne, type)])."""
    exits = 0
    bad: list[tuple[int, str]] = []
    for block in _blocks(fn):
        for i, stmt in enumerate(block):
            if isinstance(stmt, (ast.Return, ast.Raise)):
                exits += 1
                prev = block[i - 1] if i > 0 else None
                lvl = _log_level(prev)
                ok = lvl == "debug" if isinstance(stmt, ast.Return) else lvl in RAISE_OK
                if not ok:
                    bad.append((stmt.lineno, "return" if isinstance(stmt, ast.Return) else "raise"))
    if _can_fall_through(fn.body):
        exits += 1
        if _log_level(fn.body[-1]) != "debug":
            bad.append((fn.end_lineno or fn.lineno, "fin implicite"))
    logger.debug("audit_function: retour tuple de 2")
    return exits, bad


def qualname_walk(tree: ast.Module):
    def rec(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = f"{prefix}{child.name}"
                yield q, child
                yield from rec(child, q + ".<locals>.")
            elif isinstance(child, ast.ClassDef):
                yield from rec(child, f"{prefix}{child.name}.")
            else:
                yield from rec(child, prefix)
        logger.debug("qualname_walk.rec: fin")

    yield from rec(tree, "")
    logger.debug("qualname_walk: fin")


def main() -> None:
    logger.debug("main: entrée")
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    ap.add_argument("--total", action="store_true", help="affiche uniquement le total des sorties non conformes")
    args = ap.parse_args()
    result = []
    chemins = []
    for base in BASES:
        chemins.extend(base.rglob("*.py"))
    for path in sorted(chemins):
        if "egg-info" in str(path) or "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        funcs = []
        n_exits = n_bad = 0
        for q, fn in qualname_walk(tree):
            if _is_stub(fn):
                continue
            exits, bad = audit_function(fn)
            n_exits += exits
            n_bad += len(bad)
            funcs.append(
                {
                    "name": q,
                    "line": fn.lineno,
                    "lines": (fn.end_lineno or fn.lineno) - fn.lineno + 1,
                    "exits": exits,
                    "bad": bad,
                }
            )
        if not funcs:
            continue
        result.append(
            {
                "module": str(path.relative_to(path.parents[1])),
                "functions": len(funcs),
                "functions_ok": sum(1 for f in funcs if not f["bad"]),
                "exits": n_exits,
                "exits_bad": n_bad,
                "details": [f for f in funcs if f["bad"]],
            }
        )
    bad_mods = [m for m in result if m["exits_bad"]]
    tot_e = sum(m["exits"] for m in result)
    tot_b = sum(m["exits_bad"] for m in result)
    if args.total:
        print(tot_b)
        logger.debug("main: si args.total -> retour")
        return
    print(f"{len(result)} modules avec fonctions, {len(bad_mods)} non conformes")
    print(f"sorties : {tot_e - tot_b}/{tot_e} conformes ({tot_b} sans logger.debug)")
    if args.json:
        Path(args.json).write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    logger.debug("main: retour")


if __name__ == "__main__":
    main()
