# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_report.redaction_note -- encart « Anonymisation » des rapports
(issue #1159, sous-issue 5/5 du chantier #1007).

Le rapport doit **certifier ce qui a été masqué** : un encart liste
précisément le périmètre appliqué (portée, compteur d'adresses et de noms,
charges utiles des pcapng, table de correspondance). Les mêmes
informations sont servies dans le JSON (clé ``redaction``), le Markdown et
le PDF — une seule source, ``build_redaction_info()``, alimente les trois
générateurs ; ils ne recalculent rien.
"""

from __future__ import annotations

from pathlib import Path

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)


def build_redaction_info(
    redactor,
    scope: str,
    *,
    redact_map: str | Path | None = None,
    pcapng: list[str | Path] | None = None,
    garder_payload: bool = False,
) -> dict:
    """Décrit le périmètre d'anonymisation appliqué pour le rapport.

    ``redactor`` : AddressRedactor du run (même table que les paquets,
    ``--redact-map`` et les pcapng anonymisés). ``scope`` : portée
    ``adresses``/``noms``/``tout``. ``redact_map`` : chemin de la table
    écrite (``--redact-map``), ``pcapng`` : pcapng anonymisés produits
    (``--redact-pcap``), ``garder_payload`` : charges utiles conservées
    (``--redact-pcap-keep-payload``).
    """
    logger.debug(
        "build_redaction_info: entrée redactor={} scope={} redact_map={} pcapng={} garder_payload={}",
        summarize(redactor, "redactor"),
        scope,
        redact_map,
        len(pcapng or []),
        garder_payload,
    )
    from netcross_core.redact import scope_label

    info = {
        "portee": scope_label(scope),
        "portee_code": scope,
        "adresses": len(redactor),
        "noms": len(redactor.names),
        "table": str(redact_map) if redact_map else None,
        "pcapng": [str(p) for p in (pcapng or [])],
        "garde_charges_utiles": garder_payload,
    }
    logger.debug("build_redaction_info: retour info")
    return info


def lignes_encart_markdown(info: dict) -> list[str]:
    """Encart Markdown (blockquote) certifiant le périmètre appliqué."""
    logger.debug("lignes_encart_markdown: entrée")
    lignes: list[str] = ["> **Anonymisation — périmètre appliqué**", ">"]
    lignes.append(f"> - Portée : {info['portee']}")
    detail = f"{info['adresses']} adresse(s) IP/MAC et {info['noms']} nom(s) anonymisé(s)"
    lignes.append(f"> - {detail}")
    if info["pcapng"]:
        liste = ", ".join(f"`{p}`" for p in info["pcapng"])
        charge = "conservées (--redact-pcap-keep-payload)" if info["garde_charges_utiles"] else "zéroées"
        lignes.append(f"> - Capture(s) pcapng anonymisée(s) : {liste}")
        lignes.append(f"> - Charges utiles des pcapng : {charge}")
    if info["table"]:
        lignes.append(f"> - Table de correspondance : `{info['table']}`")
    lignes.append(
        "> - Les constats (protocoles, ports, longueurs, horodatages) ne changent pas : "
        "l'analyse porte sur les mêmes valeurs, pseudonymes mis à part."
    )
    logger.debug("lignes_encart_markdown: retour")
    return lignes


def lignes_encart_texte(info: dict) -> list[str]:
    """Mêmes informations en lignes de texte brutes (encart du PDF)."""
    logger.debug("lignes_encart_texte: entrée")
    lignes = [f"Anonymisation — périmètre appliqué : {info['portee']}"]
    lignes.append(f"{info['adresses']} adresse(s) IP/MAC et {info['noms']} nom(s) anonymisé(s)")
    if info["pcapng"]:
        lignes.append("Capture(s) pcapng anonymisée(s) : " + ", ".join(info["pcapng"]))
        charge = "conservées (--redact-pcap-keep-payload)" if info["garde_charges_utiles"] else "zéroées"
        lignes.append(f"Charges utiles des pcapng : {charge}")
    if info["table"]:
        lignes.append(f"Table de correspondance : {info['table']}")
    lignes.append(
        "Les constats (protocoles, ports, longueurs, horodatages) ne changent pas : "
        "l'analyse porte sur les mêmes valeurs, pseudonymes mis à part."
    )
    logger.debug("lignes_encart_texte: retour")
    return lignes
