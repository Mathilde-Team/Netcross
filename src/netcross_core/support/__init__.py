# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.support -- remontee de tickets anonymisee (issue #269).

Deux modules, une seule idee : permettre a un utilisateur de transmettre
un incident (crash, erreur de traitement) ou un simple etat de
fonctionnement SANS exposer son reseau ni son identite, et uniquement
s'il l'autorise.

- ``scrubber``  : anonymisation de texte libre (logs, tracebacks, chemins)
- ``ticket``    : construction/ecriture du ticket, consentement, crash hook

Voir docs/support-tickets.md pour l'usage et docs/quality/traceability-rule.md
pour la regle "on remonte toujours quelque chose, meme quand tout va bien".
"""

from netcross_core.logging_config import get_logger
from netcross_core.support.scrubber import (
    CATEGORIES,
    KNOWN_LIMITS,
    SECRET_PLACEHOLDER,
    ScrubReport,
    TextScrubber,
)
from netcross_core.support.ticket import (
    KINDS,
    SCHEMA_VERSION,
    SCOPES,
    Consent,
    ConsentRequiredError,
    SupportTicket,
    build_ticket,
    collect_environment,
    format_exception,
    install_crash_handler,
    write_support_map_csv,
    write_ticket,
)

logger = get_logger(__name__)

__all__ = [
    "CATEGORIES",
    "KINDS",
    "KNOWN_LIMITS",
    "SCHEMA_VERSION",
    "SCOPES",
    "SECRET_PLACEHOLDER",
    "Consent",
    "ConsentRequiredError",
    "ScrubReport",
    "SupportTicket",
    "TextScrubber",
    "build_ticket",
    "collect_environment",
    "format_exception",
    "install_crash_handler",
    "write_support_map_csv",
    "write_ticket",
]
