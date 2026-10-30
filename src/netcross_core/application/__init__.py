"""
netcross_core.application -- modele transactionnel applicatif (Job 23,
§6.9/§6.10).

Transforme les paquets HTTP/DNS en transactions (requête -> réponse),
avec temps réseau, temps serveur, temps total, et classification
automatique : réseau lent / serveur lent / application lente / absence
de réponse / normal.

Contrat de couches : vit dans netcross_core, n'importe que stdlib et
netcross_core.models. Aucun import vers netcross_report.
"""

from __future__ import annotations

from netcross_core.application.classify import (
    TransactionThresholds,
    classify_transaction,
)
from netcross_core.application.dns import build_dns_transactions
from netcross_core.application.http import build_http_transactions, http1_transactions
from netcross_core.application.models import (
    ApplicationTransaction,
    HttpConnection,
    HttpTransaction,
    TransactionClassification,
)
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

__all__ = [
    "ApplicationTransaction",
    "HttpConnection",
    "HttpTransaction",
    "TransactionClassification",
    "TransactionThresholds",
    "build_dns_transactions",
    "build_http_transactions",
    "classify_transaction",
    "http1_transactions",
]
