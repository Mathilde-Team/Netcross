"""
netcross_core.application.http -- construction de transactions HTTP a
partir des paquets (Job 23, §6.10).

Apparie requêtes et réponses HTTP sur un même flux TCP (même 5-tuple
directionnel) en FIFO. Une requête sans réponse devient une transaction
avec classification missing_response.

Issue #1051 : l'appariement HTTP/1.x produit des HttpTransaction (modèle
commun HTTP/1.x, 2 et 3 de application/models.py), converties ensuite en
ApplicationTransaction pour le rapport.
"""

from __future__ import annotations

from collections import defaultdict, deque

from netcross_core.application.models import HTTP_1X, ApplicationTransaction, HttpConnection, HttpTransaction
from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import Pkt

logger = get_logger(__name__)


def _flow_key(pkt: Pkt) -> tuple[str, str, int | None, int | None]:
    """Clé directionnelle client -> serveur pour apparier HTTP."""
    logger.debug("_flow_key: retour tuple de 4")
    return (pkt.src, pkt.dst, pkt.sport, pkt.dport)


def _reverse_flow_key(pkt: Pkt) -> tuple[str, str, int | None, int | None]:
    """Clé inverse serveur -> client pour trouver la requête correspondante."""
    logger.debug("_reverse_flow_key: retour tuple de 4")
    return (pkt.dst, pkt.src, pkt.dport, pkt.sport)


def _connection(request: Pkt) -> HttpConnection:
    """Connexion TCP client -> serveur d'une requête HTTP/1.x."""
    logger.debug("_connection: retour HttpConnection")
    return HttpConnection("TCP", request.src, request.dst, request.sport, request.dport)


def _http1_transaction(request: Pkt, response: Pkt | None) -> HttpTransaction:
    """Transaction HTTP/1.x d'une requête et de sa réponse (None : sans réponse)."""
    logger.debug("_http1_transaction: entrée")
    champs: dict = {"method": request.http_method, "request_ts": request.ts}
    if response is not None:
        champs.update(
            status=response.http_status_code,
            # réponse réassemblée par tshark : premier octet et fin confondus
            first_byte_ts=response.ts,
            end_ts=response.ts,
            # http.time de tshark (requête -> réponse), pas de séparation
            # réseau/serveur avec un seul point de capture
            server_time_ms=response.http_response_time_ms,
        )
    txn = HttpTransaction.from_target(HTTP_1X, request.point, _connection(request), request.http_uri, **champs)
    logger.debug("_http1_transaction: retour")
    return txn


def http1_transactions(packets: list[Pkt]) -> list[HttpTransaction]:
    """Adaptateur HTTP/1.x vers le modèle commun (issue #1051).

    Stratégie : FIFO par flux. Chaque requête (http_is_request) est mise
    en attente ; chaque réponse (http_is_response) dépile la plus ancienne
    requête du flux inverse. Les requêtes non servies suivent, flux par flux
    (ordre de première requête), sans réponse. Ordre non trié : celui de
    l'appariement (le tri par horodatage est fait par build_http_transactions).
    """
    logger.debug("http1_transactions: entrée ({} paquet(s))", len(packets))
    pending: dict[tuple[str, str, int | None, int | None], deque[Pkt]] = defaultdict(deque)
    transactions: list[HttpTransaction] = []

    for pkt in packets:
        if pkt.proto != "TCP":
            continue
        if pkt.http_is_request:
            pending[_flow_key(pkt)].append(pkt)
        elif pkt.http_is_response:
            # La réponse vient du serveur -> le flux inverse est la requête
            queue = pending.get(_reverse_flow_key(pkt))
            if queue and queue[0].ts <= pkt.ts:
                transactions.append(_http1_transaction(queue.popleft(), pkt))

    # Requêtes sans réponse
    for queue in pending.values():
        transactions.extend(_http1_transaction(req, None) for req in queue)

    logger.debug("http1_transactions: retour, {} transaction(s)", len(transactions))
    return transactions


def build_http_transactions(
    packets: list[Pkt],
    network_signals: dict[tuple[str, str, int | None, int | None], list[str]] | None = None,
) -> list[ApplicationTransaction]:
    """Construit les transactions HTTP en apparieant requêtes et réponses.

    Passe par le modèle commun HttpTransaction (adaptateur HTTP/1.x,
    issue #1051) ; résultats identiques à l'implémentation précédente.
    Les requêtes non servies deviennent des transactions missing_response
    (classification posée ensuite par classify).

    Args:
        packets: liste triée par timestamp croissant.
        network_signals: signaux TCP par flux (clé = 5-tuple directionnel),
            injectés par analyse.py depuis les expert_flags. Si None, vide.
    """
    logger.debug("build_http_transactions: entrée")
    transactions = [txn.to_application_transaction(network_signals) for txn in http1_transactions(packets)]
    transactions.sort(key=lambda t: t.request_ts or 0.0)
    logger.debug("build_http_transactions: retour transactions={}", summarize(transactions, "transactions"))
    return transactions
