"""
netcross_core.application.models -- structures de donnees du modele
transactionnel applicatif (Job 23, §6.9/§6.10).

Une ApplicationTransaction represente un cycle requête -> réponse pour
un protocole applicatif (HTTP, DNS...), avec les temps decomposes et
une classification automatique.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


class TransactionClassification(str, Enum):
    """Classification automatique d'une transaction applicative."""

    NORMAL = "normal"
    MISSING_RESPONSE = "missing_response"
    NETWORK_SLOW = "network_slow"
    SERVER_SLOW = "server_slow"
    APPLICATION_SLOW = "application_slow"


@dataclass(slots=True)
class ApplicationTransaction:
    """Un cycle requête -> réponse pour un protocole applicatif.

    Champs temporels (tous en millisecondes, None si non mesure) :
    - request_ts / response_ts : timestamps absolus (secondes epoch)
    - total_time_ms : temps total requête -> réponse
    - network_time_ms : temps réseau aller (estimé si multi-points)
    - server_time_ms : temps de traitement serveur (think time)
    - ttfb_ms : time to first byte (debut reponse)
    """

    protocol: str  # "HTTP", "DNS", "SMB"...
    point: str  # point de capture
    client: str  # adresse client
    server: str  # adresse serveur
    request_ts: float | None = None
    response_ts: float | None = None
    total_time_ms: float | None = None
    network_time_ms: float | None = None
    server_time_ms: float | None = None
    # Résumé de la requête (méthode+URI pour HTTP, query name pour DNS)
    request_summary: str = ""
    # Résumé de la réponse (status code pour HTTP, rcode pour DNS)
    response_summary: str = ""
    # Signaux réseau dans la fenêtre temporelle de la transaction
    # (retransmissions, lost_segment, out_of_order vus sur ce flux)
    network_signals: list[str] = field(default_factory=list)
    classification: TransactionClassification = TransactionClassification.NORMAL

    def to_dict(self) -> dict:
        """Sérialisation pour Report.application_transactions (liste de
        dicts, comme http_objects)."""
        logger.debug("ApplicationTransaction.to_dict: retour dictionnaire")
        return {
            "protocol": self.protocol,
            "point": self.point,
            "client": self.client,
            "server": self.server,
            "request_ts": self.request_ts,
            "response_ts": self.response_ts,
            "total_time_ms": self.total_time_ms,
            "network_time_ms": self.network_time_ms,
            "server_time_ms": self.server_time_ms,
            "request_summary": self.request_summary,
            "response_summary": self.response_summary,
            "network_signals": list(self.network_signals),
            "classification": self.classification.value,
        }


# --- Modèle de transaction HTTP commun (issue #1051, chantier #998) ----------
#
# Une même structure pour HTTP/1.x, HTTP/2 et HTTP/3 : la connexion de
# transport, l'identifiant de flux (HTTP/2 : stream_id ; HTTP/3 : flux QUIC
# bidirectionnel ; HTTP/1.x : None, les requêtes d'une connexion étant
# appariées dans l'ordre), les champs de requête/réponse et trois horodatages
# (requête, premier octet de réponse, fin de réponse). Les adaptateurs par
# version (application/http.py) produisent des HttpTransaction ; le rapport
# continue de consommer des ApplicationTransaction via
# HttpTransaction.to_application_transaction.

HTTP_1X = "HTTP/1.x"
HTTP_2 = "HTTP/2"
HTTP_3 = "HTTP/3"

FlowKey = tuple[str, str, int | None, int | None]


@dataclass(frozen=True, slots=True)
class HttpConnection:
    """Connexion de transport portant une transaction HTTP, vue client -> serveur."""

    transport: str  # "TCP" (HTTP/1.x, HTTP/2) ou "UDP" (HTTP/3 sur QUIC)
    client: str
    server: str
    client_port: int | None
    server_port: int | None

    def key(self) -> FlowKey:
        """Clé directionnelle (client, serveur, port client, port serveur),
        celle des signaux réseau injectés par analysis.py."""
        logger.debug("HttpConnection.key: retour tuple de 4")
        return (self.client, self.server, self.client_port, self.server_port)


def _split_target(target: str | None) -> tuple[str | None, str | None]:
    """(autorité, chemin) d'une cible de requête : forme absolue
    ``schéma://autorité/chemin?requête`` (proxy, HTTP déchiffré par tshark)
    ou forme origine ``/chemin`` (autorité inconnue au niveau paquet)."""
    logger.debug("_split_target: entrée")
    if not target or "://" not in target:
        logger.debug("_split_target: retour, forme origine")
        return None, target
    _schema, reste = target.split("://", 1)
    autorite, separateur, chemin = reste.partition("/")
    logger.debug("_split_target: retour, forme absolue")
    return autorite or None, separateur + chemin if separateur else "/"


@dataclass(slots=True)
class HttpTransaction:
    """Une transaction HTTP (requête -> réponse), toutes versions confondues.

    Horodatages en secondes epoch (None si non observé) :
    - request_ts : requête ;
    - first_byte_ts : premier octet de la réponse ;
    - end_ts : fin de la réponse.
    HTTP/1.x (tshark réassemble la réponse) : first_byte_ts et end_ts valent
    l'horodatage de la réponse réassemblée ; HTTP/2 et HTTP/3 pourront les
    distinguer (trames HEADERS puis DATA END_STREAM).
    """

    version: str  # HTTP_1X, HTTP_2 ou HTTP_3
    point: str
    connection: HttpConnection
    stream_id: int | None = None
    method: str | None = None
    # Cible brute de la requête (http.request.uri, ou :path pour HTTP/2-3)
    target: str | None = None
    # :authority (HTTP/2-3) ou autorité d'une cible absolue (HTTP/1.x)
    authority: str | None = None
    path: str | None = None
    status: int | None = None
    request_ts: float | None = None
    first_byte_ts: float | None = None
    end_ts: float | None = None
    # Temps serveur estimé par tshark (http.time : requête -> réponse)
    server_time_ms: float | None = None

    @classmethod
    def from_target(cls, version: str, point: str, connection: HttpConnection, target: str | None, **champs):
        """Construit une transaction en dérivant autorité et chemin de la cible."""
        logger.debug("HttpTransaction.from_target: entrée")
        autorite, chemin = _split_target(target)
        champs.setdefault("authority", autorite)
        champs.setdefault("path", chemin)
        logger.debug("HttpTransaction.from_target: retour")
        return cls(version=version, point=point, connection=connection, target=target, **champs)

    @property
    def answered(self) -> bool:
        """Une réponse a été observée."""
        logger.debug("HttpTransaction.answered: retour bool")
        return self.end_ts is not None or self.first_byte_ts is not None

    @property
    def ttfb_ms(self) -> float | None:
        """Requête -> premier octet de réponse (ms)."""
        logger.debug("HttpTransaction.ttfb_ms: entrée")
        if self.first_byte_ts is None or self.request_ts is None:
            logger.debug("HttpTransaction.ttfb_ms: retour None")
            return None
        logger.debug("HttpTransaction.ttfb_ms: retour valeur")
        return (self.first_byte_ts - self.request_ts) * 1000.0

    @property
    def total_ms(self) -> float | None:
        """Requête -> fin de réponse (ms). Un horodatage nul vaut « absent »,
        comme dans build_http_transactions avant #1051 (résultats inchangés)."""
        logger.debug("HttpTransaction.total_ms: entrée")
        if not (self.end_ts and self.request_ts):
            logger.debug("HttpTransaction.total_ms: retour None")
            return None
        logger.debug("HttpTransaction.total_ms: retour valeur")
        return (self.end_ts - self.request_ts) * 1000.0

    @property
    def request_summary(self) -> str:
        """« MÉTHODE cible » (GET et / par défaut), libellé historique du rapport."""
        logger.debug("HttpTransaction.request_summary: retour str")
        return f"{self.method or 'GET'} {self.target or '/'}"

    def to_application_transaction(self, network_signals: dict[FlowKey, list[str]] | None = None):
        """Transaction applicative du rapport (Report.application_transactions)."""
        logger.debug("HttpTransaction.to_application_transaction: entrée")
        signaux = (network_signals or {}).get(self.connection.key(), [])
        txn = ApplicationTransaction(
            protocol="HTTP",
            point=self.point,
            client=self.connection.client,
            server=self.connection.server,
            request_ts=self.request_ts,
            response_ts=self.end_ts,
            total_time_ms=self.total_ms if self.answered else None,
            server_time_ms=self.server_time_ms if self.answered else None,
            request_summary=self.request_summary,
            response_summary=str(self.status or "") if self.answered else "",
            network_signals=list(signaux),
        )
        logger.debug("HttpTransaction.to_application_transaction: retour")
        return txn
