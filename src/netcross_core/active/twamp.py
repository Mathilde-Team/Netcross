# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.active.twamp -- client TWAMP-Light (RFC 5357, annexe I ;
issue #1066, sous-issue 3/5 du chantier #999).

TWAMP-Light se passe de la session de contrôle TWAMP : le client (Session-
Sender) envoie des paquets de test UDP NON AUTHENTIFIÉS à un réflecteur
(Session-Reflector), qui renvoie chaque paquet complété de ses propres
horodatages. Le client en tire, sonde par sonde :

- le délai aller-retour corrigé du temps passé dans le réflecteur,
  ``(t4 - t1) - (t3 - t2)`` (RFC 5357 §4.2) -- indépendant de la
  synchronisation des horloges ;
- les délais aller ``t2 - t1`` et retour ``t4 - t3``, significatifs
  seulement si les horloges des deux extrémités sont synchronisées (NTP,
  PTP) ; ils sont donnés tels quels, jamais corrigés ;
- les pertes (sonde sans réponse avant ``timeout``) et le TTL reçu par le
  réflecteur (champ « Sender TTL », 255 au départ si le client ne le fixe
  pas : le nombre de sauts aller s'en déduit).

Formats (RFC 5357 §4.1.2 et §4.2.1, mode non authentifié) ::

    sonde (client)       : seq(4) horodatage(8) erreur(2) bourrage
    réponse (réflecteur) : seq(4) horodatage_tx(8) erreur(2) MBZ(2)
                           horodatage_rx(8) seq_client(4)
                           horodatage_client(8) erreur_client(2) MBZ(2)
                           ttl_client(1) bourrage

Les horodatages sont au format NTP 64 bits (secondes depuis 1900, fraction
sur 32 bits). La sonde est bourrée à 41 octets, la taille d'une réponse
sans bourrage, pour que l'aller et le retour aient la même taille (RFC 5357
§4.2.1, symétrie recommandée).

Garde-fous (paquet ``active`` désactivé par défaut, voir ``__init__``) :

- rien n'est émis tant que ``mesurer`` n'est pas appelée explicitement ;
  l'accord de l'utilisateur et le branchement CLI/API relèvent de #1068 ;
- au plus ``DEBIT_MAX`` sondes par seconde (``intervalle`` minimal) et
  ``SONDES_MAX`` sondes par mesure ;
- SANS réflecteur (aucune réponse, port fermé, cible injoignable ou nom
  inconnu), ``mesurer`` renvoie un résultat ``reflecteur_present=False``
  avec un message explicite au lieu de lever une exception ;
- chaque mesure est journalisée : horodatage, cible, port, nombre de sondes
  envoyées et reçues.
"""

from __future__ import annotations

import socket
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from statistics import mean

from netcross_core.active.planner import TWAMP_LIGHT, ProposedMeasurement
from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

PORT_TWAMP = 862  # port bien connu TWAMP-Test (RFC 5357, IANA)
DEBIT_MAX = 10  # sondes par seconde au plus
SONDES_MAX = 1000
TAILLE_REPONSE = 41  # réponse non authentifiée sans bourrage
_DECALAGE_NTP = 2_208_988_800  # secondes entre 1900-01-01 et 1970-01-01
# Error Estimate : S=1 (horloge synchronisée inconnue -> 0), Z=0, échelle 0,
# multiplicateur 1 -- valeur « erreur inconnue, non nulle » (RFC 4656 §4.1.2).
ERREUR_PAR_DEFAUT = 0x0001
_SONDE = struct.Struct("!IQH")
_REPONSE = struct.Struct("!IQHHQIQHHB")


class TwampError(ValueError):
    """Paramètre de mesure invalide ou paquet TWAMP mal formé."""


def vers_ntp(instant: float) -> int:
    """Horodatage Unix (secondes) -> horodatage NTP 64 bits."""
    logger.debug("vers_ntp: entrée")
    secondes = int(instant)
    fraction = int((instant - secondes) * (1 << 32)) & 0xFFFFFFFF
    valeur = ((secondes + _DECALAGE_NTP) << 32) | fraction
    logger.debug("vers_ntp: retour")
    return valeur


def depuis_ntp(valeur: int) -> float:
    """Horodatage NTP 64 bits -> horodatage Unix (secondes)."""
    logger.debug("depuis_ntp: entrée")
    instant = (valeur >> 32) - _DECALAGE_NTP + (valeur & 0xFFFFFFFF) / (1 << 32)
    logger.debug("depuis_ntp: retour")
    return instant


def construire_sonde(sequence: int, instant: float, taille: int = TAILLE_REPONSE) -> bytes:
    """Paquet de test du client (mode non authentifié), bourré de zéros
    jusqu'à ``taille`` octets (au moins l'en-tête de 14 octets)."""
    logger.debug("construire_sonde: entrée (seq {})", sequence)
    entete = _SONDE.pack(sequence & 0xFFFFFFFF, vers_ntp(instant), ERREUR_PAR_DEFAUT)
    paquet = entete + bytes(max(0, taille - len(entete)))
    logger.debug("construire_sonde: retour ({} octets)", len(paquet))
    return paquet


@dataclass(frozen=True)
class Reponse:
    """Réponse décodée d'un réflecteur TWAMP-Light."""

    sequence: int  # numéro de séquence du réflecteur
    emission: float  # t3 : départ de la réponse (horloge du réflecteur)
    reception: float  # t2 : arrivée de la sonde (horloge du réflecteur)
    sequence_client: int
    emission_client: float  # t1 recopié par le réflecteur
    ttl_client: int  # TTL de la sonde à son arrivée chez le réflecteur


def lire_reponse(paquet: bytes) -> Reponse:
    """Décode une réponse de réflecteur ; ``TwampError`` si elle est trop courte."""
    logger.debug("lire_reponse: entrée ({} octets)", len(paquet))
    if len(paquet) < _REPONSE.size:
        logger.debug("lire_reponse: paquet trop court -> levée TwampError")
        raise TwampError(f"réponse TWAMP trop courte : {len(paquet)} octets (au moins {_REPONSE.size})")
    seq, tx, _err, _mbz, rx, seq_client, t_client, _err_client, _mbz2, ttl = _REPONSE.unpack_from(paquet)
    reponse = Reponse(seq, depuis_ntp(tx), depuis_ntp(rx), seq_client, depuis_ntp(t_client), ttl)
    logger.debug("lire_reponse: retour (seq client {})", seq_client)
    return reponse


def construire_reponse(sonde: bytes, sequence: int, reception: float, emission: float, ttl: int = 255) -> bytes:
    """Réponse d'un réflecteur TWAMP-Light à ``sonde`` (RFC 5357 §4.2.1).

    Sert au réflecteur de test et à qui veut en monter un : la réponse
    recopie la séquence, l'horodatage et l'estimation d'erreur du client et
    garde la taille de la sonde si elle dépasse 41 octets."""
    logger.debug("construire_reponse: entrée (seq {})", sequence)
    if len(sonde) < _SONDE.size:
        logger.debug("construire_reponse: sonde trop courte -> levée TwampError")
        raise TwampError(f"sonde TWAMP trop courte : {len(sonde)} octets (au moins {_SONDE.size})")
    seq_client, t_client, err_client = _SONDE.unpack_from(sonde)
    entete = _REPONSE.pack(
        sequence & 0xFFFFFFFF,
        vers_ntp(emission),
        ERREUR_PAR_DEFAUT,
        0,
        vers_ntp(reception),
        seq_client,
        t_client,
        err_client,
        0,
        ttl & 0xFF,
    )
    paquet = entete + bytes(max(0, len(sonde) - len(entete)))
    logger.debug("construire_reponse: retour ({} octets)", len(paquet))
    return paquet


@dataclass(frozen=True)
class Sonde:
    """Une sonde et, si elle a reçu une réponse, ses délais (secondes)."""

    sequence: int
    envoi: float  # t1
    retour_recu: float | None = None  # t4
    reponse: Reponse | None = None

    @property
    def perdue(self) -> bool:
        """Vrai si aucune réponse n'est arrivée avant la fin de la mesure."""
        logger.debug("Sonde.perdue: retour {}", self.reponse is None)
        return self.reponse is None

    @property
    def aller_retour(self) -> float | None:
        """(t4 - t1) - (t3 - t2) : délai réseau aller-retour."""
        logger.debug("Sonde.aller_retour: entrée")
        if self.reponse is None or self.retour_recu is None:
            logger.debug("Sonde.aller_retour: sonde perdue -> retour None")
            return None
        traitement = self.reponse.emission - self.reponse.reception
        delai = (self.retour_recu - self.envoi) - traitement
        logger.debug("Sonde.aller_retour: retour {}", delai)
        return delai

    @property
    def aller(self) -> float | None:
        """t2 - t1 (horloges synchronisées requises)."""
        logger.debug("Sonde.aller: entrée")
        valeur = None if self.reponse is None else self.reponse.reception - self.envoi
        logger.debug("Sonde.aller: retour {}", valeur)
        return valeur

    @property
    def retour(self) -> float | None:
        """t4 - t3 (horloges synchronisées requises)."""
        logger.debug("Sonde.retour: entrée")
        if self.reponse is None or self.retour_recu is None:
            logger.debug("Sonde.retour: sonde perdue -> retour None")
            return None
        valeur = self.retour_recu - self.reponse.emission
        logger.debug("Sonde.retour: retour {}", valeur)
        return valeur


@dataclass
class ResultatTwamp:
    """Résultat d'une mesure TWAMP-Light vers un réflecteur."""

    cible: str
    port: int
    debut: str  # horodatage ISO 8601 UTC du début de la mesure
    reflecteur_present: bool
    message: str
    sondes: list[Sonde] = field(default_factory=list)

    @property
    def envoyees(self) -> int:
        """Nombre de sondes émises."""
        logger.debug("ResultatTwamp.envoyees: retour {}", len(self.sondes))
        return len(self.sondes)

    @property
    def recues(self) -> int:
        """Nombre de sondes ayant reçu une réponse."""
        logger.debug("ResultatTwamp.recues: entrée")
        total = sum(1 for s in self.sondes if not s.perdue)
        logger.debug("ResultatTwamp.recues: retour {}", total)
        return total

    def statistiques(self) -> dict[str, float | int | None]:
        """Pertes et délais aller-retour en millisecondes (``None`` sans réponse).

        La gigue est la moyenne des écarts absolus entre délais aller-retour
        successifs reçus (variation de délai inter-paquets, RFC 3393)."""
        logger.debug("ResultatTwamp.statistiques: entrée")
        delais = [d * 1000 for s in self.sondes if (d := s.aller_retour) is not None]
        ecarts = [abs(b - a) for a, b in zip(delais, delais[1:], strict=False)]
        pertes = self.envoyees - self.recues
        stats: dict[str, float | int | None] = {
            "envoyees": self.envoyees,
            "recues": self.recues,
            "pertes": pertes,
            "taux_pertes": pertes / self.envoyees if self.envoyees else None,
            "aller_retour_min_ms": min(delais) if delais else None,
            "aller_retour_moyen_ms": mean(delais) if delais else None,
            "aller_retour_max_ms": max(delais) if delais else None,
            "gigue_ms": mean(ecarts) if ecarts else None,
        }
        logger.debug("ResultatTwamp.statistiques: retour")
        return stats

    def to_dict(self) -> dict:
        """Représentation JSON (rapport, API) -- types natifs uniquement."""
        logger.debug("ResultatTwamp.to_dict: entrée")
        sondes = [
            {
                "sequence": s.sequence,
                "perdue": s.perdue,
                "aller_retour_ms": None if (d := s.aller_retour) is None else d * 1000,
                "ttl_recu": None if s.reponse is None else s.reponse.ttl_client,
            }
            for s in self.sondes
        ]
        document = {
            "type": TWAMP_LIGHT,
            "cible": self.cible,
            "port": self.port,
            "debut": self.debut,
            "reflecteur_present": self.reflecteur_present,
            "message": self.message,
            "statistiques": self.statistiques(),
            "sondes": sondes,
        }
        logger.debug("ResultatTwamp.to_dict: retour")
        return document


def _valider(nombre: int, intervalle: float, timeout: float, port: int) -> None:
    """Refuse une mesure hors des garde-fous (débit, volume, port)."""
    logger.debug("_valider: entrée")
    if not 1 <= nombre <= SONDES_MAX:
        logger.debug("_valider: nombre hors bornes -> levée TwampError")
        raise TwampError(f"nombre de sondes hors bornes : {nombre} (1 à {SONDES_MAX})")
    if intervalle < 1 / DEBIT_MAX:
        logger.debug("_valider: intervalle trop court -> levée TwampError")
        raise TwampError(f"intervalle trop court : {intervalle} s (au plus {DEBIT_MAX} sondes/s)")
    if timeout <= 0:
        logger.debug("_valider: timeout invalide -> levée TwampError")
        raise TwampError(f"timeout invalide : {timeout} s")
    if not 1 <= port <= 65535:
        logger.debug("_valider: port invalide -> levée TwampError")
        raise TwampError(f"port invalide : {port}")
    logger.debug("_valider: retour")


def _ouvrir(cible: str, port: int) -> socket.socket:
    """Socket UDP connectée au réflecteur (IPv4 ou IPv6 selon la cible)."""
    logger.debug("_ouvrir: entrée")
    famille, type_, proto, _nom, adresse = socket.getaddrinfo(cible, port, type=socket.SOCK_DGRAM)[0]
    sock = socket.socket(famille, type_, proto)
    try:
        sock.connect(adresse)
    except OSError:
        sock.close()
        logger.debug("_ouvrir: connect en échec -> socket fermée, relance")
        raise
    logger.debug("_ouvrir: retour")
    return sock


def _attendre(sock: socket.socket, sondes: dict[int, Sonde], limite: float, horloge: Callable[[], float]) -> None:
    """Range les réponses reçues jusqu'à ``limite`` (horloge locale). Une
    réponse inconnue, en double ou mal formée est ignorée et journalisée."""
    logger.debug("_attendre: entrée")
    while (reste := limite - horloge()) > 0:
        sock.settimeout(reste)
        try:
            paquet = sock.recv(65535)
        except TimeoutError:
            logger.debug("_attendre: délai écoulé")
            break
        arrivee = horloge()
        try:
            reponse = lire_reponse(paquet)
        except TwampError as exc:
            logger.debug("_attendre: réponse ignorée ({})", exc)
            continue
        sonde = sondes.get(reponse.sequence_client)
        if sonde is None or not sonde.perdue:
            logger.debug("_attendre: réponse inconnue ou en double (seq {}) ignorée", reponse.sequence_client)
            continue
        sondes[sonde.sequence] = Sonde(sonde.sequence, sonde.envoi, arrivee, reponse)
        if all(not s.perdue for s in sondes.values()):
            logger.debug("_attendre: toutes les sondes ont leur réponse")
            break
    logger.debug("_attendre: retour")


def mesurer(
    cible: str,
    port: int = PORT_TWAMP,
    *,
    nombre: int = 10,
    intervalle: float = 1 / DEBIT_MAX,
    timeout: float = 1.0,
    horloge: Callable[[], float] = time.time,
    attente: Callable[[float], None] = time.sleep,
) -> ResultatTwamp:
    """Envoie ``nombre`` sondes TWAMP-Light à ``cible:port``, espacées
    d'``intervalle`` secondes, puis attend les réponses jusqu'à ``timeout``
    après la dernière. Ne lève une exception que pour des paramètres hors
    garde-fous (``TwampError``) : l'absence de réflecteur est un RÉSULTAT."""
    logger.debug("mesurer: entrée ({}:{}, {} sonde(s))", cible, port, nombre)
    _valider(nombre, intervalle, timeout, port)
    debut = datetime.fromtimestamp(horloge(), UTC).isoformat()
    sondes: dict[int, Sonde] = {}
    try:
        sock = _ouvrir(cible, port)
    except OSError as exc:
        logger.info("TWAMP-Light {} : cible {}:{} injoignable ({}), aucune sonde envoyée", debut, cible, port, exc)
        logger.debug("mesurer: retour (cible injoignable)")
        return ResultatTwamp(cible, port, debut, False, f"cible injoignable : {cible}:{port} ({exc})")
    refus = None
    with sock:
        for sequence in range(nombre):
            envoi = horloge()
            sondes[sequence] = Sonde(sequence, envoi)
            try:
                sock.send(construire_sonde(sequence, envoi))
                _attendre(sock, sondes, envoi + intervalle, horloge)
            except ConnectionRefusedError as exc:
                logger.debug("mesurer: port fermé ({})", exc)
                refus = exc
                break
            except OSError as exc:
                logger.debug("mesurer: émission en échec ({})", exc)
                refus = exc
                break
            pause = envoi + intervalle - horloge()
            if pause > 0:
                attente(pause)
        if refus is None:
            try:
                _attendre(sock, sondes, horloge() + timeout, horloge)
            except OSError as exc:
                logger.debug("mesurer: réception finale en échec ({})", exc)
                refus = exc
    resultat = ResultatTwamp(cible, port, debut, False, "", [sondes[i] for i in sorted(sondes)])
    resultat.reflecteur_present = resultat.recues > 0
    resultat.message = _message(resultat, refus, timeout)
    logger.info(
        "TWAMP-Light {} : cible {}:{}, {} sonde(s) envoyée(s), {} reçue(s)",
        debut,
        cible,
        port,
        resultat.envoyees,
        resultat.recues,
    )
    logger.debug("mesurer: retour (réflecteur présent : {})", resultat.reflecteur_present)
    return resultat


def _message(resultat: ResultatTwamp, refus: OSError | None, timeout: float) -> str:
    """Phrase de synthèse d'une mesure, explicite sur l'absence de réflecteur."""
    logger.debug("_message: entrée")
    cible = f"{resultat.cible}:{resultat.port}"
    if resultat.reflecteur_present:
        stats = resultat.statistiques()
        message = (
            f"réflecteur TWAMP-Light {cible} : {stats['recues']}/{stats['envoyees']} réponse(s), "
            f"aller-retour moyen {stats['aller_retour_moyen_ms']:.3f} ms"
        )
    elif isinstance(refus, ConnectionRefusedError):
        message = f"aucun réflecteur TWAMP-Light sur {cible} : port fermé (ICMP port inaccessible)"
    elif refus is not None:
        message = f"aucun réflecteur TWAMP-Light sur {cible} : émission impossible ({refus})"
    else:
        message = (
            f"aucun réflecteur TWAMP-Light ne répond sur {cible} "
            f"({resultat.envoyees} sonde(s), aucune réponse en {timeout:g} s)"
        )
    logger.debug("_message: retour")
    return message


def cible_de_proposition(proposition: ProposedMeasurement, reflecteur: str | None = None) -> tuple[str, int]:
    """(hôte, port) à mesurer pour une proposition ``twamp_light`` du
    planificateur (#1063) : le réflecteur donné, sinon la destination du
    flux en défaut, sur le port proposé (862 par défaut)."""
    logger.debug("cible_de_proposition: entrée ({})", proposition.kind)
    if proposition.kind != TWAMP_LIGHT:
        logger.debug("cible_de_proposition: type {} -> levée TwampError", proposition.kind)
        raise TwampError(f"proposition de type {proposition.kind}, pas {TWAMP_LIGHT}")
    cible = (reflecteur or proposition.five_tuple.dst, proposition.target_port or PORT_TWAMP)
    logger.debug("cible_de_proposition: retour {}", cible)
    return cible
