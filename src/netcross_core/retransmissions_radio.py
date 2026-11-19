# SPDX-License-Identifier: GPL-3.0-or-later
"""netcross_core.retransmissions_radio -- retransmissions 802.11 (issue #1145).

Troisieme brique du chantier « Wi-Fi en mode moniteur » (#1006) : apparier
un paquet vu dans l'air (apres decapsulation et dechiffrement, #1143) avec
le meme paquet vu sur un point filaire.

Apres decapsulation, un paquet IP vu dans l'air s'apparie deja avec sa
copie filaire par la cle de flux habituelle (5-tuple + identifiant IP ou
numero de sequence TCP) : l'en-tete IP n'est pas modifie par le pont
802.11 <-> Ethernet du point d'acces. Le piege est ailleurs : une trame non
acquittee est reemise par la station avec le bit ``retry``. La sonde en
mode moniteur voit alors N+1 fois le MEME paquet IP, qui serait compte
comme retransmission TCP, ACK duplique ou doublon UDP, alors que le reseau
ne l'a transporte qu'une fois (le point d'acces filtre ces doublons).

Critere exact, celui du recepteur 802.11 (IEEE 802.11-2020, 10.3.2.14) :
une trame a bit ``retry`` dont l'identite (adresse de l'emetteur TA,
numero de sequence, numero de fragment) est celle d'une trame deja vue au
MEME point est une retransmission radio. Elle est fusionnee dans le paquet
d'origine (``Pkt.radio_retries`` + 1) et retiree du flux de paquets : le
nombre de tentatives reste disponible pour les metriques radio (#1146).

Une trame a bit ``retry`` dont l'original n'a pas ete capte (perdu par la
sonde) est conservee : c'est la seule copie vue du paquet.

Sans identite 802.11 (capture filaire, champ absent), rien n'est retire.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt

logger = get_logger(__name__)

# Au-dela, le numero de sequence (12 bits, 4096 valeurs) peut avoir fait le
# tour : une trame de meme identite n'est plus une retransmission. Une
# station reemet en quelques millisecondes ; 1 s couvre largement la
# limite de tentatives (dot11ShortRetryLimit/LongRetryLimit).
FENETRE_RETRANSMISSION_S = 1.0


class FiltreRetransmissionsRadio:
    """Filtre a etat, utilisable en lot comme au fil de l'eau (live) : un
    paquet est accepte, sauf s'il est la retransmission radio d'un paquet
    deja accepte au meme point."""

    def __init__(self, fenetre_s: float = FENETRE_RETRANSMISSION_S):
        logger.debug("FiltreRetransmissionsRadio.__init__: entrée (fenêtre {} s)", fenetre_s)
        self.fenetre_s = fenetre_s
        self._vus: dict[tuple[str, tuple[str, int, int]], Pkt] = {}
        self.retirees: dict[str, int] = {}
        logger.debug("FiltreRetransmissionsRadio.__init__: fin")

    def accepte(self, pk: Pkt) -> bool:
        """True si ``pk`` est un paquet a garder ; False si c'est une
        retransmission radio, alors comptee dans le paquet d'origine."""
        if pk.wlan_mpdu is None:
            logger.debug("FiltreRetransmissionsRadio.accepte: pas d'identité 802.11 -> retour True")
            return True
        cle = (pk.point, pk.wlan_mpdu)
        origine = self._vus.get(cle)
        retry = pk.radio is not None and pk.radio.retry
        if retry and origine is not None and 0 <= pk.ts - origine.ts <= self.fenetre_s:
            origine.radio_retries += 1
            self.retirees[pk.point] = self.retirees.get(pk.point, 0) + 1
            logger.debug("FiltreRetransmissionsRadio.accepte: retransmission radio -> retour False")
            return False
        self._vus[cle] = pk
        logger.debug("FiltreRetransmissionsRadio.accepte: retour True")
        return True

    def filtrer(self, paquets: Iterable[Pkt]) -> Iterator[Pkt]:
        """Paquets acceptes, dans l'ordre (generateur, convient au live)."""
        logger.debug("FiltreRetransmissionsRadio.filtrer: entrée")
        for pk in paquets:
            if self.accepte(pk):
                yield pk
        logger.debug("FiltreRetransmissionsRadio.filtrer: fin ({} retirée(s))", sum(self.retirees.values()))


def retirer_retransmissions_radio(paquets: list[Pkt]) -> list[Pkt]:
    """Version lot : liste sans les retransmissions radio, fusionnees dans
    leur paquet d'origine. Les paquets d'un point doivent etre dans l'ordre
    de capture (c'est le cas en sortie de parse_capture). Liste inchangee
    (meme objet) s'il n'y a rien a retirer."""
    logger.debug("retirer_retransmissions_radio: entrée ({} paquet(s))", len(paquets))
    if not any(pk.wlan_mpdu is not None for pk in paquets):
        logger.debug("retirer_retransmissions_radio: aucune trame 802.11 -> retour liste inchangée")
        return paquets
    filtre = FiltreRetransmissionsRadio()
    gardes = list(filtre.filtrer(paquets))
    for point, n in sorted(filtre.retirees.items()):
        logger.info(
            "[{}] {} retransmission(s) 802.11 (bit retry) fusionnée(s) dans leur paquet d'origine : "
            "pas comptées comme doublons réseau",
            point,
            n,
        )
    logger.debug("retirer_retransmissions_radio: retour {} paquet(s)", len(gardes))
    return gardes
