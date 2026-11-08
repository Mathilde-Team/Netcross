# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.empreinte -- empreinte compacte et invariante d'un paquet
pour l'appariement entre points de capture (issue #1021).

`correlate.flow_key()` renvoie un tuple de 6 elements (mode strict) ou de
4 elements (mode NAT-tolerant). Ce tuple reste la reference ; l'empreinte
en est une projection sur 64 bits, stable d'un processus a l'autre (pas
de `hash()` Python, qui est sale par PYTHONHASHSEED). Elle sert aux
traitements qui doivent garder une trace minimale de chaque paquet sans
conserver le tuple complet : pipeline en flux (#1022), sondes distribuees
qui echangent des identifiants de paquets, banc de performance (#1017).

Champs utilises en mode strict (stables le long du chemin hors NAT) :
protocole, adresses IP source et destination, ports, et `key_id` (numero
de sequence TCP, ou identifiant IP `ip.id` pour UDP/ICMP). Les champs qui
changent a chaque saut (TTL, somme de controle IP, adresses MAC, VLAN,
DSCP reecrit) sont volontairement exclus.

Limites documentees dans docs/empreinte-paquet.md : NAT/PAT (adresses et
ports reecrits), fragmentation (fragments suivants sans ports), reecritures
par equipement intermediaire (randomisation de `ip.id` ou des numeros de
sequence TCP, ALG qui modifie le payload).
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable

from netcross_core.correlate import flow_key
from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt

logger = get_logger(__name__)

#: Champs du paquet qui composent l'empreinte en mode strict, dans l'ordre.
CHAMPS_STRICTS: tuple[str, ...] = ("proto", "src", "sport", "dst", "dport", "key_id")

#: Taille de l'empreinte en octets (64 bits).
TAILLE_OCTETS = 8

# Separateurs ASCII (unit separator) et marqueur de valeur absente : aucun
# des champs (protocole, adresse IP, entier) ne peut contenir ces octets,
# donc deux cles differentes ne produisent jamais le meme texte encode.
_SEPARATEUR = "\x1f"
_ABSENT = "\x00"

# Protocoles exclus de la correlation, comme dans correlate.correlate().
_PROTOCOLES_LOCAUX = ("ARP", "STP")


def empreinte_de_cle(cle: tuple) -> int:
    """Projette une cle `flow_key()` sur un entier de 64 bits stable.

    L'encodage est sans ambiguite (separateur et marqueur de `None`
    reserves) ; deux cles distinctes ne se confondent qu'en cas de
    collision BLAKE2b sur 64 bits, de l'ordre de n^2 / 2^65 pour n cles.
    """
    logger.debug("empreinte_de_cle: cle de {} champ(s)", len(cle))
    texte = _SEPARATEUR.join(_ABSENT if valeur is None else str(valeur) for valeur in cle)
    condensat = hashlib.blake2b(texte.encode("utf-8"), digest_size=TAILLE_OCTETS).digest()
    valeur = int.from_bytes(condensat, "big")
    logger.debug("empreinte_de_cle: retour {:016x}", valeur)
    return valeur


def empreinte(pk: Pkt, nat_tolerant: bool = False, nat_window_ms: int = 200) -> int:
    """Empreinte compacte d'un paquet, equivalente a `flow_key()`.

    Deux paquets ont la meme empreinte si et seulement si `flow_key()`
    leur donne la meme cle (aux collisions 64 bits pres).
    """
    logger.debug("empreinte: paquet {} au point {} (nat_tolerant={})", pk.proto, pk.point, nat_tolerant)
    valeur = empreinte_de_cle(flow_key(pk, nat_tolerant, nat_window_ms))
    logger.debug("empreinte: retour {:016x}", valeur)
    return valeur


def est_correlable(pk: Pkt, exclude_duplicates: bool = False) -> bool:
    """Meme filtre que `correlate.correlate()` : doublons exclus a la
    demande, ARP et STP toujours exclus (trafic local, jamais relaye)."""
    logger.debug("est_correlable: paquet {} (exclude_duplicates={})", pk.proto, exclude_duplicates)
    if exclude_duplicates and pk.is_duplicate:
        logger.debug("est_correlable: doublon exclu -> retour False")
        return False
    resultat = pk.proto not in _PROTOCOLES_LOCAUX
    logger.debug("est_correlable: retour {}", resultat)
    return resultat


def apparier(
    all_packets: Iterable[Pkt],
    nat_tolerant: bool = False,
    nat_window_ms: int = 200,
    exclude_duplicates: bool = False,
) -> dict[int, dict[str, list[Pkt]]]:
    """Groupe les paquets par empreinte puis par point.

    Meme structure que `correlate.correlate()`, mais indexee par
    l'empreinte 64 bits au lieu du tuple de cle.
    """
    logger.debug("apparier: debut (nat_tolerant={}, doublons exclus={})", nat_tolerant, exclude_duplicates)
    groupes: dict[int, dict[str, list[Pkt]]] = defaultdict(dict)
    total = 0
    for pk in all_packets:
        total += 1
        if not est_correlable(pk, exclude_duplicates):
            continue
        groupes[empreinte(pk, nat_tolerant, nat_window_ms)].setdefault(pk.point, []).append(pk)
    logger.debug("apparier: {} paquet(s) -> {} groupe(s)", total, len(groupes))
    return groupes


def _partition(groupes: dict) -> set[frozenset[tuple[str, int]]]:
    """Ensemble des groupes, chacun vu comme l'ensemble (point, id du Pkt)."""
    logger.debug("_partition: {} groupe(s)", len(groupes))
    resultat = {
        frozenset((point, id(pk)) for point, paquets in par_point.items() for pk in paquets)
        for par_point in groupes.values()
    }
    logger.debug("_partition: retour {} element(s)", len(resultat))
    return resultat


def collisions(cles: Iterable[tuple]) -> list[tuple[int, list[tuple]]]:
    """Liste les empreintes partagees par plusieurs cles distinctes."""
    logger.debug("collisions: debut")
    par_empreinte: dict[int, list[tuple]] = defaultdict(list)
    for cle in set(cles):
        par_empreinte[empreinte_de_cle(cle)].append(cle)
    resultat = [(valeur, sorted(liste, key=repr)) for valeur, liste in par_empreinte.items() if len(liste) > 1]
    logger.debug("collisions: retour {} collision(s)", len(resultat))
    return resultat


def comparer_appariements(flows_par_cle: dict, groupes_par_empreinte: dict) -> dict:
    """Compare l'appariement de reference (`correlate()`) et celui par
    empreinte (`apparier()`) sur les memes objets Pkt.

    Renvoie le nombre de groupes de chaque cote, les collisions d'empreinte
    et `identiques` (True si les deux partitions sont exactement egales).
    """
    logger.debug("comparer_appariements: {} cle(s), {} empreinte(s)", len(flows_par_cle), len(groupes_par_empreinte))
    rapport = {
        "groupes_cle": len(flows_par_cle),
        "groupes_empreinte": len(groupes_par_empreinte),
        "collisions": len(collisions(flows_par_cle.keys())),
        "identiques": _partition(flows_par_cle) == _partition(groupes_par_empreinte),
    }
    logger.debug("comparer_appariements: retour {}", rapport)
    return rapport
