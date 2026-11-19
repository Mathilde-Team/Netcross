# SPDX-License-Identifier: GPL-3.0-or-later
"""Métriques et constats radio par client 802.11 (issue #1146).

Quatrième brique du chantier « Wi-Fi en mode moniteur » (#1006) : pour
chaque point de capture 802.11, une fiche par station cliente (adresse MAC,
anonymisée par ``--redact`` comme les autres adresses) :

- RSSI médian des trames ÉMISES par la station (le signal mesuré sur une
  trame descendante est celui du point d'accès, pas du client) ;
- distribution des MCS et des débits PHY, dans les deux sens ;
- taux de retransmission radio : copies 802.11 *retry* fusionnées par
  ``netcross_core.retransmissions_radio`` (#1145), rapportées aux
  transmissions totales ;
- itinérance : changements de BSSID, datés ;
- temps d'antenne approximatif : somme de ``longueur * 8 / débit PHY`` par
  transmission (copies retry comprises), sans préambule, intervalle
  inter-trames ni acquittement -- un ordre de grandeur, pas une mesure.

Constats :

- « perte dans l'air » / « perte après le point d'accès » : chaque segment
  TCP retransmis du client est classé selon sa transmission d'ORIGINE au
  même point. Origine vue avec des copies retry : la trame a peiné dans
  l'air. Origine vue sans retry : elle a été acquittée au niveau 802.11, la
  perte est plus loin. Origine descendante jamais vue dans l'air : perdue
  avant d'atteindre l'antenne, donc après le point d'accès côté filaire.
  Origine montante jamais vue : indéterminé (la sonde a pu la manquer).
- « débit PHY bas » : débit PHY médian sous ``SEUIL_DEBIT_PHY_BAS_MBPS``.
- « itinérance pendant le flux » : un flux du client est vu avant ET après
  un changement de BSSID.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict

from netcross_core.logging_config import get_logger
from netcross_core.models import Pkt

logger = get_logger(__name__)

SEUIL_DEBIT_PHY_BAS_MBPS = 24.0
PERTE_AIR = "perte dans l'air"
PERTE_APRES_AP = "perte après le point d'accès"
DEBIT_PHY_BAS = "débit PHY bas"
ITINERANCE_FLUX = "itinérance pendant le flux"


def _cle_flux(pkt: Pkt) -> tuple:
    """Flux non orienté (protocole et extrémités triées)."""
    logger.debug("_cle_flux: début")
    extremites = tuple(sorted(((pkt.src, pkt.sport or 0), (pkt.dst, pkt.dport or 0))))
    logger.debug("_cle_flux: retour clé")
    return (pkt.proto, extremites)


def _origine_perte(origine: Pkt | None, emise: bool) -> str:
    """Classe une retransmission TCP selon la transmission d'origine."""
    logger.debug("_origine_perte: début (origine vue={}, émise={})", origine is not None, emise)
    if origine is None:
        resultat = "indeterminee" if emise else "apres_point_acces"
    elif origine.radio_retries:
        resultat = "air"
    else:
        resultat = "apres_point_acces"
    logger.debug("_origine_perte: retour {}", resultat)
    return resultat


def _pertes_tcp(trames: list[Pkt]) -> dict[str, int]:
    """Retransmissions TCP (même segment de données revu au même point)
    classées par origine probable de la perte."""
    logger.debug("_pertes_tcp: {} trame(s)", len(trames))
    pertes = {"air": 0, "apres_point_acces": 0, "indeterminee": 0}
    vus: dict[tuple, Pkt] = {}
    for pkt in trames:
        if pkt.proto != "TCP" or not pkt.tcp_len or pkt.seq is None:
            continue
        cle = (pkt.src, pkt.sport, pkt.dst, pkt.dport, pkt.seq)
        origine = vus.get(cle)
        if origine is None:
            vus[cle] = pkt
            continue
        station = pkt.wlan_station
        pertes[_origine_perte(origine, bool(station and station[2]))] += 1
    logger.debug("_pertes_tcp: retour {}", pertes)
    return pertes


def _itinerances(trames: list[Pkt]) -> list[dict]:
    """Changements de BSSID datés, avec le nombre de flux vus avant ET après."""
    logger.debug("_itinerances: {} trame(s)", len(trames))
    itinerances: list[dict] = []
    bssid_courant = None
    for i, pkt in enumerate(trames):
        bssid = pkt.wlan_station[1] if pkt.wlan_station else None
        if bssid_courant is not None and bssid != bssid_courant:
            avant = {_cle_flux(p) for p in trames[:i] if p.proto in ("TCP", "UDP")}
            apres = {_cle_flux(p) for p in trames[i:] if p.proto in ("TCP", "UDP")}
            itinerances.append({"ts": pkt.ts, "de": bssid_courant, "vers": bssid, "flux_traverses": len(avant & apres)})
        bssid_courant = bssid
    logger.debug("_itinerances: retour {} itinérance(s)", len(itinerances))
    return itinerances


def _fiche(station: str, trames: list[Pkt]) -> dict:
    """Fiche radio d'une station à un point (trames triées par horodatage)."""
    logger.debug("_fiche: {} trame(s)", len(trames))
    emises = [p for p in trames if p.wlan_station and p.wlan_station[2]]
    rssi = [p.radio.rssi_dbm for p in emises if p.radio and p.radio.rssi_dbm is not None]
    mcs = Counter(p.radio.mcs for p in trames if p.radio and p.radio.mcs is not None)
    debits = [p.radio.data_rate_mbps for p in trames if p.radio and p.radio.data_rate_mbps]
    retries = sum(p.radio_retries for p in trames)
    transmissions = len(trames) + retries
    temps_antenne = sum(
        p.length * 8 * (1 + p.radio_retries) / (p.radio.data_rate_mbps * 1_000_000)
        for p in trames
        if p.radio and p.radio.data_rate_mbps
    )
    itinerances = _itinerances(trames)
    pertes = _pertes_tcp(trames)
    debit_median = statistics.median(debits) if debits else None
    constats = []
    if pertes["air"]:
        constats.append(PERTE_AIR)
    if pertes["apres_point_acces"]:
        constats.append(PERTE_APRES_AP)
    if debit_median is not None and debit_median < SEUIL_DEBIT_PHY_BAS_MBPS:
        constats.append(DEBIT_PHY_BAS)
    if any(it["flux_traverses"] for it in itinerances):
        constats.append(ITINERANCE_FLUX)
    fiche = {
        "station": station,
        "trames": len(trames),
        "trames_emises": len(emises),
        "rssi_median_dbm": statistics.median(rssi) if rssi else None,
        "mcs": dict(sorted(mcs.items())),
        "debits_phy_mbps": dict(sorted(Counter(debits).items())),
        "debit_phy_median_mbps": debit_median,
        "retransmissions_radio": retries,
        "taux_retransmission_radio": retries / transmissions,
        "bssids": sorted({p.wlan_station[1] for p in trames if p.wlan_station}),
        "itinerances": itinerances,
        "temps_antenne_s": temps_antenne,
        "pertes_tcp": pertes,
        "constats": constats,
    }
    logger.debug("_fiche: retour {} constat(s)", len(constats))
    return fiche


def metriques_clients(all_packets: list[Pkt]) -> dict[str, list[dict]]:
    """Point -> fiches radio des stations clientes, triées par adresse.
    Points sans trame 802.11 de station absents du résultat."""
    logger.debug("metriques_clients: {} paquet(s)", len(all_packets))
    par_station: dict[str, dict[str, list[Pkt]]] = defaultdict(lambda: defaultdict(list))
    for pkt in all_packets:
        if pkt.wlan_station is not None:
            par_station[pkt.point][pkt.wlan_station[0]].append(pkt)
    resultat = {
        point: [_fiche(station, sorted(trames, key=lambda p: p.ts)) for station, trames in sorted(stations.items())]
        for point, stations in sorted(par_station.items())
    }
    for point, fiches in resultat.items():
        for fiche in fiches:
            if fiche["constats"]:
                logger.info("Wi-Fi {} : station {} -> {}", point, fiche["station"], ", ".join(fiche["constats"]))
    logger.debug("metriques_clients: retour {} point(s)", len(resultat))
    return resultat


def format_fiche(point: str, fiche: dict) -> str:
    """Ligne de rapport texte d'une fiche radio."""
    logger.debug("format_fiche: début")
    rssi = "n/d" if fiche["rssi_median_dbm"] is None else f"{fiche['rssi_median_dbm']:g} dBm"
    debit = "n/d" if fiche["debit_phy_median_mbps"] is None else f"{fiche['debit_phy_median_mbps']:g} Mbit/s"
    ligne = (
        f"{point} : station {fiche['station']} -- {fiche['trames']} trame(s), RSSI médian {rssi}, "
        f"débit PHY médian {debit}, retransmissions radio {fiche['taux_retransmission_radio']:.1%}, "
        f"{len(fiche['itinerances'])} itinérance(s), temps d'antenne ≈ {fiche['temps_antenne_s'] * 1000:.2f} ms"
    )
    if fiche["constats"]:
        ligne += " ; constats : " + ", ".join(fiche["constats"])
    logger.debug("format_fiche: retour ligne")
    return ligne
