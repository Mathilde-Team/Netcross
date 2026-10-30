"""pcap_parser.radio -- metadonnees radio 802.11 par paquet (issue #1142).

Premiere brique du chantier « Wi-Fi en mode moniteur » (#1006) : une
capture 802.11 avec en-tete radiotap (linktype 127) est un point de
capture comme un autre -- tshark decapsule deja 802.11 -> LLC -> IP --, et
chaque trame porte en plus ses metadonnees radio : RSSI, MCS, debit,
retry, canal et frequence. Elles sont lues dans la pseudo-couche
``wlan_radio`` de tshark, qui normalise radiotap, PPI, AVS et Prism (et
calcule le debit d'une trame HT/VHT a partir du MCS), et dans ``wlan``
pour le flag retry, present meme sans en-tete radio.

Une capture 802.11 SANS en-tete radio (linktype 105) reste lisible, mais
seul le retry est disponible : ``missing_radiotap_note`` produit le
message explicite affiche a l'utilisateur.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from loguru import logger as _loguru_logger

from pcap_parser.capfile import read_structure
from pcap_parser.ek_fields import as_bool, as_float, g, hex_or_dec_to_int

logger = _loguru_logger.bind(name=__name__)

LINKTYPE_IEEE802_11 = 105  # 802.11 sans en-tete radio
LINKTYPE_IEEE802_11_RADIOTAP = 127
# En-tetes radio pris en charge par la pseudo-couche wlan_radio de tshark.
LINKTYPES_WITH_RADIO_HEADER = frozenset({119, 127, 163, 192})  # Prism, radiotap, AVS, PPI


@dataclass(frozen=True, slots=True)
class RadioInfo:
    """Metadonnees radio d'une trame 802.11 ; None = non fourni par la
    capture (pas d'en-tete radio, champ absent de l'en-tete, trame legacy
    sans MCS...)."""

    rssi_dbm: int | None = None
    mcs: int | None = None
    data_rate_mbps: float | None = None
    retry: bool | None = None
    channel: int | None = None
    frequency_mhz: int | None = None


def extract_radio(layers: dict) -> RadioInfo | None:
    """RadioInfo d'un enregistrement tshark -T ek, ou None hors 802.11.
    Le MCS est lu en 802.11n, puis 802.11ac (premier utilisateur), puis
    802.11ax."""
    logger.debug("extract_radio: debut")
    wlan = layers.get("wlan")
    radio = layers.get("wlan_radio")
    if wlan is None and radio is None:
        logger.debug("extract_radio: si pas de couche 802.11 -> retour None")
        return None
    if isinstance(wlan, list):
        wlan = wlan[-1]
    if isinstance(radio, list):
        radio = radio[0]
    mcs = None
    for name in (
        "wlan_radio_wlan_radio_11n_mcs_index",
        "wlan_radio_wlan_radio_11ac_mcs",
        "wlan_radio_wlan_radio_11ax_mcs",
    ):
        value = g(radio, name)
        if isinstance(value, list):  # VHT/HE multi-utilisateur : un MCS par utilisateur
            value = value[0] if value else None
        mcs = hex_or_dec_to_int(value)
        if mcs is not None:
            break
    retry_raw = g(wlan, "wlan_wlan_fc_retry")
    info = RadioInfo(
        rssi_dbm=hex_or_dec_to_int(g(radio, "wlan_radio_wlan_radio_signal_dbm")),
        mcs=mcs,
        data_rate_mbps=as_float(g(radio, "wlan_radio_wlan_radio_data_rate")),
        retry=None if retry_raw is None else as_bool(retry_raw),
        channel=hex_or_dec_to_int(g(radio, "wlan_radio_wlan_radio_channel")),
        frequency_mhz=hex_or_dec_to_int(g(radio, "wlan_radio_wlan_radio_frequency")),
    )
    logger.debug("extract_radio: retour {}", info)
    return info


def missing_radiotap_note(path: str) -> str | None:
    """Message explicite si `path` est une capture 802.11 sans en-tete
    radio (linktype 105 sur toutes ses interfaces 802.11), None sinon (ou
    si le fichier est illisible / de format non reconnu)."""
    logger.debug("missing_radiotap_note: debut")
    try:
        structure = read_structure(path)
    except (OSError, ValueError, struct.error) as exc:
        logger.debug("missing_radiotap_note: fichier illisible ({}) -> retour None", type(exc).__name__)
        return None
    linktypes = {i.linktype for i in structure.interfaces} if structure is not None else set()
    if LINKTYPE_IEEE802_11 not in linktypes or linktypes & LINKTYPES_WITH_RADIO_HEADER:
        logger.debug("missing_radiotap_note: si pas de 802.11 sans en-tete radio -> retour None")
        return None
    note = (
        "capture 802.11 sans en-tête radiotap (linktype 105) : RSSI, MCS, débit et canal "
        "indisponibles, seul le flag retry est lu. Recapturer en mode moniteur avec "
        "radiotap (linktype 127, par exemple dumpcap -I -i <interface>)."
    )
    logger.debug("missing_radiotap_note: retour message")
    return note
