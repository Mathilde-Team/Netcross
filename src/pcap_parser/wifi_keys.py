# SPDX-License-Identifier: GPL-3.0-or-later
"""pcap_parser.wifi_keys -- dechiffrement WPA/WPA2-PSK par tshark (issue #1143).

Deuxieme brique du chantier « Wi-Fi en mode moniteur » (#1006). tshark
decapsule deja 802.11 -> LLC/SNAP -> IP ; sur un reseau protege, les trames
de donnees sont chiffrees (CCMP/TKIP) et seules les metadonnees radio
restent lisibles. Avec la phrase de passe (et le SSID) ou la PSK brute, et
si le 4-way handshake EAPOL de la station figure dans la capture, tshark
dechiffre les trames : les paquets IP redeviennent analysables comme sur un
point filaire.

Fichier de cles (``--wifi-keys FICHIER`` ou variable d'environnement
``NETCROSS_WIFI_KEYS``), une cle par ligne, ``#`` pour un commentaire ::

    wpa-pwd:PHRASE:SSID      phrase de passe WPA/WPA2 (8 a 63 caracteres) et SSID
    wpa-psk:HEX64            PSK brute (PMK, 32 octets en hexadecimal)

Le dernier ``:`` d'une ligne ``wpa-pwd`` separe la phrase du SSID : une
phrase peut donc contenir ``:``, pas un SSID.

La phrase de passe ne passe JAMAIS sur la ligne de commande de tshark
(visible dans la liste des processus) ni dans un journal, un message
d'erreur ou un rapport : elle est ecrite dans le fichier ``80211_keys``
d'un repertoire de configuration Wireshark temporaire (0700, fichier
0600), designe a tshark par ``WIRESHARK_CONFIG_DIR`` et supprime des la fin
du processus. Seule la preference sans secret ``wlan.enable_decryption``
passe en ``-o``.

Limite : ce repertoire remplace la configuration personnelle de Wireshark
le temps de la lecture (les preferences de Netcross sont passees en ``-o``,
elles ne sont pas concernees).
"""

from __future__ import annotations

import contextlib
import os
import re
import shutil
import tempfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from urllib.parse import quote

from loguru import logger as _loguru_logger

# pcap_parser reste independant de netcross_core (contrat import-linter).
logger = _loguru_logger.bind(name=__name__)

ENV_WIFI_KEYS = "NETCROSS_WIFI_KEYS"
WLAN_DECRYPTION_PREFS: tuple[str, ...] = ("wlan.enable_decryption:TRUE",)
FICHIER_UAT = "80211_keys"

_HEX64 = re.compile(r"^[0-9A-Fa-f]{64}$")


class WifiKeysError(ValueError):
    """Fichier de cles Wi-Fi invalide. Le message ne contient jamais de secret."""


@dataclass(frozen=True)
class WifiKey:
    """Une cle de dechiffrement : ``kind`` vaut ``wpa-pwd`` ou ``wpa-psk``.
    ``secret`` (phrase ou PSK) est exclu de ``repr`` pour ne jamais fuir
    dans un journal ou une trace d'exception."""

    kind: str
    secret: str = field(repr=False)
    ssid: str | None = None

    def uat_line(self) -> str:
        """Ligne du fichier ``80211_keys`` de Wireshark. Phrase et SSID sont
        encodes en pourcentage (« : » interdit hors separateur, guillemets
        et caracteres non imprimables)."""
        logger.debug("WifiKey.uat_line: entrée ({})", self.kind)
        if self.kind == "wpa-psk":
            valeur = self.secret
        else:
            valeur = f"{quote(self.secret, safe='')}:{quote(self.ssid or '', safe='')}"
        logger.debug("WifiKey.uat_line: retour ligne {}", self.kind)
        return f'"{self.kind}","{valeur}"'


def _ligne_cle(texte: str, numero: int) -> WifiKey:
    """Analyse une ligne non vide du fichier de cles ; ``WifiKeysError``
    (numero de ligne, jamais le contenu) si elle est invalide."""
    logger.debug("_ligne_cle: entrée (ligne {})", numero)
    kind, sep, reste = texte.partition(":")
    kind = kind.strip().lower()
    if not sep or kind not in ("wpa-pwd", "wpa-psk"):
        logger.debug("_ligne_cle: type inconnu -> levée")
        raise WifiKeysError(f"ligne {numero} : type de clé attendu « wpa-pwd: » ou « wpa-psk: »")
    if kind == "wpa-psk":
        if not _HEX64.match(reste.strip()):
            logger.debug("_ligne_cle: PSK invalide -> levée")
            raise WifiKeysError(f"ligne {numero} : PSK attendue sur 64 chiffres hexadécimaux")
        logger.debug("_ligne_cle: retour PSK")
        return WifiKey(kind=kind, secret=reste.strip().lower())
    phrase, sep, ssid = reste.rpartition(":")
    if not sep or not ssid:
        logger.debug("_ligne_cle: SSID absent -> levée")
        raise WifiKeysError(f"ligne {numero} : format attendu « wpa-pwd:PHRASE:SSID »")
    if not 8 <= len(phrase) <= 63:
        logger.debug("_ligne_cle: longueur de phrase hors norme -> levée")
        raise WifiKeysError(f"ligne {numero} : la phrase de passe WPA doit faire de 8 à 63 caractères")
    if len(ssid.encode()) > 32:
        logger.debug("_ligne_cle: SSID trop long -> levée")
        raise WifiKeysError(f"ligne {numero} : SSID de plus de 32 octets")
    logger.debug("_ligne_cle: retour phrase de passe (SSID de {} octet(s))", len(ssid.encode()))
    return WifiKey(kind=kind, secret=phrase, ssid=ssid)


def parse_wifi_keys(texte: str) -> tuple[WifiKey, ...]:
    """Cles d'un contenu de fichier (lignes vides et commentaires ignores)."""
    logger.debug("parse_wifi_keys: entrée ({} caractère(s))", len(texte))
    cles = []
    for numero, brute in enumerate(texte.splitlines(), start=1):
        ligne = brute.strip()
        if not ligne or ligne.startswith("#"):
            continue
        cles.append(_ligne_cle(ligne, numero))
    if not cles:
        logger.debug("parse_wifi_keys: aucune clé -> levée")
        raise WifiKeysError("aucune clé Wi-Fi dans le fichier")
    logger.debug("parse_wifi_keys: retour {} clé(s)", len(cles))
    return tuple(cles)


def load_wifi_keys(chemin: str) -> tuple[WifiKey, ...]:
    """Lit et valide un fichier de cles ; ``WifiKeysError`` s'il est
    illisible ou invalide."""
    logger.debug("load_wifi_keys: entrée ({})", chemin)
    try:
        with open(chemin, encoding="utf-8") as fichier:
            texte = fichier.read()
    except (OSError, UnicodeDecodeError) as exc:
        logger.debug("load_wifi_keys: fichier illisible ({}) -> levée", type(exc).__name__)
        raise WifiKeysError(f"fichier de clés Wi-Fi illisible : {chemin} ({type(exc).__name__})") from exc
    cles = parse_wifi_keys(texte)
    logger.debug("load_wifi_keys: retour {} clé(s)", len(cles))
    return cles


def wifi_keys_from_env(environ: Mapping[str, str] | None = None) -> tuple[WifiKey, ...]:
    """Cles du fichier designe par ``NETCROSS_WIFI_KEYS`` ; ``()`` si la
    variable est absente ou vide."""
    logger.debug("wifi_keys_from_env: entrée")
    chemin = (os.environ if environ is None else environ).get(ENV_WIFI_KEYS, "")
    if not chemin:
        logger.debug("wifi_keys_from_env: variable absente -> retour ()")
        return ()
    cles = load_wifi_keys(chemin)
    logger.debug("wifi_keys_from_env: retour {} clé(s)", len(cles))
    return cles


@contextlib.contextmanager
def wlan_decryption(cles: tuple[WifiKey, ...]) -> Iterator[tuple[dict[str, str], tuple[str, ...]]]:
    """Contexte de dechiffrement pour un processus tshark :
    ``(variables d'environnement a ajouter, preferences -o)``. Sans cle,
    ``({}, ())`` : appel de tshark strictement inchange. Le repertoire
    temporaire est supprime a la sortie du contexte, meme en cas d'erreur."""
    logger.debug("wlan_decryption: entrée ({} clé(s))", len(cles))
    if not cles:
        logger.debug("wlan_decryption: aucune clé -> contexte vide")
        yield {}, ()
        logger.debug("wlan_decryption: fin (contexte vide)")
        return
    dossier = tempfile.mkdtemp(prefix="netcross-wifi-")  # 0700
    try:
        chemin = os.path.join(dossier, FICHIER_UAT)
        descripteur = os.open(chemin, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descripteur, "w", encoding="utf-8") as fichier:
            fichier.write("".join(cle.uat_line() + "\n" for cle in cles))
        logger.info("Déchiffrement 802.11 activé : {} clé(s) transmise(s) à tshark", len(cles))
        yield {"WIRESHARK_CONFIG_DIR": dossier}, WLAN_DECRYPTION_PREFS
    finally:
        shutil.rmtree(dossier, ignore_errors=True)
        logger.debug("wlan_decryption: répertoire temporaire supprimé")
    logger.debug("wlan_decryption: fin")
