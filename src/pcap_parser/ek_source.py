# SPDX-License-Identifier: GPL-3.0-or-later
"""
pcap_parser.ek_source -- couche 1 : execution de tshark -T ek et lecture
du flux NDJSON qui en resulte, fichier pcap ou interface live.

Cette couche ne connait rien aux protocoles applicatifs : elle expose
uniquement des dicts "layers" bruts (un par paquet), tels que tshark les
produit. Toute la semantique reseau vit dans les couches au-dessus
(tunnels.py, protocols.py, packet.py).

Pourquoi tshark -T ek :
- decodage en C dans tshark (dissecteurs Wireshark), pas en Python pur
  paquet par paquet -> gain de vitesse important sur de grosses captures
- -T ek (Elastic/Kafka bulk NDJSON) produit un objet JSON par paquet sur
  une seule ligne, ce qui permet un vrai streaming ligne par ligne (utile
  pour parse_capture comme pour la capture live), contrairement a
  une lecture qui chargerait tout le fichier en memoire avant de rendre
  la main
- les tunnels (GRE/VXLAN/GTP-U/ERSPAN/CAPWAP) et les protocoles
  applicatifs (RTP/DHCP/SIP) sont deja disseques nativement par
  Wireshark -- on n'a plus besoin de reimplementer leur decodage a la
  main comme le faisait l'ancien decodeur (cf. parse_capwap_data() dans
  l'ancienne version, remplace par le dissecteur capwap natif, cf.
  tunnels.py)
"""

from __future__ import annotations

import calendar
import contextlib
import datetime
import json
import os
import re
import shutil
import subprocess
import threading
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import IO

from loguru import logger

from pcap_parser.wifi_keys import WifiKeysError, wifi_keys_from_env, wlan_decryption

# frame_frame_time_epoch : "2026-08-20T20:19:51.632525000Z" (nanosecondes).
# Nettement plus precis que le "timestamp" racine du bulk EK (millisecondes
# seulement) -- important pour des mesures de latence inter-points fines.
_FRAME_TIME_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d+)Z?$")


def _parse_frame_time_epoch(value: str | None) -> float | None:
    if not value:
        logger.debug("_parse_frame_time_epoch: si not value -> retour None")
        return None
    m = _FRAME_TIME_RE.match(value)
    if not m:
        # chemin chaud (une fois par paquet) : TRACE, et seulement le cas anormal
        logger.trace("_parse_frame_time_epoch: horodatage non reconnu {!r}", value)
        logger.debug("_parse_frame_time_epoch: si not m -> retour None")
        return None
    y, mo, d, h, mi, se, frac = m.groups()
    dt = datetime.datetime(int(y), int(mo), int(d), int(h), int(mi), int(se), tzinfo=datetime.timezone.utc)
    frac_seconds = int(frac[:9].ljust(9, "0")) / 1e9
    logger.debug("_parse_frame_time_epoch: retour calendar.timegm(dt.timetuple()) + frac_seconds")
    return calendar.timegm(dt.timetuple()) + frac_seconds


class TsharkNotFoundError(RuntimeError):
    """tshark n'est pas installe / pas dans le PATH."""


class TsharkError(RuntimeError):
    """tshark a demarre mais a echoue (fichier illisible, interface
    inconnue, permissions insuffisantes...). Porte le code de retour et
    stderr pour que l'appelant puisse construire un message utile."""

    def __init__(self, message: str, returncode: int | None = None, stderr: str = ""):
        logger.debug("__init__: entrée")
        super().__init__(message)
        self.returncode = returncode
        self.stderr = stderr
        logger.debug("TsharkError.__init__: fin")


class CaptureAccessError(TsharkError):
    """Le fichier de capture est absent ou illisible par l'utilisateur
    courant : inutile de lancer tshark, le message explique quoi corriger."""


def check_capture_readable(path: str) -> None:
    """Verifie avant tshark que ``path`` est un fichier lisible (#468).

    Leve ``CaptureAccessError`` avec un message actionnable (proprietaire,
    droits, commande de correction) plutot que le message brut de tshark.
    """
    if not os.path.exists(path):
        logger.debug("check_capture_readable: si not os.path.exists(path) -> levée CaptureAccessError")
        raise CaptureAccessError(f"fichier de capture introuvable : {path}")
    if os.path.isdir(path):
        logger.debug("check_capture_readable: si os.path.isdir(path) -> levée CaptureAccessError")
        raise CaptureAccessError(f"{path} est un repertoire, pas un fichier de capture")
    if not os.access(path, os.R_OK):
        try:
            st = os.stat(path)
            detail = f" (proprietaire uid {st.st_uid}, droits {st.st_mode & 0o777:o})"
        except OSError as exc:
            logger.debug("check_capture_readable: stat({}) impossible : {}", path, exc)
            detail = ""
        logger.debug("check_capture_readable: si not os.access(path, os.R_OK) -> levée CaptureAccessError")
        raise CaptureAccessError(
            f"droits insuffisants pour lire {path}{detail}. "
            f"Rendez le fichier lisible, par exemple : sudo chown \"$USER\" '{path}' && chmod u+r '{path}'"
        )
    logger.debug("check_capture_readable: fin")


def is_permission_error(exc: TsharkError) -> bool:
    """tshark a refuse d'ouvrir le fichier faute de droits."""
    text = f"{exc} {exc.stderr}".lower()
    logger.debug("is_permission_error: retour 'permission' in text or 'permission non accord' i…")
    return "permission" in text or "permission non accord" in text


# Preferences tshark activees par defaut. rtp.heuristic_rtp est le point
# important : sans elle, tshark ne reconnait le RTP que sur les ports
# annonces via SDP (SIP/H.323...) -- exactement le meme angle mort que
# l'ancienne detection heuristique par octets dans parsing.py, donc on
# la garde active pour au moins egaler le comportement precedent.
#
# ip.check_checksum/tcp.check_checksum/udp.check_checksum (Job 43/issue
# #163) : DESACTIVEES par defaut cote tshark (cout de recalcul, bruit
# historique avec l'offload materiel) -- sans elles, le champ EK
# "*.checksum.status" reste TOUJOURS a "2" (Unverified), quelle que soit
# la validite reelle du checksum (verifie empiriquement, pcap scapy
# synthetique avec checksum TCP/IP volontairement invalide, tshark
# 4.2.2 : statut "2" dans les deux cas sans cette preference). Activees
# ici pour que netcross_core.forensic.validate_checksums() ait une
# donnee exploitable -- voir pcap_parser.packet pour l'extraction du
# statut et netcross_core.forensic pour la distinction offload (0x0000)
# vs invalide.
DEFAULT_PREFS: Sequence[str] = (
    "rtp.heuristic_rtp:TRUE",
    "ip.check_checksum:TRUE",
    "tcp.check_checksum:TRUE",
    "udp.check_checksum:TRUE",
)


def _tshark_path() -> str:
    path = shutil.which("tshark")
    if path is None:
        logger.warning("tshark introuvable dans le PATH")
        raise TsharkNotFoundError(
            "tshark introuvable dans le PATH -- installer le paquet "
            "'tshark' (apt install tshark / dnf install wireshark-cli)."
        )
    logger.debug("_tshark_path: {}", path)
    return path


_SECRET_PREF_RE = re.compile(r"^(extcap\.[^.:]+\.[a-z]*(?:password|passphrase)):.*$")


def redact_args(args: Sequence[str]) -> list:
    """Copie de `args` sans secret, pour les journaux (issue #166) :
    valeur de `-A utilisateur:mot_de_passe` (rpcap) et preferences extcap
    de mot de passe/phrase secrete (sshdump) masquees."""
    out = []
    mask_next = False
    for arg in args:
        if mask_next:
            user = str(arg).split(":", 1)[0]
            out.append(f"{user}:***")
            mask_next = False
            continue
        match = _SECRET_PREF_RE.match(str(arg))
        out.append(f"{match.group(1)}:***" if match else arg)
        mask_next = arg == "-A"
    masked = sum(1 for a, b in zip(args, out) if a != b)
    if masked:
        # ne jamais journaliser la valeur : seulement le nombre de secrets masques
        logger.debug("redact_args: {} argument(s) secret(s) masque(s)", masked)
    logger.debug("redact_args: retour out")
    return out


def tls_keylog_prefs(tls_keylog: str | None) -> tuple[str, ...]:
    """Preference tshark d'un fichier de cles TLS (SSLKEYLOGFILE, issue #1040) :
    ``("tls.keylog_file:CHEMIN",)``, ou ``()`` sans fichier. Seul le chemin est
    transmis (et journalise) ; tshark lit lui-meme les secrets."""
    logger.debug("tls_keylog_prefs: entrée")
    if not tls_keylog:
        logger.debug("tls_keylog_prefs: retour, aucun fichier")
        return ()
    logger.debug("tls_keylog_prefs: retour, fichier de cles fourni")
    return (f"tls.keylog_file:{tls_keylog}",)


def _build_args(
    *,
    path: str | None = None,
    interface: str | None = None,
    bpf_filter: str | None = None,
    display_filter: str | None = None,
    extra_prefs: Sequence[str] = (),
    extra_args: Sequence[str] = (),
    lua_scripts: Sequence[str] = (),
    read_via_stdin: bool = False,
) -> list:
    if (path is None) == (interface is None):
        logger.debug("_build_args: path et interface tous deux {}", "absents" if path is None else "fournis")
        raise ValueError("fournir soit path= (batch), soit interface= (live), pas les deux")
    logger.debug(
        "_build_args: mode {}, stdin={}, bpf={}, filtre={}, {} pref(s), {} script(s) lua",
        "fichier" if path is not None else "live",
        read_via_stdin,
        bool(bpf_filter),
        bool(display_filter),
        len(extra_prefs),
        len(lua_scripts),
    )

    args = [_tshark_path()]
    if path is not None:
        # read_via_stdin : le fichier est ouvert par Python et transmis sur
        # l'entree standard ("-r -"), pour les tshark confines (snap,
        # AppArmor...) qui n'ont pas le droit d'ouvrir le chemin eux-memes.
        args += ["-r", "-" if read_via_stdin else path]
    else:
        # -l : flush ligne par ligne (indispensable pour du live streaming,
        # sinon tshark bufferise sa sortie et rien n'arrive avant un bon
        # moment). -Q : reduit le bruit sur stderr (pas de compteur de
        # paquets capture).
        assert interface is not None  # garanti par le check path/interface ci-dessus
        args += ["-i", interface, "-l", "-Q"]

    if bpf_filter:
        args += ["-f", bpf_filter]
    if display_filter:
        args += ["-Y", display_filter]
    for pref in (*DEFAULT_PREFS, *extra_prefs):
        args += ["-o", pref]
    for script in lua_scripts:
        args += ["-X", f"lua_script:{script}"]
    args += ["-T", "ek"]
    args += list(extra_args)
    logger.debug("_build_args: retour args")
    return args


def _iter_ndjson_records(stream: IO[str]) -> Iterator[dict]:
    """Lit le flux ligne par ligne et yield chaque objet JSON qui contient
    une cle "layers" (les lignes "index" du format bulk Elastic sont
    ignorees -- elles ne portent aucune donnee de paquet, juste un
    marqueur d'index pour un bulk insert Elasticsearch)."""
    for raw_line in stream:
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            # une ligne tronquee/corrompue ne doit pas faire tomber tout
            # le flux -- on la saute et on continue sur la suivante
            logger.warning("_iter_ndjson_records: ligne JSON invalide ignorée ({} car., {})", len(line), exc)
            continue
        if "layers" in obj:
            yield obj
    logger.debug("_iter_ndjson_records: fin")


@dataclass
class EkRecord:
    ts: float  # secondes depuis epoch, precision nanoseconde (frame_frame_time_epoch)
    layers: dict


def _terminate_on_event(proc: subprocess.Popen, stop_event: threading.Event) -> None:
    """Tourne dans un thread daemon dedie : dort (sans polling) jusqu'a ce
    que stop_event soit positionne, puis termine `proc` immediatement.

    Necessaire car la boucle de lecture principale est bloquee sur un
    appel systeme (lecture du pipe stdout du sous-processus) : un simple
    `if stop_event.is_set(): break` verifie APRES chaque paquet ne suffit
    pas sur une interface totalement silencieuse, ou aucun paquet ne
    declenchera jamais ce test. Terminer le processus depuis un thread
    separe debloque la lecture par EOF quel que soit le trafic (valide :
    voir test_stop_mechanism.py, arret en ~1s meme sans aucune sortie)."""
    stop_event.wait()
    if proc.poll() is None:
        logger.debug("_terminate_on_event: arrêt demandé, terminate() de tshark (pid {})", getattr(proc, "pid", None))
        proc.terminate()
    logger.debug("_terminate_on_event: fin")


def iter_ek_records(
    *,
    path: str | None = None,
    interface: str | None = None,
    bpf_filter: str | None = None,
    display_filter: str | None = None,
    extra_prefs: Sequence[str] = (),
    extra_args: Sequence[str] = (),
    lua_scripts: Sequence[str] = (),
    stop_event: threading.Event | None = None,
    read_via_stdin: bool = False,
) -> Iterator[EkRecord]:
    """
    Lance tshark -T ek et yield un EkRecord par paquet, au fil de l'eau.

    Mode batch : path="capture.pcapng" (le processus tshark se termine
    de lui-meme une fois le fichier lu).
    Mode live : interface="eth0" (le generateur ne se termine que si
    l'appelant s'arrete d'iterer -- fermer le generateur ou lever
    GeneratorExit tue proprement le processus tshark, cf. finally).

    stop_event (mode live uniquement, optionnel) : threading.Event que
    l'appelant peut positionner depuis un AUTRE thread pour demander
    l'arret. Contrairement a fermer le generateur (qui ne prend effet
    qu'au prochain paquet recu), stop_event termine le sous-processus
    tshark directement -- reactif meme sur une interface sans trafic.
    Sans objet en mode batch (le processus se termine de lui-meme).

    read_via_stdin (mode batch uniquement) : le fichier est ouvert par
    Python et fourni a tshark sur son entree standard.

    Leve TsharkNotFoundError si tshark n'est pas installe, CaptureAccessError
    si le fichier n'est pas lisible par l'utilisateur courant, ou TsharkError
    si le processus tshark a echoue (code de retour non nul et aucun
    paquet produit).
    """
    if path is not None:
        check_capture_readable(path)
    # Dechiffrement 802.11 (issue #1143) : cles lues dans le fichier designe
    # par NETCROSS_WIFI_KEYS. Sans cle, appel de tshark strictement inchange.
    try:
        cles_wifi = wifi_keys_from_env()
    except WifiKeysError as exc:
        logger.error("iter_ek_records: clés Wi-Fi refusées : {}", exc)
        raise TsharkError(str(exc)) from exc
    with wlan_decryption(cles_wifi) as (env_wifi, prefs_wifi):
        yield from _run_ek(
            path=path,
            interface=interface,
            bpf_filter=bpf_filter,
            display_filter=display_filter,
            extra_prefs=(*extra_prefs, *prefs_wifi),
            extra_args=extra_args,
            lua_scripts=lua_scripts,
            stop_event=stop_event,
            read_via_stdin=read_via_stdin,
            env_wifi=env_wifi,
            avec_cles_wifi=bool(cles_wifi),
        )
    logger.debug("iter_ek_records: fin")


# Cles derivees que tshark ajoute a chaque trame dechiffree (wlan.analysis.*) :
# equivalentes a la phrase de passe pour qui les lit, jamais conservees.
CLES_DERIVEES_80211: tuple[str, ...] = tuple(f"wlan_wlan_analysis_{nom}" for nom in ("pmk", "kck", "kek", "tk", "gtk"))


def _retirer_cles_derivees(wlan: dict | list) -> None:
    """Retire en place les cles derivees de la (des) couche(s) wlan d'un
    enregistrement EK, avant toute autre lecture (issue #1143)."""
    logger.debug("_retirer_cles_derivees: entrée")
    for couche in wlan if isinstance(wlan, list) else (wlan,):
        for champ in CLES_DERIVEES_80211:
            couche.pop(champ, None)
    logger.debug("_retirer_cles_derivees: fin")


def _trame_80211_chiffree(layers: dict) -> bool:
    """Trame de donnees 802.11 protegee dont tshark n'a extrait aucune
    couche IP (pas de cle, handshake absent ou cle fausse). Chemin chaud :
    l'appelant ne l'appelle que si la couche wlan est presente."""
    if "ip" in layers or "ipv6" in layers:
        logger.debug("_trame_80211_chiffree: couche IP présente -> retour False")
        return False
    wlan = layers["wlan"]
    if isinstance(wlan, list):
        wlan = wlan[-1]
    chiffree = str(wlan.get("wlan_wlan_fc_type")) == "2" and wlan.get("wlan_wlan_fc_protected") in (True, "1", "true")
    logger.debug("_trame_80211_chiffree: retour {}", chiffree)
    return chiffree


def _signaler_80211_chiffrees(chiffrees: int, eapol: int, avec_cles: bool) -> None:
    """Repli explicite (issue #1143) : des trames chiffrees restent
    illisibles, l'utilisateur doit savoir pourquoi."""
    logger.debug("_signaler_80211_chiffrees: entrée ({} chiffrée(s), {} EAPOL)", chiffrees, eapol)
    if not chiffrees:
        logger.debug("_signaler_80211_chiffrees: rien à signaler")
        return
    if not avec_cles:
        raison = "aucune clé Wi-Fi fournie (--wifi-keys ou NETCROSS_WIFI_KEYS)"
    elif not eapol:
        raison = "4-way handshake EAPOL absent de la capture"
    else:
        raison = "clé ne correspondant pas au réseau ou handshake incomplet"
    logger.warning(
        "{} trame(s) de données 802.11 chiffrée(s) non déchiffrée(s) : {} ; métriques radio seules, aucun paquet IP",
        chiffrees,
        raison,
    )
    logger.debug("_signaler_80211_chiffrees: retour")


def _run_ek(
    *,
    path: str | None,
    interface: str | None,
    bpf_filter: str | None,
    display_filter: str | None,
    extra_prefs: Sequence[str],
    extra_args: Sequence[str],
    lua_scripts: Sequence[str],
    stop_event: threading.Event | None,
    read_via_stdin: bool,
    env_wifi: dict[str, str],
    avec_cles_wifi: bool,
) -> Iterator[EkRecord]:
    """Corps d'iter_ek_records : lance tshark et lit son flux EK."""
    args = _build_args(
        path=path,
        interface=interface,
        bpf_filter=bpf_filter,
        display_filter=display_filter,
        extra_prefs=extra_prefs,
        extra_args=extra_args,
        lua_scripts=lua_scripts,
        read_via_stdin=read_via_stdin,
    )
    logger.debug("tshark args : {}", redact_args(args))

    stdin_file = open(path, "rb") if (read_via_stdin and path is not None) else None  # noqa: SIM115
    try:
        proc = subprocess.Popen(
            args,
            stdin=stdin_file,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # bufsize=1 : line-buffered, necessaire pour le live
            # env=None (defaut de Popen) sans cle Wi-Fi : environnement herite, inchange
            env={**os.environ, **env_wifi} if env_wifi else None,
        )
    finally:
        # le processus fils a herite du descripteur : le parent peut fermer le sien
        if stdin_file is not None:
            stdin_file.close()
    if stop_event is not None:
        threading.Thread(target=_terminate_on_event, args=(proc, stop_event), daemon=True).start()
    logger.debug("iter_ek_records: tshark lancé (pid {}, source={})", getattr(proc, "pid", None), path or interface)
    records_count = 0
    produced_any = False
    chiffrees_80211 = eapol_80211 = 0
    try:
        assert proc.stdout is not None
        for obj in _iter_ndjson_records(proc.stdout):
            produced_any = True
            records_count += 1
            frame = obj["layers"].get("frame") or {}
            ts = _parse_frame_time_epoch(frame.get("frame_frame_time_epoch"))
            if ts is None:
                # repli : "timestamp" racine du bulk EK, en millisecondes
                # -- moins precis, mais toujours present.
                try:
                    ts = int(float(obj.get("timestamp", 0))) / 1000.0
                except (TypeError, ValueError):
                    logger.debug("iter_ek_records: horodatage illisible, 0.0 utilisé")
                    ts = 0.0
            layers = obj["layers"]
            if "wlan" in layers:
                _retirer_cles_derivees(layers["wlan"])
                chiffrees_80211 += _trame_80211_chiffree(layers)
                eapol_80211 += "eapol" in layers
            yield EkRecord(ts=ts, layers=layers)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                logger.warning("iter_ek_records: tshark ne s'arrête pas après terminate(), kill")
                proc.kill()
                proc.wait()
        logger.debug(
            "iter_ek_records: tshark terminé, code {}, {} enregistrement(s)",
            proc.returncode,
            records_count,
        )
        stderr_text = ""
        if proc.stderr is not None:
            with contextlib.suppress(OSError, ValueError):
                # best-effort uniquement : ce texte n'enrichit qu'un message
                # d'erreur eventuel plus bas -- son absence ne fait perdre
                # aucune fonctionnalite, juste un message legerement moins detaille.
                stderr_text = proc.stderr.read() or ""
        _signaler_80211_chiffrees(chiffrees_80211, eapol_80211, avec_cles_wifi)
        if proc.returncode not in (0, None, -15) and not produced_any:
            # -15 = SIGTERM, normal quand on arrete nous-memes un live
            # capture. Un code d'echec alors qu'aucun paquet n'est sorti
            # signale un vrai probleme (fichier illisible, interface
            # inconnue, permissions) -- a faire remonter, pas a avaler.
            logger.debug("iter_ek_records: échec tshark sans aucun paquet produit")
            raise TsharkError(
                f"tshark a echoue (code {proc.returncode}) : {stderr_text.strip()}",
                returncode=proc.returncode,
                stderr=stderr_text,
            )
    logger.debug("_run_ek: fin")
