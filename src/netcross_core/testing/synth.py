"""Jeux synthétiques multi-points déterministes (issue #1015, banc #994).

Produit, pour un chemin linéaire de N points de capture ``P1 → … → PN``,
un fichier pcapng par point **et** un fichier de vérité terrain JSON qui
décrit exactement ce qui a été injecté (pertes, retards, décalages
d'horloge). C'est la référence du banc de performance (#994) et, plus tard,
des tests d'équivalence du pipeline en flux (#995).

Principes :

- **déterminisme** : tout l'aléa vient d'un ``random.Random(graine)``
  local ; horodatages entiers en nanosecondes ; aucun champ dépendant de la
  machine (pas de nom d'hôte, d'OS ni de date dans les blocs pcapng). Même
  graine et mêmes paramètres ⇒ mêmes octets ;
- **sans tshark** : les trames Ethernet/IPv4/TCP/UDP (DNS, TLS ClientHello
  et ServerHello) sont construites octet par octet, sommes de contrôle
  comprises, et écrites directement en pcapng ;
- **mémoire bornée** : les flux sont générés par date de début croissante ;
  un tas par point ne garde que les paquets encore susceptibles d'être
  précédés par un flux futur, ce qui permet 10⁶ paquets par point ;
- **vérité terrain exacte** : chaque perte est décidée paquet par paquet et
  comptée ; seuls les segments de données TCP et les datagrammes UDP hors
  DNS peuvent être perdus (perdre un SYN ou une requête DNS sans
  retransmission rendrait la suite du flux incohérente).

Topologie : le client est en amont de ``P1``, le serveur en aval de ``PN``.
Le segment ``k`` (base 1) relie ``Pk`` à ``Pk+1``. Un paquet perdu sur le
segment ``k`` dans le sens aller est vu jusqu'à ``Pk`` puis plus après ;
dans le sens retour, il est vu de ``PN`` jusqu'à ``Pk+1``. Chaque traversée
d'un segment décrémente le TTL (somme de contrôle IP recalculée), comme un
routeur.
"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import random
import struct
from dataclasses import asdict, dataclass, field
from pathlib import Path

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

NS = 1_000_000_000
MS = 1_000_000
US = 1_000
DEBUT_NS = 1_767_225_600 * NS  # 01/01/2026 00:00:00 UTC, fixe
TAILLES_STANDARD = (10_000, 100_000, 1_000_000)
POINTS_STANDARD = (2, 3, 5, 10)
TYPES_FLUX = ("tcp", "tls", "dns", "udp")
SENS = ("aller", "retour", "les_deux")
_MAC_CLIENT = bytes.fromhex("020000000001")
_MAC_SERVEUR = bytes.fromhex("020000000002")


@dataclass
class Configuration:
    """Paramètres d'un jeu. Tous les délais sont en millisecondes."""

    points: int = 2
    paquets: int = 10_000
    graine: int = 1
    debit_pps: int = 2_000
    delai_segment_ms: float = 1.0
    gigue_ms: float = 0.1
    melange: dict[str, float] = field(default_factory=lambda: {"tcp": 0.4, "tls": 0.3, "dns": 0.2, "udp": 0.1})
    segment_perte: int | None = None
    taux_perte: float = 0.0
    sens_perte: str = "aller"
    segment_retard: int | None = None
    retard_ms: float = 0.0
    decalages_ms: list[float] = field(default_factory=list)

    def valider(self) -> None:
        """Lève ``ValueError`` sur un paramètre incohérent."""
        logger.debug("Configuration.valider: entrée")
        segments = self.points - 1
        erreurs = []
        if self.points < 2:
            erreurs.append("au moins 2 points")
        if self.paquets < 1:
            erreurs.append("au moins 1 paquet")
        if self.debit_pps < 1:
            erreurs.append("debit_pps >= 1")
        if self.delai_segment_ms < 0 or self.gigue_ms < 0 or self.retard_ms < 0:
            erreurs.append("délais positifs")
        if self.gigue_ms > self.delai_segment_ms:
            erreurs.append("gigue_ms <= delai_segment_ms (horodatages monotones par segment)")
        if not 0.0 <= self.taux_perte <= 1.0:
            erreurs.append("taux_perte entre 0 et 1")
        if self.sens_perte not in SENS:
            erreurs.append(f"sens_perte parmi {', '.join(SENS)}")
        for nom, seg in (("segment_perte", self.segment_perte), ("segment_retard", self.segment_retard)):
            if seg is not None and not 1 <= seg <= segments:
                erreurs.append(f"{nom} entre 1 et {segments}")
        if self.decalages_ms and len(self.decalages_ms) != self.points:
            erreurs.append("decalages_ms : une valeur par point")
        inconnus = set(self.melange) - set(TYPES_FLUX)
        if inconnus or not self.melange or any(p < 0 for p in self.melange.values()) or sum(self.melange.values()) <= 0:
            erreurs.append(f"melange : poids positifs parmi {', '.join(TYPES_FLUX)}")
        if erreurs:
            logger.warning("configuration de jeu synthétique invalide : {}", erreurs)
            raise ValueError("configuration invalide : " + " ; ".join(erreurs))
        logger.debug("Configuration.valider: retour")


# -- construction des trames ------------------------------------------------


def _somme_controle(donnees: bytes) -> int:
    """Somme de contrôle Internet (RFC 1071)."""
    if len(donnees) % 2:
        donnees += b"\0"
    total = sum(struct.unpack(f"!{len(donnees) // 2}H", donnees))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    logger.debug("_somme_controle: retour ~total & 65535")
    return ~total & 0xFFFF


def _ip(n: int, reseau: int) -> bytes:
    """Adresse 10.<reseau>.x.y déterministe pour l'hôte numéro ``n``."""
    logger.debug("_ip: retour bytes(…)")
    return bytes((10, reseau, (n >> 8) & 0xFF, n & 0xFF or 1))


def _entete_ip(src: bytes, dst: bytes, proto: int, ident: int, ttl: int, charge: bytes) -> bytes:
    """En-tête IPv4 de 20 octets, somme de contrôle comprise."""
    entete = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(charge), ident, 0x4000, ttl, proto, 0, src, dst)
    logger.debug("_entete_ip: retour entete[:10] + struct.pack('!H', _somme_controle(e…")
    return entete[:10] + struct.pack("!H", _somme_controle(entete)) + entete[12:]


def _segment_tcp(src: bytes, dst: bytes, sport: int, dport: int, seq: int, ack: int, drapeaux: int, charge: bytes):
    """Segment TCP (en-tête de 20 octets + charge) avec sa somme de contrôle."""
    entete = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, drapeaux, 64240, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(entete) + len(charge))
    somme = _somme_controle(pseudo + entete + charge)
    logger.debug("_segment_tcp: retour entete[:16] + struct.pack('!H', somme) + entete[1…")
    return entete[:16] + struct.pack("!H", somme) + entete[18:] + charge


def _datagramme_udp(src: bytes, dst: bytes, sport: int, dport: int, charge: bytes) -> bytes:
    """Datagramme UDP avec sa somme de contrôle."""
    longueur = 8 + len(charge)
    pseudo = src + dst + struct.pack("!BBH", 0, 17, longueur)
    somme = _somme_controle(pseudo + struct.pack("!HHHH", sport, dport, longueur, 0) + charge) or 0xFFFF
    logger.debug("_datagramme_udp: retour struct.pack('!HHHH', sport, dport, longueur, somm…")
    return struct.pack("!HHHH", sport, dport, longueur, somme) + charge


def _trame(aller: bool, ip_paquet: bytes) -> bytes:
    """Trame Ethernet II (sans FCS) autour d'un paquet IPv4."""
    dst, src = (_MAC_SERVEUR, _MAC_CLIENT) if aller else (_MAC_CLIENT, _MAC_SERVEUR)
    logger.debug("_trame: retour dst + src + b'\\x08\\x00' + ip_paquet")
    return dst + src + b"\x08\x00" + ip_paquet


def _nom_dns(nom: str) -> bytes:
    """Nom de domaine au format DNS (étiquettes préfixées par leur longueur)."""
    logger.debug("_nom_dns: retour b''.join((bytes((len(p),)) + p.encode('ascii') fo…")
    return b"".join(bytes((len(p),)) + p.encode("ascii") for p in nom.split(".")) + b"\0"


def _dns(ident: int, nom: str, reponse: bytes | None) -> bytes:
    """Requête DNS de type A, ou sa réponse si ``reponse`` (adresse IPv4) est fourni."""
    question = _nom_dns(nom) + struct.pack("!HH", 1, 1)
    if reponse is None:
        logger.debug("_dns: si reponse is None -> retour struct.pack('!HHHHHH', ident, 256, 1, 0, 0, 0) + …")
        return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + question
    reponse_rr = struct.pack("!HHHIH", 0xC00C, 1, 1, 300, 4) + reponse
    logger.debug("_dns: retour struct.pack('!HHHHHH', ident, 33152, 1, 1, 0, 0) …")
    return struct.pack("!HHHHHH", ident, 0x8180, 1, 1, 0, 0) + question + reponse_rr


def _client_hello(alea: random.Random, sni: str) -> bytes:
    """Enregistrement TLS 1.2 contenant un ClientHello avec SNI."""
    nom = sni.encode("ascii")
    ext_sni = struct.pack("!HHHBH", 0, len(nom) + 5, len(nom) + 3, 0, len(nom)) + nom
    corps = (
        b"\x03\x03"
        + alea.randbytes(32)
        + b"\x00"
        + struct.pack("!H", 4)
        + b"\x13\x01\xc0\x2f"
        + b"\x01\x00"
        + struct.pack("!H", len(ext_sni))
        + ext_sni
    )
    poignee = b"\x01" + len(corps).to_bytes(3, "big") + corps
    logger.debug("_client_hello: retour b'\\x16\\x03\\x01' + struct.pack('!H', len(poignee))…")
    return b"\x16\x03\x01" + struct.pack("!H", len(poignee)) + poignee


def _server_hello(alea: random.Random) -> bytes:
    """Enregistrement TLS 1.2 contenant un ServerHello minimal."""
    corps = b"\x03\x03" + alea.randbytes(32) + b"\x00" + b"\xc0\x2f" + b"\x00" + struct.pack("!H", 0)
    poignee = b"\x02" + len(corps).to_bytes(3, "big") + corps
    logger.debug("_server_hello: retour b'\\x16\\x03\\x03' + struct.pack('!H', len(poignee))…")
    return b"\x16\x03\x03" + struct.pack("!H", len(poignee)) + poignee


# -- scénario de flux -------------------------------------------------------


@dataclass
class _Message:
    """Un paquet du flux, avant traversée du chemin."""

    aller: bool
    proto: int
    charge_l4: bytes
    perdable: bool
    pause_ns: int


def _messages_tcp(alea: random.Random, numero: int, tls: bool) -> tuple[list[_Message], tuple]:
    """Échange TCP complet : poignée de main, données (ou TLS), fermeture."""
    client, serveur = _ip(numero % 4000 + 1, 1), _ip(numero % 250 + 1, 2)
    sport, dport = 1024 + alea.randrange(60000), 443 if tls else alea.choice((80, 8080, 22, 3306))
    sc, ss = alea.getrandbits(32), alea.getrandbits(32)
    syn, ack, psh, fin = 0x02, 0x10, 0x08, 0x01

    def seg(aller: bool, seq: int, accuse: int, drapeaux: int, charge: bytes = b"") -> bytes:
        if aller:
            logger.debug("_messages_tcp.seg: si aller -> retour _segment_tcp(…)")
            return _segment_tcp(client, serveur, sport, dport, seq & 0xFFFFFFFF, accuse & 0xFFFFFFFF, drapeaux, charge)
        logger.debug("_messages_tcp.seg: retour _segment_tcp(…)")
        return _segment_tcp(serveur, client, dport, sport, seq & 0xFFFFFFFF, accuse & 0xFFFFFFFF, drapeaux, charge)

    pause = 200 * US
    msgs = [
        _Message(True, 6, seg(True, sc, 0, syn), False, 0),
        _Message(False, 6, seg(False, ss, sc + 1, syn | ack), False, pause),
        _Message(True, 6, seg(True, sc + 1, ss + 1, ack), False, pause),
    ]
    sc, ss = sc + 1, ss + 1
    if tls:
        hello = _client_hello(alea, f"synth-{numero}.example.test")
        msgs.append(_Message(True, 6, seg(True, sc, ss, psh | ack, hello), True, pause))
        sc += len(hello)
        reponse = _server_hello(alea)
        msgs.append(_Message(False, 6, seg(False, ss, sc, psh | ack, reponse), True, pause))
        ss += len(reponse)
    for _ in range(alea.randint(2, 12)):
        aller = alea.random() < 0.5
        charge = alea.randbytes(alea.randint(40, 1400))
        if tls:
            charge = b"\x17\x03\x03" + struct.pack("!H", len(charge)) + charge
        if aller:
            msgs.append(_Message(True, 6, seg(True, sc, ss, psh | ack, charge), True, pause))
            sc += len(charge)
        else:
            msgs.append(_Message(False, 6, seg(False, ss, sc, psh | ack, charge), True, pause))
            ss += len(charge)
    msgs += [
        _Message(True, 6, seg(True, sc, ss, fin | ack), False, pause),
        _Message(False, 6, seg(False, ss, sc + 1, fin | ack), False, pause),
        _Message(True, 6, seg(True, sc + 1, ss + 1, ack), False, pause),
    ]
    logger.debug("_messages_tcp: retour tuple de 2")
    return msgs, (client, serveur)


def _messages_dns(alea: random.Random, numero: int) -> tuple[list[_Message], tuple]:
    """Requête DNS et sa réponse (jamais perdues, voir l'en-tête du module)."""
    client, serveur = _ip(numero % 4000 + 1, 1), _ip(53, 2)
    sport, ident, nom = 1024 + alea.randrange(60000), alea.getrandbits(16), f"h{numero}.example.test"
    msgs = [
        _Message(True, 17, _datagramme_udp(client, serveur, sport, 53, _dns(ident, nom, None)), False, 0),
        _Message(False, 17, _datagramme_udp(serveur, client, 53, sport, _dns(ident, nom, _ip(numero, 3))), False, MS),
    ]
    logger.debug("_messages_dns: retour tuple de 2")
    return msgs, (client, serveur)


def _messages_udp(alea: random.Random, numero: int) -> tuple[list[_Message], tuple]:
    """Flux UDP à cadence fixe dans le sens aller (type média, 20 ms)."""
    client, serveur = _ip(numero % 4000 + 1, 1), _ip(numero % 250 + 1, 2)
    sport, dport = 10000 + 2 * alea.randrange(5000), 20000 + 2 * alea.randrange(5000)
    msgs = [
        _Message(
            True, 17, _datagramme_udp(client, serveur, sport, dport, alea.randbytes(172)), True, 20 * MS if i else 0
        )
        for i in range(alea.randint(5, 25))
    ]
    logger.debug("_messages_udp: retour tuple de 2")
    return msgs, (client, serveur)


# -- génération ---------------------------------------------------------------


def _bloc(type_bloc: int, corps: bytes) -> bytes:
    """Bloc pcapng (petit-boutiste), corps complété à 4 octets."""
    corps += bytes(-len(corps) % 4)
    total = 12 + len(corps)
    logger.debug("_bloc: retour struct.pack('<II', type_bloc, total) + corps + st…")
    return struct.pack("<II", type_bloc, total) + corps + struct.pack("<I", total)


def entete_pcapng(nom_point: str) -> bytes:
    """SHB + IDB Ethernet à résolution nanoseconde (if_tsresol = 9), nommé par le point."""
    logger.debug("entete_pcapng: entrée")
    shb = _bloc(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    nom = nom_point.encode("utf-8")
    options = struct.pack("<HH", 2, len(nom)) + nom + bytes(-len(nom) % 4)
    options += struct.pack("<HHB3x", 9, 1, 9) + struct.pack("<HH", 0, 0)
    idb = _bloc(0x1, struct.pack("<HHI", 1, 0, 262144) + options)
    logger.debug("entete_pcapng: retour")
    return shb + idb


def _epb(ts_ns: int, trame: bytes) -> bytes:
    """Enhanced Packet Block, horodatage en nanosecondes."""
    logger.debug("_epb: retour _bloc(…)")
    return _bloc(0x6, struct.pack("<IIIII", 0, ts_ns >> 32, ts_ns & 0xFFFFFFFF, len(trame), len(trame)) + trame)


class _Generateur:
    """État de la génération : aléa, tas par point, compteurs de vérité terrain."""

    def __init__(self, cfg: Configuration, dossier: Path):
        logger.debug("_Generateur.__init__: entrée")
        self.cfg = cfg
        self.alea = random.Random(cfg.graine)
        self.noms = [f"P{i + 1}" for i in range(cfg.points)]
        self.decalages_ns = [round(d * MS) for d in cfg.decalages_ms] or [0] * cfg.points
        self.chemins = [dossier / f"{nom}.pcapng" for nom in self.noms]
        self.fichiers = [open(chemin, "wb") for chemin in self.chemins]  # noqa: SIM115 (fermés par fermer())
        for fichier, nom in zip(self.fichiers, self.noms):
            fichier.write(entete_pcapng(nom))
        self.tas: list[list[tuple[int, int, bytes]]] = [[] for _ in self.noms]
        self.ordre = 0
        self.emis = 0
        self.vus = [0] * cfg.points
        self.perdus = 0
        self.perdus_par_type = dict.fromkeys(TYPES_FLUX, 0)
        self.flux_par_type = dict.fromkeys(TYPES_FLUX, 0)
        self.retardes = 0
        self.fin_ns = DEBUT_NS
        logger.debug("_Generateur.__init__: retour")

    def _delai(self, segment: int, ts_ns: int, fenetre: tuple[int, int]) -> int:
        """Délai de traversée du segment (base 1) pour un paquet entré à ``ts_ns``."""
        cfg = self.cfg
        base = cfg.delai_segment_ms * MS + self.alea.uniform(-cfg.gigue_ms, cfg.gigue_ms) * MS
        if segment == cfg.segment_retard and fenetre[0] <= ts_ns < fenetre[1]:
            base += cfg.retard_ms * MS
        logger.debug("_Generateur._delai: retour round(…)")
        return round(base)

    def _perdu(self, aller: bool) -> bool:
        """Tirage de perte pour un paquet perdable, dans le sens visé."""
        cfg = self.cfg
        if cfg.segment_perte is None or cfg.taux_perte <= 0:
            logger.debug("_Generateur._perdu: si cfg.segment_perte is None or cfg.taux_perte <= 0 -> retour False")
            return False
        if cfg.sens_perte != "les_deux" and (cfg.sens_perte == "aller") != aller:
            logger.debug(
                "_Generateur._perdu: si cfg.sens_perte != 'les_deux' and (cfg.sens_perte == 'aller'… -> retour False"
            )
            return False
        logger.debug("_Generateur._perdu: retour self.alea.random() < cfg.taux_perte")
        return self.alea.random() < cfg.taux_perte

    def emettre(self, type_flux: str, messages: list[_Message], hotes: tuple, debut_ns: int, fenetre) -> int:
        """Fait traverser le chemin aux paquets d'un flux ; renvoie la date de fin du flux."""
        client, serveur = hotes
        n = self.cfg.points
        t = debut_ns
        ident = self.alea.getrandbits(16)
        self.flux_par_type[type_flux] += 1
        for message in messages:
            if self.emis >= self.cfg.paquets:
                break
            t += message.pause_ns
            ident = (ident + 1) & 0xFFFF
            src, dst = (client, serveur) if message.aller else (serveur, client)
            ordre_points = range(n) if message.aller else range(n - 1, -1, -1)
            perte_ici = message.perdable and self._perdu(message.aller)
            segment_perdu = self.cfg.segment_perte if perte_ici else None
            ts, ttl = t, 64
            for rang, point in enumerate(ordre_points):
                if rang:
                    segment = point if message.aller else point + 1
                    if segment == segment_perdu:
                        break
                    ts += self._delai(segment, ts, fenetre)
                    ttl -= 1
                trame = _trame(message.aller, _entete_ip(src, dst, message.proto, ident, ttl, message.charge_l4))
                trame += message.charge_l4
                heapq.heappush(self.tas[point], (ts + self.decalages_ns[point], self.ordre, trame))
                self.ordre += 1
                self.vus[point] += 1
            if perte_ici:
                self.perdus += 1
                self.perdus_par_type[type_flux] += 1
            if self.cfg.segment_retard is not None and fenetre[0] <= t < fenetre[1]:
                self.retardes += 1
            self.emis += 1
            t = ts
        logger.debug("_Generateur.emettre: retour t={}", summarize(t, "t"))
        return t

    def vider(self, jusqu_a_ns: int | None) -> None:
        """Écrit, dans l'ordre chronologique, les paquets antérieurs à ``jusqu_a_ns`` (tous si None)."""
        for point, (tas, fichier) in enumerate(zip(self.tas, self.fichiers)):
            limite = None if jusqu_a_ns is None else jusqu_a_ns + self.decalages_ns[point]
            while tas and (limite is None or tas[0][0] < limite):
                ts, _ordre, trame = heapq.heappop(tas)
                fichier.write(_epb(ts, trame))
                self.fin_ns = max(self.fin_ns, ts - self.decalages_ns[point])
        logger.debug("_Generateur.vider: fin")

    def fermer(self) -> None:
        """Ferme les fichiers pcapng."""
        logger.debug("_Generateur.fermer: entrée")
        for fichier in self.fichiers:
            fichier.close()
        logger.debug("_Generateur.fermer: retour")


def _empreinte(chemin: Path) -> str:
    """SHA-256 d'un fichier, par blocs."""
    logger.debug("_empreinte: entrée")
    h = hashlib.sha256()
    with chemin.open("rb") as f:
        for bloc in iter(lambda: f.read(1 << 20), b""):
            h.update(bloc)
    logger.debug("_empreinte: retour")
    return h.hexdigest()


def generer(cfg: Configuration, dossier: str | Path) -> dict:
    """Écrit ``P1.pcapng`` … ``PN.pcapng`` et ``verite.json`` dans ``dossier``.

    Renvoie la vérité terrain (le contenu de ``verite.json``).
    """
    logger.debug("generer: entrée")
    cfg.valider()
    dossier = Path(dossier)
    dossier.mkdir(parents=True, exist_ok=True)
    gen = _Generateur(cfg, dossier)
    types = sorted(cfg.melange)
    poids = [cfg.melange[t] for t in types]
    duree_estimee = cfg.paquets * NS // cfg.debit_pps
    fenetre = (DEBUT_NS + duree_estimee // 3, DEBUT_NS + 2 * duree_estimee // 3)
    intervalle_moyen = max(1, NS * 8 // cfg.debit_pps)
    debut = DEBUT_NS
    numero = 0
    try:
        while gen.emis < cfg.paquets:
            type_flux = gen.alea.choices(types, poids)[0]
            if type_flux in ("tcp", "tls"):
                messages, hotes = _messages_tcp(gen.alea, numero, type_flux == "tls")
            elif type_flux == "dns":
                messages, hotes = _messages_dns(gen.alea, numero)
            else:
                messages, hotes = _messages_udp(gen.alea, numero)
            gen.vider(debut)
            gen.emettre(type_flux, messages, hotes, debut, fenetre)
            numero += 1
            debut += 1 + int(gen.alea.expovariate(1.0) * intervalle_moyen)
        gen.vider(None)
    finally:
        gen.fermer()
    verite = {
        "format": 1,
        "configuration": asdict(cfg),
        "points": gen.noms,
        "segments": [
            {"numero": k, "de": gen.noms[k - 1], "vers": gen.noms[k], "delai_base_ms": cfg.delai_segment_ms}
            for k in range(1, cfg.points)
        ],
        "debut_ns": DEBUT_NS,
        "fin_ns": gen.fin_ns,
        "paquets_emis": gen.emis,
        "paquets_par_point": dict(zip(gen.noms, gen.vus)),
        "flux_par_type": gen.flux_par_type,
        "perte": {
            "segment": cfg.segment_perte,
            "sens": cfg.sens_perte,
            "taux": cfg.taux_perte,
            "paquets_perdus": gen.perdus,
            "par_type": gen.perdus_par_type,
        },
        "retard": {
            "segment": cfg.segment_retard,
            "retard_ms": cfg.retard_ms,
            "fenetre_ns": list(fenetre) if cfg.segment_retard is not None else None,
            "paquets_concernes": gen.retardes,
        },
        "decalages_horloge_ms": dict(zip(gen.noms, [d / MS for d in gen.decalages_ns])),
        "fichiers": {chemin.name: _empreinte(chemin) for chemin in gen.chemins},
    }
    (dossier / "verite.json").write_text(json.dumps(verite, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    logger.info("jeu synthétique : {} points, {} paquets émis, {} perdus", cfg.points, gen.emis, gen.perdus)
    logger.debug("generer: retour")
    return verite


# -- ligne de commande --------------------------------------------------------


def _nom_jeu(points: int, paquets: int, graine: int) -> str:
    """Nom de dossier stable d'un jeu : ``p3-n100000-g1``."""
    logger.debug("_nom_jeu: retour chaîne formatée")
    return f"p{points}-n{paquets}-g{graine}"


def _liste_entiers(texte: str) -> list[int]:
    """``"2,3,5"`` → ``[2, 3, 5]`` (argparse)."""
    logger.debug("_liste_entiers: retour liste")
    return [int(x) for x in texte.split(",") if x.strip()]


def _liste_reels(texte: str) -> list[float]:
    """``"0,1.5,-2"`` → ``[0.0, 1.5, -2.0]`` (argparse)."""
    logger.debug("_liste_reels: retour liste")
    return [float(x) for x in texte.split(",") if x.strip()]


def construire_parseur():
    """Analyseur d'arguments de ``scripts/bench_datasets.py``."""
    logger.debug("construire_parseur: entrée")
    p = argparse.ArgumentParser(
        prog="bench_datasets.py",
        description="Génère des jeux pcapng multi-points déterministes avec leur vérité terrain (issue #1015).",
    )
    p.add_argument("--sortie", required=True, help="dossier de destination")
    p.add_argument("--points", type=int, default=2, help="nombre de points de capture (défaut 2)")
    p.add_argument("--paquets", type=int, default=10_000, help="paquets émis par le client et le serveur")
    p.add_argument("--graine", type=int, default=1, help="graine de l'aléa (défaut 1)")
    p.add_argument("--debit-pps", type=int, default=2_000, help="débit moyen visé en paquets/s")
    p.add_argument("--delai-segment-ms", type=float, default=1.0, help="délai de base par segment")
    p.add_argument("--gigue-ms", type=float, default=0.1, help="gigue uniforme ± par segment")
    p.add_argument("--segment-perte", type=int, help="segment (base 1) où injecter des pertes")
    p.add_argument("--taux-perte", type=float, default=0.0, help="probabilité de perte d'un paquet perdable")
    p.add_argument("--sens-perte", choices=SENS, default="aller")
    p.add_argument("--segment-retard", type=int, help="segment (base 1) où injecter un retard")
    p.add_argument("--retard-ms", type=float, default=0.0, help="retard ajouté sur le tiers central du jeu")
    p.add_argument("--decalages-ms", type=_liste_reels, default=[], help="décalage d'horloge par point, ex. 0,3.5")
    p.add_argument(
        "--matrice",
        action="store_true",
        help="génère la matrice standard (points 2,3,5,10 x paquets 10⁴,10⁵,10⁶) dans un sous-dossier par jeu",
    )
    p.add_argument("--matrice-points", type=_liste_entiers, default=list(POINTS_STANDARD))
    p.add_argument("--matrice-paquets", type=_liste_entiers, default=list(TAILLES_STANDARD))
    logger.debug("construire_parseur: retour")
    return p


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée ; code 0 si tout est écrit, 2 sur paramètre invalide."""
    logger.debug("main: entrée")
    args = construire_parseur().parse_args(argv)
    commun = {
        "graine": args.graine,
        "debit_pps": args.debit_pps,
        "delai_segment_ms": args.delai_segment_ms,
        "gigue_ms": args.gigue_ms,
        "segment_perte": args.segment_perte,
        "taux_perte": args.taux_perte,
        "sens_perte": args.sens_perte,
        "segment_retard": args.segment_retard,
        "retard_ms": args.retard_ms,
        "decalages_ms": args.decalages_ms,
    }
    sortie = Path(args.sortie)
    if args.matrice:
        jeux = [(n, k) for n in args.matrice_points for k in args.matrice_paquets]
    else:
        jeux = [(args.points, args.paquets)]
    try:
        for points, paquets in jeux:
            dossier = sortie / _nom_jeu(points, paquets, args.graine) if args.matrice else sortie
            verite = generer(Configuration(points=points, paquets=paquets, **commun), dossier)
            print(f"{dossier} : {verite['paquets_emis']} paquets, {verite['perte']['paquets_perdus']} perdus")
    except ValueError as exc:
        logger.warning("bench_datasets : {}", exc)
        print(f"erreur : {exc}")
        logger.debug("main: retour 2 (paramètre invalide)")
        return 2
    logger.debug("main: retour 0")
    return 0
