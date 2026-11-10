# SPDX-License-Identifier: GPL-3.0-or-later
"""Extraction des pcap de preuve par constat (issue #1081, sous-issue 5/6 du
chantier #1000).

Pour chaque constat du rapport et chaque point de capture cite en preuve,
ce module ecrit un pcapng minimal contenant les seules trames utiles : la
trame de preuve, plus ``contexte`` trames avant et apres (meme fenetre que
le contexte du diagramme de preuve -- ``evidence_frames``). La trame de
preuve porte un commentaire de paquet pcapng indiquant le constat :
l'extrait se lit donc seul, sans le rapport a cote.

Cadrage binaire uniquement, aucune dissection : les blocs pcapng (ou les
enregistrements pcap) sont copies tels quels du fichier source, seul le
commentaire est ajoute -- meme regle que ``pcap_parser.capfile`` (le role
de tshark n'est pas remis en cause). Un fichier pcap classique est
converti en pcapng au passage, horodatage ramene a la microseconde (la
resolution nanoseconde est perdue, l'ordre et les voisins restent exacts).
Les trames citees en preuve mais absentes du fichier (numero inconnu)
sont journalisees, jamais inventees.

Fichiers produits : ``constat-<n>-<point>.pcapng`` (``n`` = rang du constat
dans le rapport, point slugifie), un par constat ET par point. Le HTML
reference ces extraits par des liens relatifs (cle ``evidence_pcaps`` du
rapport JSON : ``ref``/``point``/``frame_number``/``fichier``).
"""

from __future__ import annotations

import os
import re
import struct
from collections.abc import Iterable, Iterator, Mapping, Sequence

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

CONTEXTE_DEFAUT = 3
"""Fenetre de part et d'autre de la trame de preuve (meme valeur par
defaut que le contexte du diagramme de preuve, ``evidence_frames``)."""

_SEPARATEUR_SEGMENT = " -> "
_SLUG_RE = re.compile(r"[^A-Za-z0-9_.-]+")

# -- cadrage binaire pcap / pcapng (meme esprit que pcap_parser.capfile) ------
_MAGIC_PCAP = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),  # microsecondes, petit-boutiste
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),  # nanosecondes, petit-boutiste
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
_MAGIC_PCAPNG = b"\x0a\x0d\x0d\x0a"
_BOM_LE = b"\x4d\x3c\x2b\x1a"

_BLOC_IDB = 0x00000001
_BLOC_PB = 0x00000002
_BLOC_SPB = 0x00000003
_BLOC_EPB = 0x00000006
_BLOC_SHB = 0x0A0D0D0A
_BLOCS_PAQUET = frozenset({_BLOC_PB, _BLOC_SPB, _BLOC_EPB})

_OPT_COMMENTAIRE = 1
_OPT_FIN = 0
_OPT_TSRESOL = 9


def _slug(texte: str) -> str:
    """Caracteres sûrs pour un nom de fichier (comme l'ancre de preuve)."""
    logger.debug("_slug: entrée")
    slug = _SLUG_RE.sub("_", texte).strip("._-") or "point"
    logger.debug("_slug: retour {}", slug)
    return slug


def _point_capture(point: str) -> str:
    """Point dont la capture porte la trame : une preuve de segment
    ``A -> B`` designe une trame du point amont (meme regle que
    ``netcross_report.evidence_frames.capture_point``, dupliquee ici car
    netcross_core n'importe jamais netcross_report)."""
    logger.debug("_point_capture: entrée")
    amont = point.split(_SEPARATEUR_SEGMENT)[0] if _SEPARATEUR_SEGMENT in point else point
    logger.debug("_point_capture: retour {}", amont)
    return amont


def _micros(brut_ts: int, tsresol: float) -> int:
    """Horodatage pcapng (unites de ``tsresol`` secondes) en microsecondes."""
    logger.debug("_micros: entrée")
    micros = round(brut_ts * tsresol * 1e6)
    logger.debug("_micros: retour {}", micros)
    return micros


def _tsresol(options: bytes) -> float:
    """Resolution d'un IDB : option ``if_tsresol`` (u8), 1e-6 par defaut.
    Valeur 0-9 : 10^-valeur ; 10-255 : 2^(valeur-10) (spec pcapng)."""
    logger.debug("_tsresol: entrée")
    resolution = 1e-6
    for code, valeur in _options(options):
        if code == _OPT_TSRESOL and valeur:
            octet = valeur[0]
            resolution = 10.0 ** (-octet) if octet <= 9 else 2.0 ** (octet - 10)
    logger.debug("_tsresol: retour {}", resolution)
    return resolution


def _options(brut: bytes) -> Iterator[tuple[int, bytes]]:
    """Options pcapng ``(code, valeur)`` jusqu'a endofopt."""
    logger.debug("_options: entrée")
    pos = 0
    while pos + 4 <= len(brut):
        code, longueur = struct.unpack_from("<HH", brut, pos)
        pos += 4
        if code == _OPT_FIN:
            break
        yield code, brut[pos : pos + longueur]
        pos += longueur + (-longueur % 4)
    logger.debug("_options: fin")


def _options_brutes(options: Sequence[tuple[int, bytes]]) -> bytes:
    """Options pcapng re-empaquetees (petit-boutiste), endofopt final."""
    logger.debug("_options_brutes: entrée")
    brut = b""
    for code, valeur in options:
        brut += struct.pack("<HH", code, len(valeur)) + valeur + b"\x00" * (-len(valeur) % 4)
    logger.debug("_options_brutes: retour {} octet(s)", len(brut))
    return brut + b"\x00\x00\x00\x00"


def _epb(if_id: int, micros: int, donnees: bytes, options: bytes) -> bytes:
    """Bloc Enhanced Packet petit-boutiste : interface, horodatage en
    microsecondes, donnees et options recopies telles quelles."""
    logger.debug("_epb: entrée")
    ts_haut, ts_bas = micros >> 32, micros & 0xFFFFFFFF
    corps = struct.pack("<IIII", if_id, ts_haut, ts_bas, len(donnees)) + donnees + options
    bourrage = -len(corps) % 4
    total = 8 + len(corps) + bourrage + 4
    epb = struct.pack("<II", _BLOC_EPB, total) + corps + b"\x00" * bourrage + struct.pack("<I", total)
    logger.debug("_epb: retour {} octet(s)", len(epb))
    return epb


def _avec_commentaire(bloc: bytes, texte: str) -> bytes:
    """EPB avec l'option commentaire (code 1) ajoutee/remplacee : le
    commentaire de paquet indique le constat. Les autres options sont
    conservees."""
    logger.debug("_avec_commentaire: entrée")
    _type, _total = struct.unpack_from("<II", bloc, 0)
    corps = bloc[8:-4]
    if_id, ts_haut, ts_bas, caplen = struct.unpack_from("<IIII", corps, 0)
    donnees = corps[16 : 16 + caplen]
    conservees = [(code, valeur) for code, valeur in _options(corps[16 + caplen :]) if code != _OPT_COMMENTAIRE]
    option = (_OPT_COMMENTAIRE, texte.encode("utf-8"))
    epb = _epb(if_id, ts_haut * (1 << 32) + ts_bas, donnees, _options_brutes([option, *conservees]))
    logger.debug("_avec_commentaire: retour {} octet(s)", len(epb))
    return epb


def _epb_depuis_eb(bloc: bytes, endian: str, tsresol: float) -> bytes:
    """Bloc EPB petit-boutiste depuis un EPB pcapng (horodatage converti en
    microsecondes, options conservees)."""
    logger.debug("_epb_depuis_eb: entrée")
    _type, _total = struct.unpack_from(endian + "II", bloc, 0)
    corps = bloc[8:-4]
    if_id, ts_haut, ts_bas, caplen = struct.unpack_from(endian + "IIII", corps, 0)
    donnees = corps[16 : 16 + caplen]
    options = _options_brutes([(code, valeur) for code, valeur in _options(corps[16 + caplen :])])
    epb = _epb(if_id, _micros(ts_haut * (1 << 32) + ts_bas, tsresol), donnees, options)
    logger.debug("_epb_depuis_eb: retour {} octet(s)", len(epb))
    return epb


def _epb_depuis_pb(bloc: bytes, endian: str, tsresol: float) -> bytes:
    """Bloc EPB depuis un Packet Block obsolète : interface u16, drops u16,
    horodatage u64, longueurs u32 -- meme conversion d'unite."""
    logger.debug("_epb_depuis_pb: entrée")
    _type, _total = struct.unpack_from(endian + "II", bloc, 0)
    corps = bloc[8:-4]
    if_id, _drops, ts_haut, ts_bas, caplen = struct.unpack_from(endian + "HHIII", corps, 0)
    donnees = corps[20 : 20 + caplen]
    epb = _epb(if_id, _micros(ts_haut * (1 << 32) + ts_bas, tsresol), donnees, b"")
    logger.debug("_epb_depuis_pb: retour {} octet(s)", len(epb))
    return epb


def _epb_depuis_spb(bloc: bytes, endian: str) -> bytes:
    """Bloc EPB depuis un Simple Packet Block : longueur d'origine u32 (bit
    31 = longueur aberrante, masque), pas d'horodatage."""
    logger.debug("_epb_depuis_spb: entrée")
    _type, _total = struct.unpack_from(endian + "II", bloc, 0)
    corps = bloc[8:-4]
    caplen = struct.unpack_from(endian + "I", corps, 0)[0] & 0x7FFFFFFF
    donnees = corps[4 : 4 + caplen]
    epb = _epb(0, 0, donnees, b"")
    logger.debug("_epb_depuis_spb: retour {} octet(s)", len(epb))
    return epb


def _bloc_shb() -> bytes:
    """Section Header Block petit-boutiste (section unique, longueur de
    section inconnue)."""
    corps = _BOM_LE + struct.pack("<HH", 1, 0) + struct.pack("<Q", 0xFFFFFFFFFFFFFFFF) + b"\x00\x00\x00\x00"
    total = 8 + len(corps) + 4
    logger.debug("_bloc_shb: retour bloc")
    return struct.pack("<II", _BLOC_SHB, total) + corps + struct.pack("<I", total)


def _bloc_idb(linktype: int, snaplen: int = 262144) -> bytes:
    """Interface Description Block petit-boutiste, sans option (resolution
    par defaut : microsecondes)."""
    corps = struct.pack("<HHI", linktype & 0xFFFF, 0, snaplen) + b"\x00\x00\x00\x00"
    total = 8 + len(corps) + 4
    logger.debug("_bloc_idb: retour bloc")
    return struct.pack("<II", _BLOC_IDB, total) + corps + struct.pack("<I", total)


def _paquets_pcapng(fichier, numeros: set[int]) -> tuple[int | None, float, dict[int, bytes]]:
    """Parcours des blocs pcapng : linktype et resolution du premier IDB,
    EPB petit-boutiste pour chaque numero demande."""
    logger.debug("_paquets_pcapng: entrée")
    endian = "<"
    linktype: int | None = None
    tsresol = 1e-6
    blocs: dict[int, bytes] = {}
    numero = 0
    while True:
        entete = fichier.read(8)
        if len(entete) < 8:
            break
        if entete[:4] == _MAGIC_PCAPNG:
            bom = fichier.read(4)
            if len(bom) < 4:
                break
            endian = "<" if bom == _BOM_LE else ">"
            entete += bom
        type_bloc, total = struct.unpack_from(endian + "II", entete, 0)
        if total < len(entete) + 4 or total % 4:
            logger.debug("_paquets_pcapng: bloc de longueur invalide, arret")
            break  # fichier corrompu : extrait partiel assumé
        reste = fichier.read(total - len(entete))
        if len(reste) < total - len(entete):
            break
        bloc = entete + reste
        if type_bloc == _BLOC_IDB and linktype is None:
            linktype = struct.unpack_from(endian + "H", bloc, 8)[0]
            tsresol = _tsresol(bloc[16:-4])
        elif type_bloc in _BLOCS_PAQUET:
            numero += 1
            if numero not in numeros:
                continue
            if type_bloc == _BLOC_EPB:
                blocs[numero] = _epb_depuis_eb(bloc, endian, tsresol)
            elif type_bloc == _BLOC_PB:
                blocs[numero] = _epb_depuis_pb(bloc, endian, tsresol)
            else:
                blocs[numero] = _epb_depuis_spb(bloc, endian)
    logger.debug("_paquets_pcapng: retour {} bloc(s)", len(blocs))
    return linktype, tsresol, blocs


def _paquets_pcap(fichier, endian: str, resolution: float, numeros: set[int]) -> dict[int, bytes]:
    """Enregistrements pcap en EPB : horodatage en microsecondes (les
    nanosecondes sont arrondies), donnees recopies telles quelles."""
    logger.debug("_paquets_pcap: entrée")
    blocs: dict[int, bytes] = {}
    numero = 0
    while True:
        entete = fichier.read(16)
        if len(entete) < 16:
            break
        numero += 1
        sec, frac, incl_len, _orig = struct.unpack(endian + "IIII", entete)
        donnees = fichier.read(incl_len)
        if len(donnees) < incl_len:
            break
        if numero in numeros:
            micros = round((sec + frac * resolution) * 1e6)
            blocs[numero] = _epb(0, micros, donnees, b"")
    logger.debug("_paquets_pcap: retour {} bloc(s)", len(blocs))
    return blocs


def _lire(chemin: str, numeros: set[int]) -> tuple[int | None, dict[int, bytes]]:
    """Lit un fichier pcap/pcapng et renvoie ``(linktype, {numero: bloc
    EPB})`` pour les numeros demandes. Format non reconnu : aucun bloc
    (l'appelant signale l'absence, rien n'est invente)."""
    logger.debug("_lire: {} numero(s) demande(s) dans {}", len(numeros), chemin)
    linktype: int | None = None
    blocs: dict[int, bytes] = {}
    with open(chemin, "rb") as fichier:
        magic = fichier.read(4)
        if magic == _MAGIC_PCAPNG:
            fichier.seek(0)
            linktype, _tsresol, blocs = _paquets_pcapng(fichier, numeros)
        elif magic in _MAGIC_PCAP:
            endian, resolution = _MAGIC_PCAP[magic]
            fichier.seek(0)
            linktype = struct.unpack_from(endian + "I", fichier.read(24), 20)[0] & 0xFFFF
            blocs = _paquets_pcap(fichier, endian, resolution, numeros)
    logger.debug("_lire: retour {} bloc(s)", len(blocs))
    return linktype, blocs


def _references(constat) -> list[tuple[str, int]]:
    """Preuves d'un constat : ``(point, numero de trame)``. Accepte un dict
    JSON (``evidence``) ou un Finding (``evidence`` d'EvidenceLink)."""
    logger.debug("_references: entrée")
    refs: list[tuple[str, int]] = []
    evidence = constat.get("evidence") if isinstance(constat, dict) else getattr(constat, "evidence", None)
    for e in evidence or []:
        if isinstance(e, dict):
            point, numero = e.get("point"), e.get("frame_number")
        else:
            point = getattr(e, "point", None)
            paquet = getattr(e, "packet", None)
            numero = getattr(paquet, "frame_number", None) if paquet is not None else None
        if point and numero is not None:
            refs.append((_point_capture(point), int(numero)))
    logger.debug("_references: retour {} preuve(s)", len(refs))
    return refs


def _texte_constat(constat) -> str:
    """Commentaire de paquet : identite du constat, tronquee a 240 octets."""
    logger.debug("_texte_constat: entrée")

    def champ(nom: str) -> object:
        valeur = constat.get(nom) if isinstance(constat, dict) else getattr(constat, nom, None)
        logger.debug("_texte_constat.champ: retour {}", nom)
        return valeur

    morceaux = [str(champ("severity") or ""), str(champ("category") or ""), str(champ("message") or "")]
    logger.debug("_texte_constat: retour")
    return ("Constat : " + " / ".join(m for m in morceaux if m))[:240]


def extraire_preuves_pcaps(
    captures: Mapping[str, str] | Sequence[tuple[str, str]],
    constats: Iterable,
    dossier: str,
    contexte: int = CONTEXTE_DEFAUT,
) -> list[dict]:
    """Ecrit un pcapng par constat et par point de preuve dans ``dossier``
    et renvoie les references pour le rapport (cle ``evidence_pcaps``) :
    une entree par preuve, ``fichier`` relatif au dossier.

    ``captures`` : point -> chemin du fichier de capture (dict ou paires).
    ``constats`` : findings (dicts JSON ou Finding). Seules les preuves dont
    le point a un fichier lisible sont extraites : une preuve sans fichier
    source reste sans extrait (jamais inventee), journalisee en debug.
    """
    logger.debug("extraire_preuves_pcaps: entrée (contexte={})", contexte)
    fichiers: Mapping[str, str] = dict(captures)
    os.makedirs(dossier, exist_ok=True)
    # par point : numeros de trames a lire ; par constat : preuves regroupees
    demandes: dict[str, set[int]] = {}
    regroupes: list[tuple[int, list[tuple[str, int]], str]] = []
    for rang, constat in enumerate(constats, 1):
        refs = _references(constat)
        if not refs:
            continue
        regroupes.append((rang, refs, _texte_constat(constat)))
        for point, numero in refs:
            demandes.setdefault(point, set()).update(range(max(1, numero - contexte), numero + contexte + 1))
    lus: dict[str, tuple[int | None, dict[int, bytes]]] = {}
    for point in sorted(demandes):
        chemin = fichiers.get(point)
        if chemin and os.path.isfile(chemin):
            lus[point] = _lire(chemin, demandes[point])
    extraits: list[dict] = []
    for rang, refs, texte in regroupes:
        par_point: dict[str, list[int]] = {}
        for point, numero in refs:
            par_point.setdefault(point, []).append(numero)
        for point, numeros in par_point.items():
            if point not in lus:
                continue
            _linktype, blocs = lus[point]
            contenu = [_bloc_shb(), _bloc_idb(_linktype if _linktype is not None else 1)]
            voulues: set[int] = set()
            for numero in numeros:
                if numero in blocs:
                    voulues.update(range(max(1, numero - contexte), numero + contexte + 1))
            for numero in sorted(voulues & set(blocs)):
                bloc = blocs[numero]
                if numero in numeros:
                    bloc = _avec_commentaire(bloc, texte)
                contenu.append(bloc)
            if len(contenu) > 2:
                nom = f"constat-{rang:03d}-{_slug(point)}.pcapng"
                with open(os.path.join(dossier, nom), "wb") as sortie:
                    sortie.writelines(contenu)
                extraits.extend(
                    {
                        "ref": f"{point}#{numero}",
                        "point": point,
                        "frame_number": numero,
                        "fichier": nom,
                    }
                    for numero in numeros
                    if numero in blocs
                )
    logger.debug("extraire_preuves_pcaps: retour {} extrait(s)", len(extraits))
    return extraits
