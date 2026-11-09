# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.rtp_match -- appariement des flux RTP entre points de capture
(issue #1121, sous-issue 2/6 du chantier #1004).

``analysis._analyse_rtp`` regroupe les paquets RTP par 5-tuple et SSRC : un
flux qui traverse un NAT ou un SBC (ports, adresses, voire SSRC, numeros de
sequence et horodatages reecrits) y apparait comme plusieurs flux
independants, un par point. Ce module reconnait ces « jambes » comme un seul
flux, sans jamais se fier aux adresses ni aux ports.

Une jambe est la suite des paquets RTP d'un point pour un 5-tuple et un SSRC.
Deux jambes de points differents, qui se recouvrent dans le temps (a
``window_seconds`` pres), sont appariees :

1. ``ssrc`` : meme SSRC, et au moins la moitie des couples
   (numero de sequence, horodatage RTP) de la plus courte se retrouvent dans
   l'autre. C'est le cas d'un NAT, d'un routeur ou d'un SBC qui relaie le
   media sans le reecrire, meme si adresses et ports changent ;
2. ``ssrc_rewritten`` : SSRC different mais memes couples
   (sequence, horodatage) : SBC qui ne reecrit que le SSRC ;
3. ``sbc_offset`` : SSRC, sequence et horodatage reecrits avec un decalage
   constant (SBC qui re-emet le media). Le decalage le plus frequent entre
   les premiers paquets des deux jambes est retenu, puis verifie sur tout
   l'echantillon : au moins la moitie des paquets de la plus courte jambe,
   et au moins ``MIN_COMMON`` paquets, doivent coincider une fois decales.

Le contenu audio n'est pas compare. Une jambe n'appartient qu'a un
seul flux, et un flux n'a qu'une jambe par point : en cas de concurrence, la
paire au meilleur score l'emporte.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

SEQ_MOD = 1 << 16
TS_MOD = 1 << 32
MIN_COMMON = 5
OFFSET_PROBE = 24
DEFAULT_WINDOW_SECONDS = 5.0


@dataclass
class _Leg:
    """Jambe RTP : paquets d'un point pour un 5-tuple et un SSRC."""

    point: str
    src: str
    sport: int | None
    dst: str
    dport: int | None
    ssrc: int | None
    first_ts: float
    last_ts: float
    packets: int
    pairs: list[tuple[int, int]]  # (sequence, horodatage RTP), ordre d'arrivee
    arrivals: list[float]  # instant de capture de chaque couple

    @property
    def sample(self) -> set[tuple[int, int]]:
        logger.debug("_Leg.sample: retour set")
        return set(self.pairs)

    def around(self, ts: float, window: float) -> list[tuple[int, int]]:
        """Couples captures a ``window`` secondes de ``ts`` (au plus le double de ``OFFSET_PROBE``)."""
        logger.debug("_Leg.around: entrée")
        proches = [p for p, t in zip(self.pairs, self.arrivals, strict=True) if abs(t - ts) <= window]
        logger.debug("_Leg.around: retour {} couple(s)", len(proches))
        return proches[: 2 * OFFSET_PROBE]

    def endpoint(self) -> tuple:
        logger.debug("_Leg.endpoint: retour tuple")
        return (self.src, self.sport, self.dst, self.dport)

    def to_dict(self, seq_offset: int = 0, ts_offset: int = 0) -> dict:
        logger.debug("_Leg.to_dict: retour dict")
        return {
            "point": self.point,
            "src": self.src,
            "sport": self.sport,
            "dst": self.dst,
            "dport": self.dport,
            "ssrc": self.ssrc,
            "packets": self.packets,
            "first_ts": self.first_ts,
            "seq_offset": seq_offset,
            "ts_offset": ts_offset,
        }


def _legs(all_packets) -> list[_Leg]:
    """Jambes RTP, triees par premier paquet."""
    logger.debug("_legs: entrée")
    paquets: dict[tuple, list] = defaultdict(list)
    for pk in all_packets:
        if pk.proto == "UDP" and pk.is_rtp and pk.rtp_seq is not None and pk.rtp_ts is not None:
            paquets[(pk.point, pk.src, pk.sport, pk.dst, pk.dport, pk.rtp_ssrc)].append(pk)
    legs = []
    for (point, src, sport, dst, dport, ssrc), pkts in paquets.items():
        pkts.sort(key=lambda x: x.ts)
        legs.append(
            _Leg(
                point=point,
                src=src,
                sport=sport,
                dst=dst,
                dport=dport,
                ssrc=ssrc,
                first_ts=pkts[0].ts,
                last_ts=pkts[-1].ts,
                packets=len(pkts),
                pairs=[(x.rtp_seq, x.rtp_ts) for x in pkts],
                arrivals=[x.ts for x in pkts],
            )
        )
    legs.sort(key=lambda leg: (leg.first_ts, leg.point))
    logger.debug("_legs: retour {} jambe(s)", len(legs))
    return legs


def _shift(pairs, seq_offset: int, ts_offset: int) -> set[tuple[int, int]]:
    logger.debug("_shift: retour set")
    return {((s + seq_offset) % SEQ_MOD, (t + ts_offset) % TS_MOD) for s, t in pairs}


def _required(a: _Leg, b: _Leg) -> int:
    """Nombre de paquets communs exige : la moitie de la plus courte jambe,
    au moins ``MIN_COMMON`` (ou toute la jambe si elle est plus courte)."""
    logger.debug("_required: entrée")
    plus_courte = min(len(a.pairs), len(b.pairs))
    exige = max((plus_courte + 1) // 2, min(MIN_COMMON, plus_courte))
    logger.debug("_required: retour {}", exige)
    return exige


def _match(a: _Leg, b: _Leg, window: float) -> tuple[str, int, int, int] | None:
    """(methode, paquets communs, decalage de sequence, decalage d'horodatage)
    pour passer de ``a`` a ``b``, ou None si les jambes ne coincident pas."""
    logger.debug("_match: entrée ({} / {})", a.point, b.point)
    exige = _required(a, b)
    communs = len(a.sample & b.sample)
    if communs >= exige:
        methode = "ssrc" if a.ssrc == b.ssrc else "ssrc_rewritten"
        logger.debug("_match: si couples identiques -> retour {}", methode)
        return methode, communs, 0, 0
    decalages = Counter(
        ((sb - sa) % SEQ_MOD, (tb - ta) % TS_MOD)
        for sa, ta in a.around(b.first_ts, window)
        for sb, tb in b.pairs[:OFFSET_PROBE]
    )
    for (dseq, dts), _n in decalages.most_common(3):
        communs = len(_shift(a.pairs, dseq, dts) & b.sample)
        if communs >= max(exige, MIN_COMMON):
            logger.debug("_match: si decalage constant -> retour sbc_offset")
            return "sbc_offset", communs, dseq, dts
    logger.debug("_match: retour None")
    return None


def _lost(amont: _Leg, aval: _Leg, dseq: int, dts: int) -> int:
    """Paquets vus en amont et absents en aval, entre le premier et le dernier
    paquet commun (un paquet capture avant le debut ou apres la fin de la
    capture aval n'est pas une perte)."""
    logger.debug("_lost: entrée ({} -> {})", amont.point, aval.point)
    vus_aval = aval.sample
    decales = [((sq + dseq) % SEQ_MOD, (t + dts) % TS_MOD) for sq, t in amont.pairs]
    communs = [n for n, p in enumerate(decales) if p in vus_aval]
    if not communs:
        logger.debug("_lost: si aucun paquet commun -> retour 0")
        return 0
    manquants = sum(1 for p in decales[communs[0] : communs[-1] + 1] if p not in vus_aval)
    logger.debug("_lost: retour {}", manquants)
    return manquants


def _overlap(a: _Leg, b: _Leg, window: float) -> bool:
    logger.debug("_overlap: retour bool")
    return a.first_ts - window <= b.last_ts and b.first_ts - window <= a.last_ts


def match_rtp_streams(all_packets, points=None, window_seconds: float = DEFAULT_WINDOW_SECONDS) -> list[dict]:
    """Flux RTP vus a au moins deux points, jambes appariees.

    ``points`` : ordre du chemin (``--order``) ; les jambes et les pertes
    entre jambes consecutives suivent cet ordre, sinon celui du premier
    paquet. Chaque flux expose sa ``method`` (``ssrc``, ``ssrc_rewritten``,
    ``sbc_offset`` ou ``mixed``), ``nat_rewritten`` (adresses ou ports
    differents entre points) et ``lost_between`` (paquets de l'echantillon
    vus a une jambe et absents de la suivante).
    """
    logger.debug("match_rtp_streams: entrée")
    legs = _legs(all_packets)
    candidats = []
    for i, a in enumerate(legs):
        for j in range(i + 1, len(legs)):
            b = legs[j]
            if b.first_ts - window_seconds > a.last_ts:
                break
            if a.point == b.point or not _overlap(a, b, window_seconds):
                continue
            m = _match(a, b, window_seconds)
            if m is not None:
                methode, communs, dseq, dts = m
                rang = {"ssrc": 0, "ssrc_rewritten": 1, "sbc_offset": 2}[methode]
                candidats.append((-communs, rang, i, j, methode, dseq, dts))
    candidats.sort()

    groupe_de = list(range(len(legs)))
    membres: dict[int, dict[int, tuple[int, int, str]]] = {i: {i: (0, 0, "")} for i in range(len(legs))}

    for _c, _r, i, j, methode, dseq, dts in candidats:
        gi, gj = groupe_de[i], groupe_de[j]
        if gi == gj:
            continue
        points_i = {legs[k].point for k in membres[gi]}
        if points_i & {legs[k].point for k in membres[gj]}:
            continue
        # decalages exprimes par rapport a la premiere jambe du groupe gi
        oi_seq, oi_ts, _ = membres[gi][i]
        oj_seq, oj_ts, _ = membres[gj][j]
        base_seq = (oi_seq + dseq - oj_seq) % SEQ_MOD
        base_ts = (oi_ts + dts - oj_ts) % TS_MOD
        for k, (s, t, meth) in membres.pop(gj).items():
            membres[gi][k] = ((s + base_seq) % SEQ_MOD, (t + base_ts) % TS_MOD, meth or methode)
            groupe_de[k] = gi
        membres[gi][i] = (oi_seq, oi_ts, membres[gi][i][2] or methode)

    ordre = {p: n for n, p in enumerate(points or [])}
    flux = []
    for _g, contenu in sorted(membres.items()):
        if len(contenu) < 2:
            continue
        cles = sorted(contenu, key=lambda k: (ordre.get(legs[k].point, len(ordre)), legs[k].first_ts))
        methodes = {contenu[k][2] for k in cles if contenu[k][2]}
        jambes = [legs[k].to_dict(contenu[k][0], contenu[k][1]) for k in cles]
        pertes = {}
        for k1, k2 in zip(cles, cles[1:], strict=False):
            s1, t1, _ = contenu[k1]
            s2, t2, _ = contenu[k2]
            pertes[f"{legs[k1].point} -> {legs[k2].point}"] = _lost(
                legs[k1], legs[k2], (s2 - s1) % SEQ_MOD, (t2 - t1) % TS_MOD
            )
        premiere = legs[cles[0]]
        flux.append(
            {
                "label": f"{premiere.src}:{premiere.sport} -> {premiere.dst}:{premiere.dport} "
                f"(SSRC=0x{(premiere.ssrc or 0):08x})",
                "method": methodes.pop() if len(methodes) == 1 else "mixed",
                "nat_rewritten": len({legs[k].endpoint() for k in cles}) > 1,
                "legs": jambes,
                "lost_between": pertes,
            }
        )
    logger.debug("match_rtp_streams: retour {} flux apparie(s) sur {} jambe(s)", len(flux), len(legs))
    return flux
