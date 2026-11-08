"""Analyse VoIP orientee appel, association SIP/RTP par SDP.

Cette couche fusionne les informations SIP et RTP deja extraites par le
parseur. Un flux RTP est d'abord rattache par SDP (issue #1120) : l'appel
dont l'offre ou la reponse annonce, en ``c=``/``m=``, le point de reception
du flux (adresse et port de destination). A defaut, il est rattache a
l'appel dont la fenetre temporelle contient son premier paquet. La methode
retenue est toujours exposee (``correlation_method`` par flux et par appel)
afin de ne pas presenter la correlation temporelle comme une association
SDP certaine.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)

_RTP_GRACE_SECONDS = 300.0


@dataclass
class Call:
    """Vue consolidee d'un appel SIP et de ses medias RTP."""

    call_id: str
    participants: tuple[str, ...] = ()
    signaling: list[dict] = field(default_factory=list)
    setup_duration_ms: float | None = None
    duration_ms: float | None = None
    rtp_streams: list[dict] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)
    quality: str = "unknown"
    correlation_method: str = "time_window"

    def to_dict(self) -> dict:
        logger.debug("Call.to_dict: retour dictionnaire")
        return {
            "call_id": self.call_id,
            "participants": list(self.participants),
            "signaling": list(self.signaling),
            "setup_duration_ms": self.setup_duration_ms,
            "duration_ms": self.duration_ms,
            "rtp_streams": list(self.rtp_streams),
            "events": list(self.events),
            "quality": self.quality,
            "correlation_method": self.correlation_method,
        }


def _quality(mos_values: list[float]) -> str:
    if not mos_values:
        logger.debug("_quality: si not mos_values -> retour 'unknown'")
        return "unknown"
    mos = sum(mos_values) / len(mos_values)
    if mos < 3.0:
        result = "poor"
    elif mos < 3.6:
        result = "fair"
    else:
        result = "good"
    logger.debug("_quality: MOS moyen={} -> {}", round(mos, 2), result)
    return result


def build_calls(all_packets, rtp_streams: list[dict]) -> tuple[list[Call], dict[str, int]]:
    """Construit les appels SIP et leur associe les flux RTP.

    Les appels sont d'abord reconstruits par Call-ID. Le flux RTP est ensuite
    rattache a l'appel dont l'intervalle temporel contient son premier paquet.
    En l'absence de BYE, une fenetre de 300 s apres le dernier message SIP
    permet de couvrir les appels normaux dont seule la signalisation initiale
    est visible. Un flux ambigu n'est jamais duplique : l'appel dont
    l'INVITE est le plus proche avant le RTP est retenu.

    Issue #1120 : avant ce repli temporel, un flux dont la destination
    ``(dst, dport)`` figure parmi les points media annonces par le SDP de
    l'offre ou de la reponse d'un appel (``Pkt.sip_sdp_media``) est rattache
    a cet appel avec ``correlation_method = "sdp"`` -- y compris quand deux
    appels simultanes se chevauchent dans le temps. Si plusieurs appels
    annoncent le meme point (reutilisation de ports), le choix temporel
    s'applique entre eux seuls. Chaque flux rattache porte sa methode ;
    l'appel vaut ``"sdp"`` si tous ses flux sont associes par SDP,
    ``"time_window"`` si aucun ne l'est (ou sans flux), ``"mixed"`` sinon.
    """
    logger.debug("build_calls: debut ({} flux RTP)", len(rtp_streams))
    by_id: dict[str, list] = {}
    for pk in all_packets:
        if pk.sip_call_id and pk.sip_msg_type:
            by_id.setdefault(pk.sip_call_id, []).append(pk)

    calls: list[Call] = []
    sdp_endpoints: dict[str, set[tuple[str, int]]] = {}
    for call_id, packets in by_id.items():
        packets = sorted(packets, key=lambda p: p.ts)
        sdp_endpoints[call_id] = {
            (addr, port) for p in packets for addr, port in (getattr(p, "sip_sdp_media", ()) or ())
        }
        invite = next((p for p in packets if p.sip_msg_type == "INVITE"), None)
        if invite is None:
            invite = packets[0]

        participants = sorted({p.src for p in packets} | {p.dst for p in packets})
        signaling = [
            {
                "ts": p.ts,
                "point": p.point,
                "message": p.sip_msg_type,
                "cseq": p.sip_cseq,
                **({"frame_number": p.frame_number} if p.frame_number is not None else {}),
            }
            for p in packets
        ]

        ok = next(
            (
                p
                for p in packets
                if p.sip_msg_type
                and p.sip_msg_type.startswith("200")
                and p.sip_cseq
                and "INVITE" in p.sip_cseq
                and p.ts >= invite.ts
            ),
            None,
        )
        bye = next(
            (p for p in packets if p.sip_msg_type in {"BYE", "CANCEL"} and p.ts >= invite.ts),
            None,
        )
        setup_ms = (ok.ts - invite.ts) * 1000.0 if ok else None
        duration_ms = (bye.ts - invite.ts) * 1000.0 if bye else None

        events = [
            {
                "type": "invite",
                "ts": invite.ts,
                "point": invite.point,
            }
        ]
        if ok:
            events.append({"type": "connected", "ts": ok.ts, "point": ok.point})
        if bye:
            events.append({"type": bye.sip_msg_type.lower(), "ts": bye.ts, "point": bye.point})

        failed = next(
            (
                p
                for p in packets
                if p.sip_msg_type
                and p.sip_cseq
                and "INVITE" in p.sip_cseq
                and p.sip_msg_type.split(" ", 1)[0][:1] in {"4", "5", "6"}
            ),
            None,
        )
        if failed:
            code = failed.sip_msg_type.split(" ", 1)[0]
            events.append({"type": "failure", "code": code, "ts": failed.ts, "point": failed.point})

        calls.append(
            Call(
                call_id=call_id,
                participants=tuple(participants),
                signaling=signaling,
                setup_duration_ms=setup_ms,
                duration_ms=duration_ms,
                events=events,
            )
        )

    calls.sort(key=lambda c: c.signaling[0]["ts"] if c.signaling else float("inf"))

    # Interval de chaque appel. La prochaine INVITE borne un appel sans BYE.
    intervals = []
    for i, call in enumerate(calls):
        start = call.signaling[0]["ts"]
        bye_ts = next((e["ts"] for e in call.events if e["type"] in {"bye", "cancel"}), None)
        if bye_ts is not None:
            end = bye_ts
        elif i + 1 < len(calls):
            end = calls[i + 1].signaling[0]["ts"]
        else:
            end = max(e["ts"] for e in call.signaling) + _RTP_GRACE_SECONDS
        intervals.append((start, end, call))

    # Index point media SDP -> appels qui l'annoncent, dans l'ordre des appels.
    calls_by_endpoint: dict[tuple[Any, Any], list[Call]] = {}
    for call in calls:
        for endpoint in sorted(sdp_endpoints[call.call_id]):
            calls_by_endpoint.setdefault(endpoint, []).append(call)

    attached = 0
    ambiguous = 0
    by_sdp = 0
    for stream in rtp_streams:
        points = stream.get("first_ts_by_point", {})
        first_ts = min(points.values()) if points else stream.get("first_ts")
        if first_ts is None:
            continue
        in_window = [c for start, end, c in intervals if start <= first_ts <= end]
        target: tuple[Any, Any] = (stream.get("dst"), stream.get("dport"))
        sdp_matches = calls_by_endpoint.get(target, [])
        if sdp_matches:
            method = "sdp"
            window_ids = {id(c) for c in in_window}
            candidates = [c for c in sdp_matches if id(c) in window_ids] or sdp_matches
            by_sdp += 1
        elif in_window:
            method = "time_window"
            candidates = in_window
        else:
            continue
        if len(candidates) > 1:
            ambiguous += 1
        call = min(
            candidates,
            key=lambda c: abs(first_ts - c.signaling[0]["ts"]),
        )
        # Copie : le flux de Report.rtp_streams reste inchange, seule la
        # vue rattachee a l'appel porte la methode d'association.
        call.rtp_streams.append({**stream, "correlation_method": method})
        attached += 1

    for call in calls:
        mos_values = [s["mos"] for s in call.rtp_streams if s.get("mos") is not None]
        call.quality = _quality(mos_values)
        methods = {s["correlation_method"] for s in call.rtp_streams}
        call.correlation_method = "sdp" if methods == {"sdp"} else "mixed" if "sdp" in methods else "time_window"
        if call.rtp_streams:
            call.events.append(
                {
                    "type": "media",
                    "ts": min(ts for s in call.rtp_streams if (ts := s.get("first_ts")) is not None),
                    "streams": len(call.rtp_streams),
                }
            )

    distribution = Counter(call.quality for call in calls)
    logger.debug(
        "build_calls: {} appel(s), {} flux RTP rattaché(s) dont {} par SDP, {} ambigu(s)",
        len(calls),
        attached,
        by_sdp,
        ambiguous,
    )
    return calls, dict(distribution)
