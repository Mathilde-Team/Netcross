"""
netcross_report.zeek_export -- journaux de flux au format Zeek ``conn.log``
(issue #1115, chantier #1003).

Un enregistrement par connexion ET par point de capture, comme si Zeek avait
tourne sur chaque sonde : les colonnes standard de ``conn.log`` d'abord, dans
l'ordre de Zeek, puis des colonnes ``netcross_*`` propres a l'analyse
multi-points (point, points qui voient la connexion, segment amont, latence
et paquets perdus sur ce segment, premier segment de perte).

Deux formats :

- **TSV** (defaut de Zeek) : en-tetes ``#separator``, ``#set_separator``,
  ``#empty_field``, ``#unset_field``, ``#path``, ``#open``, ``#fields``,
  ``#types``, une ligne par connexion, ``#close`` -- lisible par
  ``zeek-cut``, Splunk (TA Zeek), Elastic (module Zeek), RITA... ;
- **JSON** (``LogAscii::use_json=T``) : un objet par ligne, champs non
  renseignes omis, ensembles en listes.

Les paquets recus sont ceux de l'analyse : apres ``--redact``, adresses et
noms y sont deja pseudonymises, et l'identifiant ``uid`` est derive des
valeurs pseudonymisees -- rien de l'adresse reelle ne fuit.

Limites assumees (documentees dans docs/zeek-export.md) : ``orig_bytes`` et
``resp_bytes`` additionnent la charge utile observee (retransmissions
comprises, Zeek les deduit des numeros de sequence) ; ``*_ip_bytes`` est la
longueur de trame ; ``local_orig``, ``local_resp`` et ``missed_bytes`` ne
sont pas renseignes ; ``service`` n'est rempli que si un champ applicatif
dissequé l'atteste (pas de deduction par numero de port, comme Zeek).

Usage :

    from netcross_report.zeek_export import build_conn_records, write_zeek_conn

    records = build_conn_records(packets, points, points_order)
    write_zeek_conn(records, "conn.log", fmt="tsv")   # ou "json"
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import statistics
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from netcross_core.logging_config import get_logger, summarize
from netcross_core.models import Pkt

logger = get_logger(__name__)

ZEEK_FORMATS = ("tsv", "json")

# Colonnes standard de Zeek conn.log (base/protocols/conn/main.zeek), dans
# l'ordre de Zeek -- les outils qui lisent par position s'y retrouvent.
ZEEK_STANDARD_FIELDS: tuple[tuple[str, str], ...] = (
    ("ts", "time"),
    ("uid", "string"),
    ("id.orig_h", "addr"),
    ("id.orig_p", "port"),
    ("id.resp_h", "addr"),
    ("id.resp_p", "port"),
    ("proto", "enum"),
    ("service", "string"),
    ("duration", "interval"),
    ("orig_bytes", "count"),
    ("resp_bytes", "count"),
    ("conn_state", "string"),
    ("local_orig", "bool"),
    ("local_resp", "bool"),
    ("missed_bytes", "count"),
    ("history", "string"),
    ("orig_pkts", "count"),
    ("orig_ip_bytes", "count"),
    ("resp_pkts", "count"),
    ("resp_ip_bytes", "count"),
    ("tunnel_parents", "set[string]"),
)

# Colonnes propres a Netcross, toujours APRES les colonnes standard.
NETCROSS_FIELDS: tuple[tuple[str, str], ...] = (
    ("netcross_point", "string"),
    ("netcross_points", "set[string]"),
    ("netcross_segment", "string"),
    ("netcross_segment_delay_ms", "double"),
    ("netcross_segment_lost_pkts", "count"),
    ("netcross_loss_segment", "string"),
)

ZEEK_FIELDS = ZEEK_STANDARD_FIELDS + NETCROSS_FIELDS

# Protocoles Netcross -> enum transport_proto de Zeek. ARP, STP et IP sans
# transport connu n'ont pas de connexion au sens de Zeek : ignores.
_PROTO_MAP = {"TCP": "tcp", "UDP": "udp", "ICMP": "icmp", "ICMPv6": "icmp"}

_TCP_FLAG_NAMES = ("URG", "ACK", "PSH", "RST", "SYN", "FIN")

# Echappement TSV de Zeek : separateur, fins de ligne et antislash en \xNN.
_TSV_ESCAPE = str.maketrans({"\\": "\\x5c", "\t": "\\x09", "\n": "\\x0a", "\r": "\\x0d"})
_SET_ESCAPE = str.maketrans({"\\": "\\x5c", "\t": "\\x09", "\n": "\\x0a", "\r": "\\x0d", ",": "\\x2c"})

_BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


@dataclass
class ZeekConn:
    """Une connexion vue a un point de capture (une ligne de conn.log)."""

    point: str
    proto: str
    orig_h: str
    orig_p: int | None
    resp_h: str
    resp_p: int | None
    ts: float
    last_ts: float
    uid: str = ""
    service: str | None = None
    orig_bytes: int = 0
    resp_bytes: int = 0
    orig_pkts: int = 0
    resp_pkts: int = 0
    orig_ip_bytes: int = 0
    resp_ip_bytes: int = 0
    conn_state: str = "OTH"
    history: str = ""
    points_seen: tuple[str, ...] = ()
    segment: str | None = None
    segment_delay_ms: float | None = None
    segment_lost_pkts: int | None = None
    loss_segment: str | None = None
    _orig_flags: set[str] = field(default_factory=set, repr=False)
    _resp_flags: set[str] = field(default_factory=set, repr=False)
    _orig_data: bool = field(default=False, repr=False)
    _resp_data: bool = field(default=False, repr=False)

    def values(self) -> dict[str, object]:
        """Valeurs par nom de colonne Zeek ; ``None`` = champ non renseigne."""
        logger.debug("ZeekConn.values: point={} proto={}", self.point, self.proto)
        out: dict[str, object] = {
            "ts": self.ts,
            "uid": self.uid,
            "id.orig_h": self.orig_h,
            "id.orig_p": self.orig_p,
            "id.resp_h": self.resp_h,
            "id.resp_p": self.resp_p,
            "proto": self.proto,
            "service": self.service,
            "duration": max(0.0, self.last_ts - self.ts),
            "orig_bytes": self.orig_bytes,
            "resp_bytes": self.resp_bytes,
            "conn_state": self.conn_state,
            "local_orig": None,
            "local_resp": None,
            "missed_bytes": None,
            "history": self.history,
            "orig_pkts": self.orig_pkts,
            "orig_ip_bytes": self.orig_ip_bytes,
            "resp_pkts": self.resp_pkts,
            "resp_ip_bytes": self.resp_ip_bytes,
            "tunnel_parents": (),
            "netcross_point": self.point,
            "netcross_points": self.points_seen,
            "netcross_segment": self.segment,
            "netcross_segment_delay_ms": self.segment_delay_ms,
            "netcross_segment_lost_pkts": self.segment_lost_pkts,
            "netcross_loss_segment": self.loss_segment,
        }
        logger.debug("ZeekConn.values: retour {} champ(s)", len(out))
        return out


def tcp_flag_names(flags: str | None) -> frozenset[str]:
    """Noms des drapeaux TCP d'une chaine ``Pkt.flags``.

    Accepte les deux formes rencontrees : ``tcp.flags.str`` de tshark
    (positionnelle, les six derniers caracteres sont U A P R S F, un point
    ou ``·`` quand le drapeau est absent) et les noms en clair
    (``"SYN,ACK"``), employes par certains tests et imports.
    """
    if not flags:
        names: frozenset[str] = frozenset()
    elif any(name in flags for name in _TCP_FLAG_NAMES):
        names = frozenset(name for name in _TCP_FLAG_NAMES if name in flags)
    else:
        tail = flags[-6:].rjust(6)
        names = frozenset(name for name, ch in zip(_TCP_FLAG_NAMES, tail, strict=True) if ch.isalpha())
    logger.debug("tcp_flag_names: retour {}", sorted(names))
    return names


def _service(pk: Pkt) -> str | None:
    """Service applicatif atteste par un champ dissequé (``None`` sinon)."""
    if pk.dns_qry_name or pk.dns_txn_id is not None:
        service = "dns"
    elif pk.tls_client_hello or pk.tls_server_hello or pk.tls_application_data:
        service = "ssl"
    elif pk.http_is_request or pk.http_is_response:
        service = "http"
    elif pk.sip_call_id or pk.sip_msg_type:
        service = "sip"
    elif pk.dhcp_msg_type is not None:
        service = "dhcp"
    elif pk.ssh_hassh:
        service = "ssh"
    else:
        service = None
    logger.debug("_service: retour {}", service)
    return service


def _uid(point: str, proto: str, orig: tuple[str, int | None], resp: tuple[str, int | None], ts: float) -> str:
    """Identifiant de connexion stable facon Zeek (``C`` + 17 caracteres base 62).

    Derive des valeurs deja pseudonymisees (``--redact``) : il ne revele
    rien de plus que les colonnes de la ligne, et deux exports d'une meme
    capture donnent les memes identifiants (comparables d'un run a l'autre).
    """
    digest = hashlib.sha256(f"{point}|{proto}|{orig}|{resp}|{ts:.6f}".encode()).digest()
    n = int.from_bytes(digest[:13], "big")
    chars = []
    for _ in range(17):
        n, rem = divmod(n, 62)
        chars.append(_BASE62[rem])
    uid = "C" + "".join(chars)
    logger.debug("_uid: retour uid (point={}, proto={})", point, proto)
    return uid


def _conn_state(conn: ZeekConn) -> str:
    """Etat de connexion Zeek (sous-ensemble : S0, S1, SF, REJ, RSTO, RSTR, SH, OTH)."""
    o, r = conn._orig_flags, conn._resp_flags
    if conn.proto != "tcp":
        state = "SF" if conn.resp_pkts else "S0"
    elif "SYN" in o and not ({"SYN", "ACK"} <= r):
        if "RST" in r:
            state = "REJ"
        elif "FIN" in o:
            state = "SH"
        else:
            state = "S0"
    elif "SYN" in o:
        if "RST" in o:
            state = "RSTO"
        elif "RST" in r:
            state = "RSTR"
        elif "FIN" in o and "FIN" in r:
            state = "SF"
        else:
            state = "S1"
    else:
        state = "OTH"
    logger.debug("_conn_state: retour {}", state)
    return state


def _segments(order: Sequence[str]) -> dict[str, str]:
    """Point -> point immediatement en amont dans ``--order``."""
    logger.debug("_segments: order={}", summarize(list(order), "order"))
    seg = {order[i]: order[i - 1] for i in range(1, len(order))}
    logger.debug("_segments: retour {} segment(s)", len(seg))
    return seg


def build_conn_records(
    packets: Iterable[Pkt],
    points: Sequence[str],
    points_order: Sequence[str] | None = None,
) -> list[ZeekConn]:
    """Agrege les paquets en connexions Zeek, une par (connexion, point).

    Une connexion est identifiee par protocole et couple de points
    d'extremite non oriente (ICMP : couple d'adresses). L'initiateur est
    l'emetteur du SYN sans ACK s'il est vu, sinon celui du premier paquet.

    Les colonnes ``netcross_segment*`` ne sont remplies que si un ordre de
    chemin (``--order``) est fourni : le segment d'une ligne relie le point
    immediatement en amont au point de la ligne. Les paquets perdus sur ce
    segment sont ceux vus en amont et absents a ce point (meme convention
    que le comptage de pertes du rapport) ; la latence est la mediane des
    ecarts entre les deux observations d'un meme paquet. Les paquets
    marques doublons (``is_duplicate``) sont ignores.
    """
    logger.debug(
        "build_conn_records: points={} points_order={}",
        summarize(list(points), "points"),
        summarize(list(points_order or ()), "points_order"),
    )
    # (cle de connexion) -> {point: [paquets]} ; cle de paquet -> {point: ts}
    by_conn: dict[tuple, dict[str, list[Pkt]]] = {}
    for pk in packets:
        proto = _PROTO_MAP.get(pk.proto)
        if proto is None or not pk.src or not pk.dst or pk.is_duplicate:
            continue
        a: tuple[str, int | None] = (pk.src, None if proto == "icmp" else pk.sport)
        b: tuple[str, int | None] = (pk.dst, None if proto == "icmp" else pk.dport)
        ends = (a, b) if (a[0], a[1] or 0) <= (b[0], b[1] or 0) else (b, a)
        by_conn.setdefault((proto, ends), {}).setdefault(pk.point, []).append(pk)

    segments = _segments(points_order) if points_order else {}
    order = list(points_order) if points_order else list(points)
    records: list[ZeekConn] = []
    for (proto, _ends), per_point in by_conn.items():
        all_pkts = sorted((p for pk_list in per_point.values() for p in pk_list), key=lambda p: p.ts)
        first = all_pkts[0]
        if proto == "tcp":
            syn = next(
                (p for p in all_pkts if tcp_flag_names(p.flags) >= {"SYN"} and "ACK" not in tcp_flag_names(p.flags)),
                None,
            )
            first = syn or first
        orig_h = first.src
        if proto == "icmp":
            orig = (first.src, first.icmp_type)
            resp = (first.dst, first.icmp_code)
        else:
            orig = (first.src, first.sport)
            resp = (first.dst, first.dport)
        points_seen = tuple(p for p in order if p in per_point) + tuple(sorted(p for p in per_point if p not in order))

        # Observations par paquet (direction + cle) pour les colonnes de segment.
        obs: dict[str, dict[tuple, float]] = {}
        if segments:
            for point, pk_list in per_point.items():
                d = obs.setdefault(point, {})
                for p in pk_list:
                    d.setdefault((p.src, p.sport, p.dst, p.dport, p.key_id, p.payload_hash), p.ts)
        loss_segment = None
        for point in order[1:]:
            up = segments.get(point)
            if up in obs and any(k not in obs.get(point, {}) for k in obs[up]):
                loss_segment = f"{up}->{point}"
                break

        for point, pk_list in per_point.items():
            pk_list.sort(key=lambda p: p.ts)
            conn = ZeekConn(
                point=point,
                proto=proto,
                orig_h=orig[0],
                orig_p=orig[1],
                resp_h=resp[0],
                resp_p=resp[1],
                ts=pk_list[0].ts,
                last_ts=pk_list[-1].ts,
                points_seen=points_seen,
                loss_segment=loss_segment,
            )
            seen_letters: list[str] = []
            for p in pk_list:
                from_orig = p.src == orig_h
                payload = (p.tcp_len if p.tcp_len is not None else p.payload_len) or 0
                names = tcp_flag_names(p.flags) if proto == "tcp" else frozenset()
                if from_orig:
                    conn.orig_pkts += 1
                    conn.orig_bytes += payload
                    conn.orig_ip_bytes += p.length or 0
                    conn._orig_flags |= names
                else:
                    conn.resp_pkts += 1
                    conn.resp_bytes += payload
                    conn.resp_ip_bytes += p.length or 0
                    conn._resp_flags |= names
                if conn.service is None:
                    conn.service = _service(p)
                # historique Zeek : majuscule = initiateur, minuscule = repondeur,
                # chaque lettre une fois par sens (sans les repetitions de Zeek).
                letters = []
                if "SYN" in names:
                    letters.append("H" if "ACK" in names else "S")
                if "FIN" in names:
                    letters.append("F")
                if "RST" in names:
                    letters.append("R")
                if payload:
                    letters.append("D")
                elif "ACK" in names and not names & {"SYN", "FIN", "RST"}:
                    letters.append("A")
                for letter in letters:
                    letter = letter if from_orig else letter.lower()
                    if letter not in seen_letters:
                        seen_letters.append(letter)
            conn.history = "".join(seen_letters)
            conn.conn_state = _conn_state(conn)
            conn.uid = _uid(point, proto, orig, resp, conn.ts)
            up = segments.get(point)
            if up is not None:
                conn.segment = f"{up}->{point}"
                here = obs.get(point, {})
                upstream = obs.get(up, {})
                conn.segment_lost_pkts = sum(1 for k in upstream if k not in here)
                deltas = [abs(here[k] - upstream[k]) * 1000.0 for k in upstream if k in here]
                conn.segment_delay_ms = statistics.median(deltas) if deltas else None
            records.append(conn)

    records.sort(key=lambda c: (c.ts, c.point, c.uid))
    logger.debug("build_conn_records: retour {} enregistrement(s)", len(records))
    return records


def _tsv_value(value: object, zeek_type: str) -> str:
    """Valeur au format TSV de Zeek (``-`` non renseigne, ``(empty)`` vide)."""
    if value is None:
        out = "-"
    elif zeek_type.startswith("set["):
        items = [str(v).translate(_SET_ESCAPE) for v in cast("Iterable[object]", value)]
        out = ",".join(items) if items else "(empty)"
    elif zeek_type in ("time", "interval"):
        out = f"{float(value):.6f}"  # type: ignore[arg-type]
    elif zeek_type == "double":
        out = f"{float(value):.3f}"  # type: ignore[arg-type]
    else:
        text = str(value)
        out = text.translate(_TSV_ESCAPE) if text else "(empty)"
    logger.debug("_tsv_value: retour ({})", zeek_type)
    return out


def _zeek_time(ts: float) -> str:
    """Horodatage des lignes ``#open``/``#close`` (``%Y-%m-%d-%H-%M-%S``, UTC)."""
    logger.debug("_zeek_time: ts={}", ts)
    out = _dt.datetime.fromtimestamp(ts, tz=_dt.UTC).strftime("%Y-%m-%d-%H-%M-%S")
    logger.debug("_zeek_time: retour {}", out)
    return out


def to_tsv(records: Sequence[ZeekConn]) -> str:
    """``conn.log`` au format TSV de Zeek, en-tetes et ``#close`` compris.

    ``#open`` et ``#close`` portent les bornes des captures (premier et
    dernier paquet) plutot que l'heure de l'export : deux exports d'une meme
    capture sont identiques octet pour octet.
    """
    logger.debug("to_tsv: records={}", len(records))
    if records:
        opened = _zeek_time(min(r.ts for r in records))
        closed = _zeek_time(max(r.last_ts for r in records))
    else:
        opened = closed = _zeek_time(0.0)
    lines = [
        "#separator \\x09",
        "#set_separator\t,",
        "#empty_field\t(empty)",
        "#unset_field\t-",
        "#path\tconn",
        f"#open\t{opened}",
        "#fields\t" + "\t".join(name for name, _t in ZEEK_FIELDS),
        "#types\t" + "\t".join(t for _n, t in ZEEK_FIELDS),
    ]
    for rec in records:
        values = rec.values()
        lines.append("\t".join(_tsv_value(values[name], t) for name, t in ZEEK_FIELDS))
    lines.append(f"#close\t{closed}")
    out = "\n".join(lines) + "\n"
    logger.debug("to_tsv: retour {} ligne(s)", len(lines))
    return out


def to_json_lines(records: Sequence[ZeekConn]) -> str:
    """``conn.log`` au format JSON de Zeek : un objet par ligne.

    Comme ``LogAscii::use_json=T`` : champs non renseignes omis, ensembles en
    listes (omis s'ils sont vides), ``ts`` en secondes flottantes.
    """
    logger.debug("to_json_lines: records={}", len(records))
    lines = []
    for rec in records:
        obj: dict[str, object] = {}
        values = rec.values()
        for name, zeek_type in ZEEK_FIELDS:
            value = values[name]
            if value is None:
                continue
            if zeek_type.startswith("set["):
                if not value:
                    continue
                value = list(value)  # type: ignore[call-overload]
            obj[name] = value
        lines.append(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))
    out = "".join(line + "\n" for line in lines)
    logger.debug("to_json_lines: retour {} ligne(s)", len(lines))
    return out


def write_zeek_conn(records: Sequence[ZeekConn], output_path: str | Path, fmt: str = "tsv") -> str:
    """Ecrit ``conn.log`` (``fmt`` : ``tsv`` ou ``json``) et retourne le chemin."""
    logger.debug("write_zeek_conn: records={} output_path={} fmt={}", len(records), output_path, fmt)
    if fmt not in ZEEK_FORMATS:
        logger.debug("write_zeek_conn: format inconnu {}", fmt)
        raise ValueError(f"format Zeek inconnu : {fmt!r} (attendu : {', '.join(ZEEK_FORMATS)})")
    text = to_tsv(records) if fmt == "tsv" else to_json_lines(records)
    path = Path(output_path)
    path.write_text(text, encoding="utf-8")
    logger.debug("write_zeek_conn: retour {}", path)
    return str(path)
