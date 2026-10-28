# SPDX-License-Identifier: GPL-3.0-or-later
"""
Issue #329 -- test de non-regression : chaque type de detection produit par
les modules de securite apparait dans au moins un rendu utilisateur, avec un
texte exploitable. Aucune detection silencieuse (produite mais invisible).

Esprit des issues #218/#259 : on ne s'arrete pas a l'objet intermediaire.
Pour chaque detecteur, on part de paquets synthetiques qui le declenchent,
on passe par la chaine reelle (`apply_expert_correlation`,
`apply_security_findings`, `plugins.run_detectors`), puis on relit ce qui
sort des fichiers et chaines produits : JSON, HTML, texte, PDF (pdftotext),
CEF, LEEF, STIX.

Constat de l'audit du 23/09/2026 reproduit par ce test : les constats de
`protocol_mismatch` sortaient avec un `detail` vide dans tous les rendus
(cles `type`/`description` au lieu de `category`/`detail`, issue #345).

Les cas encore ouverts sont marques `xfail(strict=True)` avec leur issue :
ils deviendront rouges (XPASS) le jour ou ils seront corriges, ce qui
obligera a retirer le marqueur.
"""

from __future__ import annotations

import base64
import html
import json
import random
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest
from conftest import make_pkt

from netcross_core.models import Banner, Report
from netcross_core.plugins import run_detectors
from netcross_core.security.beaconing import detect_beaconing
from netcross_core.security.dga import detect_dga
from netcross_core.security.dns_tunnel import detect_dns_tunneling
from netcross_core.security.exfiltration import correlate_exfiltration, detect_exfiltration
from netcross_core.security.expert_correlation import apply_expert_correlation, correlate_expert_alerts
from netcross_core.security.fast_flux import detect_fast_flux
from netcross_core.security.findings import (
    anomaly_findings,
    apply_security_findings,
    beaconing_findings,
    dga_findings,
    dns_tunnel_findings,
    exfiltration_findings,
    fast_flux_findings,
    flow_stats_findings,
    lateral_movement_findings,
    tls_audit_findings,
)
from netcross_core.security.flow_stats import analyze_flow_stats
from netcross_core.security.lateral_movement import detect_lateral_movement
from netcross_core.security.protocol_mismatch import detect_protocol_mismatches, protocol_mismatch_findings
from netcross_core.security.tls_audit import DEFAULT_POLICY, audit_tls_certificates
from netcross_report.json_report import generate_json_report
from netcross_report.security_html import render_security_html
from netcross_report.security_report import build_security_report, format_security_report
from netcross_report.siem_export import export_cef, export_leef
from netcross_report.stix_export import to_stix_bundle

POINT = "LAN"
CLIENT = "192.168.1.10"
C2 = "93.184.216.34"  # routable (les plages de documentation sont traitees comme internes)
EXFIL = "185.220.101.77"
NOON = 12 * 3600
NOW = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc).timestamp()
MALFORMED = "_ws_malformed__ws_malformed_expert"


# -- declencheurs : un par detecteur de l'issue #329 ------------------------------


def _beaconing():
    return [
        make_pkt(
            point=POINT,
            ts=NOON + i * 60.0,
            proto="TCP",
            src=CLIENT,
            dst=C2,
            sport=40000,
            dport=443,
            length=174,
            tcp_len=120,
            frame_number=i + 1,
        )
        for i in range(20)
    ]


def _dns_tunnel():
    rng = random.Random(1)
    out = []
    for i in range(20):
        label = base64.b32encode(bytes(rng.randrange(256) for _ in range(32))).decode().lower().rstrip("=")[:32]
        out.append(
            make_pkt(
                point=POINT,
                ts=i * 0.37,
                proto="UDP",
                src=CLIENT,
                dst="10.0.0.53",
                sport=40000,
                dport=53,
                dns_txn_id=i,
                dns_is_response=False,
                dns_qry_name=f"{label}.t.evil.example",
                frame_number=i + 1,
                length=90,
            )
        )
    return out


def _exfiltration():
    return [
        make_pkt(
            point=POINT,
            src=CLIENT,
            dst=EXFIL,
            sport=41000,
            dport=443,
            length=1400,
            tcp_len=1346,
            ts=2 * 3600 + i * 0.01,
            proto="TCP",
            frame_number=i + 1,
        )
        for i in range(8000)
    ]


def _protocol_mismatch():
    ssh = Banner(protocol="ssh", service="OpenSSH", version="8.9", raw="SSH-2.0-OpenSSH_8.9")
    return [
        make_pkt(
            point=POINT, src=CLIENT, dst="10.0.0.2", sport=51000, dport=443, frame_number=3, service_banners=(ssh,)
        )
    ]


def _dga():
    names = ["xkqjfwbvtzq.com", "qzvxkjwpfh.net", "bvcxzqwrtp.org"]
    out = []
    for i, n in enumerate(names):
        out.append(
            make_pkt(point=POINT, ts=float(i), proto="UDP", src=CLIENT, dport=53, dns_qry_name=n, dns_is_response=False)
        )
        out.append(
            make_pkt(
                point=POINT,
                ts=i + 0.1,
                proto="UDP",
                dst=CLIENT,
                sport=53,
                dns_qry_name=n,
                dns_is_response=True,
                dns_rcode=3,
            )
        )
    return out


def _fast_flux():
    # #344 : la rotation se lit dans les reponses DNS (dns_answers), plus
    # dans les connexions TCP du client.
    domain = "suspicious.example.com"
    return [
        make_pkt(
            point=POINT,
            src="10.0.0.53",
            dst=CLIENT,
            dns_qry_name=domain,
            dns_is_response=True,
            dns_rcode=0,
            dns_answers=(f"203.0.113.{i + 1}",),
            ts=float(i * 30),
            proto="UDP",
            sport=53,
        )
        for i in range(6)
    ]


def _lateral_movement():
    return [
        make_pkt(
            point=POINT, src="192.168.1.100", dst=f"192.168.1.{host}", dport=port + 1000, flags="S.......", proto="TCP"
        )
        for host in range(1, 6)
        for port in range(1, 21)
    ]


def _tls_audit():
    return [
        make_pkt(
            point=POINT,
            ts=NOW,
            src="10.0.0.5",
            sport=443,
            dst="203.0.113.9",
            dport=51000,
            frame_number=7,
            tls_cert_serial="10:01",
            tls_cert_not_before="2020-01-01 00:00:00 (UTC)",
            tls_cert_not_after="2021-01-01 00:00:00 (UTC)",
            tls_cert_san=("www.example.com",),
            tls_cert_issuer="CN=Lab Intermediate CA,O=Lab",
            tls_cert_subject="CN=www.example.com,O=Lab",
            tls_cert_sig_hash="sha1",
            tls_cert_key_type="RSA",
            tls_cert_key_bits=1024,
            tls_cert_san_ip=(),
            tls_cert_chain_len=2,
        )
    ]


def _flow_stats():
    return [
        make_pkt(
            point=POINT,
            src=CLIENT,
            dst=EXFIL,
            sport=42000,
            dport=8443,
            length=1400 + (i * 37) % 97,
            ts=i * 0.01,
            proto="TCP",
        )
        for i in range(400)
    ]


def _expert_correlation():
    return [
        make_pkt(
            point=POINT,
            ts=float(t),
            proto="UDP",
            src="10.0.0.1",
            dst="10.0.0.2",
            sport=40000,
            dport=53,
            frame_number=t + 1,
            expert_flags=(MALFORMED,),
            expert_details=((MALFORMED, "Error", "Malformed", "Malformed Packet (Exception occurred)"),),
        )
        for t in range(3)
    ]


@dataclass
class _Det:
    """Detecteur tiers minimal (issue #284), au sens de plugins.api.Detector."""

    name: str = "maison"

    def analyse(self, ctx):  # noqa: ARG002 -- le contexte n'est pas utile ici
        return [
            {
                "category": "anomalie",
                "severity": "moyenne",
                "point": POINT,
                "detail": "detecteur tiers maison : motif interne XYZ-329 observe",
            }
        ]


# Pour chaque detecteur : (declencheur, constats attendus calcules par le
# module producteur lui-meme). Les constats attendus sont recalcules ici a
# partir du detecteur, puis on verifie qu'ils ont atteint le Report ET les
# rendus : c'est la chaine complete detecteur -> Report -> fichier.
DETECTORS = {
    "beaconing": (_beaconing, lambda p: beaconing_findings(detect_beaconing(p).suspicions)),
    "dns_tunnel": (_dns_tunnel, lambda p: dns_tunnel_findings(detect_dns_tunneling(p).suspicions)),
    "exfiltration": (
        _exfiltration,
        lambda p: exfiltration_findings(correlate_exfiltration(detect_exfiltration(p).alerts, [], set())),
    ),
    "protocol_mismatch": (_protocol_mismatch, lambda p: protocol_mismatch_findings(detect_protocol_mismatches(p))),
    "dga": (_dga, lambda p: dga_findings(_dga_alerts(p))),
    "fast_flux": (_fast_flux, lambda p: fast_flux_findings(_ff_alerts(p))),
    "lateral_movement": (_lateral_movement, lambda p: lateral_movement_findings(_lateral_events(p))),
    "tls_audit": (_tls_audit, lambda p: tls_audit_findings(audit_tls_certificates(p, DEFAULT_POLICY))),
    "flow_stats": (_flow_stats, lambda p: flow_stats_findings([f.to_dict() for f in analyze_flow_stats(p).flows])),
    "expert_correlation": (_expert_correlation, lambda p: anomaly_findings(correlate_expert_alerts(p).suspicions)),
    "plugins_runner": (lambda: [], lambda p: [_Det().analyse(None)[0] | {"plugin": "maison"}]),
}


def _dga_alerts(p):
    return [
        {
            "point": a.point,
            "domain": a.domain,
            "score": a.score,
            "reason": a.reason,
            "entropy": a.entropy,
            "consonant_ratio": a.consonant_ratio,
            "rare_bigram_ratio": a.rare_bigram_ratio,
            "length": a.length,
            "nxdomain_ratio": a.nxdomain_ratio,
        }
        for a in detect_dga(p).alerts
    ]


def _ff_alerts(p):
    return [
        {
            "point": a.point,
            "domain": a.domain,
            "alert_type": a.alert_type,
            "score": a.score,
            "reason": a.reason,
            "ips": a.ips,
            "nxdomain_ratio": a.nxdomain_ratio,
        }
        for a in detect_fast_flux(p).alerts
    ]


def _lateral_events(p):
    return [
        {
            "point": ev.point,
            "source": ev.source,
            "type": ev.event_type,
            "details": ev.details,
            "score": ev.score,
            "targets": ev.targets,
        }
        for ev in detect_lateral_movement(p).events
    ]


# -- chaine reelle et rendus -------------------------------------------------------


def _analyse(pkts, *, with_plugin=False) -> Report:
    r = Report(points=[POINT])
    apply_expert_correlation(r, pkts)
    apply_security_findings(r, pkts)
    if with_plugin:
        run_detectors([_Det()], pkts, r)
    return r


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _pdf_text(r: Report, sr, tmp_path) -> str | None:
    if shutil.which("pdftotext") is None:
        return None
    from netcross_report.pdf import generate_pdf

    pdf = tmp_path / "r.pdf"
    generate_pdf(r, str(pdf), security_report=sr)
    return subprocess.run(["pdftotext", str(pdf), "-"], capture_output=True, text=True, check=True).stdout


def _renders(r: Report, tmp_path, *, pdf=True) -> dict[str, str]:
    """Texte lisible de chaque rendu, desechappe selon le format."""
    sr = build_security_report(r)
    js = tmp_path / "r.json"
    generate_json_report(r, str(js), security_report=sr)
    out = {
        "json": json.dumps(json.loads(js.read_text(encoding="utf-8")), ensure_ascii=False),
        "html": html.unescape(render_security_html(sr)),
        "texte": "\n".join(format_security_report(sr)),
        "cef": "\n".join(export_cef(r)).replace("\\=", "=").replace("\\|", "|").replace("\\\\", "\\"),
        "leef": "\n".join(export_leef(r)),
        "stix": json.dumps(to_stix_bundle(r), ensure_ascii=False),
    }
    if pdf:
        text = _pdf_text(r, sr, tmp_path)
        if text is not None:
            out["pdf"] = text
    return {k: _norm(v) for k, v in out.items()}


def _where(detail: str, renders: dict[str, str]) -> list[str]:
    # prefixe de 40 caracteres : robuste aux coupures de ligne et aux
    # troncatures volontaires des rendus lisibles (MAX_READABLE_LEN)
    needle = _norm(detail)[:40]
    return [name for name, text in renders.items() if needle in text]


# -- tests -------------------------------------------------------------------------


@pytest.mark.parametrize("name", list(DETECTORS))
def test_chaque_detection_est_rendue_avec_un_texte(name, tmp_path):
    trigger, expected_of = DETECTORS[name]
    pkts = trigger()
    expected = expected_of(pkts)
    assert expected, f"{name} : le declencheur synthetique ne produit aucun constat (test a revoir)"

    r = _analyse(pkts, with_plugin=(name == "plugins_runner"))
    renders = _renders(r, tmp_path)

    for finding in expected:
        assert finding in r.security_findings, f"{name} : constat absent de Report.security_findings"
        detail = finding.get("detail") or ""
        assert detail.strip(), f"{name} : constat sans texte (`detail` vide) -- invisible pour l'analyste : {finding}"
        assert finding.get("category"), f"{name} : constat sans categorie : {finding}"
        seen = _where(detail, renders)
        assert seen, f"{name} : detection silencieuse, absente de tous les rendus ({sorted(renders)}) : {detail!r}"


def test_rapport_texte_montre_chaque_detecteur_quand_tous_se_declenchent(tmp_path):
    """Scenario combine (critere de #347) : 75 domaines DGA (bruit) +
    exfiltration + beaconing. Chaque detecteur ayant produit un constat doit
    garder au moins une ligne dans le rapport texte ET dans le PDF."""
    rng = random.Random(7)
    noise = []
    for i in range(75):
        n = "".join(rng.choice("bcdfghjklmnpqrstvwxz") for _ in range(12)) + ".com"
        noise.append(
            make_pkt(point=POINT, ts=float(i), proto="UDP", src=CLIENT, dport=53, dns_qry_name=n, dns_is_response=False)
        )
        noise.append(
            make_pkt(
                point=POINT,
                ts=i + 0.1,
                proto="UDP",
                dst=CLIENT,
                sport=53,
                dns_qry_name=n,
                dns_is_response=True,
                dns_rcode=3,
            )
        )
    pkts = noise + _exfiltration() + _beaconing()
    r = _analyse(pkts)
    renders = _renders(r, tmp_path)
    for rendu in ("texte", "pdf"):
        if rendu not in renders:
            continue
        for name in ("exfiltration", "beaconing"):
            for finding in DETECTORS[name][1](DETECTORS[name][0]()):
                assert _norm(finding["detail"])[:40] in renders[rendu], f"{name} masque dans le rendu {rendu}"
        # le bruit reste visible, mais resume : une ligne de synthese DGA
        assert "Domaines generes (DGA)" in renders[rendu]
    assert "autre(s) constat(s) Domaines generes (DGA)" in renders["texte"]


def test_fichiers_extraits_rendus(tmp_path):
    r = Report(points=[POINT])
    sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    r.extracted_files = [
        {
            "point": POINT,
            "proto_source": "HTTP",
            "src": EXFIL,
            "dst": CLIENT,
            "ts": 0.0,
            "uri": "/update.exe",
            "content_type": "application/octet-stream",
            "size": 4096,
            "hash_md5": "",
            "hash_sha256": sha,
            "type_detected": "PE",
            "frame_number": 12,
        }
    ]
    assert _where(sha, _renders(r, tmp_path, pdf=False))


def test_inventaire_d_actifs_porte_par_le_report():
    r = _analyse(_lateral_movement())
    assert getattr(r, "asset_inventory", None)


def test_libelles_distinguent_detecteurs_netcross_et_expert_info(tmp_path):
    """#348 : les constats des detecteurs Netcross ne sont plus presentes
    sous le libelle « anomalies (Expert Info) »."""
    pkts = _exfiltration() + _beaconing()
    r = _analyse(pkts)
    renders = _renders(r, tmp_path)
    for rendu in ("texte", "pdf"):
        if rendu not in renders:
            continue
        assert "anomalies (expert info)" not in renders[rendu].lower()
        assert "Anomalies (detecteurs Netcross)" in renders[rendu]
        assert "Anomalies (alertes Expert Info correlees)" in renders[rendu]
    from netcross_report.security_report import build_security_report, security_report_to_dict

    d = security_report_to_dict(build_security_report(r))
    assert d["dashboard"]["anomalies_netcross"] >= 2
    assert d["dashboard"]["anomalies_expert_info"] == 0
    assert d["dashboard"]["anomalies"] == d["dashboard"]["anomalies_netcross"] + d["dashboard"]["anomalies_expert_info"]
    assert {i["detector"] for i in d["anomalies"]} >= {"exfiltration", "beaconing"}
