# SPDX-License-Identifier: GPL-3.0-or-later
"""
Notifications sortantes sur seuil de gravite (issue #280).

Criteres d'acceptation couverts :
- une notification par analyse, uniquement au-dessus du seuil ;
- le meme lot de constats n'est pas re-notifie dans la fenetre de silence ;
- un canal en echec ne bloque pas l'analyse et apparait dans le rapport ;
- en mode `resume` (defaut), aucune IP interne ni banniere brute dans le corps ;
- sans `--notify-on`, aucun appel reseau -- verifie en interdisant les sockets.
"""

from __future__ import annotations

import json
import smtplib
import socket
import sys
import threading
from argparse import Namespace
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace
from typing import ClassVar

import pytest

import cross_capture_analyzer_cli as cli
from netcross_core.config import NotifyConfig, load_config
from netcross_core.notify import (
    DeliveryResult,
    EmailNotifier,
    NotifyError,
    SlackNotifier,
    WebhookNotifier,
    build_summary,
    findings_fingerprint,
    meets_threshold,
    notifiers_from_config,
    run_notifications,
    send_notifications,
)
from netcross_core.notify.transports import slack_blocks
from netcross_report.security_html import render_security_html
from netcross_report.security_report import (
    SecurityDashboard,
    SecurityReport,
    format_security_report,
    security_report_to_dict,
)

FINDINGS = [
    {
        "severity": "critique",
        "category": "exploit",
        "detail": "Log4Shell (LOG4SHELL) depuis 10.0.0.42 vers srv-compta.corp.local, 12 occurrences",
        "point": "LAN",
        "host": "10.0.0.5",
        "port": 80,
        "src": "10.0.0.42",
        "signature_id": "LOG4SHELL",
    },
    {
        "severity": "elevee",
        "category": "cve",
        "cve_id": "CVE-2021-41773",
        "cvss": 7.5,
        "detail": "Apache/2.4.49 (Unix) sur 10.0.0.5:80 -- path traversal",
        "service": "HTTP",
        "version": "Apache/2.4.49 (Unix)",
        "host": "10.0.0.5",
        "port": 80,
        "point": "LAN",
    },
    {"severity": "faible", "category": "anomalie", "detail": "retransmissions trame 1234", "point": "LAN"},
]


def _summary(threshold="elevee", detail="resume", findings=FINDINGS, level="critique"):
    return build_summary(findings, score=73, level=level, threshold=threshold, report_path=None, detail=detail)


class FakeNotifier:
    def __init__(self, name="webhook", fail=None):
        self.name = name
        self.fail = fail
        self.sent = []

    def send(self, summary):
        if self.fail:
            raise self.fail
        self.sent.append(summary)
        return True


# -- seuil et resume -----------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "threshold", "expected"),
    [
        ("critique", "elevee", True),
        ("elevee", "elevee", True),
        ("moyenne", "elevee", False),
        ("faible", "faible", True),
        (None, "faible", False),
        ("inconnue", "faible", False),
    ],
)
def test_seuil(severity, threshold, expected):
    assert meets_threshold(severity, threshold) is expected


def test_un_seul_resume_pour_toute_l_analyse_au_dessus_du_seuil(tmp_path):
    notifier = FakeNotifier()
    results = send_notifications(_summary(), [notifier], state_path=tmp_path / "s.json")
    assert [r.status for r in results] == ["envoye"]
    assert len(notifier.sent) == 1
    summary = notifier.sent[0]
    assert summary.by_severity == {"critique": 1, "elevee": 1, "moyenne": 0, "faible": 1}
    assert summary.total == 3
    # les pires constats seulement, et seulement ceux au-dessus du seuil
    assert [t["severity"] for t in summary.top] == ["critique", "elevee"]


def test_sous_le_seuil_rien_n_est_envoye(tmp_path):
    notifier = FakeNotifier()
    results = send_notifications(_summary("critique", level="elevee"), [notifier], state_path=tmp_path / "s.json")
    assert [r.status for r in results] == ["sous_le_seuil"]
    assert notifier.sent == []
    assert not (tmp_path / "s.json").exists()


def test_top_limite_a_trois_et_trie_par_gravite():
    findings = [{"severity": "moyenne", "category": "anomalie", "detail": f"a{i}"} for i in range(5)]
    findings.append({"severity": "critique", "category": "exploit", "detail": "pire"})
    summary = build_summary(findings, score=50, level="critique", threshold="moyenne")
    assert len(summary.top) == 3
    assert summary.top[0]["detail"] == "pire"


def test_parametres_invalides():
    with pytest.raises(ValueError, match="seuil"):
        build_summary([], score=0, level=None, threshold="grave")
    with pytest.raises(ValueError, match="detail"):
        build_summary([], score=0, level=None, threshold="faible", detail="tout")


# -- anonymisation ------------------------------------------------------------


def test_resume_par_defaut_sans_ip_interne_ni_banniere():
    summary = _summary()
    body = json.dumps(summary.to_dict(), ensure_ascii=False) + summary.to_text()
    body += json.dumps(slack_blocks(summary))
    for secret in ("10.0.0.42", "10.0.0.5", "srv-compta.corp.local", "Apache/2.4.49", "(Unix)"):
        assert secret not in body, secret
    # la CVE reste exploitable : identifiant + score
    assert "CVE-2021-41773 (CVSS 7.5)" in body
    assert summary.anonymized is True


def test_detail_complet_assume_le_texte_brut():
    summary = _summary(detail="complet")
    assert "10.0.0.42" in summary.to_text()
    assert summary.anonymized is False


def test_chemin_du_rapport_anonymise_en_mode_resume():
    summary = build_summary(
        FINDINGS, score=73, level="critique", threshold="elevee", report_path="/home/alice/rapports/secu.html"
    )
    assert "alice" not in (summary.report_path or "")


def test_detail_tronque():
    long = [{"severity": "critique", "category": "exploit", "detail": "x" * 1000}]
    summary = build_summary(long, score=40, level="critique", threshold="critique")
    assert len(summary.top[0]["detail"]) == 200


# -- anti-repetition ------------------------------------------------------------


def test_empreinte_stable_malgre_ordre_et_compteurs():
    variant = [dict(f) for f in reversed(FINDINGS)]
    variant[-1]["detail"] = variant[-1]["detail"].replace("12 occurrences", "40 occurrences")
    assert findings_fingerprint(FINDINGS) == findings_fingerprint(variant)
    changed = [*FINDINGS, {"severity": "critique", "category": "exploit", "detail": "autre"}]
    assert findings_fingerprint(FINDINGS) != findings_fingerprint(changed)


def test_meme_lot_non_renotifie_dans_la_fenetre(tmp_path):
    state = tmp_path / "state.json"
    notifier = FakeNotifier()
    first = send_notifications(_summary(), [notifier], state_path=state, silence_seconds=3600, now=1000.0)
    second = send_notifications(_summary(), [notifier], state_path=state, silence_seconds=3600, now=1600.0)
    third = send_notifications(_summary(), [notifier], state_path=state, silence_seconds=3600, now=5000.0)
    assert [first[0].status, second[0].status, third[0].status] == ["envoye", "silence", "envoye"]
    assert "10 min" in (second[0].reason or "")
    assert len(notifier.sent) == 2


def test_silence_zero_desactive_l_anti_repetition(tmp_path):
    notifier = FakeNotifier()
    for _ in range(2):
        send_notifications(_summary(), [notifier], state_path=tmp_path / "s.json", silence_seconds=0)
    assert len(notifier.sent) == 2


def test_echec_total_n_enregistre_pas_l_etat(tmp_path):
    state = tmp_path / "state.json"
    send_notifications(_summary(), [FakeNotifier(fail=NotifyError("delai depasse"))], state_path=state)
    assert not state.exists()
    ok = FakeNotifier()
    assert send_notifications(_summary(), [ok], state_path=state)[0].status == "envoye"


def test_etat_corrompu_ignore(tmp_path):
    state = tmp_path / "state.json"
    state.write_text("{pas du json", encoding="utf-8")
    assert send_notifications(_summary(), [FakeNotifier()], state_path=state)[0].status == "envoye"
    assert json.loads(state.read_text(encoding="utf-8"))


# -- echecs de canal --------------------------------------------------------------


def test_canal_en_echec_ne_bloque_pas_les_autres(tmp_path):
    good = FakeNotifier("courriel")
    results = send_notifications(
        _summary(),
        [FakeNotifier("slack", fail=NotifyError("delai depasse")), FakeNotifier("webhook", fail=RuntimeError()), good],
        state_path=tmp_path / "s.json",
    )
    assert [r.status for r in results] == ["echec", "echec", "envoye"]
    assert results[0].line() == "notification slack : echec, delai depasse"
    assert results[1].reason == "RuntimeError"
    assert len(good.sent) == 1


def test_tracabilite_dans_le_rapport():
    sr = SecurityReport(dashboard=SecurityDashboard(score=73, level="critique"))
    sr.notifications = [DeliveryResult("slack", "echec", "delai depasse").to_dict()]
    text = "\n".join(format_security_report(sr))
    assert "-- Notifications --" in text
    assert "notification slack : echec, delai depasse" in text
    assert security_report_to_dict(sr)["notifications"][0]["status"] == "echec"
    html = render_security_html(sr)
    assert '<ul id="notifications"><li>notification slack : echec, delai depasse</li></ul>' in html
    assert 'id="notifications"' not in render_security_html(SecurityReport())
    # sans notification demandee, pas de section
    assert "Notifications" not in "\n".join(format_security_report(SecurityReport()))


# -- configuration des canaux --------------------------------------------------------


def test_canaux_absents_signales_non_configures():
    notifiers, lines = notifiers_from_config(NotifyConfig(), env={})
    assert notifiers == []
    assert [(r.channel, r.status) for r in lines] == [
        ("webhook", "non_configure"),
        ("slack", "non_configure"),
        ("courriel", "non_configure"),
    ]


def test_priorite_cli_puis_environnement_puis_fichier():
    cfg = NotifyConfig(webhook="https://fichier.example/h", slack_webhook="https://fichier.example/s")
    env = {"NETCROSS_SLACK_WEBHOOK": "https://env.example/s"}
    notifiers, _ = notifiers_from_config(cfg, webhook="https://cli.example/h", env=env)
    urls = {n.name: n.url for n in notifiers}
    assert urls == {"webhook": "https://cli.example/h", "slack": "https://env.example/s"}


def test_url_non_http_refusee():
    _, lines = notifiers_from_config(NotifyConfig(), webhook="file:///etc/passwd", env={})
    assert lines[0].channel == "webhook" and lines[0].status == "echec"
    assert "configuration invalide" in (lines[0].reason or "")


def test_courriel_sans_serveur_smtp_signale():
    _, lines = notifiers_from_config(NotifyConfig(), email_to="soc@example.org", env={})
    email = next(r for r in lines if r.channel == "courriel")
    assert email.status == "echec" and "SMTP" in (email.reason or "")


def test_section_notify_du_fichier_de_configuration(tmp_path):
    cfg_file = tmp_path / ".netcross.toml"
    cfg_file.write_text(
        '[notify]\nslack_webhook = "https://hooks.example/s"\nsmtp_host = "smtp.example"\n'
        "smtp_port = 2525\nsmtp_starttls = false\nsilence_hours = 6\n",
        encoding="utf-8",
    )
    cfg = load_config(cfg_file).notify
    assert cfg.slack_webhook == "https://hooks.example/s"
    assert (cfg.smtp_host, cfg.smtp_port, cfg.smtp_starttls, cfg.silence_hours) == ("smtp.example", 2525, False, 6.0)
    assert "password" not in repr(NotifyConfig(smtp_password="s3cret"))


# -- aucun appel reseau sans seuil ---------------------------------------------------


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*_a, **_k):
        raise AssertionError("appel reseau interdit")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def test_sans_seuil_aucun_canal_ni_appel_reseau(no_network):
    called = []
    cfg = NotifyConfig(webhook="https://hooks.example/h", slack_webhook="https://hooks.example/s")
    assert run_notifications(called.append, threshold=None, cfg=cfg, env={}) == []
    assert called == []  # le resume n'est meme pas construit


# -- transports reels (serveur HTTP local, SMTP simule) --------------------------------


class _Recorder(BaseHTTPRequestHandler):
    bodies: ClassVar[list] = []
    codes: ClassVar[list] = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        type(self).bodies.append(json.loads(self.rfile.read(length)))
        code = type(self).codes.pop(0) if type(self).codes else 200
        self.send_response(code)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_a):
        pass


@pytest.fixture
def http_server():
    _Recorder.bodies, _Recorder.codes = [], []
    server = HTTPServer(("127.0.0.1", 0), _Recorder)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, _Recorder
    server.shutdown()
    server.server_close()


def _url(server):
    return f"http://127.0.0.1:{server.server_address[1]}/hook"


def test_webhook_envoie_le_resume_json(http_server):
    server, rec = http_server
    assert WebhookNotifier(_url(server)).send(_summary())
    body = rec.bodies[0]
    assert body["source"] == "netcross"
    assert body["level"] == "critique" and body["score"] == 73
    assert body["by_severity"]["critique"] == 1


def test_webhook_http_erreur_leve_un_motif(http_server):
    server, rec = http_server
    rec.codes = [500]
    with pytest.raises(NotifyError, match="HTTP 500"):
        WebhookNotifier(_url(server)).send(_summary())


def test_webhook_injoignable_leve_un_motif():
    # port 9 (discard) ferme en local : connexion refusee
    with pytest.raises(NotifyError, match="injoignable"):
        WebhookNotifier("http://127.0.0.1:9/hook", timeout=2).send(_summary())


def test_slack_block_kit_puis_repli_texte(http_server):
    server, rec = http_server
    notifier = SlackNotifier(_url(server))
    assert notifier.send(_summary())
    assert rec.bodies[0]["blocks"][0]["type"] == "header"
    assert "Netcross" in rec.bodies[0]["text"]
    assert notifier.degraded is False

    rec.bodies.clear()
    rec.codes = [400, 200]
    degraded = SlackNotifier(_url(server))
    assert degraded.send(_summary())
    assert "blocks" in rec.bodies[0] and "blocks" not in rec.bodies[1]
    assert degraded.degraded is True
    results = send_notifications(_summary(), [SlackNotifier(_url(server))], silence_seconds=0)
    assert results[0].status == "envoye"


class _FakeSMTP:
    instances: ClassVar[list] = []

    def __init__(self, host, port, timeout):
        self.host, self.port, self.timeout = host, port, timeout
        self.tls = self.login_args = None
        self.messages = []
        type(self).instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def starttls(self, context):
        self.tls = context

    def login(self, user, password):
        self.login_args = (user, password)

    def send_message(self, msg):
        self.messages.append(msg)


def test_courriel_smtp_starttls_et_identifiants_d_environnement(monkeypatch):
    _FakeSMTP.instances = []
    monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)
    env = {
        "NETCROSS_SMTP_HOST": "smtp.example",
        "NETCROSS_SMTP_PORT": "2525",
        "NETCROSS_SMTP_USER": "bot",
        "NETCROSS_SMTP_PASSWORD": "s3cret",
        "NETCROSS_SMTP_FROM": "netcross@example.org",
    }
    notifiers, _ = notifiers_from_config(NotifyConfig(), email_to="soc@example.org, astreinte@example.org", env=env)
    (email,) = notifiers
    assert isinstance(email, EmailNotifier)
    assert email.send(_summary())
    smtp = _FakeSMTP.instances[0]
    assert (smtp.host, smtp.port) == ("smtp.example", 2525)
    assert smtp.tls is not None and smtp.login_args == ("bot", "s3cret")
    msg = smtp.messages[0]
    assert msg["To"] == "soc@example.org, astreinte@example.org"
    assert "critique" in msg["Subject"] and "73/100" in msg["Subject"]
    assert "10.0.0.42" not in msg.get_content()


def test_courriel_echec_smtp_leve_un_motif(monkeypatch):
    class Refused(_FakeSMTP):
        def login(self, user, password):
            raise smtplib.SMTPAuthenticationError(535, b"no")

    monkeypatch.setattr(smtplib, "SMTP", Refused)
    email = EmailNotifier(host="smtp.example", recipients=("a@b.c",), sender="n@b.c", username="u", password="p")
    with pytest.raises(NotifyError, match="authentification SMTP refusee"):
        email.send(_summary())


# -- CLI -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--security-report", "--notify-slack", "https://hooks.example/s"], "sans --notify-on"),
        (["--security-report", "--notify-detail", "complet"], "sans --notify-on"),
        (["--notify-on", "critique"], "necessite --security-report"),
        (["--security-report", "--notify-on", "critique", "--notify-silence", "-1"], ">= 0"),
    ],
)
def test_cli_validations(monkeypatch, capsys, tmp_path, extra, message):
    pcap = tmp_path / "a.pcap"
    pcap.write_bytes(b"")
    monkeypatch.setattr(sys, "argv", ["cross_capture_analyzer_cli.py", "--capture", f"LAN={pcap}", *extra])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 1
    assert message in capsys.readouterr().err


def _args(**kw):
    base = {
        "notify_on": "elevee",
        "notify_webhook": None,
        "notify_slack": None,
        "notify_email": None,
        "notify_detail": "resume",
        "notify_silence": 0.0,
        "notify_state": None,
        "security_html": None,
        "json_report": None,
        "pdf_report": None,
    }
    base.update(kw)
    return Namespace(**base)


def test_cli_envoie_et_trace_chaque_canal(http_server, tmp_path, monkeypatch):
    server, rec = http_server
    monkeypatch.chdir(tmp_path)  # pas de .netcross.toml de l'utilisateur
    for var in ("NETCROSS_NOTIFY_WEBHOOK", "NETCROSS_SLACK_WEBHOOK", "NETCROSS_NOTIFY_EMAIL"):
        monkeypatch.delenv(var, raising=False)
    report = SimpleNamespace(security_findings=FINDINGS)
    sr = SecurityReport(dashboard=SecurityDashboard(score=73, level="critique"))
    args = _args(
        notify_webhook=_url(server),
        notify_slack="http://127.0.0.1:9/ferme",
        notify_state=str(tmp_path / "state.json"),
        json_report="rapport.json",
    )
    lines = cli._send_notifications(args, report, sr)
    by_channel = {line["channel"]: line for line in lines}
    assert by_channel["webhook"]["status"] == "envoye"
    assert by_channel["slack"]["status"] == "echec"
    assert by_channel["courriel"]["status"] == "non_configure"
    assert rec.bodies[0]["report_path"].endswith("rapport.json")
