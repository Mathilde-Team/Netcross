# SPDX-License-Identifier: GPL-3.0-or-later
"""Sources de capture distantes (issue #166) : rpcap://, sshdump:// (ssh://),
pipe:// -- analyse des URL, arguments tshark (subprocess simule), CLI et GUI.
tshark n'est jamais lance : subprocess.Popen est remplace."""

from __future__ import annotations

import io
import os
import sys

import pytest

import cross_capture_analyzer_cli as analyzer_cli
import cross_capture_diff_cli as diff_cli
from netcross_gtk4.live_capture_points import invalid_sources
from pcap_parser import capture as capture_mod
from pcap_parser.ek_source import redact_args
from pcap_parser.remote import (
    ENV_RPCAP_PASSWORD,
    ENV_SSH_PASSWORD,
    CaptureSourceError,
    is_source_url,
    parse_source,
    source_display,
    split_live_target,
)

# ---------------------------------------------------------------------------
# parse_source
# ---------------------------------------------------------------------------


def test_interface_locale_inchangee():
    src = parse_source("eth0", env={})
    assert (src.kind, src.interface, src.extra_args, src.is_remote) == ("local", "eth0", (), False)


def test_rpcap_port_par_defaut_et_explicite():
    assert parse_source("rpcap://10.0.0.5/eth0", env={}).interface == "rpcap://10.0.0.5:2002/eth0"
    src = parse_source("rpcap://capteur.lan:3000/eth1", env={})
    assert src.interface == "rpcap://capteur.lan:3000/eth1"
    assert src.kind == "rpcap" and src.is_remote and src.extra_args == ()


def test_rpcap_ipv6_entre_crochets():
    src = parse_source("rpcap://[2001:db8::1]:2002/eth0", env={})
    assert src.interface == "rpcap://[2001:db8::1]:2002/eth0"


def test_rpcap_interface_windows_distante():
    src = parse_source("rpcap://10.0.0.5/\\Device\\NPF_{0A1B2C3D-0000}", env={})
    assert src.interface.endswith("/\\Device\\NPF_{0A1B2C3D-0000}")


def test_rpcap_authentification_par_variable_d_environnement():
    src = parse_source("rpcap://admin@10.0.0.5/eth0", env={ENV_RPCAP_PASSWORD: "s3cret"})
    assert src.extra_args == ("-A", "admin:s3cret")
    assert "s3cret" not in src.display
    assert src.display == "rpcap://admin@10.0.0.5:2002/eth0"


def test_rpcap_utilisateur_sans_mot_de_passe_refuse():
    with pytest.raises(CaptureSourceError, match=ENV_RPCAP_PASSWORD):
        parse_source("rpcap://admin@10.0.0.5/eth0", env={})


@pytest.mark.parametrize("url", ["rpcap://admin:pw@10.0.0.5/eth0", "sshdump://root:pw@routeur/eth0"])
def test_mot_de_passe_dans_l_url_refuse(url):
    with pytest.raises(CaptureSourceError, match="mot de passe interdit"):
        parse_source(url, env={})


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("rpcap://10.0.0.5", "interface distante manquante"),
        ("rpcap://10.0.0.5/", "interface distante manquante"),
        ("rpcap:///eth0", "hote manquant"),
        ("rpcap://10.0.0.5:0/eth0", "port invalide"),
        ("rpcap://10.0.0.5:99999/eth0", "port invalide"),
        ("rpcap://10.0.0.5:abc/eth0", "port invalide"),
        ("rpcap://hote_invalide!/eth0", "hote invalide"),
        ("rpcap://[zz::1]/eth0", "IPv6 invalide"),
        ("rpcap://[2001:db8::1/eth0", "IPv6 non fermee"),
        ("rpcap://10.0.0.5/-w", "nom d'interface invalide"),
        ("rpcap://10.0.0.5/eth0 -w x", "nom d'interface invalide"),
        ("rpcap://-oops@10.0.0.5/eth0", "utilisateur invalide"),
        ("rpcap://10.0.0.5/eth0?x=1", "n'accepte pas de parametres"),
        ("ftp://10.0.0.5/eth0", "schema de source inconnu"),
        ("-i", "nom d'interface invalide"),
        ("", "interface manquante"),
    ],
)
def test_urls_invalides(url, message):
    with pytest.raises(CaptureSourceError, match=message):
        parse_source(url, env={})


def test_sshdump_preferences_extcap():
    src = parse_source("sshdump://capture@routeur.lan:2222/br-lan?priv=sudo", env={})
    assert src.kind == "sshdump" and src.interface == "sshdump" and src.is_remote
    prefs = [src.extra_args[i + 1] for i in range(0, len(src.extra_args), 2)]
    assert all(src.extra_args[i] == "-o" for i in range(0, len(src.extra_args), 2))
    assert prefs == [
        "extcap.sshdump.remotehost:routeur.lan",
        "extcap.sshdump.remoteport:2222",
        "extcap.sshdump.remoteusername:capture",
        "extcap.sshdump.remoteinterface:br-lan",
        "extcap.sshdump.remotepriv:sudo",
    ]
    assert src.display == "sshdump://capture@routeur.lan:2222/br-lan?priv=sudo"


def test_ssh_alias_de_sshdump_port_22():
    src = parse_source("ssh://10.1.1.1/eth0", env={})
    assert src.kind == "sshdump"
    assert "extcap.sshdump.remoteport:22" in src.extra_args
    assert not any("remoteusername" in a for a in src.extra_args)  # agent / ~/.ssh/config


def test_sshdump_cle(tmp_path):
    key = tmp_path / "id_ed25519"
    key.write_text("cle")
    src = parse_source(f"sshdump://root@routeur/eth0?key={key}", env={})
    assert f"extcap.sshdump.sshkey:{key}" in src.extra_args
    with pytest.raises(CaptureSourceError, match="cle SSH introuvable"):
        parse_source(f"sshdump://root@routeur/eth0?key={tmp_path / 'absente'}", env={})


def test_sshdump_parametres_invalides():
    with pytest.raises(CaptureSourceError, match="inconnu"):
        parse_source("sshdump://routeur/eth0?cmd=rm", env={})
    with pytest.raises(CaptureSourceError, match="priv="):
        parse_source("sshdump://routeur/eth0?priv=su", env={})


def test_sshdump_mot_de_passe_par_environnement_hors_affichage():
    src = parse_source("sshdump://root@routeur/eth0", env={ENV_SSH_PASSWORD: "pw!"})
    assert "extcap.sshdump.remotepassword:pw!" in src.extra_args
    assert "pw!" not in src.display


def test_pipe_entree_standard():
    for text in ("-", "pipe://-"):
        src = parse_source(text, env={})
        assert (src.kind, src.interface, src.uses_stdin) == ("pipe", "-", True)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="mkfifo indisponible")
def test_pipe_tube_nomme(tmp_path):
    fifo = tmp_path / "flux"
    os.mkfifo(fifo)
    src = parse_source(f"pipe://{fifo}", env={})
    assert (src.kind, src.interface, src.uses_stdin) == ("pipe", str(fifo), False)


def test_pipe_invalides(tmp_path):
    fichier = tmp_path / "trace.pcap"
    fichier.write_bytes(b"")
    with pytest.raises(CaptureSourceError, match="pas un tube nomme"):
        parse_source(f"pipe://{fichier}", env={})
    with pytest.raises(CaptureSourceError, match="introuvable"):
        parse_source(f"pipe://{tmp_path / 'absent'}", env={})
    with pytest.raises(CaptureSourceError, match="chemin absolu"):
        parse_source("pipe://relatif", env={})


def test_is_source_url_et_affichage():
    assert is_source_url("RPCAP://h/eth0") and is_source_url("pipe://-")
    assert not is_source_url("eth0") and not is_source_url("http://x/y")
    assert source_display("rpcap://h/eth0") == "rpcap://h:2002/eth0"
    assert source_display("ftp://x") == "ftp://x"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("eth0", ("eth0", None)),
        ("eth0:tcp port 443", ("eth0", "tcp port 443")),
        ("eth0:host 2001:db8::1", ("eth0", "host 2001:db8::1")),
        ("rpcap://10.0.0.5:2002/eth0", ("rpcap://10.0.0.5:2002/eth0", None)),
        ("rpcap://10.0.0.5:2002/eth0:tcp port 80", ("rpcap://10.0.0.5:2002/eth0", "tcp port 80")),
        ("rpcap://[2001:db8::1]:2002/eth0:udp", ("rpcap://[2001:db8::1]:2002/eth0", "udp")),
        ("sshdump://u@h:22/eth0?priv=sudo:port 53", ("sshdump://u@h:22/eth0?priv=sudo", "port 53")),
        ("pipe://-:tcp", ("pipe://-", "tcp")),
        ("pipe:///tmp/f:icmp", ("pipe:///tmp/f", "icmp")),
    ],
)
def test_split_live_target(text, expected):
    assert split_live_target(text) == expected


# ---------------------------------------------------------------------------
# Arguments tshark (subprocess simule)
# ---------------------------------------------------------------------------


class _FakePopen:
    launched: list = []  # noqa: RUF012 -- reinitialise par la fixture

    def __init__(self, args, **_kwargs):
        _FakePopen.launched.append(list(args))
        self.stdout = io.StringIO("")
        self.stderr = io.StringIO("")
        self.returncode = 0

    def poll(self):
        return self.returncode

    def terminate(self):
        pass

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        pass


@pytest.fixture
def fake_tshark(monkeypatch):
    _FakePopen.launched = []
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/tshark")
    monkeypatch.setattr("subprocess.Popen", _FakePopen)
    return _FakePopen.launched


def test_iter_live_rpcap_avec_authentification(fake_tshark, monkeypatch):
    monkeypatch.setenv(ENV_RPCAP_PASSWORD, "pw")
    assert list(capture_mod.iter_live("rpcap://admin@10.0.0.5/eth0", bpf_filter="tcp")) == []
    (args,) = fake_tshark
    assert args[args.index("-i") + 1] == "rpcap://10.0.0.5:2002/eth0"
    assert args[args.index("-A") + 1] == "admin:pw"
    assert args[args.index("-f") + 1] == "tcp"  # filtre applique cote rpcapd


def test_iter_live_sshdump(fake_tshark, monkeypatch):
    monkeypatch.delenv(ENV_SSH_PASSWORD, raising=False)
    list(capture_mod.iter_live("ssh://root@10.0.0.1/eth0"))
    (args,) = fake_tshark
    assert args[args.index("-i") + 1] == "sshdump"
    assert "extcap.sshdump.remotehost:10.0.0.1" in args
    assert "extcap.sshdump.remoteinterface:eth0" in args


def test_iter_live_pipe_stdin(fake_tshark):
    list(capture_mod.iter_live("pipe://-"))
    (args,) = fake_tshark
    assert args[args.index("-i") + 1] == "-"


def test_iter_live_local_sans_argument_supplementaire(fake_tshark):
    list(capture_mod.iter_live("eth0"))
    (args,) = fake_tshark
    assert "-A" not in args and not any(a.startswith("extcap.") for a in args)


def test_iter_live_url_invalide_ne_lance_rien(fake_tshark):
    with pytest.raises(CaptureSourceError):
        list(capture_mod.iter_live("rpcap://10.0.0.5"))
    assert fake_tshark == []


def test_iter_live_multi_mixe_local_et_distant(fake_tshark):
    assert list(capture_mod.iter_live_multi([("LAN", "eth0"), ("DMZ", "rpcap://10.0.0.5/eth1")])) == []
    interfaces = sorted(args[args.index("-i") + 1] for args in fake_tshark)
    assert interfaces == ["eth0", "rpcap://10.0.0.5:2002/eth1"]


def test_iter_live_multi_valide_des_l_appel(fake_tshark):
    with pytest.raises(ValueError, match="entree standard"):
        capture_mod.iter_live_multi([("A", "-"), ("B", "pipe://-")])
    with pytest.raises(ValueError, match="port invalide"):
        capture_mod.iter_live_multi([("A", "rpcap://h:0/eth0")])
    assert fake_tshark == []


def test_redact_args_masque_les_secrets():
    args = ["tshark", "-i", "x", "-A", "admin:pw", "-o", "extcap.sshdump.remotepassword:pw", "-o", "tcp.x:TRUE"]
    redacted = redact_args(args)
    assert "pw" not in " ".join(redacted).replace("remotepassword", "")
    assert redacted[4] == "admin:***"
    assert redacted[6] == "extcap.sshdump.remotepassword:***"
    assert redacted[8] == "tcp.x:TRUE"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cli", [analyzer_cli, diff_cli])
def test_cli_parse_live_spec_url(cli):
    assert cli._parse_live_spec("DMZ:rpcap://10.0.0.5:2002/eth0:tcp port 80") == (
        "DMZ",
        "rpcap://10.0.0.5:2002/eth0",
        "tcp port 80",
    )
    assert cli._parse_live_spec("LAN:eth0") == ("LAN", "eth0", None)
    assert cli._parse_live_spec("LAN:eth0:host 2001:db8::1") == ("LAN", "eth0", "host 2001:db8::1")
    assert cli._parse_live_spec("R:-") == ("R", "-", None)


@pytest.mark.parametrize("cli", [analyzer_cli, diff_cli])
@pytest.mark.parametrize("spec", ["DMZ:rpcap://10.0.0.5", "LAN", ":eth0", "X:rpcap://a:pw@h/eth0"])
def test_cli_parse_live_spec_invalide(cli, spec, capsys):
    with pytest.raises(SystemExit):
        cli._parse_live_spec(spec)
    assert "pw" not in capsys.readouterr().err.replace("pipe", "")


@pytest.mark.parametrize("cli", [analyzer_cli, diff_cli])
def test_cli_une_seule_entree_standard(cli, capsys):
    cli._check_single_stdin([("A", "-", None), ("B", "eth0", None)])
    with pytest.raises(SystemExit):
        cli._check_single_stdin([("A", "-", None), ("B", "pipe://-", None)])
    assert "entree standard" in capsys.readouterr().err


def test_cli_analyzer_live_distant_de_bout_en_bout(monkeypatch, fake_tshark, capsys):
    """--live avec une URL rpcap : la capture (vide) est lancee avec les bons
    arguments tshark et l'analyse se termine sans erreur."""
    monkeypatch.setattr(
        sys, "argv", ["netcross-analyze", "--live", "DMZ:rpcap://10.0.0.5/eth0", "--live-duration", "1"]
    )
    try:
        analyzer_cli.main()
    except SystemExit as exc:  # certains chemins de sortie terminent par sys.exit(0)
        assert exc.code in (0, None)
    assert any(args[args.index("-i") + 1] == "rpcap://10.0.0.5:2002/eth0" for args in fake_tshark)


def test_cli_analyzer_live_url_invalide(monkeypatch, fake_tshark, capsys):
    monkeypatch.setattr(sys, "argv", ["netcross-analyze", "--live", "DMZ:rpcap://10.0.0.5:0/eth0"])
    with pytest.raises(SystemExit) as exc:
        analyzer_cli.main()
    assert exc.value.code == 1
    assert "port invalide" in capsys.readouterr().err
    assert fake_tshark == []


# ---------------------------------------------------------------------------
# GUI (logique sans GTK)
# ---------------------------------------------------------------------------


def test_gui_invalid_sources():
    points = [
        ("LAN", "eth0", None),
        ("DMZ", "rpcap://10.0.0.5/eth0", None),
        ("KO", "rpcap://10.0.0.5", None),
        ("VIDE", "", None),
    ]
    errors = invalid_sources(points)
    assert len(errors) == 1 and errors[0].startswith("KO : ")
    errors = invalid_sources([("A", "-", None), ("B", "pipe://-", "tcp")])
    assert errors == ["une seule source peut lire l'entree standard (pipe://-) : A, B"]
    assert invalid_sources([("A", "eth0", None)]) == []
