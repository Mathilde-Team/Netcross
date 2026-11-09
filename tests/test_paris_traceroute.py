# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests purs du contrat Scamper : jamais de sonde depuis cette sélection."""

import json
import shlex
import subprocess
from dataclasses import replace
from datetime import datetime
from types import SimpleNamespace

import pytest

from netcross_core.active import paris_traceroute as paris
from netcross_core.active.planner import PARIS_TRACEROUTE, FiveTuple, ProposedMeasurement


def flux(proto="UDP"):
    icmp = proto.startswith("ICMP")
    ipv6 = proto == "ICMPv6"
    return FiveTuple(
        proto,
        "2001:db8::1" if ipv6 else "192.0.2.1",
        None if icmp else 49000,
        "2001:db8::2" if ipv6 else "198.51.100.2",
        None if icmp else 33435,
    )


def native(flow=None, **overrides):
    flow = flow or flux()
    result = {
        "type": "trace",
        "method": {"UDP": "udp-paris", "TCP": "tcp", "ICMP": "icmp-echo-paris", "ICMPv6": "icmp-echo-paris"}[
            flow.proto
        ],
        "src": flow.src,
        "dst": flow.dst,
        "sport": flow.sport,
        "dport": flow.dport,
        "probe_count": 2,
        "stop_reason": "COMPLETED",
        "hops": [{"addr": "192.0.2.254", "probe_ttl": 1}, {"addr": flow.dst, "probe_ttl": 2}],
    }
    return {**result, **overrides}


@pytest.fixture
def backend(monkeypatch):
    state = SimpleNamespace(stdout=json.dumps(native()), stderr="", returncode=0, calls=[], error=None)
    monkeypatch.setattr(paris.shutil, "which", lambda _name: "/outil/scamper")

    def run(command, **kwargs):
        state.calls.append((command, kwargs))
        if state.error:
            raise state.error
        return state

    monkeypatch.setattr(paris.subprocess, "run", run)
    return state


@pytest.mark.parametrize(
    ("proto", "command_method"),
    [("UDP", "udp-paris"), ("TCP", "tcp"), ("ICMP", "icmp-paris"), ("ICMPv6", "icmp-paris")],
)
def test_commande_paris_flux_constant_sans_shell_et_sortie_structuree(backend, proto, command_method):
    flow = flux(proto)
    backend.stdout = '\n{"type":"cycle-start"}\n' + json.dumps(native(flow)) + '\n{"type":"cycle-stop"}\n'
    result = paris.mesurer(flow)
    assert result.statut == "ok" and result.envoyees == 2
    assert result.message == "COMPLETED"
    command, options = backend.calls[0]
    assert command[:6] == ["/outil/scamper", "-p", "10", "-O", "json", "-I"]
    trace = shlex.split(command[-1])
    assert trace[trace.index("-P") + 1] == command_method
    assert trace[trace.index("-S") + 1] == flow.src and trace[-1] == flow.dst
    assert trace[trace.index("-s") + 1] == str(flow.sport or 33436)
    assert trace[trace.index("-d") + 1] == str(flow.dport or 33435)
    assert trace[trace.index("-N") + 1] == "1"
    assert trace[trace.index("-G") + 1] == "1"
    assert trace[trace.index("-W") + 1] == "11"
    assert trace[trace.index("-f") + 1] == "1"
    assert options["shell"] is False and options["check"] is False
    assert options["timeout"] > 30 and options["capture_output"] is True
    assert datetime.fromisoformat(result.debut).utcoffset().total_seconds() == 0
    document = result.to_dict()
    assert document["type"] == PARIS_TRACEROUTE
    assert document["flux"]["dst"] == flow.dst
    assert document["donnees"]["hops"][1]["probe_ttl"] == 2
    json.dumps(document, allow_nan=False)


@pytest.mark.parametrize("proto", ["ICMP", "ICMPv6"])
@pytest.mark.parametrize("method", ["icmp-echo", "icmp-paris"])
def test_icmp_natif_non_paris_ou_nom_de_commande_refuse(backend, proto, method):
    backend.stdout = json.dumps(native(flux(proto), method=method))
    result = paris.mesurer(flux(proto))
    assert result.statut == "erreur" and result.envoyees is None
    assert "méthode native" in result.message


def test_budget_configurable_et_silence_persistant(backend):
    backend.stdout = json.dumps(native(stop_reason="GAPLIMIT"))
    config = paris.Parametres(max_ttl=12, tentatives=3, debit_max=3, timeout=2, silence_max=2)
    result = paris.mesurer(flux(), config)
    assert result.statut == "ok" and result.message == "GAPLIMIT"
    command = backend.calls[0][0]
    assert command[2] == "3"
    for option in ("-m 12", "-q 3", "-g 2", "-w 2", "-W 35"):
        assert option in command[-1]


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("max_ttl", 0),
        ("max_ttl", 256),
        ("tentatives", 4),
        ("debit_max", 0),
        ("debit_max", 11),
        ("timeout", 0),
        ("timeout", 11),
        ("silence_max", 1),
        ("silence_max", 21),
        ("debit_max", True),
        ("tentatives", 1.5),
    ],
)
def test_parametres_bornes(name, value):
    with pytest.raises(paris.ParisError, match=name):
        paris.Parametres(**{name: value})


@pytest.mark.parametrize(
    "changes",
    [
        {"proto": "SCTP"},
        {"src": "host.example"},
        {"src": "192.0.2.1 -P tcp"},
        {"dst": "2001:db8::1"},
        {"dst": "224.0.0.1"},
        {"src": "0.0.0.0"},
        {"dst": "255.255.255.255"},
        {"src": "fe80::1%eth0", "dst": "fe80::2%eth0"},
        {"proto": "ICMP", "sport": None, "dport": None, "src": "2001:db8::1", "dst": "2001:db8::2"},
        {"proto": "ICMPv6", "sport": None, "dport": None},
        {"proto": "ICMP"},
        {"sport": None},
        {"dport": 0},
        {"sport": True},
        {"dport": 65536},
    ],
)
def test_flux_invalides_refuses_avant_toute_execution(backend, changes):
    with pytest.raises(paris.ParisError):
        paris.mesurer(replace(flux(), **changes))
    assert backend.calls == []


def test_binaire_absent_et_nombre_zero_certain(backend, monkeypatch):
    monkeypatch.setattr(paris.shutil, "which", lambda _name: None)
    result = paris.mesurer(flux())
    assert result.statut == "indisponible" and result.envoyees == 0
    assert "installer" in result.message
    assert backend.calls == []


@pytest.mark.parametrize(
    "error",
    [
        PermissionError("Operation not permitted"),
        FileNotFoundError("binaire disparu"),
        subprocess.TimeoutExpired("scamper", 1),
    ],
)
def test_erreurs_processus_jamais_faux_zero(backend, error):
    backend.error = error
    result = paris.mesurer(flux())
    assert result.envoyees is None and result.statut != "ok"
    if isinstance(error, OSError):
        assert "CAP_NET_RAW" in result.message


def test_backend_nonzero_et_erreur_native_sont_explicites(backend):
    backend.returncode, backend.stderr = 1, "raw socket: Operation not permitted"
    result = paris.mesurer(flux())
    assert result.statut == "erreur" and result.envoyees is None
    assert "CAP_NET_RAW" in result.message and "Operation not permitted" in result.message
    backend.returncode = 0
    backend.stdout = json.dumps(native(probe_count=0, stop_reason="ERROR", hops=[]))
    result = paris.mesurer(flux())
    assert result.statut == "erreur" and result.envoyees == 0 and "CAP_NET_RAW" in result.message


@pytest.mark.parametrize(
    "overrides",
    [
        {"src": "192.0.2.3"},
        {"dst": "198.51.100.3"},
        {"method": "udp"},
        {"sport": 12},
        {"dport": 13},
        {"probe_count": None},
        {"probe_count": True},
        {"probe_count": -1},
        {"probe_count": 31},
        {"stop_reason": None},
        {"hops": {}},
        {"hops": [None]},
        {"hops": [{}]},
        {"hops": [{"probe_ttl": True}]},
        {"hops": [{"probe_ttl": 31}]},
    ],
)
def test_resultat_hors_contrat_refuse(backend, overrides):
    backend.stdout = json.dumps(native(**overrides))
    result = paris.mesurer(flux())
    assert result.statut == "erreur" and result.envoyees is None
    assert "non vérifiable" in result.message


@pytest.mark.parametrize("output", ["", "[]", '{"type":"trace"}\n{"type":"trace"}', "pas du JSON", "NaN"])
def test_json_invalide_ou_nombre_de_mesures_incorrect(backend, output):
    backend.stdout = output
    assert paris.mesurer(flux()).statut == "erreur"


def test_proposition_explicite_et_journal_de_mesure(backend, monkeypatch):
    logs = []
    monkeypatch.setattr(paris.logger, "info", lambda message, *args: logs.append(message.format(*args)))
    proposal = ProposedMeasurement(PARIS_TRACEROUTE, flux(), "udp", 33435, "pertes")
    result = paris.mesurer_proposition(proposal)
    assert result.envoyees == 2
    assert len(logs) == 2 and all("198.51.100.2" in message for message in logs)
    assert result.debut in logs[0] and "budget_sondes=30" in logs[0] and "sondes_envoyees=2" in logs[1]
    proposal.kind = "twamp_light"
    with pytest.raises(paris.ParisError, match="proposition"):
        paris.mesurer_proposition(proposal)
