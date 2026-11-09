# SPDX-License-Identifier: GPL-3.0-or-later
"""Intégration réelle isolée, appelée explicitement par le job Paris réseau.

Ce fichier n'est pas un test unitaire test_*.py : il exige root, iproute2,
iptables et Scamper. Le job dédié l'exécute sans skip ni réseau extérieur.
"""

import json
import os
import subprocess
import sys
import uuid

import pytest

# Exécuté DANS l'espace source. Les horodatages viennent de recvmsg et
# SO_TIMESTAMPNS, pas de l'ordonnancement du thread Python.
_PROGRAM = r"""
import json
import socket
import struct
import sys
import threading
from netcross_core.active.paris_traceroute import Parametres, mesurer
from netcross_core.active.planner import FiveTuple

proto = sys.argv[1]
flow = FiveTuple(proto, "192.0.2.2", None if proto == "ICMP" else 49000,
                 "198.51.100.2", None if proto == "ICMP" else 33435)
packets = []
stop = threading.Event()
receiver = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
receiver.bind(("c0", 0))
receiver.setsockopt(socket.SOL_SOCKET, 35, 1)  # Linux SO_TIMESTAMPNS
receiver.settimeout(0.05)

def listen():
    while True:
        try:
            data, ancillary, _flags, _addr = receiver.recvmsg(65535, 256)
        except socket.timeout:
            if stop.is_set():
                return
            continue
        if len(data) < 42 or data[12:14] != b"\x08\x00":
            continue
        source, target = socket.inet_ntoa(data[26:30]), socket.inet_ntoa(data[30:34])
        if source != flow.src or target != flow.dst:
            continue
        protocol = data[23]
        if protocol != {"TCP": 6, "UDP": 17, "ICMP": 1}[proto]:
            continue
        offset = 14 + (data[14] & 15) * 4
        timestamps = [struct.unpack("@ll", value[:16]) for level, kind, value in ancillary
                      if level == socket.SOL_SOCKET and kind == 35]
        assert len(timestamps) == 1, "horodatage noyau requis"
        seconds, nanos = timestamps[0]
        packet = {"source": source, "target": target, "proto": protocol,
                  "ttl": data[22], "ns": seconds * 1000000000 + nanos}
        if proto == "ICMP":
            packet["checksum"] = struct.unpack("!H", data[offset + 2:offset + 4])[0]
        else:
            packet["sport"], packet["dport"] = struct.unpack("!HH", data[offset:offset + 4])
        packets.append(packet)

listener = threading.Thread(target=listen, daemon=True)
listener.start()
try:
    result = mesurer(flow, Parametres(max_ttl=8, silence_max=2))
finally:
    stop.set()
    listener.join(timeout=3)
    receiver.close()
assert not listener.is_alive(), "écoute non terminée"
print(json.dumps({"result": result.to_dict(), "packets": packets}, allow_nan=False))
"""


def run(*args):
    return subprocess.run(list(args), check=True, text=True, capture_output=True, timeout=30)


@pytest.fixture
def lab():
    assert os.geteuid() == 0, "ce test dédié doit s'exécuter comme root en VM éphémère"
    suffix = uuid.uuid4().hex[:7]
    client, router, target = (f"nc-{suffix}-{role}" for role in ("c", "r", "d"))
    created = []
    try:
        for namespace in (client, router, target):
            run("ip", "netns", "add", namespace)
            created.append(namespace)
            run("ip", "-n", namespace, "link", "set", "lo", "up")
        for index, left, right, lname, rname in (
            (0, client, router, "c0", "r0"),
            (1, router, target, "r1", "d0"),
        ):
            a, b = f"na{index}{suffix}", f"nb{index}{suffix}"
            run("ip", "link", "add", a, "type", "veth", "peer", "name", b)
            run("ip", "link", "set", a, "netns", left)
            run("ip", "link", "set", b, "netns", right)
            run("ip", "-n", left, "link", "set", a, "name", lname)
            run("ip", "-n", right, "link", "set", b, "name", rname)
        for namespace, iface, address in (
            (client, "c0", "192.0.2.2/24"),
            (router, "r0", "192.0.2.1/24"),
            (router, "r1", "198.51.100.1/24"),
            (target, "d0", "198.51.100.2/24"),
        ):
            run("ip", "-n", namespace, "address", "add", address, "dev", iface)
            run("ip", "-n", namespace, "link", "set", iface, "up")
        run("ip", "-n", client, "route", "add", "default", "via", "192.0.2.1")
        run("ip", "-n", target, "route", "add", "default", "via", "198.51.100.1")
        run("ip", "netns", "exec", router, "sysctl", "-qw", "net.ipv4.ip_forward=1")
        # Le routeur n'a AUCUNE route par défaut ni interface vers l'hôte.
        assert run("ip", "-n", router, "route", "show", "default").stdout == ""
        yield client, router
    finally:
        for namespace in reversed(created):
            subprocess.run(["ip", "netns", "delete", namespace], check=False, capture_output=True, timeout=10)


def measure(namespace, proto):
    completed = subprocess.run(
        ["ip", "netns", "exec", namespace, sys.executable, "-c", _PROGRAM, proto],
        check=True,
        capture_output=True,
        text=True,
        timeout=90,
    )
    return json.loads(completed.stdout)


def verify_packets(document, proto, expected_ttls):
    result, packets = document["result"], document["packets"]
    assert result["statut"] == "ok", json.dumps(result, ensure_ascii=False)
    assert result["envoyees"] == len(packets) == len(expected_ttls)
    assert [packet["ttl"] for packet in packets] == expected_ttls
    assert all(packet["source"] == "192.0.2.2" and packet["target"] == "198.51.100.2" for packet in packets)
    assert all(b["ns"] - a["ns"] >= 100_000_000 for a, b in zip(packets, packets[1:], strict=False))
    if proto == "ICMP":
        assert len({packet["checksum"] for packet in packets}) == 1
    else:
        assert all(packet["sport"] == 49000 and packet["dport"] == 33435 for packet in packets)


@pytest.mark.parametrize("proto", ["TCP", "UDP", "ICMP"])
def test_chemin_reel_ttl_flux_et_debit(lab, proto):
    document = measure(lab[0], proto)
    verify_packets(document, proto, [1, 2])
    assert document["result"]["donnees"]["stop_reason"] == "COMPLETED"
    assert [hop["addr"] for hop in document["result"]["donnees"]["hops"]] == ["192.0.2.1", "198.51.100.2"]


def test_routeur_qui_perd_et_arret_au_silence_persistant(lab):
    run("ip", "netns", "exec", lab[1], "iptables", "-A", "FORWARD", "-j", "DROP")
    document = measure(lab[0], "UDP")
    verify_packets(document, "UDP", [1, 2, 3])
    assert document["result"]["donnees"]["stop_reason"] == "GAPLIMIT"
    assert [hop["addr"] for hop in document["result"]["donnees"]["hops"]] == ["192.0.2.1"]
