# SPDX-License-Identifier: GPL-3.0-or-later
"""
Plugin d'exemple Netcross (issue #284) : detecteur minimal.

Signale toute session Telnet (TCP/23) -- protocole en clair, identifiants
lisibles sur le fil. Un detecteur de site ressemble a ceci : quelques
lignes, aucune modification du depot Netcross.

Utilisation :

    netcross-analyze --capture LAN=trace.pcap --security-report \\
        --plugin-path examples/plugins/detecteur_telnet.py --plugins telnet_clair

Contrat (docs/plugins.md) :
- `name` : identifiant a citer dans --plugins ;
- `analyse(contexte)` renvoie une liste de constats au schema de
  `security_findings` ; `contexte` est en LECTURE SEULE ;
- n'importer que la bibliotheque standard et `netcross_core`.
"""

from __future__ import annotations

TELNET_PORT = 23


class TelnetEnClair:
    name = "telnet_clair"

    def analyse(self, contexte):
        sessions = {}
        for pkt in contexte.packets:
            if pkt.proto != "TCP" or TELNET_PORT not in (pkt.sport, pkt.dport):
                continue
            client, serveur = (pkt.src, pkt.dst) if pkt.dport == TELNET_PORT else (pkt.dst, pkt.src)
            sessions.setdefault((client, serveur, pkt.point), 0)
            sessions[(client, serveur, pkt.point)] += 1
        return [
            {
                "category": "anomalie",
                "severity": "elevee",
                "detail": f"session Telnet en clair {client} -> {serveur} ({n} paquets)",
                "point": point,
                "host": serveur,
                "port": TELNET_PORT,
                "service": "Telnet",
            }
            for (client, serveur, point), n in sorted(sessions.items())
        ]


DETECTORS = [TelnetEnClair]
