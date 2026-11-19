# SPDX-License-Identifier: GPL-3.0-or-later
"""Issue #1107 : paquets de déploiement de la sonde.

Vérifie statiquement les trois livrables — unité systemd durcie, image
conteneur minimale, workflow de construction en CI — et le guide de
déploiement. La construction réelle de l'image est couverte par le
workflow `Image de sonde` (ci-image-sonde.yml) ; ces tests garantissent
que rien ne régresse silencieusement entre deux CI.
"""

from __future__ import annotations

import configparser
import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent

UNITE = ROOT / "deploy/systemd/netcross-probe.service"
CONF = ROOT / "deploy/systemd/netcross-probe.conf"
DOCKERFILE = ROOT / "deploy/conteneur/Dockerfile"
WORKFLOW = ROOT / ".github/workflows/ci-image-sonde.yml"
GUIDE = ROOT / "docs/deploiement-sonde.md"

DURCISSEMENTS = (
    "NoNewPrivileges=yes",
    "DynamicUser=yes",
    "StateDirectory=netcross-probe",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "PrivateTmp=yes",
    "PrivateDevices=yes",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectControlGroups=yes",
    "ProtectClock=yes",
    "ProtectHostname=yes",
    "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN",
    "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN",
    "RestrictAddressFamilies=AF_INET AF_INET6 AF_PACKET AF_UNIX",
    "SystemCallFilter=@system-service",
    "SystemCallArchitectures=native",
    "LockPersonality=yes",
    "MemoryDenyWriteExecute=yes",
    "RestrictRealtime=yes",
    "RestrictSUIDSGID=yes",
)


def _directives_service() -> dict[str, str]:
    """Lit l'unité et fusionne les directives multi-lignes."""
    contenu = UNITE.read_text(encoding="utf-8")
    contenu = re.sub(r"\\\n\s*", " ", contenu)
    analyseur = configparser.ConfigParser(strict=False, delimiters=("="))
    analyseur.optionxform = str  # les directives systemd sont sensibles à la casse
    analyseur.read_string(contenu)
    return dict(analyseur["Service"])


def test_unite_systemd_est_durcie():
    service = _directives_service()
    for durcissement in DURCISSEMENTS:
        assert service.get(durcissement.split("=", 1)[0], "").strip() == durcissement.split("=", 1)[1], durcissement
    # pas de capacités au-delà de la capture : le bounding set est fermé
    assert set(service["CapabilityBoundingSet"].split()) == {"CAP_NET_RAW", "CAP_NET_ADMIN"}


def test_unite_systemd_lance_servir_sans_tampon_fixe():
    service = _directives_service()
    assert service["ExecStart"].startswith("/usr/bin/netcross-probe servir")
    assert "--interface ${NETCROSS_PROBE_INTERFACE}" in service["ExecStart"]
    assert "--identite /var/lib/netcross-probe/identite" in service["ExecStart"]
    assert "--dossier /var/lib/netcross-probe/tampon" in service["ExecStart"]
    # redémarrage automatique, jamais considered successful sans écoute
    assert service["Restart"] == "on-failure"


def test_unite_systemd_variables_definies_par_le_conf():
    service = _directives_service()
    utilisees = set(re.findall(r"\$\{(NETCROSS_PROBE_[A-Z_]+)\}", service["ExecStart"]))
    conf = CONF.read_text(encoding="utf-8")
    definies = set(re.findall(r"^(NETCROSS_PROBE_[A-Z_]+)=", conf, re.MULTILINE))
    assert utilisees <= definies, utilisees - definies
    # le jeton d'enrôlement reste optionnel : vide, --enrolement "" est
    # faux pour _commande_servir (if args.enrolement), l'inscription est sautée
    assert "NETCROSS_PROBE_JETON=" in conf
    assert "NETCROSS_PROBE_ENROLEMENT=" in conf


def test_unite_systemd_syntaxe_valide_si_systemd_analyze_present():
    if subprocess.run(["sh", "-c", "command -v systemd-analyze"], capture_output=True).returncode != 0:
        return  # pas de systemd ici : vérification statique uniquement
    resultat = subprocess.run(
        ["systemd-analyze", "verify", str(UNITE)],
        capture_output=True,
        text=True,
        check=False,
    )
    sortie = resultat.stdout + resultat.stderr
    # /usr/bin/netcross-probe n'existe pas sur la machine de test : cette
    # seule plainte est tolérée, toute autre est un défaut de syntaxe
    tolerees = [ligne for ligne in sortie.splitlines() if "is not executable" not in ligne]
    assert not [ligne for ligne in tolerees if "netcross-probe" in ligne], tolerees


def test_dockerfile_sonde_minimal():
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    # dépendances système : tshark (capture/découpe/fusion) + libpcap (BPF)
    assert "tshark" in dockerfile
    assert "libpcap" in dockerfile
    # pas de GTK ni d'API REST : l'image de la sonde n'est pas l'image d'analyse
    for absent in ("netcross_gtk4", "netcross_api", "netcross_ai", "netcross_report", "netcross_core"):
        assert absent not in dockerfile, absent
    # code réduit à l'agent et à la couche tampon qu'il importe
    assert "COPY src/netcross_probe/ /app/src/netcross_probe/" in dockerfile
    assert "COPY src/pcap_parser/ /app/src/pcap_parser/" in dockerfile
    # exécution sans privilèges, capacités passées par docker run
    assert re.search(r"^USER (?!root\b)\w+$", dockerfile, re.MULTILINE)
    assert 'ENTRYPOINT ["python3", "-m", "netcross_probe"]' in dockerfile
    # santé vérifiée
    assert "HEALTHCHECK" in dockerfile


def test_workflow_construit_et_controle_l_image():
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    declencheurs = workflow["on"]
    assert "deploy/**" in declencheurs["pull_request"]["paths"]
    assert "deploy/**" in declencheurs["push"]["paths"]
    etapes = workflow["jobs"]["image"]["steps"]
    construction = next(e for e in etapes if e["name"] == "Construction")
    assert "deploy/conteneur" in construction["run"]
    assert "docker build" in construction["run"]
    controle = next(e for e in etapes if e["name"].startswith("Contrôle"))
    assert "tshark" in controle["run"]
    assert "import netcross_probe, pcap_parser" in controle["run"]
    publication = next(e for e in etapes if e["name"] == "Push")
    assert publication["if"] == "github.event_name != 'pull_request'"


def test_guide_de_deploiement_complet():
    guide = GUIDE.read_text(encoding="utf-8")
    # les trois critères d'acceptation de l'issue
    assert "systemd" in guide
    assert "Dockerfile" in guide or "conteneur" in guide
    assert "netcross-probe.service" in guide
    assert "enrôlement" in guide or "enrolement" in guide
    assert "ghcr.io/mathilde-team/netcross-probe" in guide
    # paquets : les deux formats construits par le dépôt
    assert "build-deb" in guide
    assert "build-rpm" in guide
    # le durcissement est expliqué, pas juste subi
    assert "CAP_NET_RAW" in guide
    assert "DynamicUser" in guide


def test_guide_referencé_dans_la_navigation():
    mkdocs = (ROOT / "mkdocs.yml").read_text(encoding="utf-8")
    assert "deploiement-sonde.md" in mkdocs


def test_workflow_shlex_du_run_de_controle():
    """Le contrôle de l'image reste une commande shell bien formée."""
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    etapes = workflow["jobs"]["image"]["steps"]
    for etape in etapes:
        run = etape.get("run", "")
        assert run.count("'") % 2 == 0, etape["name"]
        # docker run de contrôle : ENTRYPOINT (python3 -m netcross_probe)
        # doit être neutralisé pour lancer bash
        if "Contrôle" in etape["name"]:
            assert "--entrypoint bash" in run
