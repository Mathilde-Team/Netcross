# SPDX-License-Identifier: GPL-3.0-or-later
"""Vérifie le branchement de l'image et exécute les gardes apt sans réseau."""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
JOBS = WORKFLOW["jobs"]
CONTAINER_JOBS = ("quality", "gtk4", "couverture-combinee", "packaging", "i18n")
APT_STEPS = [
    (job_id, step) for job_id in CONTAINER_JOBS for step in JOBS[job_id]["steps"] if "apt-get" in step.get("run", "")
]


@pytest.mark.parametrize("job_id", CONTAINER_JOBS)
def test_jobs_utilisent_image_publiee_et_lecture_seule(job_id):
    container = JOBS[job_id]["container"]
    assert container["image"] == "ghcr.io/mathilde-team/netcross-ci:26.04"
    assert container["credentials"] == {
        "username": "${{ github.actor }}",
        "password": "${{ secrets.GITHUB_TOKEN }}",
    }
    assert WORKFLOW["permissions"] == {"contents": "read", "packages": "read"}


def _garde(script):
    debut = script.index("if ! dpkg-query ")
    fin = script.index("\nfi", debut) + len("\nfi")
    garde = script[debut:fin]
    assert garde.count("apt-get") == script.count("apt-get") == 2
    return garde


@pytest.fixture
def faux_systeme(tmp_path):
    """Simule dpkg/apt seulement, sans installer ni lire de credential."""
    executable = tmp_path / "bin"
    executable.mkdir()
    dpkg = executable / "dpkg-query"
    dpkg.write_text(
        '#!/bin/bash\nprintf "%s" "$STATUTS_DPKG"\nexit "$CODE_DPKG"\n',
        encoding="utf-8",
    )
    apt = executable / "apt-get"
    apt.write_text(
        '#!/bin/bash\nprintf "%s\\n" "$*" >> "$APPELS_APT"\nif [ "$1" = "$ECHEC_APT" ]; then exit 42; fi\n',
        encoding="utf-8",
    )
    dpkg.chmod(0o755)
    apt.chmod(0o755)
    appels = tmp_path / "apt.log"
    env = {
        "PATH": f"{executable}{os.pathsep}{os.defpath}",
        "APPELS_APT": str(appels),
        "ECHEC_APT": "",
        "CODE_DPKG": "0",
        "STATUTS_DPKG": "installed\ninstalled\n",
    }
    return env, appels


@pytest.mark.parametrize(("job_id", "step"), APT_STEPS, ids=[f"{job}-{i}" for i, (job, _) in enumerate(APT_STEPS)])
@pytest.mark.parametrize(
    ("statuts", "code_dpkg", "installe"),
    [
        ("installed\ninstalled\n", "0", False),
        ("config-files\n", "0", True),
        ("installed\nnot-installed\n", "0", True),
        ("", "1", True),
        ("installed\n", "2", True),
    ],
)
def test_gardes_apt_presence_absence_et_erreur(job_id, step, statuts, code_dpkg, installe, faux_systeme):
    env, appels = faux_systeme
    env.update(STATUTS_DPKG=statuts, CODE_DPKG=code_dpkg)
    result = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", _garde(step["run"])],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (job_id, result.stderr)
    if installe:
        lignes = appels.read_text(encoding="utf-8").splitlines()
        assert lignes[0] == "update -qq"
        assert lignes[1].startswith("install -y -qq ")
        assert len(lignes) == 2
    else:
        assert not appels.exists(), job_id


@pytest.mark.parametrize("echec", ["update", "install"])
@pytest.mark.parametrize(("job_id", "step"), APT_STEPS, ids=[f"{job}-{i}" for i, (job, _) in enumerate(APT_STEPS)])
def test_echec_apt_reste_bloquant(job_id, step, echec, faux_systeme):
    env, appels = faux_systeme
    env.update(STATUTS_DPKG="", CODE_DPKG="1", ECHEC_APT=echec)
    result = subprocess.run(
        ["bash", "-e", "-o", "pipefail", "-c", _garde(step["run"])],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 42, (job_id, result.stderr)
    lignes = appels.read_text(encoding="utf-8").splitlines()
    assert len(lignes) == (1 if echec == "update" else 2)


def test_image_fournit_tous_paquets_controles():
    dockerfile = (ROOT / ".github/ci-image/Dockerfile").read_text(encoding="utf-8")
    sans_commentaires = "\n".join(ligne.split("#", 1)[0] for ligne in dockerfile.splitlines())
    installation = sans_commentaires.split("apt-get install -y -qq --no-install-recommends", 1)[1].split("&&", 1)[0]
    paquets_image = set(shlex.split(installation.replace("\\\n", " ")))
    assert len(APT_STEPS) == 9
    for job_id, step in APT_STEPS:
        garde = _garde(step["run"])
        controle = garde.split("dpkg-query -W ", 1)[1].split("2>/dev/null", 1)[0]
        paquets = set(shlex.split(controle.replace("\\\n", " "))[1:])
        assert paquets <= paquets_image, (job_id, paquets - paquets_image)
    image_workflow = yaml.safe_load((ROOT / ".github/workflows/ci-image.yml").read_text(encoding="utf-8"))
    controle_outils = next(
        step["run"] for step in image_workflow["jobs"]["image"]["steps"] if "Contrôle" in step["name"]
    )
    assert "node" in shlex.split(controle_outils.split("for outil in ", 1)[1].split("; do", 1)[0])


def test_publication_et_frequence_existantes_conservees():
    image = yaml.safe_load((ROOT / ".github/workflows/ci-image.yml").read_text(encoding="utf-8"))
    assert image["on"]["schedule"] == [{"cron": "0 4 * * 1"}]
    assert image["on"]["push"]["branches"] == ["dev"]
    assert ".github/ci-image/**" in image["on"]["pull_request"]["paths"]
    push = next(step for step in image["jobs"]["image"]["steps"] if step["name"] == "Push")
    assert push["if"] == "github.event_name != 'pull_request'"
    assert "docker push" in push["run"]


def test_garde_paquets_couvre_depends_et_recommends_du_deb():
    control = (ROOT / "build-deb/debian/control").read_text(encoding="utf-8")
    depends = control.split("\nDepends:", 1)[1].split("\nSuggests:", 1)[0]
    requis = set(re.findall(r"\b(?:python3(?:-[a-z0-9-]+)?|tshark|gir1\.2-gtk-4\.0)\b", depends))
    assert len(requis) == 9
    etape = next(step for job_id, step in APT_STEPS if job_id == "packaging" and "debhelper" in step["name"])
    controle = _garde(etape["run"]).split("dpkg-query -W ", 1)[1].split("2>/dev/null", 1)[0]
    paquets = set(shlex.split(controle.replace("\\\n", " "))[1:])
    assert requis <= paquets
    image = (ROOT / ".github/workflows/ci-image.yml").read_text(encoding="utf-8")
    assert "import cryptography, loguru, reportlab, matplotlib, networkx, gi" in image
