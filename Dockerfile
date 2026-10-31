# SPDX-License-Identifier: GPL-3.0-or-later
# Netcross — image Docker pour déploiement rapide (issue #170)
#
# Construction :
#   docker build -t netcross:latest .
#
# Utilisation :
#   docker run --rm -v /chemin/vers/captures:/data netcross:latest \
#     cross_capture_analyzer_cli.py /data/capture1.pcap /data/capture2.pcap
#
# L'image inclut tshark (dépendance système) et Python 3.12.

FROM python:3.12-slim AS base

# Dépendances système : tshark pour le décodage des captures
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tshark \
        ca-certificates \
        && \
    rm -rf /var/lib/apt/lists/*

# Répertoire de travail
WORKDIR /app

# Copier d'abord les dependances d'execution pour optimiser le cache Docker.
# pyproject.toml declare `package = false` sans build-system : un
# `pip install -e .` n'a pas de sens ici. On installe uniquement les
# dependances d'execution (miroir de [project.dependencies]), jamais
# l'outillage de dev ni les tests.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code source uniquement (pas de tests/ ni scripts/ en production)
COPY src/ ./src/

# Execution sans privileges root
RUN useradd --create-home --uid 10001 netcross
USER netcross

# PYTHONPATH nécessaire car package = false (voir pyproject.toml)
ENV PYTHONPATH=/app/src

# Point d'entrée : la CLI Netcross
ENTRYPOINT ["python", "src/cross_capture_analyzer_cli.py"]
CMD ["--help"]
