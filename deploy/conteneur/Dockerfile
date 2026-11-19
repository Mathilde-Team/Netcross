# SPDX-License-Identifier: GPL-3.0-or-later
# Netcross — image conteneur minimale de la sonde (issue #1107).
#
# Contrairement au Dockerfile racine (image d'analyse complète, issue
# #170), celle-ci ne porte que l'agent : pas de GTK, pas de rapport PDF,
# pas d'API REST. tshark (capture, découpe, fusion) et libpcap
# (compilation des filtres BPF par ctypes) sont les seuls apports
# système ; cryptography et loguru les seuls paquets Python.
#
# Construction (contexte à la racine du dépôt, comme le Dockerfile
# racine de l'image d'analyse) :
#   docker build -f deploy/conteneur/Dockerfile -t netcross-probe:latest .
#
# Utilisation (les capacités réseau sont nécessaires à la capture) :
#   docker run --rm --network host \
#     --cap-add=NET_RAW --cap-add=NET_ADMIN \
#     -v netcross-probe-identite:/var/lib/netcross-probe/identite \
#     netcross-probe:latest \
#     netcross-probe servir --interface eth0 \
#       --dossier /var/lib/netcross-probe/tampon \
#       --identite /var/lib/netcross-probe/identite \
#       --nom ROUTEUR \
#       --ecoute 0.0.0.0:9443 \
#       --enrolement https://collecteur.lan:8443/probe/v1/enrollments \
#       --jeton <jeton-à-usage-unique> \
#       --listen-url https://sonde.lan:9443
#
# Lancement suivant : l'identité relue suffit (plus d'enrôlement).

FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/Mathilde-Team/Netcross" \
      org.opencontainers.image.description="Sonde Netcross : capture locale en tampon circulaire et fenêtres servies en mTLS" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

# Dépendances système : tshark (dumpcap/editcap/mergecap), libpcap
# (compilation BPF via ctypes, netcross_probe.bpf), certificats.
# Préréponse : l'installeur de wireshark-common pose sinon une question
# interactive sur les droits de capture.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      tshark \
      libpcap0.8 \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Dépendances Python : miroir borné de requirements.txt, restreint à ce
# que la sonde importe réellement (cryptography, loguru).
RUN pip install --no-cache-dir "cryptography>=41.0" "loguru>=0.7"

# Code : netcross_probe (l'agent) et pcap_parser (capture/tampon, importé
# par netcross_probe.capture) — rien d'autre de src/.
WORKDIR /app/src
COPY src/netcross_probe/ /app/src/netcross_probe/
COPY src/pcap_parser/ /app/src/pcap_parser/

# Lanceur : PYTHONPATH suffit, le paquet s'exécute par module
ENV PYTHONPATH=/app/src PYTHONUNBUFFERED=1
RUN useradd --create-home --uid 10001 sonde \
 && mkdir -p /var/lib/netcross-probe \
 && chown sonde:sonde /var/lib/netcross-probe
USER sonde

# Santé : la sonde répond au GET /probe/v1/health en mTLS ; un conteneur
# sans certificat client ne peut que vérifier que le port écoute.
HEALTHCHECK --interval=60s --timeout=5s --start-period=10s \
  CMD python3 -c "import socket; s=socket.create_connection(('127.0.0.1',9443),5); s.close()" \
  || exit 1

ENTRYPOINT ["python3", "-m", "netcross_probe"]
CMD ["--help"]
