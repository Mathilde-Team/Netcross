# Image de CI préconstruite de Netcross (issue #968).
#
# Regroupe les paquets apt que les jobs en conteneur de ci.yml (quality, gtk4,
# packaging) réinstallaient à chaque run : environ 12 min d'apt par run sur
# l'unique runner docker, et plus de 25 min les soirs de miroir lent.
# Construite et poussée par .github/workflows/ci-image.yml vers
# ghcr.io/mathilde-team/netcross-ci:26.04.
#
# Modifier la liste ci-dessous quand une étape de ci.yml a besoin d'un nouveau
# paquet : ci.yml garde un repli apt si un paquet manque, mais ce repli
# coûte le temps que cette image économise.
FROM ubuntu:26.04

LABEL org.opencontainers.image.source="https://github.com/Mathilde-Team/Netcross" \
      org.opencontainers.image.description="Image de CI de Netcross : prérequis, GTK4/Xvfb, tshark, pdftotext, deb/rpm" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

ENV DEBIAN_FRONTEND=noninteractive

# Préréponse : l'installeur de wireshark-common pose sinon une question
# interactive sur les droits de capture.
RUN echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections \
 && apt-get update -qq \
 && apt-get install -y -qq --no-install-recommends \
      # Prérequis du conteneur (les quatre jobs)
      git ca-certificates curl build-essential sudo python3 python3-venv \
      # Wireshark CLI (tshark, editcap, capinfos), pdftotext, gettext
      tshark poppler-utils gettext \
      # GTK4, introspection, Xvfb (job gtk4)
      gir1.2-gtk-4.0 libgirepository-2.0-dev libcairo2-dev pkg-config xvfb xauth \
      # Construction des paquets (job packaging)
      debhelper dpkg-dev rpm \
 && rm -rf /var/lib/apt/lists/*
