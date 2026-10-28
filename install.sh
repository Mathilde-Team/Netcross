#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# install.sh -- installe les dependances systeme de netcross.
#
# Utilise les paquets systeme (apt/dnf) plutot que pip quand ils existent :
# c'est ce que les paquets .deb/.rpm de build-deb/ et build-rpm/ declarent
# eux aussi comme dependances, donc ce script et les paquets restent
# coherents entre eux.
#
# Usage :
#   ./install.sh            installe les dependances CLI + interface GTK4
#   ./install.sh --cli-only installe uniquement ce qu'il faut pour le CLI
#                           et le rapport PDF (pas de GTK4)

set -euo pipefail

CLI_ONLY=0
if [ "${1:-}" = "--cli-only" ]; then
    CLI_ONLY=1
fi

if [ "$(id -u)" = "0" ]; then
    SUDO=""
else
    SUDO="sudo"
fi

if [ ! -f /etc/os-release ]; then
    echo "Impossible de detecter la distribution (/etc/os-release absent)." >&2
    echo "Installez manuellement : tshark, python3-cryptography, loguru, reportlab, matplotlib, networkx" >&2
    echo "(+ PyGObject et GTK4 pour l'interface graphique), ou via pip :" >&2
    echo "  pip install -r requirements.txt" >&2
    exit 1
fi
. /etc/os-release

echo "=== netcross : installation des dependances ==="
echo "Distribution detectee : ${PRETTY_NAME:-$ID}"
echo ""

CLI_PKGS_APT="python3 python3-pip tshark python3-cryptography python3-loguru python3-reportlab python3-matplotlib python3-networkx"
GUI_PKGS_APT="python3-gi gir1.2-gtk-4.0"

# le paquet CLI de Wireshark (tshark, dumpcap...) s'appelle wireshark-cli
# sur Fedora/RHEL/Rocky recents -- sur EL8 ancien il peut s'agir du
# paquet "wireshark" complet si wireshark-cli n'existe pas encore
CLI_PKGS_DNF="python3 python3-pip wireshark-cli python3-cryptography python3-loguru python3-reportlab python3-matplotlib python3-networkx"
GUI_PKGS_DNF="python3-gobject gtk4"

case "$ID" in
    ubuntu|debian)
        $SUDO apt-get update
        $SUDO apt-get install -y $CLI_PKGS_APT
        if [ "$CLI_ONLY" = "0" ]; then
            $SUDO apt-get install -y $GUI_PKGS_APT
        fi
        ;;

    rocky|rhel|centos|almalinux)
        # reportlab/networkx sont dans EPEL, pas les depots de base
        # (python3-cryptography est generalement deja dans les depots de base)
        if ! $SUDO rpm -q epel-release >/dev/null 2>&1; then
            echo "-> depot EPEL absent, activation (necessaire pour reportlab/networkx)"
            $SUDO dnf install -y epel-release
        fi
        $SUDO dnf install -y $CLI_PKGS_DNF || {
            # wireshark-cli n'existe pas encore sur certaines bases EL8 :
            # se rabattre sur le paquet "wireshark" complet (qui inclut
            # aussi tshark) dans ce cas precis.
            echo "-> wireshark-cli indisponible, tentative avec le paquet wireshark complet"
            $SUDO dnf install -y ${CLI_PKGS_DNF/wireshark-cli/wireshark}
        }
        if [ "$CLI_ONLY" = "0" ]; then
            echo "-> installation de GTK4 (interface graphique)"
            echo "   ATTENTION : sur Rocky/RHEL 8, GTK4 n'est pas toujours disponible"
            echo "   nativement selon les depots actives. En cas d'echec, relancez avec"
            echo "   --cli-only : le CLI et le rapport PDF n'ont pas besoin de GTK4."
            $SUDO dnf install -y $GUI_PKGS_DNF || {
                echo "GTK4 non installe -- le CLI et le rapport PDF restent utilisables." >&2
            }
        fi
        ;;

    *)
        echo "Distribution '$ID' non reconnue par ce script." >&2
        echo "Dependances necessaires : tshark, python3-cryptography, loguru, reportlab, matplotlib, networkx" >&2
        echo "(+ PyGObject et GTK4 pour l'interface graphique)." >&2
        echo "Installation alternative via pip :" >&2
        echo "  pip install -r requirements.txt" >&2
        exit 1
        ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo "=== Installation terminee ==="
echo ""
echo "CLI :"
echo "  python3 $SCRIPT_DIR/src/cross_capture_analyzer_cli.py --help"
echo ""
if [ "$CLI_ONLY" = "0" ]; then
    echo "Interface graphique :"
    echo "  cd $SCRIPT_DIR/src && python3 -m netcross_gtk4.app"
    echo ""
fi
echo "Voir le README.md pour les exemples d'utilisation et les solutions"
echo "de capture prises en charge."
