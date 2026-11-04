#!/usr/bin/env python3
"""
Captures d'écran du guide utilisateur (issue #465).

Pilote la vraie interface GTK4 sur les captures d'exemple du guide
(``docs/guide/exemples/``) et enregistre les PNG de
``docs/guide/images/`` : rien n'est retouché, chaque image est le rendu
de la fenêtre au moment indiqué.

Deux passes, chacune dans son propre processus (une application GTK par
processus) :

    # dossier de travail neutre : les chemins s'affichent dans les images
    sudo mkdir -p /srv/captures && sudo chown "$USER" /srv/captures
    cp docs/guide/exemples/*.pcap /srv/captures/   # (dans exemples/)

    GSK_RENDERER=cairo xvfb-run -a -s "-screen 0 1700x1500x24" \\
        python3 tools/captures_ecran_gui.py configuration
    GSK_RENDERER=cairo xvfb-run -a -s "-screen 0 1700x1500x24" \\
        python3 tools/captures_ecran_gui.py analyse

``configuration`` produit 01 ; ``analyse`` lance l'analyse LAN/WAN puis
produit 02 à 08 (onglets Travail et Résultats, cartographie, et les
quatre fenêtres de la barre de titre). L'historique (08) lit
``--history-db`` : remplissez-le d'abord avec la CLI, sur les captures
avant et après correction, étiquette ``banc``.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from loguru import logger

RACINE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RACINE / "src"))

import gi  # noqa: E402 -- après l'ajout de src/ au chemin

gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk  # noqa: E402 -- doit suivre gi.require_version()

from netcross_gtk4.app import NetcrossApp  # noqa: E402

LARGEUR = 1502


def photographier(fenetre: Gtk.Window, dossier: Path, nom: str) -> Path:
    """Rend la fenêtre telle qu'affichée et l'enregistre en PNG."""
    logger.debug("photographier: entrée | nom={}", nom)
    largeur, hauteur = fenetre.get_width(), fenetre.get_height()
    instantane = Gtk.Snapshot()
    Gtk.WidgetPaintable.new(fenetre).snapshot(instantane, largeur, hauteur)
    texture = fenetre.get_native().get_renderer().render_texture(instantane.to_node(), None)
    chemin = dossier / f"{nom}.png"
    texture.save_to_png(str(chemin))
    logger.info("capture {} ({}x{})", chemin, largeur, hauteur)
    logger.debug("photographier: retour {}", chemin)
    return chemin


def plus_tard(delai_ms: int, action) -> None:
    """Exécute ``action`` une seule fois après ``delai_ms`` millisecondes."""
    logger.debug("plus_tard: entrée | delai_ms={}", delai_ms)

    def une_fois() -> bool:
        logger.debug("plus_tard.une_fois: entrée")
        action()
        logger.debug("plus_tard.une_fois: retour False")
        return False

    GLib.timeout_add(delai_ms, une_fois)
    logger.debug("plus_tard: retour")


def passe_configuration(app: NetcrossApp, fenetre, args) -> None:
    """01 : onglet Configuration, deux points LAN/WAN, toutes les options visibles."""
    logger.debug("passe_configuration: entrée")
    fenetre.set_default_size(LARGEUR, args.hauteur_configuration)
    plus_tard(1500, lambda: photographier(fenetre, args.sortie, "01-configuration"))
    plus_tard(1800, app.quit)
    logger.debug("passe_configuration: retour")


def passe_analyse(app: NetcrossApp, fenetre, args) -> None:
    """02 à 08 : analyse réelle, puis onglets et fenêtres de la barre de titre."""
    logger.debug("passe_analyse: entrée")
    fenetre.set_default_size(LARGEUR, 900)
    plus_tard(1200, lambda: fenetre.run_btn.emit("clicked"))

    def onglets() -> None:
        logger.debug("passe_analyse.onglets: entrée")
        plus_tard(800, lambda: photographier(fenetre, args.sortie, "03-resultats"))
        plus_tard(1200, lambda: fenetre.stack.set_visible_child_name("log"))
        plus_tard(2000, lambda: photographier(fenetre, args.sortie, "02-travail"))
        plus_tard(2400, lambda: fenetre.stack.set_visible_child_name("results"))
        plus_tard(2600, lambda: fenetre.comm_map_expander.set_expanded(True))
        plus_tard(6000, lambda: photographier(fenetre, args.sortie, "04-cartographie"))
        logger.debug("passe_analyse.onglets: retour")

    def outils() -> None:
        logger.debug("passe_analyse.outils: entrée")
        fen = fenetre.open_capture_tools()
        plus_tard(1500, lambda: photographier(fen, args.sortie, "05-outils-capture"))
        plus_tard(1800, fen.close)
        logger.debug("passe_analyse.outils: retour")

    def dossier() -> None:
        logger.debug("passe_analyse.dossier: entrée")
        fen = fenetre.open_batch()
        fen.input_dir.set_path(str(args.captures))
        fen.output_dir.set_path(str(args.rapports))
        plus_tard(500, lambda: fen.run_btn.emit("clicked"))
        plus_tard(12000, lambda: photographier(fen, args.sortie, "06-analyse-dossier"))
        plus_tard(12300, fen.close)
        logger.debug("passe_analyse.dossier: retour")

    def lua() -> None:
        logger.debug("passe_analyse.lua: entrée")
        fen = fenetre.open_lua_doc()
        fen.set_default_size(1240, 720)
        plus_tard(3000, lambda: fen.open_class("Tvb"))
        plus_tard(5000, lambda: photographier(fen, args.sortie, "07-documentation-lua"))
        plus_tard(5300, fen.close)
        logger.debug("passe_analyse.lua: retour")

    def historique() -> None:
        logger.debug("passe_analyse.historique: entrée")
        fenetre.history_option.set_path(str(args.historique))
        fenetre.history_label_entry.set_text(args.etiquette)
        fen = fenetre.open_history()
        plus_tard(800, lambda: fen.show_btn.emit("clicked"))
        plus_tard(2500, lambda: photographier(fen, args.sortie, "08-historique"))
        plus_tard(2800, fen.close)
        logger.debug("passe_analyse.historique: retour")

    def attendre_resultats() -> bool:
        logger.debug("passe_analyse.attendre_resultats: entrée")
        if fenetre.stack.get_visible_child_name() != "results":
            logger.debug("passe_analyse.attendre_resultats: retour True (analyse en cours)")
            return True
        onglets()
        plus_tard(6500, outils)
        plus_tard(8800, dossier)
        plus_tard(21500, lua)
        plus_tard(27500, historique)
        plus_tard(31000, app.quit)
        logger.debug("passe_analyse.attendre_resultats: retour False")
        return False

    GLib.timeout_add(300, attendre_resultats)
    logger.debug("passe_analyse: retour")


def construire_parseur() -> argparse.ArgumentParser:
    """Options de la ligne de commande."""
    logger.debug("construire_parseur: entrée")
    parseur = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parseur.add_argument("passe", choices=("configuration", "analyse"))
    parseur.add_argument("--captures", type=Path, default=Path("/srv/captures/exemples"))
    parseur.add_argument("--rapports", type=Path, default=Path("/srv/captures/rapports"))
    parseur.add_argument("--historique", type=Path, default=Path("/srv/captures/historique.db"))
    parseur.add_argument("--etiquette", default="banc")
    parseur.add_argument("--sortie", type=Path, default=RACINE / "docs" / "guide" / "images")
    parseur.add_argument("--hauteur-configuration", type=int, default=1300)
    logger.debug("construire_parseur: retour")
    return parseur


def main(argv: list[str] | None = None) -> int:
    """Lance une passe de captures d'écran ; code de sortie de l'application."""
    logger.debug("main: entrée | argv={}", argv)
    args = construire_parseur().parse_args(argv)
    if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
        logger.error("aucun affichage : lancez ce script sous xvfb-run")
        logger.debug("main: retour 2 (pas d'affichage)")
        return 2
    args.sortie.mkdir(parents=True, exist_ok=True)
    app = NetcrossApp()

    def activee(_app) -> None:
        logger.debug("main.activee: entrée")
        fenetre = app.main_window
        fenetre.single_panel.add_row(str(args.captures / "lan.pcap"), "LAN")
        fenetre.single_panel.add_row(str(args.captures / "wan.pcap"), "WAN")
        if args.passe == "configuration":
            passe_configuration(app, fenetre, args)
        else:
            passe_analyse(app, fenetre, args)
        logger.debug("main.activee: retour")

    app.connect_after("activate", activee)
    code = app.run([])
    logger.debug("main: retour {}", code)
    return code


if __name__ == "__main__":
    sys.exit(main())
