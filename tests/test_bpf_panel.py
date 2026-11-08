# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests des decisions du panneau de filtres BPF (`netcross_gtk4.bpf_panel`,
issue #285, quatrieme lot).

Ces regles decident ce que l'utilisateur CROIT capturer. Aucune ne leve
d'erreur quand elle se trompe : la capture tourne, et l'ecart entre le filtre
annonce par le menu et celui reellement applique ne se voit qu'en relisant
les resultats, parfois longtemps apres. Les tests portent donc sur ce que
l'utilisateur voit -- infobulle, message de refus, contenu du champ -- et pas
seulement sur des valeurs de retour.

Les messages de refus sont verifies par leur constante et non par une chaine
recopiee : un test qui recopie le message passe aussi bien avec un message
faux, et c'est le genre de test qui a ete corrige sur #285 lot 3.
"""

from __future__ import annotations

import pytest

from netcross_core.bpf_filters import PREDEFINED_BPF_FILTERS, BPFFilter
from netcross_gtk4.bpf_panel import (
    DECALAGE_TITRE,
    INDICE_AUCUNE_SELECTION,
    MSG_EXPRESSION_VIDE,
    MSG_NOM_MANQUANT,
    MSG_SAUVEGARDE_INDISPONIBLE,
    TITRE_MENU_FILTRES,
    doit_desolidariser_le_menu,
    filtre_a_l_indice,
    indice_apres_deplacement,
    indice_du_filtre_nomme,
    infobulle_du_menu,
    noms_du_menu,
    selection_apres_choix,
    valider_sauvegarde,
)

# Position que GTK renvoie quand rien n'est selectionne
# (`Gtk.INVALID_LIST_POSITION`). Valeur reelle, pas un grand nombre choisi au
# hasard : c'est l'entree hors bornes que le code rencontre vraiment.
POSITION_INVALIDE_GTK = 4294967295

DNS = BPFFilter("DNS", "port 53", "Requetes et reponses DNS.")
SANS_DESCRIPTION = BPFFilter("Perso", "tcp port 8080", "")
SIP = BPFFilter("SIP", "port 5060", "Signalisation SIP.")


@pytest.fixture
def filtres():
    return [DNS, SANS_DESCRIPTION, SIP]


# -- filtre_a_l_indice ---------------------------------------------------------


def test_l_indice_un_designe_le_premier_filtre_pas_le_titre(filtres):
    """Le decalage d'une unite est la source d'erreur naturelle de ce module :
    l'indice 1 doit donner le PREMIER filtre, l'indice 0 etant le titre.
    Un test qui se contenterait de verifier que 1 renvoie « quelque chose »
    laisserait passer un decalage d'un cran, qui appliquerait silencieusement
    le mauvais filtre.
    """
    assert filtre_a_l_indice(DECALAGE_TITRE, filtres) is filtres[0]
    assert filtre_a_l_indice(DECALAGE_TITRE + 1, filtres) is filtres[1]
    # Le dernier indice valide est len(filtres), pas len(filtres) - 1 : encore
    # le meme decalage, et je m'y suis trompe en ecrivant ce test.
    assert filtre_a_l_indice(len(filtres), filtres) is filtres[-1]


def test_le_titre_ne_designe_aucun_filtre(filtres):
    assert filtre_a_l_indice(INDICE_AUCUNE_SELECTION, filtres) is None


@pytest.mark.parametrize(
    "index",
    [-1, 4, 99, POSITION_INVALIDE_GTK, None],
    ids=["negatif", "juste_au_dela", "loin_au_dela", "invalid_list_position_gtk", "aucun"],
)
def test_un_indice_hors_bornes_ne_designe_aucun_filtre(index, filtres):
    """Ces entrees ne sont pas theoriques : GTK renvoie
    `INVALID_LIST_POSITION` quand rien n'est selectionne, et le menu est
    reconstruit a chaque rafraichissement, donc un indice memorise peut
    designer une position disparue. L'ancien code s'en protegeait par
    `0 < index <= len(...)` recopie a quatre endroits.
    """
    assert filtre_a_l_indice(index, filtres) is None


def test_aucun_indice_ne_designe_de_filtre_sur_une_liste_vide():
    for index in (INDICE_AUCUNE_SELECTION, DECALAGE_TITRE, 5):
        assert filtre_a_l_indice(index, []) is None


# -- infobulle_du_menu --------------------------------------------------------


def test_l_infobulle_montre_la_description_du_filtre(filtres):
    assert infobulle_du_menu(DECALAGE_TITRE, filtres, "invite") == DNS.description


def test_un_filtre_sans_description_retombe_sur_son_nom(filtres):
    """Une description vide donnerait une infobulle vide, et l'utilisateur ne
    saurait pas si le filtre est sans description ou si l'infobulle est
    cassee. Le nom est toujours present : il dit au moins quel filtre est
    annonce. Cas reel -- la description est optionnelle a l'enregistrement.
    """
    resultat = infobulle_du_menu(DECALAGE_TITRE + 1, filtres, "invite")
    assert resultat == SANS_DESCRIPTION.name
    assert resultat, "l'infobulle ne doit jamais etre vide sur un filtre"


def test_sur_le_titre_l_infobulle_est_l_invite(filtres):
    assert infobulle_du_menu(INDICE_AUCUNE_SELECTION, filtres, "invite") == "invite"


def test_sur_un_indice_invalide_l_infobulle_est_l_invite(filtres):
    """Pas d'infobulle vide et pas d'exception : un indice perime apres
    reconstruction du menu doit ramener l'invite, pas un trou.
    """
    assert infobulle_du_menu(POSITION_INVALIDE_GTK, filtres, "invite") == "invite"


def test_chaque_filtre_predefini_a_une_infobulle_non_vide():
    """Les filtres du catalogue sont ceux que la plupart des utilisateurs
    verront. Une infobulle vide sur l'un d'eux est un defaut d'affichage
    silencieux, et le catalogue est amene a grossir : la garantie est verifiee
    sur la vraie constante plutot que sur des filtres de test.
    """
    catalogue = list(PREDEFINED_BPF_FILTERS)
    for position in range(len(catalogue)):
        resultat = infobulle_du_menu(position + DECALAGE_TITRE, catalogue, "invite")
        assert resultat, f"infobulle vide pour {catalogue[position].name}"
        assert resultat != "invite", f"{catalogue[position].name} retombe sur l'invite"


# -- selection_apres_choix ----------------------------------------------------


def test_choisir_un_filtre_ecrit_son_expression_dans_le_champ(filtres):
    index, expression = selection_apres_choix(DECALAGE_TITRE + 2, filtres)
    assert index == DECALAGE_TITRE + 2
    assert expression == SIP.expression


def test_choisir_le_titre_n_efface_pas_le_champ(filtres):
    """Point important : ecrire une chaine vide effacerait un filtre tape a la
    main, transformant un clic malencontreux sur le titre en perte de saisie.
    Le contrat est donc « ne rien faire », pas « ecrire du vide » -- et le
    test distingue les deux, ce qu'une assertion sur une chaine vide ne
    ferait pas.
    """
    index, expression = selection_apres_choix(INDICE_AUCUNE_SELECTION, filtres)
    assert index is None
    assert expression is None


def test_choisir_un_indice_invalide_ne_fait_rien(filtres):
    assert selection_apres_choix(POSITION_INVALIDE_GTK, filtres) == (None, None)


# -- doit_desolidariser_le_menu ----------------------------------------------


def test_editer_le_champ_desolidarise_le_menu(filtres):
    """C'est LE defaut que cette regle empeche : le menu annoncant « DNS »
    alors que le champ contient autre chose. La capture tournerait avec
    l'expression du champ et l'utilisateur croirait capturer du DNS.
    """
    assert doit_desolidariser_le_menu(DECALAGE_TITRE, filtres, "tcp port 443") is True


def test_un_champ_identique_au_filtre_garde_le_menu(filtres):
    assert doit_desolidariser_le_menu(DECALAGE_TITRE, filtres, DNS.expression) is False


@pytest.mark.parametrize(
    "texte",
    ["  port 53", "port 53  ", "\tport 53\n"],
    ids=["avant", "apres", "tabulation_et_retour"],
)
def test_les_espaces_de_bord_ne_desolidarisent_pas(texte, filtres):
    """Les espaces de bord arrivent par copier-coller et ne changent rien pour
    BPF : desolidariser dessus ferait clignoter le menu sans raison visible.
    """
    assert doit_desolidariser_le_menu(DECALAGE_TITRE, filtres, texte) is False


def test_un_espace_interne_en_plus_desolidarise(filtres):
    """Limite assumee et documentee : `port  53` est equivalent a `port 53`
    pour BPF, donc ce cas desolidarise a tort. C'est le choix prudent --
    normaliser les espaces internes finirait par confondre des filtres
    reellement differents (`tcp port 53` et `port 53`), ce qui serait pire :
    le menu annoncerait un filtre qui n'est pas celui applique.

    Le test fige le comportement reel plutot que celui qu'on aimerait, pour
    qu'un changement de normalisation soit une decision et pas une surprise.
    """
    assert doit_desolidariser_le_menu(DECALAGE_TITRE, filtres, "port  53") is True


def test_un_champ_vide_desolidarise(filtres):
    """Un champ vide ne capture pas ce que « DNS » annonce : il capture tout.
    Le menu doit cesser de l'annoncer.
    """
    assert doit_desolidariser_le_menu(DECALAGE_TITRE, filtres, "") is True
    assert doit_desolidariser_le_menu(DECALAGE_TITRE, filtres, None) is True


def test_sans_filtre_annonce_il_n_y_a_rien_a_desolidariser(filtres):
    assert doit_desolidariser_le_menu(INDICE_AUCUNE_SELECTION, filtres, "n importe quoi") is False
    assert doit_desolidariser_le_menu(POSITION_INVALIDE_GTK, filtres, "") is False


# -- valider_sauvegarde -------------------------------------------------------


def test_une_demande_complete_produit_le_filtre():
    demande = valider_sauvegarde("tcp port 8080", "Proxy", "Proxy interne")
    assert demande.acceptee
    assert demande.filtre == BPFFilter("Proxy", "tcp port 8080", "Proxy interne")
    assert demande.message == ""


def test_la_description_est_optionnelle():
    demande = valider_sauvegarde("tcp port 8080", "Proxy")
    assert demande.acceptee
    assert demande.filtre.description == ""


def test_les_espaces_de_bord_sont_retires_des_trois_champs():
    """Sans cela, « DNS » et « DNS » (avec espace) seraient deux filtres
    distincts dans le fichier de sauvegarde, et la recherche par nom au
    repositionnement echouerait sur l'un des deux.
    """
    demande = valider_sauvegarde("  port 53 ", "  Mon DNS  ", "  chez moi  ")
    assert demande.filtre == BPFFilter("Mon DNS", "port 53", "chez moi")


@pytest.mark.parametrize("expression", ["", "   ", "\t\n", None], ids=["vide", "espaces", "blancs", "aucune"])
def test_une_expression_vide_est_refusee_avec_le_message_dedie(expression):
    demande = valider_sauvegarde(expression, "Proxy")
    assert not demande.acceptee
    assert demande.message == MSG_EXPRESSION_VIDE


@pytest.mark.parametrize("nom", ["", "   ", None], ids=["vide", "espaces", "aucun"])
def test_un_nom_manquant_est_refuse_avec_le_message_dedie(nom):
    demande = valider_sauvegarde("tcp port 80", nom)
    assert not demande.acceptee
    assert demande.message == MSG_NOM_MANQUANT


def test_sans_mecanisme_de_sauvegarde_la_demande_est_refusee():
    """Etat anormal, mais qui ne doit surtout pas passer pour un succes :
    sans ce controle, le filtre semblerait enregistre et disparaitrait a la
    fermeture de l'application, sans qu'aucun message ne l'ait annonce.
    """
    demande = valider_sauvegarde("tcp port 80", "Web", sauvegarde_possible=False)
    assert not demande.acceptee
    assert demande.message == MSG_SAUVEGARDE_INDISPONIBLE


def test_le_champ_vide_est_signale_avant_l_indisponibilite():
    """L'ordre des controles est significatif : un champ vide est l'oubli
    courant, l'absence de mecanisme de sauvegarde est un defaut de
    configuration. Les signaler dans l'autre sens ferait croire a une panne
    de l'outil la ou il ne manque qu'une saisie.
    """
    demande = valider_sauvegarde("", "", sauvegarde_possible=False)
    assert demande.message == MSG_EXPRESSION_VIDE


def test_le_nom_manquant_est_signale_avant_l_indisponibilite():
    demande = valider_sauvegarde("tcp port 80", "", sauvegarde_possible=False)
    assert demande.message == MSG_NOM_MANQUANT


@pytest.mark.parametrize(
    ("expression", "nom", "possible"),
    [
        ("tcp port 80", "Web", True),
        ("", "Web", True),
        ("tcp port 80", "", True),
        ("tcp port 80", "Web", False),
        ("", "", False),
    ],
)
def test_un_refus_porte_toujours_un_message_et_un_succes_jamais(expression, nom, possible):
    """Invariant de `DemandeSauvegarde` : `message` est non vide exactement
    quand `filtre` est None. Un refus silencieux laisserait l'utilisateur
    cliquer sans comprendre ; un message affiche en cas de succes ferait
    croire a un probleme. Verifie plutot que seulement documente.
    """
    demande = valider_sauvegarde(expression, nom, sauvegarde_possible=possible)
    assert demande.acceptee == (demande.message == "")
    assert demande.acceptee == (demande.filtre is not None)


def test_un_nom_identique_a_un_filtre_predefini_est_accepte_ici():
    """La validation du panneau n'arbitre pas les collisions de noms : c'est
    `netcross_core.bpf_filters` qui ignore un filtre sauvegarde collisionnant
    avec le catalogue. Le test fige la frontiere -- sinon le refus serait
    duplique aux deux etages, avec deux regles a maintenir en phase.
    """
    demande = valider_sauvegarde("tcp port 80", PREDEFINED_BPF_FILTERS[0].name)
    assert demande.acceptee


# -- indice_du_filtre_nomme ---------------------------------------------------


def test_le_filtre_enregistre_est_retrouve_par_son_nom(filtres):
    assert indice_du_filtre_nomme("SIP", filtres) == DECALAGE_TITRE + 2


def test_la_recherche_par_nom_ignore_la_casse(filtres):
    """Alignee sur `netcross_core.bpf_filters`, qui traite deja « DNS » et
    « dns » comme un seul filtre. Une comparaison sensible a la casse
    laisserait le menu sur le titre apres un enregistrement reussi :
    l'utilisateur verrait son filtre sauvegarde mais non selectionne, et le
    choisirait a nouveau sans savoir s'il vient d'en creer un doublon.
    """
    assert indice_du_filtre_nomme("dns", filtres) == DECALAGE_TITRE
    assert indice_du_filtre_nomme("DnS", filtres) == DECALAGE_TITRE


def test_un_nom_inconnu_ne_renvoie_aucun_indice(filtres):
    assert indice_du_filtre_nomme("Jamais enregistre", filtres) is None


@pytest.mark.parametrize("nom", ["", None], ids=["vide", "aucun"])
def test_un_nom_absent_ne_renvoie_aucun_indice(nom, filtres):
    assert indice_du_filtre_nomme(nom, filtres) is None


def test_la_recherche_ne_renvoie_jamais_l_indice_du_titre(filtres):
    """Garde-fou sur le decalage : si la conversion etait fausse, le premier
    filtre renverrait 0, et le code appelant repositionnerait le menu sur le
    titre en croyant avoir trouve le filtre.
    """
    for flt in filtres:
        assert indice_du_filtre_nomme(flt.name, filtres) != INDICE_AUCUNE_SELECTION


def test_la_recherche_et_l_acces_par_indice_sont_reciproques(filtres):
    """Les deux conversions d'indice du module doivent s'annuler. C'est cette
    reciprocite qui garantit qu'un filtre enregistre est bien celui que le
    menu selectionne ensuite.
    """
    for flt in filtres:
        indice = indice_du_filtre_nomme(flt.name, filtres)
        assert filtre_a_l_indice(indice, filtres) is flt


# -- noms_du_menu -------------------------------------------------------------


def test_le_menu_commence_par_le_titre(filtres):
    noms = noms_du_menu(filtres)
    assert noms[0] == TITRE_MENU_FILTRES
    assert noms[1:] == [DNS.name, SANS_DESCRIPTION.name, SIP.name]


def test_le_titre_reste_present_sans_aucun_filtre():
    """Un menu vide n'aurait rien a afficher et paraitrait casse, alors que le
    titre sur une liste vide dit au moins que la fonction existe.
    """
    assert noms_du_menu([]) == [TITRE_MENU_FILTRES]


def test_les_noms_du_menu_s_alignent_sur_les_indices(filtres):
    """Le lien entre ce que le menu AFFICHE et ce que les indices DESIGNENT :
    si les deux se decalaient, le menu montrerait « DNS » et appliquerait le
    filtre suivant, sans aucune erreur visible.
    """
    noms = noms_du_menu(filtres)
    for index in range(1, len(noms)):
        assert noms[index] == filtre_a_l_indice(index, filtres).name


# -- indice_apres_deplacement -------------------------------------------------


def test_une_ligne_du_milieu_monte_et_descend():
    assert indice_apres_deplacement(1, 3, vers_le_haut=True) == 0
    assert indice_apres_deplacement(1, 3, vers_le_haut=False) == 2


def test_la_premiere_ligne_ne_monte_pas():
    assert indice_apres_deplacement(0, 3, vers_le_haut=True) is None


def test_la_derniere_ligne_ne_descend_pas():
    """Le defaut de dissymetrie corrige par ce lot : monter etait garde par
    `if idx > 0`, descendre ne l'etait pas et inserait a `idx + 1` meme sur la
    derniere ligne. GTK appendant silencieusement quand la position depasse la
    longueur, la ligne restait en place -- aucun degat visible, mais la borne
    n'etait respectee que par accident. Une borne tenue par le hasard cassera
    le jour ou le conteneur changera, et c'est l'ordre des points de capture
    qui en depend.
    """
    assert indice_apres_deplacement(2, 3, vers_le_haut=False) is None


def test_une_ligne_seule_ne_bouge_dans_aucun_sens():
    assert indice_apres_deplacement(0, 1, vers_le_haut=True) is None
    assert indice_apres_deplacement(0, 1, vers_le_haut=False) is None


@pytest.mark.parametrize("vers_le_haut", [True, False])
def test_une_ligne_hors_bornes_ne_bouge_pas(vers_le_haut):
    """Retirer une ligne pendant qu'on la deplace n'est pas impossible : le
    panneau reconstruit sa liste sur plusieurs evenements.
    """
    for index in (-1, 3, 99, None):
        assert indice_apres_deplacement(index, 3, vers_le_haut=vers_le_haut) is None


def test_aucune_ligne_ne_bouge_dans_une_liste_vide():
    assert indice_apres_deplacement(0, 0, vers_le_haut=True) is None
    assert indice_apres_deplacement(0, 0, vers_le_haut=False) is None


def test_monter_puis_descendre_ramene_a_la_position_de_depart():
    """Reciprocite des deux sens. Sans elle, l'ordre des points de capture
    pourrait deriver au fil des manipulations -- et cet ordre determine quel
    point est l'amont dans les mesures de perte et de latence.
    """
    for depart in range(1, 4):
        monte = indice_apres_deplacement(depart, 5, vers_le_haut=True)
        assert indice_apres_deplacement(monte, 5, vers_le_haut=False) == depart


def test_un_deplacement_reste_toujours_dans_la_liste():
    """Balayage complet des positions : aucune ne doit produire un indice hors
    bornes. C'est la propriete dont depend l'absence de perte de ligne.
    """
    for nombre in range(1, 6):
        for index in range(nombre):
            for vers_le_haut in (True, False):
                cible = indice_apres_deplacement(index, nombre, vers_le_haut=vers_le_haut)
                if cible is not None:
                    assert 0 <= cible < nombre
                    assert abs(cible - index) == 1, "un deplacement doit etre d'un seul cran"
