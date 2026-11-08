# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests des libelles de lignes de la GUI (`netcross_gtk4/row_labels.py`).

Premier lot de l'issue #285. Ces douze fonctions vivaient dans
`netcross_gtk4/app.py` et etaient a 0 % de couverture -- non pas parce
qu'elles etaient dures a tester, mais parce que leur fichier fait
`import gi` en tete : intestables en CI, ou PyGObject est absent. Une
fois sorties, elles se testent sans aucune infrastructure.

Ce qui est verifie ici n'est pas cosmetique : ce sont les chaines que
l'utilisateur lit dans l'interface. Un `None` affiche, une unite oubliee
ou un champ escamote lui font tirer une conclusion fausse sur sa
capture -- c'est exactement la classe de defaut que l'issue #259 a mise
en evidence sur une autre sortie.
"""

from netcross_gtk4 import row_labels

# --------------------------------------------------------------------------
# Timeline
# --------------------------------------------------------------------------


def test_le_libelle_timeline_annonce_le_nombre_de_pertes():
    ligne = {"label": "10:00:00 - 10:00:05", "loss_events": 3, "bucket": 42}
    assert row_labels.timeline_row_label(ligne) == "10:00:00 - 10:00:05 — 3 perte(s)"


def test_le_libelle_timeline_ecrit_zero_perte_au_lieu_de_se_taire():
    """Un intervalle sans perte doit s'afficher avec « 0 perte(s) ».
    Masquer le compteur laisserait croire que l'information manque alors
    que c'est un resultat : cet intervalle est sain."""
    ligne = {"label": "10:00:05 - 10:00:10", "loss_events": 0, "bucket": 43}
    assert row_labels.timeline_row_label(ligne) == "10:00:05 - 10:00:10 — 0 perte(s)"


def test_la_cle_timeline_est_le_bucket():
    assert row_labels.timeline_row_key({"bucket": 42, "label": "x", "loss_events": 0}) == 42


def test_la_cle_timeline_conserve_le_type_entier():
    """La cle sert au tri : rendue en chaine, « 10 » passerait avant « 9 »."""
    cle = row_labels.timeline_row_key({"bucket": 10, "label": "x", "loss_events": 0})
    assert isinstance(cle, int)


# --------------------------------------------------------------------------
# Segments
# --------------------------------------------------------------------------


def _segment(latence=12.5):
    return {
        "pair": "POINT_A -> POINT_B",
        "loss": 2,
        "retrans": 5,
        "latency_ms": latence,
        "pair_tuple": ("POINT_A", "POINT_B"),
    }


def test_le_libelle_segment_inclut_la_latence_quand_elle_existe():
    assert row_labels.segment_row_label(_segment()) == "POINT_A -> POINT_B — 2 perte(s), 5 retrans, latence 12.5 ms"


def test_le_libelle_segment_omet_la_latence_absente_sans_ecrire_none():
    """La latence est la seule valeur optionnelle de cette ligne. Absente,
    le fragment entier disparait : afficher « latence None ms » serait pire
    que ne rien dire, car cela ressemble a une mesure."""
    libelle = row_labels.segment_row_label(_segment(latence=None))
    assert libelle == "POINT_A -> POINT_B — 2 perte(s), 5 retrans"
    assert "None" not in libelle
    assert "latence" not in libelle


def test_le_libelle_segment_garde_une_latence_nulle():
    """0 ms est une mesure, pas une absence : `if ... is not None` et non
    `if ...`, sans quoi une latence nulle disparaitrait de l'affichage."""
    assert "latence 0 ms" in row_labels.segment_row_label(_segment(latence=0))


def test_la_cle_segment_est_le_premier_point_de_la_paire():
    assert row_labels.segment_row_key(_segment()) == "POINT_A"


# --------------------------------------------------------------------------
# Flux
# --------------------------------------------------------------------------


def test_le_libelle_flux_annonce_paquets_et_octets():
    ligne = {"label": "10.0.0.1:443 -> 10.0.0.2:51000", "packets": 120, "bytes": 8400, "flow_key": "k"}
    attendu = "10.0.0.1:443 -> 10.0.0.2:51000 — 120 paquets, 8400 octets"
    assert row_labels.flow_row_label(ligne) == attendu


def test_le_libelle_flux_precise_les_unites():
    """« 120, 8400 » sans unite serait ambigu : l'utilisateur ne saurait pas
    lequel est un volume."""
    libelle = row_labels.flow_row_label({"label": "f", "packets": 1, "bytes": 2, "flow_key": "k"})
    assert "paquets" in libelle and "octets" in libelle


def test_la_cle_flux_est_la_cle_de_flux():
    assert row_labels.flow_row_key({"flow_key": ("tcp", "a", "b"), "label": "f", "packets": 0, "bytes": 0}) == (
        "tcp",
        "a",
        "b",
    )


# --------------------------------------------------------------------------
# Machines (endpoints)
# --------------------------------------------------------------------------


def _endpoint(pairs):
    return {"endpoint": "10.0.0.1", "peers": pairs, "flows": 3, "packets": 90}


def test_le_libelle_machine_joint_les_pairs_par_des_virgules():
    attendu = "10.0.0.1 <-> 10.0.0.2, 10.0.0.3 — 3 flux, 90 paquets"
    assert row_labels.endpoint_row_label(_endpoint(["10.0.0.2", "10.0.0.3"])) == attendu


def test_le_libelle_machine_affiche_un_point_d_interrogation_sans_pair():
    """Une machine vue sans correspondant est un resultat inhabituel mais
    reel (trafic unidirectionnel, capture tronquee). Le `?` dit « on ne sait
    pas » ; une chaine vide donnerait « 10.0.0.1 <->  — » et ressemblerait
    a un bug de rendu."""
    libelle = row_labels.endpoint_row_label(_endpoint([]))
    assert libelle == "10.0.0.1 <-> ? — 3 flux, 90 paquets"


def test_le_libelle_machine_supporte_un_seul_pair():
    assert row_labels.endpoint_row_label(_endpoint(["10.0.0.2"])).startswith("10.0.0.1 <-> 10.0.0.2 —")


def test_la_cle_machine_est_l_adresse():
    assert row_labels.endpoint_row_key(_endpoint(["x"])) == "10.0.0.1"


# --------------------------------------------------------------------------
# Protocoles
# --------------------------------------------------------------------------


def test_le_libelle_protocole_annonce_flux_et_paquets():
    ligne = {"protocol": "TLS", "flows": 4, "packets": 250}
    assert row_labels.proto_row_label(ligne) == "TLS — 4 flux, 250 paquets"


def test_la_cle_protocole_est_le_nom_du_protocole():
    assert row_labels.proto_row_key({"protocol": "QUIC", "flows": 1, "packets": 2}) == "QUIC"


# --------------------------------------------------------------------------
# Evenements Expert Info
# --------------------------------------------------------------------------


def _evenement(**champs):
    base = {
        "id": 7,
        "category": "Sequence",
        "severity": "Warning",
        "protocol": "TCP",
        "message": "retransmission (suspected)",
    }
    base.update(champs)
    return base


def test_le_libelle_evenement_assemble_tous_ses_champs():
    attendu = "#7 Sequence (Warning) [TCP] — retransmission (suspected)"
    assert row_labels.event_row_label(_evenement()) == attendu


def test_le_libelle_evenement_remplace_une_categorie_absente_par_un_point_d_interrogation():
    """Les evenements Expert Info viennent de tshark : certains champs
    manquent selon le dissecteur. Un `?` trace le trou ; laisser passer
    `None` ferait croire a une categorie nommee « None »."""
    libelle = row_labels.event_row_label(_evenement(category=None, severity=None))
    assert libelle == "#7 ? (?) [TCP] — retransmission (suspected)"
    assert "None" not in libelle


def test_le_libelle_evenement_omet_le_protocole_absent():
    """Contrairement a la categorie, le protocole absent ne laisse pas de
    `?` : les crochets vides `[]` seraient du bruit visuel sur toute une
    colonne, et le champ n'est pas structurant pour identifier la ligne."""
    libelle = row_labels.event_row_label(_evenement(protocol=None))
    assert libelle == "#7 Sequence (Warning) — retransmission (suspected)"
    assert "[" not in libelle


def test_le_libelle_evenement_supporte_un_message_absent():
    libelle = row_labels.event_row_label(_evenement(message=None))
    assert libelle == "#7 Sequence (Warning) [TCP] — "
    assert "None" not in libelle


def test_le_libelle_evenement_conserve_le_message_entier():
    """Aucune troncature ici : la GUI dispose de la largeur et d'une
    infobulle. Tronquer en silence dans un libelle de liste priverait
    l'utilisateur de la fin du diagnostic sans le lui signaler."""
    message = "A" * 400
    assert message in row_labels.event_row_label(_evenement(message=message))


def test_la_cle_evenement_est_l_identifiant():
    assert row_labels.event_row_key(_evenement(id=99)) == 99


# --------------------------------------------------------------------------
# Invariants communs
# --------------------------------------------------------------------------


LIBELLES = [
    (row_labels.timeline_row_label, {"label": "l", "loss_events": 0}),
    (row_labels.segment_row_label, _segment()),
    (row_labels.flow_row_label, {"label": "f", "packets": 0, "bytes": 0}),
    (row_labels.endpoint_row_label, _endpoint(["p"])),
    (row_labels.proto_row_label, {"protocol": "TCP", "flows": 0, "packets": 0}),
    (row_labels.event_row_label, _evenement()),
]


def test_tous_les_libelles_rendent_une_chaine_non_vide():
    """Une ligne au libelle vide serait selectionnable mais illisible :
    l'utilisateur verrait une entree blanche sans pouvoir deviner ce
    qu'elle designe."""
    for fonction, ligne in LIBELLES:
        libelle = fonction(ligne)
        assert isinstance(libelle, str)
        assert libelle.strip(), fonction.__name__


def test_aucun_libelle_ne_laisse_fuiter_le_mot_none():
    """Verification transverse : `None` visible dans l'interface est
    toujours un defaut de rendu, jamais une information.

    Seuls les champs REELLEMENT optionnels sont mis a `None`. Un premier
    jet mettait tous les champs a `None` d'un coup et signalait
    `timeline_row_label` -- a tort : `label` et `loss_events` sont
    toujours renseignes par `build_dashboard_snapshot()`. Un test qui
    exige une protection contre une entree impossible pousse a ecrire du
    code defensif inutile, et surtout il ferait passer pour verifie un
    scenario qui ne se produit jamais.

    La liste ci-dessous est donc la liste des champs dont l'absence est
    documentee comme possible. Si un nouveau champ optionnel apparait, il
    doit y etre ajoute -- sinon il n'est pas couvert, et ce commentaire
    est la pour le dire.
    """
    cas = [
        ("segment latence absente", row_labels.segment_row_label, _segment(latence=None)),
        ("machine sans pair", row_labels.endpoint_row_label, _endpoint([])),
        ("evenement sans categorie", row_labels.event_row_label, _evenement(category=None)),
        ("evenement sans severite", row_labels.event_row_label, _evenement(severity=None)),
        ("evenement sans protocole", row_labels.event_row_label, _evenement(protocol=None)),
        ("evenement sans message", row_labels.event_row_label, _evenement(message=None)),
        (
            "evenement sans aucun champ optionnel",
            row_labels.event_row_label,
            _evenement(category=None, severity=None, protocol=None, message=None),
        ),
    ]
    for description, fonction, ligne in cas:
        libelle = fonction(ligne)
        assert "None" not in libelle, f"{description} : {fonction.__name__} affiche None -> {libelle!r}"
        assert libelle.strip(), f"{description} : libelle vide"


def test_les_douze_fonctions_sont_exportees():
    """Garde-fou de l'extraction : si une fonction est oubliee lors d'un
    prochain lot de #285, ce test le dit au lieu de laisser `app.py`
    echouer a l'import sur un poste avec GTK -- echec qu'aucun test de la
    CI ne verrait, PyGObject y etant absent."""
    attendues = {
        f"{famille}_row_{genre}"
        for famille in ("timeline", "segment", "flow", "endpoint", "proto", "event")
        for genre in ("label", "key")
    }
    publiques = {n for n in dir(row_labels) if not n.startswith("_")}
    assert attendues <= publiques, attendues - publiques
