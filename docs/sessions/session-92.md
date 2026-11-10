# Session 92 : zooms des microrafales et pertes aval

## Objectif

Issue #1139, après livraison de #1137 : un graphique zoomé par épisode et ses preuves de pertes aval.
Les épisodes et corrélations existaient, mais pas la série temporelle nécessaire au zoom.

## Réalisation

- Profils calculés depuis les mêmes paquets que l'analyse, avec au plus 512 tranches par épisode.
  Les volumes sont conservés, les durées terminales partielles explicites et les bornes limitées à la capture.
- Débit moyen par tranche, zone de l'épisode et preuves de pertes sur une seconde bande.
  Les horloges aval ne sont pas mélangées : les marqueurs utilisent `upstream_ts`.
- Une section PDF parcourt tous les épisodes disposant d'un profil, sans inventer de série pour les anciens rapports.
  La crête glissante reste affichée séparément de la moyenne graphique.
- Figures fermées même en cas d'erreur d'écriture ; aucun changement aux critères de détection ou de corrélation.

## Vérification et limites

Les tests couvrent la conservation de volume, plusieurs points et épisodes, la troncature à la capture,
les anciens rapports, les associations étrangères, l'horloge des marqueurs, l'erreur d'écriture et un PDF réel
réextrait avec les outils Poppler du dépôt. La validation complète et les contrôles distants doivent être verts
avant livraison ; aucune nouvelle exclusion ni diminution de seuil n'est prévue.

Les courbes montrent une moyenne par tranche et peuvent lisser un pic bref lorsque le contexte impose
une agrégation. Les preuves de pertes sont échantillonnées, pas les compteurs. Aucune cause physique
ni mesure sur équipement réel n'est revendiquée.
