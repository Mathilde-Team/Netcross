# Session 81 : robustesse avant sélection des minima

Date : 9 novembre 2026. Périmètre : réouverture justifiée de #1027,
dont ma clôture précédente ne démontrait pas le test de propriété demandé.

## Régression

Sur soixante échanges synthétiques portant +37 ms et +15 ppm, modifier
six observations choisies sur les minima suffit à faire passer le
décalage de 37 à 537 ms. Ces 10 % d'aberrants deviennent majoritaires
après le choix de huit minima ; la robustesse de la régression finale
ne protège donc pas celle de toute la chaîne.

Les nouveaux cas de test ont été exécutés avant correction : neuf des
dix-huit premiers cas échouaient. Ils restent conservés et sont étendus
aux amplitudes négatives, au décalage seul, à la dérive seule, à leurs
combinaisons et à des jeux bruités avec files asymétriques.

## Correctif

Une tendance préliminaire sur au plus 64 groupes de population voisine permet
de rejeter les résidus extrêmes avant le choix des minima. Tous les
échantillons participent au contrôle des résidus. Les médianes portent
sur la moitié des échanges les plus rapides ; une médiane répétée des
pentes (Siegel) borne le coût quadratique à 64 représentants. Le filtre au
délai minimal, la régression finale et la publication des sources restent
en place. La méthode indique le rejet MAD ; aucun seuil de couverture
n'est réduit et aucun test n'est désactivé.

Les 238 premiers tests ciblés réussissent, et couvrent 100 % des lignes et branches
de `clock_sync.py`. Deux régressions supplémentaires vérifient les instants
identiques et l'absence de méthode de rejet annoncée à tort en petit effectif.
La suite complète et la CI du dernier head restent
nécessaires ; aucune nouvelle clôture avant livraison vérifiée dans main.
Le parent #996 n'est pas clôturé par agrégation.
