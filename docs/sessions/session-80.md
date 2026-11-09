# Session 80 : incertitude des rapports d'horloge

Date : 9 novembre 2026. Périmètre : correctif de l'issue #1033 après
réouverture. La clôture précédente était prématurée : le PDF omettait la
méthode et le HTML n'affichait pas l'IC, le nombre d'échantillons ni la
méthode, tout en présentant encore des latences trop incertaines.

## Correctif

Une fonction commune contrôle la validité de la latence sans modifier
les observations brutes. Le JSON distingue `latency_measurable` de
`measured` pour préserver les pertes et les autres mesures indépendantes.
Le contrôle est repris par les détails HTML, leur version sans
JavaScript, le tableau PDF, les graphiques et le classement des délais.
Les transits des preuves HTML publient leur IC et refusent également une
latence dominée par l'incertitude.
La synthèse réseau/serveur ne déduit pas une cause applicative à partir
d'une latence dont l'IC dépasse la valeur mesurée.

Le PDF échappe la méthode avant son insertion dans le balisage
ReportLab ; les rendus HTML utilisent du texte ou l'échappement HTML.
La gigue reste une variation observée, distincte de la latence absolue.
Les ajouts récents de diagrammes de séquence sont conservés.
Les tableaux statiques, les constats et les preuves disposent de régions
défilantes accessibles au clavier pour ne pas déborder de l'écran étroit.

## Vérifications et limites

Les régressions reproduisent un délai de 4 ms avec un IC de 8 ms, la
conservation des pertes, une méthode contenant des chevrons et une
esperluette, le texte réextrait du vrai PDF et le JavaScript exécuté
dans Node. Des tests inspectent aussi les valeurs réellement tracées,
les transits des preuves et les bornes de validité, dont l'égalité.

Les résultats chiffrés des suites et de la couverture sont conservés dans
les journaux et la PR, plutôt que figés ici avant leur exécution. La
CI du dernier commit, les validations requises et la livraison dans main
restent nécessaires avant une nouvelle clôture ; cette session ne clôt
pas le parent #996.
