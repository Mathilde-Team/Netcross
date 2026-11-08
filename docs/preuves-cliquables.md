# Constats filtrables et preuves cliquables (rapport HTML)

Issue #1077, sous-issue 3/6 du rapport HTML interactif (#1000).

## Filtres

Au-dessus du tableau des constats, trois menus filtrent les lignes par
**sévérité**, **segment** et **protocole**. Les filtres se combinent ; le
compteur « N / M constat(s) affiché(s) » est annoncé aux lecteurs d'écran
(`aria-live`). Les menus ne proposent que les valeurs présentes dans le
rapport.

Le protocole d'un constat vient de sa clé `protocol` si elle existe, sinon de
sa catégorie (`netcross_report.evidence_frames.CATEGORY_PROTOCOLS`) : TCP,
DNS, HTTP, TLS, QUIC, SIP, DHCP, ARP et STP gardent leur nom, `VLAN` donne
`802.1Q`, `RTP/Voix` donne `RTP` et `PMTUD` donne `ICMP`. Les catégories
transverses (pertes, QoS, saturation…) valent `IP`.

## Preuves cliquables

La colonne « Preuves » affiche un bouton par preuve qui porte un numéro de
trame. Un clic ouvre le panneau « Preuve », qui contient :

- la trame de preuve et ses voisines de la même conversation au point de la
  preuve (3 avant, 3 après), la trame de preuve étant mise en évidence ;
- une colonne par point de capture : le numéro de trame et la date relative
  (en ms depuis la preuve) à chaque point où la même trame a été vue, ou
  « non vue » ;
- le temps de transit de la trame de preuve sur chaque segment, corrigé du
  décalage d'horloge estimé (#996) quand il existe, sinon marqué « non
  corrigé du décalage d'horloge ».

Une preuve de segment `A -> B` (PMTUD, inactivité) désigne une trame du point
amont `A`. Une preuve introuvable parmi les paquets corrélés est signalée
comme telle : aucun diagramme n'est inventé.

Chaque diagramme a une ancre stable `#preuve-<point>-<trame>` (caractères
hors `[A-Za-z0-9_-]` remplacés par `_`). Sans JavaScript, le rapport contient
les mêmes diagrammes en tableaux statiques, et les preuves du tableau des
constats y renvoient par lien.

## JSON

`build_json_report_document(..., packet_flows=flows)` (sortie de
`correlate()`) ajoute la clé `evidence_frames` : une entrée par preuve
distincte (au plus 200), avec `ref`, `anchor`, `point`, `frame_number`,
`found`, puis, si la trame est trouvée, `proto`, `summary`, `points`, `rows`
(`frame_number`, `evidence`, `summary`, `cells` par point avec
`frame_number` et `rel_ms`) et `transits` (`segment`, `transit_ms`, `raw_ms`,
`corrected`). Sans `packet_flows`, la clé est absente.

## Limites

- Le rapport HTML n'est pas encore produit par la CLI, la GUI ni l'API
  (#1083) : `packet_flows` doit être fourni par l'appelant.
- La correspondance entre points repose sur la corrélation : une trame
  réécrite au point de vue de la corrélation (NAT non apparié) apparaît « non
  vue ».
- La date relative aux autres points n'est pas corrigée du décalage
  d'horloge ; seul le transit l'est.
