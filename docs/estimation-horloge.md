# Estimation du décalage d'horloge

Netcross mesure la latence entre points à partir de captures réalisées sur
des machines différentes. Sauf synchronisation matérielle (PTP), leurs
horloges ne montrent pas la même heure : la « latence » brute contient ce
décalage. Netcross estime automatiquement **décalage et dérive** entre
chaque paire de points, corrige chaque mesure et publie son incertitude
(issue #996).

## La méthode

Pour chaque paire de points, l'estimation se fait en deux temps
(`src/netcross_core/clock_sync.py`) :

1. **Collecte des échantillons.** Chaque aller-retour observé aux deux
   points fournit un échantillon : décalage apparent
   `((t2-t1) - (t4-t3)) / 2` et délai `((t4-t1) - (t3-t2))`, où `t1..t4`
   sont les instants de la requête et de la réponse vus de part et d'autre.
2. **Filtre au délai minimal (RFC 5905).** Comme le filtre d'horloge de
   NTP, seul l'échantillon au plus petit délai de chaque fenêtre de 2
   secondes est conservé (8 fenêtres au maximum). Un échantillon rapide a
   moins subi de files d'attente ; un échantillon retardé dans un seul
   sens fausse le décalage apparent.
3. **Régression de Theil-Sen.** La médiane des pentes entre paires
   d'échantillons conservés donne la **dérive** (en ppm) ; le décalage à
   l'instant de référence `t0` suit. La médiane rend l'estimation
   insensible aux échantillons aberrants.

Les intervalles de confiance à 95 % sont calculés sur l'écart robuste
(MAD) des échantillons conservés. Avec peu d'échantillons, l'intervalle
est volontairement large : il doit refléter honnêtement l'incertitude.

## Les sources d'échantillons

- **TCP** : chaque handshake SYN / SYN-ACK vu aux deux points (appariement
  par numéro de séquence).
- **DNS** : chaque couple requête / réponse UDP apparié par `dns.id`,
  nom de requête normalisé, adresses et ports client/serveur. Il faut
  une requête et une réponse uniques à chaque point ; les identifiants
  réutilisés sans identité unique et les captures incomplètes sont refusés.
  Un nom absent peut être complété seulement s'il existe un unique nom
  non vide pour cette transaction locale. En mode `--nat-tolerant`,
  des extrémités différentes ne sont rapprochées que si le nom et les
  empreintes des deux messages concordent, sans collision locale.
- **RTP** : datagrammes uniques aux deux points, identifiés par SSRC,
  séquence, horodatage RTP, longueur et empreinte de charge utile
  lorsqu'elle est disponible. Deux datagrammes de sens opposés de la
  même connexion fournissent les quatre observations ; ils doivent
  être séparés d'au plus une seconde selon chacune des deux horloges.
- **RTCP** : même traitement bidirectionnel, avec empreinte SHA-256 de
  la charge utile d'un datagramme disséqué comme RTCP par TShark.
  Sans charge utile disponible, aucun échantillon RTCP n'est produit.
  La présence de RTCP natif interdit le repli heuristique RTP.

Les sources média n'utilisent ni l'horodatage RTP comme une heure murale,
ni une simple différence d'arrivée d'un flux unidirectionnel. Elles
apparient des datagrammes observés de part et d'autre : il n'est pas
nécessaire que le second soit une réponse causale au premier, mais les
délais de transit opposés doivent être comparables. L'ancre temporelle
est le milieu des deux observations au point de référence et le délai
apparent est la valeur absolue de la différence des deux transits.
Un paquet reconnu DNS n'est jamais compté aussi comme média.

L'estimation n'exige aucune action : elle se déduit des captures
existantes. Plus la capture est longue et échantillonnée régulièrement,
plus l'intervalle de confiance se resserre.

## La correction

Le décalage corrigé est appliqué **au temps de chaque paquet** — pas
comme une constante. Une horloge qui dérive de 20 ppm décale de 72 ms en
une heure : la correction tient compte de la dérive entre le début et la
fin de la capture, pour la latence par segment comme pour le délai RTP.

## Lire l'incertitude dans le rapport

Chaque rapport (texte, PDF, JSON, HTML) affiche par paire de points :
décalage, dérive, intervalles de confiance à 95 %, nombre d'échantillons
et méthode. La méthode indique les sources collectées avant le filtre ;
le JSON ajoute leur liste structurée dans `clock_offsets[].sources`
(`TCP`, `DNS`, `RTP`, `RTCP`). Le nombre d'échantillons retenus peut
être inférieur au nombre collecté ; une source collectée n'est pas
nécessairement conservée par le filtre. Un décalage imposé n'a aucune
source automatique (`sources: []`).

```text
-- Latence / gigue entre points (necessite horloges synchronisees) --
  A -> B : n=412  moy=41.97ms  min=39.90ms  max=44.31ms  gigue=1.02ms
      -> decalage d'horloge estime : +37.12ms (derive +14.9ppm,
         IC95% +-0.21ms, 96 echantillon(s), filtre au délai
         minimal + Theil-Sen ; sources : DNS, TCP) => latence corrigee ~= 4.85ms
```

Dans le tableau « Latence par segment » du PDF, la colonne
« Horloge (décalage / dérive) » reprend ces valeurs.
Dans le HTML, ces informations figurent dans les détails du segment et
dans le tableau statique lorsque JavaScript est désactivé. La méthode
reste du texte, même si elle contient des caractères de balisage.

### Segment « non mesurable »

Quand l'incertitude du décalage dépasse la latence mesurée, le segment
est marqué « **non mesurable** » (tiret cadratin à la place de la
latence). Ce n'est pas une erreur : la capture ne permet pas de
distinguer une vraie latence d'un artefact d'horloge. Pour la rendre
mesurable : synchroniser les machines de capture (NTP, PTP), ou capturer
plus longtemps (davantage d'échantillons resserre l'intervalle).

Ce refus concerne les délais moyen et percentiles : ils ne sont plus
présentés comme des latences mesurables dans les détails HTML, les
graphiques ou le classement des délais. Les pertes, le débit et les
compteurs restent utilisables ; la gigue décrit toujours la variation
des observations et non une latence absolue garantie.

Le JSON conserve les observations pour l'audit et ajoute
`path_metrics[].latency_measurable`, distinct de `measured` : ce dernier
signifie qu'au moins une métrique du segment existe, pas que sa latence
est fiable. L'égalité entre IC et valeur absolue du délai est acceptée ;
une incertitude négative ou non finie est refusée. En l'absence d'IC,
le comportement historique est conservé, sans inventer une estimation.

Les transits des preuves HTML appliquent le même contrôle à chaque trame,
avant l'arrondi d'affichage. Le JSON des preuves garde `raw_ms` et
`transit_ms`, accompagnés de `clock_ci_ms` et de `latency_measurable`.
Un transit brut sans estimation conserve sa mention « non corrigé ».

## Imposer un décalage connu : `--clock-offset`

Quand le décalage réel est connu — par exemple des machines
synchronisées par PTP avec un décalage de capture mesuré par ailleurs —
l'option `--clock-offset` l'impose et **désactive l'estimation** pour la
paire concernée :

```bash
python3 src/cross_capture_analyzer_cli.py --capture LAN=lan.pcap \
    --capture WAN=wan.pcap --clock-offset LAN:WAN=+12.5ms
```

Le format est `A:B=valeur` avec l'unité (`ms`, `us`, `s` ; `ms` par
défaut), répérable pour plusieurs paires. Le rapport indique que la
valeur est imposée (dérive nulle).

## Les limites

Avant le choix des délais minimaux, l'estimateur écarte les résidus
extrêmes d'une tendance préliminaire robuste. Celle-ci utilise les
médianes d'au plus 64 groupes d'effectifs voisins parmi la moitié
des échanges les plus rapides, puis une médiane répétée des pentes
(Siegel). Le bruit est estimé sur cette population rapide, pour ne
pas le confondre avec les files d'attente ; 10 % d'aberrants bruts
en constituent au plus 20 %, plutôt qu'une majorité de minima isolés.
Le rejet porte sur tous les échantillons, à trois écarts MAD avec
un plancher de 1 ms. Le choix final au délai minimal et la
régression de décalage/dérive restent appliqués aux observations
conservées. La méthode publiée mentionne ce rejet MAD.

Cette étape évite que quelques observations aberrantes au RTT très bas
deviennent majoritaires après le choix des minima. Les régressions
couvrent exactement 10 % d'aberrants positifs ou négatifs, groupés,
aléatoires ou placés sur les minima, ainsi que vingt jeux avec bruit
et files asymétriques, perturbés de 2, 5, 20 ou 500 ms dans les deux
sens. Il ne s'agit pas d'une garantie sur toute
contamination arbitraire ni d'une authentification des captures.
Avec moins de seize observations, cette étape préalable n'est pas
appliquée ; la régression robuste existante reste utilisée.

- **Chemin asymétrique.** La formule suppose des délais aller et retour
  égaux ; une file d'attente permanente dans un seul sens biaise
  l'estimation. Le filtre au délai minimal atténue ce biais en ne gardant
  que les allers-retours les plus rapides, sans l'éliminer.
- **Horloges non synchronisées et instables.** Un décalage qui varie
  beaucoup (IC large, échantillons conservés peu nombreux) signale une
  machine sans NTP ou un chemin réellement asymétrique : à prendre comme
  un indice, pas comme une mesure de précision.
- **Décalage imposé.** `--clock-offset` fait confiance à la valeur
  fournie ; une valeur erronée décale d'autant toutes les latences de la
  paire.
- **Média incomplet ou transformé.** Un flux uniquement unidirectionnel
  ne fournit pas d'offset, même avec beaucoup de paquets. Copies multiples,
  collisions de signatures, changement de SSRC/séquence/charge utile ou
  de longueur entre les captures peuvent empêcher l'appariement.
  Les connexions doivent rester cohérentes dans les deux sens à chaque
  point ; il n'y a pas d'inférence de traduction de contenu par un SBC.
  La proximité temporelle ne prouve pas la symétrie du chemin et les
  empreintes ne constituent pas une authentification des captures.
