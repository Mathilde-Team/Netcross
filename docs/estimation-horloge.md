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
- **DNS** : chaque couple requête / réponse apparié par `dns.id` (utilise
  le trafic UDP pur — RTP, QUIC, DNS — quand aucun handshake TCP n'est
  observable).

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
et méthode.

```text
-- Latence / gigue entre points (necessite horloges synchronisees) --
  A -> B : n=412  moy=41.97ms  min=39.90ms  max=44.31ms  gigue=1.02ms
      -> decalage d'horloge estime : +37.12ms (derive +14.9ppm,
         IC95% +-0.21ms, 96 echantillon(s) TCP/DNS, filtre au delai
         minimal + Theil-Sen) => latence corrigee ~= 4.85ms
```

Dans le tableau « Latence par segment » du PDF, la colonne
« Horloge (décalage / dérive) » reprend ces valeurs.

### Segment « non mesurable »

Quand l'incertitude du décalage dépasse la latence mesurée, le segment
est marqué « **non mesurable** » (tiret cadratin à la place de la
latence). Ce n'est pas une erreur : la capture ne permet pas de
distinguer une vraie latence d'un artefact d'horloge. Pour la rendre
mesurable : synchroniser les machines de capture (NTP, PTP), ou capturer
plus longtemps (davantage d'échantillons resserre l'intervalle).

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
