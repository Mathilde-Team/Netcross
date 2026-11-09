# Campagne de performance

Issue #1018 (sous-issue 5/5 du [banc de performance #994](https://github.com/Mathilde-Team/Netcross/issues/994)).
Cette page présente une campagne de mesure complète du pipeline réel
(`cross_capture_analyzer_cli.py`, `tshark` compris) sur les
[jeux synthétiques](quality/jeux-synthetiques.md), produite avec
[`scripts/bench.py`](quality/banc-performance.md) : tableaux jeux × degré de
parallélisme, description de la machine et commandes pour reproduire.

## Machine de mesure

| Élément | Valeur |
|---|---|
| CPU | Intel(R) Xeon(R) Processor @ 2.90 GHz |
| Cœurs | 2 logiques, 2 utilisables |
| RAM | 7 957 Mio |
| Système | Linux 6.1.155 x86_64 |
| Python | 3.14.8 |
| TShark (Wireshark) | 4.6.4 |
| Netcross | 1.0.0 |

Les mesures datent du 2026-11-09 (UTC). Le banc mesure, pour chaque jeu et
chaque degré de parallélisme, la durée totale, la durée de chaque étape
(`lecture`, `correlation`, `detecteurs`, `rapport`), le pic RSS du processus
d'analyse et de ses enfants, et le débit en paquets/s (paquets de tous les
points divisés par la durée totale). Chaque analyse tourne dans un processus
neuf. Avec `--repetitions R`, l'essai retenu est celui de durée médiane.

## Reproduire la campagne

```bash
# générer les jeux (matrice 2, 3, 5 et 10 points, 10^4 / 10^5 paquets par point)
python3 scripts/bench_datasets.py --sortie /tmp/jeux-t1e4 --matrice --matrice-paquets 10000
python3 scripts/bench_datasets.py --sortie /tmp/jeux-t1e5 --matrice --matrice-paquets 100000
# jeu 10^6 (2 points seulement : voir « limites » ci-dessous)
python3 scripts/bench_datasets.py --sortie /tmp/jeux-t1e6 --matrice --matrice-points 2 --matrice-paquets 1000000

# mesurer : lecture séquentielle puis 2, 4 et 8 processus, 3 essais par mesure
python3 scripts/bench.py --jeux /tmp/jeux-t1e4 --parallel 1,2,4,8 --repetitions 3 \
    --json banc-t1e4.json --markdown banc-t1e4.md
# (idem pour /tmp/jeux-t1e5 et /tmp/jeux-t1e6 ; durées ci-dessous)
```

Le workflow [`bench.yml`](https://github.com/Mathilde-Team/Netcross/blob/dev/.github/workflows/bench.yml)
(relance manuelle possible) exécute le banc sur le runner « maison » et
complète ces mesures en continu ; `benchmarks/reference.json` sert de
référence de non-régression.

## Résultats : 10⁴ paquets par point

Matrice 2, 3, 5 et 10 points × 10⁴ paquets par point (10⁵ paquets au total
pour p10), parallélisme 1 à 8, médiane de 3 essais :

| Jeu | Points | Paquets | Parallèle | Total (s) | lecture (s) | correlation (s) | detecteurs (s) | rapport (s) | Pic RSS (Mio) | Paquets/s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| p2-n10000-g1 | 2 | 20 000 | 1 | 5,090 | 3,369 | 0,038 | 1,668 | 0,016 | 151,4 | 3 929 |
| p2-n10000-g1 | 2 | 20 000 | 2 | 6,052 | 4,365 | 0,039 | 1,632 | 0,016 | 191,8 | 3 305 |
| p2-n10000-g1 | 2 | 20 000 | 4 | 6,166 | 4,469 | 0,039 | 1,643 | 0,016 | 186,9 | 3 243 |
| p2-n10000-g1 | 2 | 20 000 | 8 | 6,061 | 4,381 | 0,038 | 1,627 | 0,016 | 187,4 | 3 300 |
| p3-n10000-g1 | 3 | 30 000 | 1 | 9,175 | 5,130 | 0,107 | 3,915 | 0,023 | 172,0 | 3 270 |
| p3-n10000-g1 | 3 | 30 000 | 2 | 10,263 | 6,015 | 0,069 | 4,156 | 0,022 | 207,3 | 2 923 |
| p3-n10000-g1 | 3 | 30 000 | 4 | 10,318 | 6,052 | 0,063 | 4,180 | 0,022 | 210,1 | 2 908 |
| p3-n10000-g1 | 3 | 30 000 | 8 | 10,320 | 6,245 | 0,063 | 3,989 | 0,022 | 211,4 | 2 907 |
| p5-n10000-g1 | 5 | 50 000 | 1 | 17,045 | 8,520 | 0,172 | 8,304 | 0,050 | 212,2 | 2 933 |
| p5-n10000-g1 | 5 | 50 000 | 2 | 17,997 | 9,906 | 0,107 | 7,940 | 0,044 | 247,1 | 2 778 |
| p5-n10000-g1 | 5 | 50 000 | 4 | 18,409 | 10,175 | 0,106 | 8,083 | 0,044 | 251,6 | 2 716 |
| p5-n10000-g1 | 5 | 50 000 | 8 | 18,383 | 10,299 | 0,103 | 7,938 | 0,044 | 251,5 | 2 720 |
| p10-n10000-g1 | 10 | 100 000 | 1 | 50,865 | 17,421 | 0,105 | 33,210 | 0,129 | 314,0 | 1 966 |
| p10-n10000-g1 | 10 | 100 000 | 2 | 51,942 | 18,974 | 0,482 | 32,388 | 0,097 | 352,4 | 1 925 |
| p10-n10000-g1 | 10 | 100 000 | 4 | 51,620 | 19,759 | 0,448 | 31,316 | 0,096 | 352,4 | 1 937 |
| p10-n10000-g1 | 10 | 100 000 | 8 | 52,797 | 20,264 | 0,415 | 32,020 | 0,098 | 352,6 | 1 894 |

## Résultats : 10⁵ paquets par point

Matrice 2, 3, 5 et 10 points × 10⁵ paquets par point (10⁶ paquets au total
pour p10), parallélisme 1 et 2, médiane de 3 essais :

| Jeu | Points | Paquets | Parallèle | Total (s) | lecture (s) | correlation (s) | detecteurs (s) | rapport (s) | Pic RSS (Mio) | Paquets/s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| p2-n100000-g1 | 2 | 200 000 | 1 | 61,528 | 31,845 | 0,808 | 28,730 | 0,145 | 599,2 | 3 251 |
| p2-n100000-g1 | 2 | 200 000 | 2 | 66,586 | 36,526 | 1,130 | 28,789 | 0,142 | 945,6 | 3 004 |
| p3-n100000-g1 | 3 | 300 000 | 1 | 134,020 | 46,790 | 1,399 | 85,614 | 0,216 | 791,3 | 2 238 |
| p3-n100000-g1 | 3 | 300 000 | 2 | 142,197 | 54,379 | 1,783 | 85,823 | 0,211 | 1 133,6 | 2 110 |
| p5-n100000-g1 | 5 | 500 000 | 1 | 356,375 | 79,937 | 2,248 | 273,722 | 0,468 | 1 181,7 | 1 403 |
| p5-n100000-g1 | 5 | 500 000 | 2 | 367,250 | 87,570 | 3,741 | 275,519 | 0,419 | 1 516,1 | 1 361 |
| p10-n100000-g1 | 10 | 1 000 000 | 1 | 1 253,823 | 166,312 | 5,943 | 1 080,402 | 1,167 | 2 273,6 | 798 |
| p10-n100000-g1 | 10 | 1 000 000 | 2 | 1 255,966 | 179,142 | 7,629 | 1 068,182 | 1,013 | 2 575,3 | 796 |

## Résultats : 10⁶ paquets par point

Jeu 2 points × 10⁶ paquets par point (2 000 000 paquets au total),
parallélisme 1, médiane de 3 essais :

| Jeu | Points | Paquets | Parallèle | Total (s) | lecture (s) | correlation (s) | detecteurs (s) | rapport (s) | Pic RSS (Mio) | Paquets/s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| p2-n1000000-g1 | 2 | 2 000 000 | 1 | 678,875 | 333,285 | 15,556 | 328,510 | 1,524 | 4 793,5 | 2 946 |

## Lecture des résultats

- **Débit** : de 798 à 3 929 paquets/s selon le nombre de points. Le débit
  décroît quand le nombre de points augmente (p2 : ~3 250–3 930 ; p10 :
  ~800–1 970) : l'étape `detecteurs`, qui compare chaque flux entre tous les
  points, domine dès 5 points (à p10-10⁵, elle représente 1 080 s sur 1 254 s,
  soit 86 % du temps total).
- **Mémoire** : le pic RSS croît à peu près linéirement avec le nombre de
  paquets, à environ 2,4–3,1 Kio par paquet pour le pipeline complet
  (processus d'analyse + `tshark`). Le jeu 2 points × 10⁶ paquets culmine à
  4 793,5 Mio pour 2 000 000 paquets (≈ 2,4 Kio/paquet). Le seul pipeline
  Python (sans `tshark`, objets `Pkt` à emplacements fixes) descend à environ
  636 o/paquet — voir `docs/sessions/session-19.md`. Avec `--parallel 2`, le
  pic RSS monte nettement (p2-10⁵ : 599 → 946 Mio) : chaque processus de
  lecture garde ses tampons en mémoire.
- **Parallélisme** : sur cette machine de 2 cœurs, `--parallel 2` est 0 à 8 %
  plus lent que la lecture séquentielle, et `--parallel 4`/`8` ne changent
  rien de plus (p3-10⁴ : 9,2 s à 1 contre 10,3 s à 2, 4 et 8). La lecture
  n'est pas le goulot d'étranglement (`detecteurs`, monocœur, domine), et les
  valeurs 4 et 8 correspondent ici à une sur-souscription (plus de processus
  que de cœurs), pas à un vrai parallélisme.

### Dimensionnement

En extrapolant ces mesures : une capture de 1 000 000 paquets par point sur
2 points demande ~5 Go de RAM et ~11 minutes ; sur 10 points (10 000 000
paquets), il faudrait ~24 Go de RAM et ~3,5 h — au-delà de cette machine.
Le pipeline tient entièrement en RAM (pas de streaming multi-passes : la
corrélation multi-points a besoin d'une vue d'ensemble) : dimensionner la
machine d'analyse en conséquence sur de très gros volumes.

## Limites et suites

- Mesures faites sur une machine de **2 cœurs logiques** : les colonnes
  parallèle 4 et 8 de la table 10⁴ sont de la sur-souscription. Une campagne
  sur une vraie machine 4/8 cœurs (par exemple via le runner « maison »,
  `workflow_dispatch` sur `bench.yml`) reste à produire pour mesurer le gain
  réel de `--parallel`.
- Les paliers 10⁶ pour 3, 5 et 10 points n'ont pas été mesurés : ils
  dépassent la RAM (7,8 Gio) et le temps raisonnable de cette machine.
- Les jeux utilisent la matrice standard `--matrice-points 2,3,5,10`
  (suffixe `g<graine>` = graine du générateur, voir
  [jeux synthétiques](quality/jeux-synthetiques.md)) ; d'autres topologies
  (pertes, retards, décalages d'horloges) se mesurent avec les mêmes
  commandes.
