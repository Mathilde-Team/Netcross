# Débordement sur disque des flux longs

Issue #1024 (sous-issue 5/6 du chantier #995 : pipeline en flux à empreinte
mémoire bornée). Suite de l'[état par flux](etat-flux.md) (#1023).

## Pourquoi

La table d'état par flux borne déjà sa mémoire par le nombre de flux
**actifs** : un état fermé ne laisse que des compteurs. Mais deux structures
du détecteur de coupure NAT grandissent avec le nombre **total** de
conversations vues pendant la capture :

- `_tcp_prev` : le résumé compact du dernier enregistrement TCP de chaque
  clé (points vus, paquets par point, raison de fermeture) — une entrée par
  conversation TCP ;
- `_cutoff_seen` : les coupures déjà comptées par clé et par segment, pour
  ne compter chaque coupure qu'une fois.

Sur une capture de plusieurs millions de paquets, des millions de
conversations TCP représentent des centaines de Mo : mesure sur la machine
de développement (2 cœurs, 7,8 Gio), 10⁶ conversations TCP distinctes
occupent **~650 Mo** en RAM sans débordement.

## Comment

`netcross_core/spill.py` fournit deux structures à seuil :

- `SpillDict` : table associative dont les `seuil` entrées les plus
  récemment utilisées restent en mémoire (LRU) ; une écriture au-delà
  déporte la plus ancienne dans une base **SQLite temporaire**. Une lecture
  manquante en mémoire y est retrouvée et **promue** (rechargée en mémoire,
  la plus ancienne partant à son tour sur disque).
- `SpillSet` : ensemble dont les `seuil` éléments les plus récents restent
  en mémoire, les suivants étant écrits sur disque sans relire.

Une seule base SQLite est créée pour l'analyse (une table par structure),
dans un fichier temporaire, **supprimé à la fermeture** (`finish()` de la
table de flux). À seuil nul — le défaut —, les deux structures sont de
simples conteneurs en RAM : aucun fichier n'est créé, le comportement est
inchangé.

## Usage

```bash
cross_capture_analyzer_cli.py ... --streaming --spill-seuil 5000
```

`--spill-seuil N` (entier, défaut : sans limite) déporte au-delà de N
entrées. Les résultats sont **identiques avec ou sans débordement** — seul
l'ordre de stockage (mémoire ou disque) change, jamais les valeurs : le
test d'équivalence alimente la même table avec et sans seuil et compare
les rapports.

## Mesure

Le test de mémoire bornée (`tests/test_spill.py`) alimente la table avec
10⁶ conversations TCP distinctes, seuil 5 000 : la croissance du RSS reste
sous le plafond vérifié (~10 Mo mesurés, plafond 250 Mo), contre ~650 Mo
sans débordement.
