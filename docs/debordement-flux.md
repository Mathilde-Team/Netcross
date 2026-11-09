# Débordement sur disque des flux longs

Issue #1024 (sous-issue 5/6 du chantier #995 : pipeline en flux à empreinte
mémoire bornée). Suite de l'[état par flux](etat-flux.md) (#1023).

## Pourquoi

La réalisation initiale #1024 ajoutait un débordement facultatif aux
structures `_tcp_prev` et `_cutoff_seen`. L'audit #1023 a confirmé que les
laisser sans limite par défaut ne satisfait pas la borne mémoire du
chantier : même un flux terminé doit pouvoir laisser une preuve exacte
sans rester indéfiniment en RAM.

La table utilise maintenant `FlowHistory` pour ces preuves TCP et leurs
statistiques globales par point. Elles sont sur disque même sans option
de cache, et la réconciliation NAT conserve le résultat batch à seuil
TCP identique, y compris après plusieurs silences.

## Comment

`netcross_core/flow_history.py` utilise une base SQLite temporaire dans
un répertoire privé, sans paquet ni contenu applicatif. Le cache SQLite
est plafonné à 1 Mio ; un cache LRU Python de N résumés peut s'y ajouter
avec `--spill-seuil N`. La base est la preuve de référence : les évictions
du cache ne font jamais disparaître une conversation.

Le module générique `netcross_core/spill.py`, conservé de la réalisation
initiale et testé séparément, fournit aussi deux structures à seuil :

- `SpillDict` : table associative dont les `seuil` entrées les plus
  récemment utilisées restent en mémoire (LRU) ; une écriture au-delà
  déporte la plus ancienne dans une base **SQLite temporaire**. Une lecture
  manquante en mémoire y est retrouvée et **promue** (rechargée en mémoire,
  la plus ancienne partant à son tour sur disque).
- `SpillSet` : ensemble dont les `seuil` éléments les plus récents restent
  en mémoire, les suivants étant écrits sur disque sans relire.

Pour `FlowTable`, une seule base privée est créée au premier résumé TCP
utile, et son répertoire est supprimé à `finish()` ou à la finalisation.
Sans segment possible (un seul point), aucun historique NAT n'est créé.
Le seuil zéro des conteneurs génériques reste un mode RAM pour ces
conteneurs seulement : ce n'est plus le défaut de l'historique TCP.

## Usage

```bash
cross_capture_analyzer_cli.py ... --streaming --spill-seuil 5000
```

`--spill-seuil N` (entier, défaut : zéro) borne le cache Python à N
résumés ; les suivants ne sont conservés que sur disque. Les résultats
sont identiques avec ou sans cache : seules les lectures de SQLite
changent, pas les valeurs. Le test d'équivalence compare les rapports
et les tests de silences multiples comparent aussi au détecteur batch.

## Mesure

Le test `tests/test_spill.py` vérifie un plafond de croissance du RSS de
250 Mio sur 10⁶ conversations TCP à un point. Ce cas ne prouve pas à lui
seul le débordement multi-points : celui-ci est exercé par les tests LRU,
les réouvertures tardives après éviction et le test tracemalloc de
`tests/test_flow_state_bounds.py`, avec 5 000 conversations à deux points.
Ces tests ne déclarent pas bornée la lecture entière des captures ni le
reste du pipeline #995.
