# Banc de performance

Issue #1017 (sous-issue 3/5 du banc de performance #994).

`scripts/bench.py` lance la vraie analyse (`cross_capture_analyzer_cli.py`,
tshark compris) sur les [jeux synthétiques](jeux-synthetiques.md) et mesure,
pour chaque jeu et chaque degré de parallélisme :

- la durée totale et la durée de chaque étape (`lecture`, `correlation`,
  `detecteurs`, `rapport`), lues dans le fichier `--profile-steps` (#1016) ;
- le pic RSS du processus d'analyse et celui de ses enfants (tshark, et
  les processus de lecture avec `--parallel`) ;
- le débit en paquets/s : paquets de tous les points divisés par la durée
  totale.

Chaque analyse tourne dans un processus neuf, pour qu'un pic RSS ne
déborde pas sur l'essai suivant.

## Utilisation

```bash
# mini-jeu (2 points x 2 000 paquets, généré à la volée) : quelques secondes, pour la CI
python3 scripts/bench.py --mini --json /tmp/banc.json

# matrice standard, lecture séquentielle puis 2, 4 et 8 processus, 3 essais par mesure
python3 scripts/bench_datasets.py --sortie /tmp/jeux --matrice
python3 scripts/bench.py --jeux /tmp/jeux --parallel 1,2,4,8 --repetitions 3 \
    --json banc.json --markdown banc.md
```

- `--jeux` accepte un jeu (dossier contenant `verite.json`) ou un dossier de
  jeux (sortie de `--matrice`).
- `--parallel 1` correspond à la lecture séquentielle. Une valeur `N > 1`
  lance `--parallel --parallel-workers N`.
- Avec `--repetitions R`, l'essai retenu est celui de durée médiane. Toutes
  les durées restent dans `durees_totales_s`.
- Code de sortie : 0 si le banc est complet, 2 si un jeu manque ou si une
  analyse échoue.

`scripts/bench_memory.py` (#283) reste disponible : il trace la courbe
mémoire du seul pipeline Python sur des objets `Pkt`, sans tshark.

## Résultat JSON (schéma `netcross-bench`, version 1)

```json
{
  "schema": "netcross-bench",
  "version": 1,
  "date": "2026-11-08T10:48:19Z",
  "environnement": {
    "coeurs_logiques": 2, "coeurs_utilisables": 2,
    "cpu": "Intel(R) Xeon(R) Processor @ 2.90GHz", "ram_mio": 7957,
    "systeme": "Linux 6.1.155 x86_64", "python": "3.14.8",
    "tshark": "TShark (Wireshark) 4.6.4.", "netcross": "1.0.0"
  },
  "essais": [
    {
      "jeu": "mini", "points": 2, "paquets": 4000, "parallele": 1, "repetitions": 1,
      "total_s": 1.073089, "durees_totales_s": [1.073089], "mur_s": 1.844924,
      "etapes_s": {"lecture": 0.943409, "correlation": 0.008249, "detecteurs": 0.117293, "rapport": 0.004138},
      "rss_max_mio": 109.2, "rss_max_enfants_mio": 180.6, "paquets_par_s": 3728
    }
  ]
}
```

- `coeurs_utilisables` tient compte de l'affinité du processus (conteneur,
  `taskset`). Il peut donc être inférieur à `coeurs_logiques`.
- `mur_s` inclut le démarrage de Python et les imports. `total_s` ne compte
  que le pipeline mesuré.
- `tshark` vaut `null` si l'outil est absent.
- `paquets_par_s` vaut `null` si la durée totale est nulle.

`netcross_core.testing.bench.valider(resultat)` renvoie la liste des écarts
au schéma. Une nouvelle version du schéma incrémente `version`.

## Tableau Markdown

`--markdown` écrit, et la sortie standard affiche, l'environnement suivi
d'une ligne par essai :

| Jeu | Points | Paquets | Parallèle | Total (s) | lecture (s) | correlation (s) | detecteurs (s) | rapport (s) | Pic RSS (Mio) | Pic RSS enfants (Mio) | Paquets/s |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| mini | 2 | 4000 | 1 | 1.073 | 0.943 | 0.008 | 0.117 | 0.004 | 109.2 | 180.6 | 3728 |

Sur ce mini-jeu, `--parallel 2` est plus lent que la lecture séquentielle :
le lancement des processus coûte plus que ce qu'ils font gagner sur
2 000 paquets. Les vrais chiffres, sur la matrice et sur plusieurs
machines, relèvent de #1018 (`docs/performance.md`).

## Non-régression

Issue #1019. Le workflow `.github/workflows/bench.yml` mesure chaque lundi,
et à la demande (onglet Actions, « Banc de performance »), le jeu moyen :
3 points × 100 000 paquets émis (graine 1), en lecture séquentielle et avec
`--parallel 2`, 3 essais par mesure. Il ne se déclenche jamais sur une PR.

Le résultat est comparé à la référence versionnée `benchmarks/reference.json` :

```bash
python3 scripts/bench_datasets.py --sortie /tmp/jeux/p3-n100000-g1 --points 3 --paquets 100000
python3 scripts/bench.py --jeux /tmp/jeux --parallel 1,2 --repetitions 3 --json banc.json \
    --reference benchmarks/reference.json --seuil-duree 20 --seuil-memoire 20

# comparer un résultat déjà mesuré, sans relancer le banc
python3 scripts/bench.py --resultat banc.json --reference benchmarks/reference.json
```

Pour chaque essai de la référence (même jeu, même parallélisme), le
comparateur vérifie la durée totale (`total_s`) et les deux pics RSS
(`rss_max_mio`, `rss_max_enfants_mio`). Une mesure en régression dépasse la
référence de plus du seuil : `--seuil-duree` et `--seuil-memoire`, 20 % par
défaut, réglables à la demande dans le workflow. Une amélioration n'est
jamais une régression.

| Statut | Code de sortie | Cas |
| --- | --- | --- |
| `ok` | 0 | toutes les mesures restent sous le seuil |
| `regression` | 3 | au moins une mesure dépasse le seuil |
| `environnement_different` | 0 (avertissement) | CPU ou cœurs utilisables différents de la référence : rien n'est comparé |
| `incomparable` | 2 | un essai de la référence manque dans le résultat |

Le workflow publie `banc.json` et `banc.md` en artefact `banc-performance`
(90 jours) et ajoute le tableau et la comparaison au résumé du job.

### Mettre à jour la référence

La référence n'a de sens que sur la machine qui la mesure. Le workflow tourne
sur le runner maison (`NETCROSS_RUNS_ON_BENCH`, sinon `NETCROSS_RUNS_ON`).
La référence initiale vient d'un poste de développement (2 cœurs Xeon) :
tant qu'elle n'a pas été remplacée, le workflow rend le statut
`environnement_different`. Pour la remplacer, après un changement de runner
ou une amélioration voulue :

1. lancer le workflow à la demande sur `dev` ;
2. télécharger l'artefact `banc-performance` ;
3. copier `banc.json` dans `benchmarks/reference.json` dans une PR qui
   explique le changement.
