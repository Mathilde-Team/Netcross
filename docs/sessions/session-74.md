# Session 74 : traces d'entrée restantes hors amorçage du journaliseur

Date : 08/11/2026. Issue #954, branche `fix/954-traces-entree-restantes`.

## Périmètre

L'audit des entrées sur le `dev` de départ mesure 192 fonctions éligibles
sans première instruction DEBUG, pour une référence versionnée de 193.
La référence des sorties vaut déjà zéro. Le lot ajoute 183 appels DEBUG
dans 37 fichiers de `src/`, `scripts/` et `tools/`, sans modifier les
conditions d'éligibilité ni la classification des chemins chauds.

Les messages sont constants : nom de fonction et « entrée », sans argument,
chemin, objet, paquet ni secret. L'insertion conserve les docstrings et ne
modifie ni les branches, ni les retours, ni les exceptions. La migration
mécanique locale a vérifié que retirer ses seuls ajouts retrouve l'AST
initial ; le formatage du dépôt est ensuite appliqué.

## Limite conservée

Les neuf fonctions de `src/netcross_core/logging_config.py` restent intactes
et restent comptées par l'audit. Ce module doit retirer le handler DEBUG par
défaut avant ses premiers messages, faute de quoi le mode normal peut écrire
sur stderr. Aucun ajout d'exclusion, changement de seuil de couverture ou
désactivation de contrôle n'est effectué. La référence des entrées passe à
9 ; celle des sorties reste à 0.

## Vérifications

La suite de référence, avant modifications, passe avec 6 144 tests réussis
et 94 tests sautés dans l'environnement sans PyGObject. La couverture hors
GUI de cette référence vaut 98,8 %, au-dessus du seuil inchangé de 95 %.

Huit cas de test supplémentaires vérifient le garde-fou des entrées :
fonctions synchrones et asynchrones, docstring conservée, DEBUG direct ou
via `opt()` accepté, INFO ou trace tardive refusé.

Commandes de validation du lot :

```sh
uv run ruff check .
uv run ruff format --check .
PYTHONPATH=src uv run lint-imports
uv run python scripts/generate_class_diagram.py --check
PYTHONPATH=src uv run python scripts/generate_openapi.py --check
uv run pytest --cov --cov-fail-under=0 --cov-report=xml
uv run coverage report --omit='src/netcross_gtk4/*'
xvfb-run -a /tmp/netcross-gtk-env/bin/python -m pytest -q -rs --no-header \
  -p no:cacheprovider --cov=netcross_gtk4 --cov-report=term --cov-fail-under=0
```

Résultats locaux après modifications : 6 152 tests réussis, 94 sautés dans
l'environnement Qualité ; couverture hors GUI de 98,8 %. La suite complète
sous GTK/Xvfb passe avec 6 498 tests réussis et deux sauts explicites :
conversion ERF non prise en charge par le tshark installé et Graphviz absent.
La mesure GUI seule vaut 94,7 % ; comme en CI, elle est combinée à la mesure
Qualité avant l'application du seuil global inchangé de 95 %.

Lint, formatage, contrats d'import, diagramme, OpenAPI, mypy (218 fichiers),
documentation stricte et cohérence i18n passent également. Les résultats
de la CI sont consignés dans la PR avant fusion. Aucun test sauté pour
absence de GTK dans la suite Qualité n'est présenté comme une validation
graphique.

## Isolation du test asynchrone révélée par la validation

Le premier passage du lot a révélé la course décrite dans l'issue #1215 :
le test de réponse 202 quittait ses doublures avant la fin du worker de
comparaison. Celui-ci pouvait alors appeler le parseur remplacé par le test
d'upload suivant. Le test utilise désormais un vrai exécuteur dédié, fermé
avec attente avant de restaurer les doublures. Les assertions 202 et
`pending` sont conservées, et deux assertions vérifient l'exécution des
deux parsings et le résultat `completed`. L'API de production est inchangée.
