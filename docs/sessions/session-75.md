# Session 75 : guide utilisateur des clés TLS

Date : 09/11/2026. Issue #1049, branche `docs/1049-guide-keylog`,
depuis `dev` au commit `5a32c28`.

## Périmètre

Le guide `docs/guide/cles-tls.md` décrit la préparation d'une collecte
autorisée, la production d'un keylog côté navigateur, curl, Java et
Python, son association aux points Netcross, et l'injection ou le
retrait de blocs DSB avec editcap. Les recettes sont reliées aux
documentations officielles dans le guide, avec les URL complètes.

L'exemple Java fige extract-tls-secrets à 5.0.0 et ne télécharge ni
n'exécute automatiquement un agent. Les exemples de collecte conservent
la vérification des certificats ; ils ne lisent ni n'affichent de secrets
dans les journaux de mission.

Les renvois sont ajoutés au README, à MkDocs, au suivi des fonctionnalités
et à la page existante sur la couverture du déchiffrement.

## Limites conservées

Le lot ne modifie pas le pipeline, les options, les seuils, les exclusions
de couverture ni les protections. Les incompatibilités actuelles de
`--redact` restent en place ; le guide rappelle qu'une capture contenant
des DSB n'est pas partageable sans secrets du seul fait de l'anonymisation.

Les tests locaux du pipeline ne constituent pas une validation des
différents navigateurs, fournisseurs TLS Java ou backends curl en
production. Aucun secret de site ni aucune capture de production n'a
été utilisé pour rédiger ce guide.

## Vérifications

Les dépendances sont installées avec `uv sync --locked`, extras dev,
docs et api. Les tests ciblés des incidents, métriques, keylogs,
déchiffrement et absence de fuite de données anonymisées réussissent :
161 tests, sans saut dans cette sélection.

Sous Python 3.14, avec le `PATH` de l'environnement virtuel transmis aux
sous-processus, la suite complète réussit : 6 460 tests passés, 93 sautés
selon les dépendances graphiques disponibles et deux avertissements de
dépréciation FastAPI/Starlette.

`ruff check`, `ruff format --check`, `PYTHONPATH=src lint-imports`, les
contrôles de fraîcheur du diagramme et d'OpenAPI, ainsi que
`mkdocs build --strict` réussissent.

Le premier passage sous Python 3.12 avait un seul échec : le libellé
standard HTTP 413 diffère entre interpréteurs (« Request Entity Too Large »
contre « Content Too Large » dans la spécification versionnée). Le même
écart a été reproduit sur le `dev` de départ, sans nos modifications.
La spécification, le générateur et son test n'ont pas été modifiés.
