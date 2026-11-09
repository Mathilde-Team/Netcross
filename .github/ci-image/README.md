# Image préconstruite de CI

Le Dockerfile et le workflow de construction proviennent du travail de
docker25200, repris par docker24016 dans les PR #1014 et #1188.
Le complément de #968 branche effectivement les cinq jobs conteneur de
`ci.yml` sur `ghcr.io/mathilde-team/netcross-ci:26.04` :
qualité, GTK4, couverture combinée, paquets et traductions.

## Publication et lecture

Le workflow `ci-image.yml` construit et contrôle l'image sur une PR
modifiant ses sources, sans la publier. Après fusion dans dev, il construit
et pousse les tags `26.04` et `26.04-<sha court>`. La reconstruction
hebdomadaire du lundi à 04:00 UTC et le déclenchement manuel sont conservés.
La publication utilise le droit `packages: write` préexistant du workflow.

Le workflow consommateur ne demande que `contents: read` et `packages: read`.
L'authentification du conteneur utilise le jeton éphémère du job, sans
secret supplémentaire ni modification de visibilité du paquet. Si le pull
de l'image échoue, le job échoue : aucun repli vers une autre image ni
contournement d'un contrôle n'est prévu.

## Contrôle des prérequis

Avant chaque ancienne installation apt, `dpkg-query` vérifie tous les
paquets concernés. Si chaque paquet est installé, aucun index apt n'est
téléchargé et aucun appel à apt n'est exécuté. Un paquet absent, partiellement
installé ou une erreur de requête déclenche le repli apt existant ; un échec
de mise à jour ou d'installation reste bloquant.

Node.js fait partie de l'image et du contrôle de construction, car les
tests des rapports HTML l'utilisent maintenant dans les jobs qualité et GTK4.
Pendant la transition depuis une image déjà publiée sans Node.js, le repli
reste fonctionnel. Après une modification de dépendance système, mettre à
jour le Dockerfile, le contrôle des outils et la liste du job concerné.

Les dépendances `Depends` et `Recommends` du `.deb` sont aussi préinstallées
et contrôlées dans le job paquets. L'image supprime ses index apt ; sans
ce contrôle, le test d'installation du `.deb` ne pourrait pas résoudre
une dépendance absente lorsque toutes les gardes de construction passent.
Le repli recharge les index et installe ces dépendances pendant la transition
depuis une ancienne image, sans retirer le test de fumée du paquet installé.

## Validation et limites

Les tests `tests/test_ci_prebuilt_image.py` exécutent les gardes Bash avec
de faux exécutables dpkg/apt : présence complète, paquet non installé,
configuration résiduelle, requête en échec et échecs apt. Ils vérifient aussi
que l'image déclare tous les paquets contrôlés et que la publication hors PR
et la fréquence existantes restent conservées.

Ces tests ne remplacent pas la construction Docker et les jobs réels.
Le gain de durée annoncé dans l'issue est un objectif, pas une nouvelle
mesure : aucun gain chiffré n'est revendiqué sans comparaison de runs.
