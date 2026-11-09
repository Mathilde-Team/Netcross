# Session 88 : consommer l'image CI préconstruite (#968)

L'audit distingue la construction/publication déjà livrée par docker25200
et docker24016 de sa consommation : `ci.yml` utilisait toujours Ubuntu nu.
Le workflow planifié du 9 novembre confirme la publication existante :
https://github.com/Mathilde-Team/Netcross/actions/runs/42617734999.

Les cinq jobs conteneur consomment maintenant l'image du registre avec
lecture seule. Les gardes de présence couvrent chaque ancienne installation
apt, avant comme après checkout, en conservant un repli bloquant si un paquet
manque ou si la requête dpkg échoue. Node.js rejoint l'image et son contrôle.

Les 70 tests dédiés passent ; les deux workflows sont validés avec
actionlint 1.7.12 et ShellCheck 0.11.0, sans désactiver d'analyse.
Les tests de gardes ne font aucun appel réseau ni installation réelle.
La construction Docker locale n'est pas revendiquée ; sa validation réelle
reste obligatoire en CI, comme la suite globale et la livraison jusqu'à main.
L'économie de temps attendue n'est pas présentée comme une mesure.

Après intégration de `dev` au commit `d6c7148` (qualité RTP/SRTP #1123),
la suite complète sous Xvfb donne 7 425 tests réussis, 1 ignoré existant,
111 avertissements, une couverture lignes/branches combinée de 98,08 %
et un code de sortie nul. Les hooks, mypy, MkDocs strict et actionlint
avec ShellCheck restent verts. La construction et le téléchargement de
l'image restent à vérifier par les workflows, sans revendiquer un gain
chronométré ni modifier les autorisations du compte local.

Le premier run a réellement téléchargé l'image mais son test du `.deb`
installé a révélé une dépendance absente, avec index apt nettoyés :
https://github.com/Mathilde-Team/Netcross/actions/runs/42718455188/job/129505955596.
La correction préinstalle les Depends/Recommends, les contrôle dans le
job paquets et teste leur alignement avec `build-deb/debian/control`.
L'installation et l'analyse réelles du paquet restent obligatoires ;
aucun contrôle n'est retiré pour résoudre cet échec.

Après correction, les 71 tests dédiés et la nouvelle suite complète passent :
7 426 réussis, 1 ignoré existant, 111 avertissements en 249,20 secondes,
98,08 % de couverture combinée et code de sortie zéro. Les hooks, mypy,
MkDocs strict et actionlint avec ShellCheck sont verts avant le nouveau push.

Après avancement de dev à `1f2ee59`, fusion normale de cette base dans la
branche de travail, en préservant les contributions et les deux entrées du
changelog. Nouvelle suite complète sous Xvfb : 7 433 réussites, un saut
préexistant, 111 avertissements, 294,38 secondes, 98,08 % de couverture
combinée et code zéro. Hooks, mypy sur 244 fichiers et MkDocs strict passent.
Actionlint 1.7.12 avec ShellCheck 0.11.0 passe sur les deux workflows modifiés.

L'audit actionlint de tous les workflows, plus large que ce changement,
signale l'interpolation directe de `github.head_ref` dans `guard-main.yml:26`.
Ce fichier est identique à la base dev et n'est pas modifié par #968.
Le résultat global est donc un échec préexistant, pas un contrôle vert ;
aucune règle ni vérification n'est désactivée.
