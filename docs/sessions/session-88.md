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
