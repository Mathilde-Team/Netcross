# Session 83 : audit du guide utilisateur (#465)

Le guide utilisateur et ses captures existent déjà sur `main`. Le présent
travail audite cette livraison sans se réattribuer les réalisations des
PR #467 et #1183 ni les autres compléments du guide.

Le démarrage API utilisait une affectation limitée au processus Uvicorn :
le jeton n'était donc plus disponible pour les commandes `curl` suivantes.
L'exemple exporte désormais le jeton et lance le serveur en arrière-plan,
avec une commande d'arrêt et la consigne de conserver le même terminal.

Un test rejoue le premier bloc shell avec des doublures de `pip`,
`openssl` et `uvicorn`, sans installer de paquet, démarrer de serveur ni
créer de véritable secret. Il vérifie la transmission du jeton au serveur
et sa disponibilité pour un processus client lancé ensuite. La régression
a été reproduite avant correction.

La première analyse des captures fournies et la construction stricte de
la documentation ont été reproduites sur `main`. La comparaison retrouve
zéro régression et une amélioration ; le parcours inverse signale une
régression et renvoie le code 1 documenté. L'API, exercée en processus
avec TestClient sans simulation du parsing, accepte les captures fournies :
réponse 201, deux points et 253 paquets.

La suite locale après correction du guide réussit : 7 012 tests, un sauté
lié au format ERF de TShark. La CI du dernier head, le relais et les
vérifications sur `main` restent nécessaires avant clôture.
