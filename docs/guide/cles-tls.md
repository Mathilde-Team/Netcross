# Obtenir et utiliser les clés TLS

Ce guide concerne une analyse autorisée de captures déjà enregistrées, sur des
applications que vous contrôlez. Il complète la page sur la
[couverture réelle du déchiffrement](../couverture-dechiffrement.md) :
fournir un fichier de clés ne signifie pas que toutes les sessions sont lisibles.

## Préparer une collecte limitée

Un keylog contient des secrets de session, pas seulement des métadonnées de
diagnostic ; associé à la capture correspondante, il permet de lire les échanges,
y compris avec un échange de clés Diffie-Hellman ([documentation TLS de
Wireshark](https://gitlab.com/wireshark/wireshark/-/wikis/tls)).
Notre recommandation est de limiter la collecte à un compte et un scénario
de test autorisés, avec une durée de conservation convenue à l'avance.

Sous Linux, préparer un répertoire privé et un chemin absolu, dans le même
terminal que les commandes suivantes :

```sh
umask 077
DOSSIER_TLS="$(mktemp -d "${TMPDIR:-/tmp}/netcross-tls.XXXXXXXX")"
KEYLOG="$DOSSIER_TLS/cles-tls.log"
```

Ne pas activer cette collecte globalement dans le profil de session ou dans un
service partagé. Fermer les autres sessions de test, démarrer la capture au
point voulu, puis provoquer de nouvelles connexions avec l'une des méthodes
ci-dessous ; Wireshark demande notamment de définir la variable avant de
démarrer le navigateur ([procédure Wireshark](https://gitlab.com/wireshark/wireshark/-/wikis/tls)).

## Produire le keylog côté application

### Firefox ou Chromium

Fermer complètement le navigateur avant de le relancer depuis ce terminal :
un processus déjà ouvert ne reprend pas nécessairement son nouvel
environnement ; utiliser un chemin absolu accessible en écriture
([procédure Wireshark](https://gitlab.com/wireshark/wireshark/-/wikis/tls)).
Choisir un navigateur et un profil réservés au diagnostic, sans session
personnelle connectée.

```sh
SSLKEYLOGFILE="$KEYLOG" firefox
# Autre navigateur, à adapter au binaire installé :
SSLKEYLOGFILE="$KEYLOG" chromium
```

Ouvrir ensuite le service de test pendant la capture, puis fermer le navigateur
après le scénario. Vérifier seulement la présence de données, sans afficher les
secrets dans le terminal ou les journaux :

```sh
test -s "$KEYLOG"
```

### curl

`SSLKEYLOGFILE` fonctionne si la bibliothèque TLS du curl installé prend en charge
la journalisation des secrets ; ce n'est pas une garantie applicable à tous les
binaires ([documentation libcurl](https://curl.se/libcurl/c/libcurl-env.html)).
Identifier le backend avec `curl --version`, puis essayer une requête autorisée ;
ne pas utiliser `--insecure` pour contourner un problème de certificat.

```sh
curl --version
SSLKEYLOGFILE="$KEYLOG" curl --fail --silent --show-error \
  --output /dev/null https://example.com/
test -s "$KEYLOG"
```

Remplacer `https://example.com/` par le service de test. Si le fichier reste
absent ou vide, vérifier le backend et sa configuration plutôt que de conclure
que la capture est déchiffrable.

### Java avec extract-tls-secrets

Le projet `extract-tls-secrets` documente l'agent JVM avec la syntaxe
`-javaagent:CHEMIN_JAR=CHEMIN_KEYLOG` ; sa version 5.0.0 est utilisée dans cet
exemple pour ne pas dépendre d'un téléchargement « latest »
([instructions du projet](https://github.com/neykov/extract-tls-secrets)).
Faire approuver et vérifier le JAR par la procédure habituelle de votre
organisation avant de l'instrumenter dans une application.

```sh
AGENT="/chemin/valide/extract-tls-secrets-5.0.0.jar"
java "-javaagent:$AGENT=$KEYLOG" -jar application-test.jar
test -s "$KEYLOG"
```

Le fournisseur TLS utilisé compte : le projet indique notamment que Conscrypt
n'est pas pris en charge ; vérifier sa matrice de compatibilité et la JVM
cible, sans supposer que toute application Java utilise le fournisseur attendu
([compatibilité extract-tls-secrets](https://github.com/neykov/extract-tls-secrets)).
Privilégier ce démarrage explicite d'une application de test plutôt qu'un
attachement à un processus de production.

### Python

Depuis Python 3.8, `ssl.create_default_context()` active la journalisation quand
`SSLKEYLOGFILE` est défini et que cette fonction est prise en charge ; un contexte
peut aussi définir explicitement `keylog_filename`
([documentation Python ssl](https://docs.python.org/3/library/ssl.html)).
L'exemple suivant conserve la vérification du certificat et passe le contexte
instrumenté au client qui effectue réellement la requête.

```sh
SSLKEYLOGFILE="$KEYLOG" python3 - <<'PY'
import os
import ssl
import urllib.request

contexte = ssl.create_default_context()
contexte.keylog_filename = os.environ["SSLKEYLOGFILE"]
with urllib.request.urlopen("https://example.com/", context=contexte, timeout=10) as reponse:
    reponse.read()
PY
test -s "$KEYLOG"
```

Avec une autre bibliothèque HTTP, vérifier qu'elle emploie effectivement ce
contexte ; exporter une variable ne remplace pas cette vérification.
Les écritures du keylog Python sont synchronisées entre threads, mais pas entre
processus : prévoir des fichiers distincts pour des processus de test séparés
([documentation Python ssl](https://docs.python.org/3/library/ssl.html)).

## Associer les clés aux points Netcross

Depuis la racine du dépôt, fournir le même fichier à tous les points avec
`--tls-keylog FICHIER`, ou un fichier propre à un point avec
`--tls-keylog NOM=FICHIER`. L'option est répétable ; une association nommée est
prioritaire sur l'association globale.

```sh
PYTHONPATH=src uv run python src/cross_capture_analyzer_cli.py \
  --capture CLIENT=client.pcapng --capture SERVEUR=serveur.pcapng \
  --tls-keylog "CLIENT=$KEYLOG" --tls-keylog "SERVEUR=$KEYLOG" \
  --json-report rapport.json
```

Un nom de point inconnu ou un fichier absent est refusé. La GUI propose
« Cles TLS... » et l'API accepte `tls_keylog` avec `tls_keylog_labels` ;
voir les [exemples multipart de l'API](../api-rest.md) et la
[parité des surfaces](../parite-surfaces.md).

Consulter ensuite les compteurs par point : une session partiellement lisible
ne prouve ni un déchiffrement complet de tous ses enregistrements, ni la
présence de toutes les sessions attendues. Les définitions et limites sont
dans [Couverture du déchiffrement TLS/QUIC](../couverture-dechiffrement.md).

## Embarquer les secrets dans un pcapng

`editcap --inject-secrets` insère les secrets dans un bloc DSB du fichier
pcapng de sortie ; le destinataire peut donc les utiliser sans recevoir un
keylog séparé ([manuel editcap](https://www.wireshark.org/docs/man-pages/editcap.html)).
Traiter cette sortie comme un fichier de secrets, pas comme une simple capture
anonymisée.

```sh
editcap -F pcapng --inject-secrets "tls,$KEYLOG" \
  client.pcapng "$DOSSIER_TLS/client-avec-secrets.pcapng"
```

Pour produire une autre copie sans les DSB d'entrée, utiliser une commande
séparée : `--discard-all-secrets` ne retire pas les secrets injectés sur cette
même ligne de commande ([manuel editcap](https://www.wireshark.org/docs/man-pages/editcap.html)).
Ne pas écraser l'original servant de preuve.

```sh
editcap --discard-all-secrets \
  "$DOSSIER_TLS/client-avec-secrets.pcapng" "$DOSSIER_TLS/client-sans-dsb.pcapng"
```

Cette opération n'anonymise ni les adresses, ni le contenu applicatif déjà en
clair dans la capture. Relire et classifier la copie avant tout partage.

## Limites et fin de diagnostic

- **Anonymisation** : Netcross refuse actuellement `--tls-keylog` avec
  `--redact`, ainsi que certaines analyses applicatives avec `--redact`.
  Ne pas enlever cette protection pour distribuer un rapport ; la levée de
  ces incompatibilités appartient au chantier #1155.
- **Secrets embarqués** : le mode `--redact` ne garantit pas le retrait des
  DSB d'une capture d'entrée. Ne jamais le considérer comme une garantie
  de partage sans secrets ; le fichier de correspondance de pseudonymes
  reste lui aussi privé.
- **Portée** : les clés doivent correspondre aux connexions présentes dans
  la capture ; démarrer la collecte avant les connexions de test et ne pas
  extrapoler un compteur positif à toutes les sessions.
- **Rétention** : arrêter l'application instrumentée, retirer l'agent JVM
  de son lancement, et exécuter `unset SSLKEYLOGFILE` si la variable avait
  été exportée. Conserver puis supprimer keylogs et captures contenant des
  secrets selon la politique convenue, sans les envoyer dans un ticket,
  une PR, un artefact CI ou un dépôt Git.

Les exemples de collecte dépendent de votre navigateur, backend TLS, fournisseur
Java et client Python. La construction documentaire et les tests du pipeline
ne constituent pas une validation de chacun de ces environnements sur un site
de production.
