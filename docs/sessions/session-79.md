# Session 79 : traceroute Paris borné et explicitement autorisé

Date : 9 novembre 2026. Périmètre : #1065, dépendance #1063 déjà livrée.
Le raccordement CLI/API et son accord utilisateur restent dans #1068.

## Choix du backend

Scamper est un binaire optionnel existant, appelé avec une liste d'arguments
et `shell=False`, sans sudo, setcap, résolution DNS ou modification du
système. Source, destination et ports sont conservés ; un échec ne déclenche
jamais de repli vers une source différente. TCP, UDP-Paris et ICMP-Paris
utilisent les mécanismes natifs de Scamper.

Les options sont vérifiées dans le manuel du paquet Ubuntu
`scamper=20211212-1.2build2`, également figé dans le job dédié. En
particulier, `-p` n'impose pas seul une limite stricte entre les sondes :
`trace -W` ajoute un intervalle minimal en unités de 10 ms (110 ms par
défaut), avec `-N 1` et `-G 1`. TTL, tentatives, débit, attente et silence
sont bornés ; les IP littérales, protocoles, familles et ports sont validés
avant lancement.

Le JSON natif est contrôlé : une seule trace, flux demandé, méthode,
ports, budget et TTL. Le compte envoyé vient du backend ; il reste
inconnu si le processus échoue ou expire. Les erreurs de droits sont
explicites. Les traces INFO donnent début UTC, cible, budget et compte
final vérifiable, sans prétendre connaître ce qui a été émis en cas
d'échec du processus.

## Tests et environnement

La première sélection unitaire finale réussit : 57 tests en 0,09 s.
Elle remplace le binaire par une doublure et ne prouve pas un chemin
réseau réel. Ruff est vert sur le backend et les deux fichiers de tests.

La mesure ciblée confirme **100 % des lignes et branches** du backend
(137 instructions, 42 branches, aucune manquante ; 57 tests en 0,12 s).
La suite complète locale réussit ensuite : **6 576 tests, 94 sautés,
2 avertissements, 154,60 s**. Les sauts liés à l'environnement ne valent
pas des validations réussies. Ruff vérifie 733 fichiers formatés ;
import-linter conserve son contrat, mypy ne signale aucune erreur sur le
nouveau module, diagramme et OpenAPI sont à jour, et MkDocs strict
construit la documentation en 3,10 s. La couverture ciblée n'est pas
présentée comme la couverture combinée de toute l'application.

Les essais locaux `ip netns` ont effectivement été tentés dans un espace
de montage et de réseau privé, avec des adresses de documentation et
aucune route vers l'extérieur. Le sandbox bloque le `chroot` de la
séparation de privilèges de Scamper (`Operation not permitted`) et son
noyau ne fournit pas `nftables` (`Protocol not supported`). Les quatre
essais locaux sont donc en échec d'environnement, pas déclarés réussis ;
aucune protection n'est contournée pour les faire passer.

Le job CI dédié utilise une VM hébergée `ubuntu-24.04` éphémère, un
conteneur Ubuntu 26.04 privilégié uniquement dans cette VM et les outils
réseau système. Il n'ajoute aucun droit aux runners maison. Python 3.14.8,
uv 0.13.4 et le paquet Scamper sont figés ; les actions sont épinglées par
SHA et le checkout ne conserve pas de credentials.

Le job appelle explicitement quatre tests : TCP, UDP, ICMP et routeur qui
perd les paquets. Le routeur n'a aucune route extérieure. AF_PACKET et
SO_TIMESTAMPNS vérifient flux, TTL, intervalle et checksum ICMP stable.
Le compte natif doit correspondre aux paquets capturés, et la perte
persistante doit produire `GAPLIMIT`. Le JUnit impose quatre tests et
zéro skip. Une CI dédiée verte, ainsi que les autres contrôles du dernier
head, restent obligatoires avant fusion ; aucun résultat réseau n'est
revendiqué à ce stade du journal.

## Limites conservées

Pas d'émission implicite, de déploiement sur des points clients, de preuve
IPv6 réelle ni de garantie universelle de sélection ECMP. Les réponses
ICMP peuvent être filtrées ou limitées et le chemin retour asymétrique.
Le backend ne fabrique pas de latence unidirectionnelle synchronisée.

Références techniques :
[manuel Scamper](https://manpages.opensuse.org/Tumbleweed/scamper/scamper.1.en.html)
et [principe Paris traceroute](https://paris-traceroute.net/about/).
