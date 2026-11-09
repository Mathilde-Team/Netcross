# Mesures actives

Chantier #999. Le paquet `netcross_core.active` confirme un diagnostic passif par une mesure active ciblée.
Il est **désactivé par défaut** : l'analyse d'une capture n'émet rien sans accord explicite.
Le [raccordement CLI/API](confirmation-active.md) de #1068 propose une simulation prioritaire sans émission,
puis une activation volontaire ; le serveur API exige aussi son propre verrou d'autorisation.

## Planificateur (#1063)

`netcross_core.active.planner.plan_measurements` lit les constats localisés et propose, sans rien émettre, un
traceroute à la Paris sur le 5-uplet du flux en défaut et/ou une mesure TWAMP-Light (`ProposedMeasurement`).

## Traceroute Paris (#1065)

`netcross_core.active.paris_traceroute.mesurer(flux, parametres=None)` utilise le
binaire optionnel **Scamper**, sans shell, résolution DNS, changement de source,
élévation de privilège ou émission à l'import. `mesurer_proposition(proposition)`
accepte une proposition Paris du planificateur. Ces deux appels émettent réellement :
l'appelant doit obtenir l'autorisation et les exécuter au point source du flux.
Ils ne sont pas appelés par défaut par la CLI ou l'API ; seul le raccordement
explicitement activé de #1068 peut les lancer, jamais l'ouverture d'un rapport.

### Flux et budget

Les adresses doivent être des IP littérales unicast de même famille, sans zone
IPv6. TCP et UDP conservent source, destination et ports ; ICMP/ICMPv6 n'a pas
de ports et doit correspondre à la famille. La méthode native est `tcp`,
`udp-paris` ou `icmp-paris`. Le mécanisme Paris est celui de Scamper, pas une
réimplémentation de ses compensations de checksum. L'objectif est de conserver
les champs de sélection ECMP, pas de garantir que chaque équipement utilise
exclusivement ces champs.

| Paramètre | Défaut | Bornes |
|---|---:|---|
| `max_ttl` | 30 | 1–255 |
| `tentatives` par saut | 1 | 1–3 |
| `debit_max`, sondes/s | 10 | 1–10 |
| `timeout`, secondes par attente | 1 | 1–10 |
| `silence_max`, sauts consécutifs sans réponse | 3 | 2–20 |

Le TTL commence à 1 et un seul saut est en attente (`-N 1`). `-p` est
seulement l'objectif global du backend : le minimum entre sondes est imposé
séparément par `trace -W`, en unités de 10 ms, avec une unité de marge
(110 ms au débit par défaut). Le premier silence persistant configuré arrête
la mesure (`-g`, `-G 1`), sans sondes de dernier recours. Le budget maximal
est `max_ttl × tentatives`, avec une borne de durée du processus.

### Installation et résultat

Installer le paquet Scamper par les moyens autorisés au point d'exécution.
Le build doit avoir les droits nécessaires, notamment `CAP_NET_RAW` ou root
selon sa séparation de privilèges ; le paquet Ubuntu utilisé en CI a aussi
besoin de son environnement de séparation de privilèges. Netcross n'appelle
ni `sudo` ni `setcap`, ne change aucun droit, et ne se rabat jamais sur une
autre source si celle demandée est indisponible.

`ResultatParis.to_dict()` expose le flux, le début UTC, le statut, un message,
`envoyees` et les données JSON natives. Les adresses, méthode, ports, nombre
de sondes et TTL sont vérifiés avant acceptation. Le nombre réellement émis
est lu dans `probe_count` ; il reste `None` si le processus échoue ou dépasse
son délai, plutôt qu'un faux zéro. Un binaire absent produit `indisponible`
et zéro sonde ; un paramètre invalide lève `ParisError` avant exécution.
Les erreurs de droits rappellent explicitement `CAP_NET_RAW/root`. Chaque
mesure validée journalise son début UTC, la cible et le budget, puis son
nombre natif de sondes, ou l'absence de compte vérifiable.

### Validation et limites

Les tests unitaires ne lancent jamais le binaire. Le job dédié
`paris-netns.yml` exécute explicitement quatre tests réels dans trois espaces
réseau reliés par des veth, sans route extérieure : TCP, UDP, ICMP et routeur
qui perd les paquets. Une capture AF_PACKET horodatée par le noyau vérifie
adresses, ports, TTL, espacement et checksum ICMP stable ; les pertes doivent
arrêter la mesure sur `GAPLIMIT`. Le rapport JUnit doit compter quatre tests
et aucun test sauté. La VM GitHub hébergée est éphémère ; aucun privilège
supplémentaire n'est demandé aux runners maison.

Une absence de réponse ICMP ne prouve pas une panne : filtrage, limitation
ICMP et équipements silencieux restent possibles. Le chemin retour peut
différer ; aucune mesure de latence unidirectionnelle synchronisée n'est
déduite du traceroute. La validation réseau dédiée porte sur IPv4 synthétique,
pas sur des réseaux clients, IPv6 réel ou tous les algorithmes ECMP.

Les options et unités sont celles du [manuel Scamper](https://manpages.opensuse.org/Tumbleweed/scamper/scamper.1.en.html).
Le principe et ses limites sont décrits par le [projet Paris traceroute](https://paris-traceroute.net/about/).

## Client TWAMP-Light (#1066)

`netcross_core.active.twamp.mesurer(cible, port=862, nombre=10, intervalle=0.1, timeout=1.0)` envoie des sondes
TWAMP-Light (RFC 5357, annexe I : paquets de test non authentifiés, sans session de contrôle) à un réflecteur et
renvoie un `ResultatTwamp` :

| Mesure | Calcul | Remarque |
|---|---|---|
| Aller-retour | \((t_4 - t_1) - (t_3 - t_2)\) | temps de traitement du réflecteur retiré, indépendant des horloges |
| Aller, retour | \(t_2 - t_1\), \(t_4 - t_3\) | n'ont de sens que si les horloges sont synchronisées (NTP, PTP) |
| Pertes | sondes sans réponse avant `timeout` | taux et nombre |
| Gigue | moyenne des écarts entre délais aller-retour successifs | variation de délai inter-paquets (RFC 3393) |
| TTL reçu | champ « Sender TTL » de la réponse | sauts aller = TTL initial du système (souvent 64) moins cette valeur |

`statistiques()` résume en millisecondes, `to_dict()` donne une représentation JSON. Pour une proposition du
planificateur, `cible_de_proposition(proposition, reflecteur=None)` donne l'hôte et le port : le réflecteur
indiqué, sinon la destination du flux.

### Sans réflecteur

`mesurer` ne lève pas d'exception quand il n'y a pas de réflecteur : le résultat porte `reflecteur_present=False` et
un message explicite.

- « aucun réflecteur TWAMP-Light ne répond sur H:P (N sonde(s), aucune réponse en T s) » : rien ne répond ;
- « … port fermé (ICMP port inaccessible) » : l'hôte a refusé le port ;
- « cible injoignable : H:P (…) » : nom inconnu ou adresse inutilisable, aucune sonde envoyée ;
- « … émission impossible (…) » : erreur réseau à l'envoi.

Seuls des paramètres hors garde-fous lèvent `TwampError`.

### Garde-fous

- 10 sondes par seconde au plus (`intervalle` ≥ 0,1 s) et 1 000 sondes par mesure ;
- chaque mesure est journalisée au niveau INFO : horodatage UTC, cible, port, sondes envoyées et reçues ;
- `construire_reponse` permet de monter un réflecteur (utilisé par les tests sur la boucle locale).

### Limites

- Mode non authentifié seulement (pas de modes authentifié ni chiffré de RFC 5357).
- La sonde porte un TTL fixé par le système. Le TTL de départ n'est pas imposé, il faut donc connaître celui du
  système pour en déduire le nombre de sauts.
- Pas de traitement des réponses arrivées après `timeout` : la sonde reste comptée perdue.
