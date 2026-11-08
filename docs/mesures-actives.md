# Mesures actives

Chantier #999. Le paquet `netcross_core.active` confirme un diagnostic passif par une mesure active ciblée.
Il est **désactivé par défaut** : l'analyse d'une capture n'émet jamais rien sur le réseau. Le branchement dans le CLI
et l'API, avec accord explicite de l'utilisateur, relève de #1068.

## Planificateur (#1063)

`netcross_core.active.planner.plan_measurements` lit les constats localisés et propose, sans rien émettre, un
traceroute à la Paris sur le 5-uplet du flux en défaut et/ou une mesure TWAMP-Light (`ProposedMeasurement`).

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
