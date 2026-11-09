# État par flux

Issue #1023, sous-issue 4/6 du chantier
[#995](https://github.com/Mathilde-Team/Netcross/issues/995) (pipeline à
empreinte mémoire bornée). Elle s'appuie sur la
[corrélation en flux](correlation-en-flux.md) de #1022.

`netcross_core.flow_state` tient, comme la table de connexions de Zeek, un
état par flux actif et le libère à l'expiration : la mémoire dépend du
nombre de flux **actifs**, pas du nombre total de paquets ni de flux vus
pendant la capture.

## Utilisation

```bash
netcross --capture CLIENT=client.pcap --capture SERVEUR=serveur.pcap \
    --order CLIENT,SERVEUR --streaming --flow-timeouts TCP=3600,UDP=60,ICMP=60,AUTRE=60 \
    --json-report r.json
```

- `--streaming` active la corrélation en flux **et** l'état par flux : la
  clé `flow_state` s'ajoute à la section `streaming` de `--json-report`,
  et les lignes « État par flux » suivent le rapport texte.
- `--flow-timeouts` fixe les délais d'expiration par protocole, en
  secondes d'inactivité (défauts à la Zeek : TCP 3600, UDP 60, ICMP 60 ;
  `AUTRE` couvre les autres protocoles). Les protocoles inconnus et les
  délais non positifs sont refusés explicitement.

Un flux est une conversation directionnelle — clé
`(proto, src, sport, dst, dport)`, comme le détecteur batch d'expiration
silencieuse. L'état ouvert ne garde que des compteurs (paquets et octets
par point, premier et dernier horodatage), jamais les paquets.

## Expiration

Deux mécanismes complémentaires ferment un état :

- **au fil de l'eau** : un paquet qui arrive plus de `timeout` secondes
  après le dernier paquet du même flux au même point ferme l'état
  (raison `expiration`) et ouvre un nouvel enregistrement — c'est le
  silence mesuré au point amont, la même règle que le plus grand silence
  du détecteur batch ;
- **en tâche de fond** : à chaque paquet, un index d'échéances ferme les
  états dont le délai est atteint. Un TCP à délai long ne bloque pas
  l'expiration d'un UDP à délai court, même s'il a été vu avant lui.
  L'index est compacté pour ne pas grossir avec les paquets d'un flux actif.

Les délais doivent être strictement positifs et finis, y compris pour
un appel direct à `FlowTable` : NaN et les infinis sont refusés.

La réouverture d'un flux après expiration est comptée par protocole
(`reopened`) : le réveil d'un flux expiré ouvre un nouvel enregistrement,
comme une nouvelle connexion Zeek.

## Détecteur incrémental : coupure NAT/pare-feu

Le détecteur de coupure silencieuse NAT/pare-feu est branché sur cet état
(`nat_cutoffs`, lignes `COUPURE NAT/PARE-FEU` du rapport texte). Les
constats intermédiaires restent provisoires jusqu'à `finish()` : un
paquet aval plus tardif peut encore invalider une coupure supposée.
La réconciliation finale applique les règles de `_analyse_idle_timeout`
à seuil TCP identique, même si plusieurs silences ont eu lieu :

- au moins deux paquets au total en amont, pour mesurer un silence ;
- le plus grand silence, et le premier maximum en cas d'égalité ;
- une observation aval avant la reprise, et aucune après la reprise ;
- un seul constat par flux et par segment ;
- jamais vu en aval avant le silence : pas ce scénario.

Les tests comparent au mode actuel (`analyse`) les reprises tardivement
revues en aval, les maxima égaux et les silences multiples, avec des seuils
de 1, 60 et 3 600 secondes. Les entrées de `feed()` sont fusionnées en ordre
chronologique par `run_flow_table`, comme celles de la corrélation en flux.

## Limites et mémoire

- Les états ouverts et leurs statistiques temporelles par point sont
  proportionnels aux flux actifs. Le tas d'échéances contient au plus
  deux entrées par flux actif plus 64 entrées de marge.
- Les résumés TCP, statistiques globales et coupures déjà comptées sont
  dans une base SQLite temporaire, dans un répertoire privé ; le cache
  natif est plafonné à 1 Mio et les structures temporaires utilisent le
  disque. Le disque peut croître avec les conversations et segments,
  mais la RAM ne retient pas toutes les conversations terminées.
- Aucun paquet ni contenu applicatif n'est enregistré dans cet
  historique. Les clés de conversation et statistiques sont sensibles :
  la base n'est pas un export, et son répertoire est supprimé à `finish()`
  ou à la finalisation de l'objet abandonné. Les erreurs d'ouverture ou
  d'initialisation sont journalisées et propagées, pas transformées en
  rapport silencieusement incomplet.
- Les clés récemment fermées, utilisées pour compter `reopened`, restent
  plafonnées à 65 536 entrées ; une très ancienne réouverture peut donc
  ne plus incrémenter ce compteur. Cela n'efface pas les preuves NAT,
  conservées séparément sur disque jusqu'à la fin.
- La lecture des captures reste entière avant la fusion (même limite que
  #1022) : le branchement de la lecture tshark en flux est le reste du
  chantier #995.
- `nat_cutoffs` final est l'équivalent de `idle_timeout_dropped` à seuil
  identique : les deux sont calculés indépendamment, le mode batch
  restant la référence du rapport principal. Les délais d'expiration
  configurés différemment ne sont pas supposés donner les mêmes constats.
