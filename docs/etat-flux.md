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
- **en tâche de fond** : à chaque paquet, les états silencieux depuis
  plus de `timeout` secondes ferment, pour borner la mémoire même sans
  trafic sur le flux.

La réouverture d'un flux après expiration est comptée par protocole
(`reopened`) : le réveil d'un flux expiré ouvre un nouvel enregistrement,
comme une nouvelle connexion Zeek.

## Détecteur incrémental : coupure NAT/pare-feu

Le détecteur de coupure silencieuse NAT/pare-feu (celui du mode batch,
`_analyse_idle_timeout`) est branché sur cet état : un enregistrement TCP
vu aux deux points d'un segment, fermé par expiration, dont le réveil
n'est jamais revu au point aval, compte une coupure pour ce segment
(`nat_cutoffs`, lignes `COUPURE NAT/PARE-FEU` du rapport texte). Les
règles sont celles du mode actuel :

- au moins deux paquets en amont, pour que le silence soit mesurable ;
- le réveil vu en aval exclut la coupure ;
- un seul silence retenu par flux et par segment ;
- jamais vu en aval avant le silence : pas ce scénario.

Les tests vérifient l'égalité des constats entre le mode actuel
(`analyse`) et l'état par flux sur ces scénarios, y compris les contre-
cas (réveil vu en aval, silence plus court que le délai, flux vu d'un
seul point).

## Limites et mémoire

- Les états ouverts sont proportionnels aux flux actifs ; un état fermé
  ne laisse que des compteurs.
- Deux mémoires bornées documentées : le résumé du dernier enregistrement
  TCP multipoint (pour le détecteur de coupure) est proportionnel au
  nombre de conversations TCP multipoints — comme `_conversations` de la
  corrélation en flux ; les clés récemment fermées (pour compter les
  réouvertures) sont plafonnées à 65 536 entrées.
- La lecture des captures reste entière avant la fusion (même limite que
  #1022) : le branchement de la lecture tshark en flux est le reste du
  chantier #995.
- `nat_cutoffs` est l'équivalent flux du constat batch
  `idle_timeout_dropped` : les deux sont calculés indépendamment (le mode
  batch reste la référence du rapport principal).
