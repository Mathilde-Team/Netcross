# Corrélation en flux

Issue #1022, sous-issue 3/6 du chantier #995 (pipeline à mémoire bornée).
Elle s'appuie sur l'empreinte de paquet de #1021.

`correlate()` charge tous les paquets de tous les points avant de les grouper
par clé. `netcross_core.streaming` corrèle au contraire les points en flux :

1. chaque point est lu comme une suite de paquets triée par temps ;
2. les suites sont fusionnées en k voies (`heapq.merge`), avec un seul paquet
   d'avance par point ;
3. un groupe (une clé `flow_key()`, en pratique un même paquet vu à plusieurs
   points) reste ouvert tant que le temps courant ne dépasse pas son dernier
   paquet de plus de la fenêtre ;
4. un groupe fermé ne laisse que des compteurs.

La mémoire dépend du nombre de groupes ouverts dans la fenêtre
(`peak_open_groups`), pas du nombre total de paquets.

## Utilisation

```bash
netcross --capture CLIENT=client.pcap --capture SERVEUR=serveur.pcap \
    --order CLIENT,SERVEUR --streaming --streaming-window 2 --json-report r.json
```

- `--streaming` : ajoute la corrélation en flux au rapport texte et la clé
  `streaming` au rapport JSON (`by_point`, `by_segment`, compteurs ci-dessous).
- `--streaming-window SECONDES` (2 s par défaut) : au moins le transit le
  plus long entre deux points, plus le délai de retransmission TCP à
  rattacher au paquet d'origine.

## Ce qui n'est jamais silencieux

| Compteur | Sens |
| --- | --- |
| `out_of_order` | paquet plus ancien que le temps courant, rattaché à son groupe encore ouvert |
| `late_packets` | paquet arrivé après la fermeture de son groupe par la fenêtre : il ouvre un second groupe |
| `open_at_end` | groupes encore ouverts en fin de capture, fermés à la fin |
| `truncated` | vrai dès qu'un paquet est tardif |

Dès qu'un paquet est tardif, le rapport texte affiche une ligne
`TRONCATURE` : les compteurs sont alors approchés, et il faut élargir
`--streaming-window`. Une clé fermée est mémorisée pendant deux fenêtres
pour reconnaître ses paquets tardifs.

## Équivalence avec le mode actuel

Si la fenêtre couvre le transit et les retransmissions, les compteurs sont
identiques à ceux d'`analyse()`. Les tests le vérifient sur du trafic
synthétique désordonné entre points : paquets, flux vus, retransmissions,
ACK dupliqués, pertes, hors chemin et latence moyenne par segment.

- Une perte n'est comptée qu'au premier point manquant, comme dans `analyse()`.
- La distinction perte / hors chemin (#352) dépend de tout le trafic d'un
  couple d'hôtes : elle est tranchée en fin de capture, avec une mémoire
  proportionnelle au nombre de couples d'hôtes.

## Limites

- La CLI lit encore les captures en entier avant de les corréler : le gain
  mémoire de la corrélation elle-même est acquis, mais la lecture en flux de
  la sortie tshark reste à brancher (chantier #995).
- La latence est une moyenne brute, sans la correction d'horloge de #996 ;
  aucune liste de latences n'est conservée.
- Sans `--order`, aucune perte n'est comptée (pas d'inférence de topologie
  en flux).
