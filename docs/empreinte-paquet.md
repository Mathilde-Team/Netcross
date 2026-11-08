# Empreinte de paquet invariante

Issue #1021, préalable au pipeline en flux (#1022).

`netcross_core.empreinte` calcule pour chaque paquet un entier de 64 bits qui
l'identifie d'un point de capture à l'autre. C'est une projection de la clé
`correlate.flow_key()` : deux paquets ont la même empreinte si et seulement si
ils ont la même clé (aux collisions près, voir plus bas). Les appariements
sont donc identiques à ceux d'aujourd'hui, mais chaque paquet n'a plus besoin
de garder un tuple de six valeurs pour être retrouvé.

## Champs utilisés

| Mode | Champs |
| --- | --- |
| strict (défaut) | protocole, IP source, port source, IP destination, port destination, `key_id` |
| `--nat-tolerant` (paquet avec payload) | `"NAT"`, protocole, hash MD5 du payload, fenêtre temporelle (`--nat-window-ms`) |

`key_id` vaut le numéro de séquence TCP pour TCP et l'identifiant IP
(`ip.id`) pour UDP et ICMP. Les champs qui changent à chaque saut sont
exclus : TTL, somme de contrôle IP, adresses MAC, VLAN, DSCP réécrit, horodatage.

L'empreinte est un condensat BLAKE2b de 8 octets d'un encodage sans
ambiguïté (séparateur ASCII `0x1F`, marqueur dédié pour une valeur absente).
Elle ne dépend pas de `PYTHONHASHSEED` : deux processus, ou deux sondes
distribuées, calculent la même valeur pour le même paquet.

## API

```python
from netcross_core.correlate import correlate
from netcross_core.empreinte import apparier, comparer_appariements, empreinte

valeur = empreinte(pk)  # int sur 64 bits
groupes = apparier(paquets)  # {empreinte: {point: [Pkt, ...]}}
rapport = comparer_appariements(correlate(paquets), groupes)
# {"groupes_cle": ..., "groupes_empreinte": ..., "collisions": 0, "identiques": True}
```

`apparier()` applique le même filtre que `correlate()` : ARP et STP sont
exclus, et les doublons aussi avec `exclude_duplicates=True`.

## Limites

- **NAT/PAT** : l'adresse et le port réécrits changent l'empreinte stricte.
  Le mode NAT-tolérant rapproche les deux vues par le payload, mais il ne
  fonctionne pas sur les paquets sans payload (SYN, ACK purs : retour à
  l'empreinte stricte) ni quand un ALG réécrit le contenu (FTP actif, SIP).
  Deux paquets identiques à cheval sur une frontière de fenêtre tombent dans
  deux fenêtres différentes.
- **Fragmentation** : seuls les premiers fragments portent les ports. Les
  fragments suivants d'un même datagramme partagent une empreinte (ports
  absents, même `ip.id`) distincte de celle du premier. Si un routeur
  fragmente entre deux points, le premier fragment reste apparié au
  datagramme d'origine et les suivants ne sont vus qu'en aval. C'est le
  comportement actuel de `correlate()`. En IPv6, `ip.id` n'existe que si
  l'en-tête Fragment est présent : les datagrammes UDP non fragmentés d'un
  même 5-tuple se regroupent.
- **Réécritures** : un équipement qui randomise `ip.id` (certaines piles et
  NAT) ou les numéros de séquence TCP (pare-feu) casse l'appariement strict.
  Les retransmissions TCP gardent le même numéro de séquence et partagent
  donc l'empreinte du segment d'origine, comme aujourd'hui.
- **Collisions** : sur 64 bits, la probabilité d'au moins une collision
  parmi n clés est d'environ n² / 2⁶⁵, soit moins de 3·10⁻⁶ pour 10⁷ clés.
  `collisions()` les liste et `comparer_appariements()` les compte.

## Vérification

`tests/test_empreinte.py` vérifie l'équivalence avec `correlate()` sur un
trafic construit à la main, sur des cas NAT et fragmentation, et sur un jeu
synthétique du banc (#1015) lu par tshark, en mode strict et en mode
NAT-tolérant.
