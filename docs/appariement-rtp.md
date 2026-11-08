# Appariement RTP entre points

Issue #1121, sous-issue 2/6 du chantier #1004 (VoIP multi-points).

L'analyse RTP regroupe les paquets par 5-tuple et SSRC. Un flux qui traverse
un NAT ou un SBC change d'adresses, de ports, parfois de SSRC, de numéros de
séquence et d'horodatages : il apparaît alors comme plusieurs flux sans lien,
un par point. `netcross_core.rtp_match` reconnaît ces « jambes » comme un
seul flux, sans jamais se fier aux adresses ni aux ports.

## Méthodes

Une jambe est la suite des paquets RTP d'un point pour un 5-tuple et un SSRC.
Deux jambes de points différents, qui se recouvrent dans le temps (à 5 s
près), sont comparées sur leurs couples (numéro de séquence, horodatage RTP) :

| Méthode | Cas | Règle |
| --- | --- | --- |
| `ssrc` | NAT, routeur, SBC qui relaie le média sans le réécrire | même SSRC, couples identiques |
| `ssrc_rewritten` | SBC qui ne réécrit que le SSRC | SSRC différent, couples identiques |
| `sbc_offset` | SBC qui réémet le média (SSRC, séquence, horodatage réécrits) | décalage constant de séquence et d'horodatage |

Seuil commun : au moins la moitié des paquets de la plus courte jambe doivent
coïncider, et au moins `MIN_COMMON` (5) ; une jambe plus courte doit coïncider
en entier.

### Heuristique NAT/SBC

Pour `sbc_offset`, les décalages (séquence, horodatage), modulo 2^16 et 2^32,
sont comptés entre les 24 premiers paquets de la jambe aval et les paquets de
la jambe amont capturés à moins de 5 s de son début. Un vrai décalage revient
pour chaque paquet commun, un faux une seule fois : les trois plus fréquents
sont essayés sur toute la jambe, et le premier qui atteint le seuil est
retenu. Les passages à zéro des compteurs sont gérés par le modulo.

En cas de concurrence (plusieurs jambes candidates à un même point), la paire
au plus grand nombre de paquets communs l'emporte, puis la méthode la plus
directe (`ssrc` avant `ssrc_rewritten`, avant `sbc_offset`). Une jambe
n'appartient qu'à un seul flux, et un flux n'a qu'une jambe par point.

## Sortie

Clé `rtp_matches` de `--json-report`, une entrée par flux vu à au moins deux
points :

- `method` : méthode de la jambe ajoutée, ou `mixed` si elles diffèrent
  (par exemple NAT puis SBC) ;
- `nat_rewritten` : adresses ou ports différents entre points ;
- `legs` : une jambe par point, dans l'ordre de `--order` (sinon du premier
  paquet), avec `seq_offset` et `ts_offset` par rapport à la première jambe ;
- `lost_between` : pour chaque couple de jambes consécutives, paquets vus en
  amont et absents en aval, entre le premier et le dernier paquet commun (un
  paquet capturé avant le début de la capture aval n'est pas une perte).

`rtp_streams` reste inchangé : chaque jambe y garde ses propres pertes, sa
gigue et son MOS.

## Limites

- Le contenu audio n'est pas comparé : un SBC qui transcode (autre codec,
  autre rythme d'horodatage) n'est pas reconnu.
- Un SBC qui renumérote la séquence sans décalage constant (paquets insérés
  ou supprimés) n'est apparié que sur la partie où le décalage tient.
