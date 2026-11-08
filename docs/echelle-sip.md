# Échelle SIP multi-points

Le diagramme d'échelle SIP (issue #1125, chantier VoIP #1004) montre, pour
chaque appel, à quel point de capture chaque message SIP a été vu, et ce
qui lui est arrivé en chemin. Il figure dans le rapport PDF (section
« Echelle SIP multi-points »), dans le rapport HTML autonome (avec ou sans
JavaScript) et dans le JSON du rapport, sous la clé `sip_ladders`.

## Lecture

Une ligne par message de l'appel (méthode ou ligne de statut, avec son
CSeq), une colonne par point de capture. Une cellule donne la date du
message en millisecondes depuis le premier message de l'appel, tous points
confondus. Trois constats sont écrits en toutes lettres dans la cellule (la
couleur ne fait que doubler le texte) :

| Constat | Signification |
|---|---|
| `ABSENT` | message vu à un autre point, mais pas à celui-ci : il s'est perdu (ou a été filtré) entre les deux |
| `xN (retransmis)` | message vu N fois au même point : retransmission UDP (temporisateurs de la RFC 3261, section 17) |
| `reecrit : SDP, Via, Contact` | champs différents de ceux du premier point où le message a été vu |

Les réponses `100 Trying` sont produites à chaque saut (RFC 3261, 16.2) :
leur absence à un point n'est jamais une perte (« saut par saut »).

Un point qui n'a vu aucun message de l'appel n'a pas de colonne : il n'est
pas sur le chemin de signalisation (capture du seul média, autre lien), et
aucun message n'y est donc déclaré perdu.

## Réécritures détectées

- **SDP** : adresses et ports média des lignes `c=` et `m=` (issue #1120).
  Un SDP supprimé entre deux points compte comme une réécriture.
- **Via** : le premier en-tête `Via` (celui du dernier saut). Un proxy SIP
  ajoute légitimement le sien : un `Via` changé est un indice, pas une
  anomalie à lui seul.
- **Contact** : l'en-tête `Contact`, réécrit par un ALG ou un SBC qui
  traduit les adresses.

`Via` et `Contact` (formes compactes `v` et `m` comprises) sont lus dans la
charge utile SIP et tronqués à 200 caractères. Ils ne sont comparés que
s'ils sont connus aux deux points. Avec `--redact`, leurs adresses IP
reçoivent le même pseudonyme que les adresses des paquets, si bien que la
comparaison reste exacte ; le reste du texte (utilisateur, paramètres) est
conservé, comme les autres identifiants SIP.

## Format JSON

```json
{
  "call_id": "a84b4c76e66710",
  "points": ["CLIENT", "SBC", "SERVEUR"],
  "messages": [
    {
      "message": "INVITE",
      "cseq": "1 INVITE",
      "hop_by_hop": false,
      "cells": {
        "CLIENT": {"count": 1, "rel_ms": 0.0, "frame_number": 12, "rewritten": []},
        "SBC": {"count": 1, "rel_ms": 2.1, "frame_number": 40, "rewritten": ["sdp", "contact"]}
      },
      "lost_at": ["SERVEUR"],
      "retransmitted_at": [],
      "rewritten": [{"point": "SBC", "fields": ["sdp", "contact"]}]
    }
  ],
  "total_messages": 1,
  "truncated": 0,
  "lost": 1,
  "retransmitted": 0,
  "rewritten": 1
}
```

## Limites

- 20 appels au plus (ceux qui portent un constat d'abord, puis dans l'ordre
  chronologique), 40 messages par appel (les premiers) ; `truncated` donne
  le nombre de messages non représentés.
- Les colonnes suivent l'ordre du chemin quand il est connu
  (`--order`), sinon l'ordre de première observation de l'appel.
- Les dates sont brutes : le décalage d'horloge entre points n'est pas
  corrigé ici.
- SIP sur TLS (port 5061) non déchiffré : les messages ne sont pas lisibles et
  n'apparaissent pas.
