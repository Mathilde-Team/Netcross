# Couverture du déchiffrement TLS/QUIC

Pour produire et associer les fichiers de clés, suivre le
[guide des clés TLS](guide/cles-tls.md). Il couvre navigateur, curl,
Java, Python et les précautions propres aux captures contenant des DSB.

Un fichier de clés (`--tls-keylog`, champ « Cles TLS... » de la GUI, `tls_keylog` de l'API) ou des secrets
embarqués dans une capture pcapng (blocs DSB, `editcap --inject-secrets`) ne couvrent souvent qu'une partie des
sessions : navigateur lancé avant `SSLKEYLOGFILE`, autre poste, sessions reprises. Depuis l'issue #1043, le
rapport indique, pour chaque point concerné, combien de sessions ont réellement été déchiffrées :

```text
-- Dechiffrement TLS / QUIC --
  42/50 sessions TLS déchiffrées au point CLIENT
  3/4 sessions QUIC déchiffrées au point CLIENT
```

## Définitions

- **Session TLS** : un `tls.stream` de tshark dans la capture du point. Elle est comptée déchiffrée si au moins
  un de ses enregistrements l'a été (tshark n'ajoute `tls.record.sequence_number` qu'aux enregistrements
  déchiffrés, TLS 1.2 comme 1.3).
- **Session QUIC** : un `quic.connection.number`. Elle est comptée déchiffrée si au moins un paquet 1-RTT
  (en-tête court) a été déchiffré, c'est-à-dire dont tshark a disséqué les trames. Les paquets Initial, toujours déchiffrables, ne comptent pas.
- Un paquet sans identifiant de session est rattaché à sa conversation (adresses et ports, sans le sens).

## Points affichés

Un point apparaît s'il a reçu un fichier de clés, si sa capture embarque des blocs DSB, ou si au moins une de ses
sessions a été déchiffrée. Un point qui a reçu une clé sans aucune session TLS ni QUIC est signalé (« aucune
session TLS ou QUIC au point X ») : la clé n'a rien trouvé. Sans clé ni secret, la section est absente.

## Sorties

| Sortie | Forme |
|---|---|
| Rapport texte | section « Dechiffrement TLS / QUIC » |
| PDF | sous-section « Déchiffrement TLS / QUIC » du détail par module |
| JSON (`--json-report`, API) | clé `decryption.by_point` : `point`, `keylog`, `tls_sessions`, `tls_decrypted`, `quic_sessions`, `quic_decrypted`, `summary` |

La clé `decryption` est absente quand rien n'est à signaler.

## Limites

- Le compteur QUIC est testé sur une vraie connexion QUIC v1 versionnée (`tests/data/quic-1rtt.pcap` et son
  fichier de clés, produits une fois par `scripts/generer_capture_quic.py` avec aioquic, qui n'est pas une
  dépendance du projet). Sans clé, tshark ne signale pas d'échec sur un paquet 1-RTT : seule la présence de
  trames disséquées prouve le déchiffrement.
- Une session dont la capture ne contient que la fin (ni poignée de main ni clé) est comptée non déchiffrée.

## Diagnostics sur le contenu déchiffré

Issue #1045. Avec un fichier de clés (`--tls-keylog`, API `tls_keylogs`, onglet avancé de l'interface), trois
analyses lisent aussi le contenu déchiffré :

- **Certificat TLS 1.3** : le message Certificate, chiffré en TLS 1.3, devient lisible. tshark rend la trame
  déchiffrée comme plusieurs couches `tls` (EncryptedExtensions, Certificate, CertificateVerify, Finished) ;
  Netcross lit celle qui porte le certificat. Le numéro de série alimente alors le détecteur de substitution
  entre points (`tls_cert_mismatch`, « interception/substitution TLS possible »), qui reste muet sans clé.
- **QUIC 1-RTT** (`--quic`) : chaque paquet à en-tête court donne un constat par point, « N/M paquet(s) QUIC
  1-RTT déchiffré(s) sur C connexion(s) », ou « aucun ... déchiffré malgré le fichier de clés ». Une trame
  CONNECTION_CLOSE lue dans le contenu déchiffré donne « connexion QUIC fermée par ... : code applicatif 0x42
  (raison) » : à surveiller si le code est non nul, informatif sinon.
- **Signatures d'exploits** (`--security`) : les signatures sont aussi appliquées aux octets TLS en clair que
  tshark expose (bloc « Decrypted TLS » de `-x`). Ces détections portent `decrypted=True` et leur détail se
  termine par « contenu TLS déchiffré ».

Sans fichier de clés, ces trois lectures sont inchangées.

### Limites du branchement

- Les signatures ne s'appliquent pas au contenu QUIC déchiffré : ses blocs portent des trames QUIC, pas un flux
  HTTP directement exploitable.
- La lecture du contenu en clair relance tshark une seconde fois, limitée aux trames `tls.app_data`. Si elle
  échoue, l'erreur est journalisée et seules les détections sur le contenu chiffré restent.
- `nc diff` ne transmet pas encore le fichier de clés aux diagnostics QUIC.
