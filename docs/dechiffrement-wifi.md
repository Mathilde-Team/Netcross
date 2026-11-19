# Déchiffrement Wi-Fi WPA/WPA2-PSK

Issue #1143, sous-issue 2/5 du chantier « Wi-Fi en mode moniteur » (#1006).

Une capture en mode moniteur (radiotap, linktype 127) contient des trames
802.11. tshark les décapsule seul (802.11 → LLC/SNAP → IP). Sur un réseau
ouvert, les paquets IP sont donc analysés comme sur un point filaire.

Sur un réseau protégé, les trames de données sont chiffrées (CCMP/TKIP).
Sans clé, seules leurs métadonnées radio restent lisibles (`Pkt.radio`,
issue #1142) et aucun paquet IP n'en est extrait.

## Fournir les clés

Il faut un fichier de clés, avec une clé par ligne. Les lignes vides et les
lignes commençant par `#` sont ignorées.

```text
# phrase de passe (8 à 63 caractères) et SSID
wpa-pwd:ma phrase de passe:MonReseau
# ou PSK brute (PMK, 64 chiffres hexadécimaux)
wpa-psk:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Le dernier `:` d'une ligne `wpa-pwd` sépare la phrase du SSID. La phrase peut
donc contenir `:`, mais le SSID ne le peut pas.

| Surface | Moyen |
|---|---|
| CLI `cross_capture_analyzer_cli.py` | `--wifi-keys FICHIER` |
| API, GUI, autres CLI, mode batch | variable d'environnement `NETCROSS_WIFI_KEYS=FICHIER`, positionnée avant le lancement |

La lecture fichier, la lecture parallèle et la capture live passent toutes
par `pcap_parser.ek_source.iter_ek_records`. Le fichier y est relu à chaque
lancement de tshark. Si le fichier est invalide, la lecture est refusée avec
un message qui donne le numéro de ligne, jamais le contenu.

Le déchiffrement suppose aussi que le 4-way handshake EAPOL de la station
figure dans la capture, au moins les messages 1 et 2. C'est le cas si la
capture a commencé avant l'association de la station.

## Repli sans clé

Quand des trames de données chiffrées restent illisibles, un avertissement
explicite en donne le nombre et la cause probable :

- aucune clé fournie ;
- 4-way handshake EAPOL absent de la capture ;
- clé ne correspondant pas au réseau, ou handshake incomplet.

L'analyse continue alors avec les seules métriques radio.

## Traçabilité

Chaque paquet IP extrait d'une trame 802.11 déchiffrée porte le tag
d'encapsulation `802.11(déchiffré)`. Les trames 802.11 transportées par
CAPWAP gardent leur seul tag CAPWAP.

## Appariement air ↔ filaire

Issue #1145. Après décapsulation, un paquet IP vu dans l'air s'apparie
avec sa copie filaire comme entre deux points filaires. La clé de flux est
le 5-tuple, plus l'identifiant IP ou le numéro de séquence TCP. Le pont
802.11 ↔ Ethernet du point d'accès ne modifie pas l'en-tête IP.

Une trame non acquittée est réémise par la station avec le bit `retry`. La
sonde en mode moniteur voit alors plusieurs fois le même paquet IP, alors
que le réseau ne l'a transporté qu'une fois, car le point d'accès filtre ces
doublons. Sans traitement, ces copies seraient comptées comme
retransmissions TCP, ACK dupliqués ou doublons UDP.

Netcross applique le critère du récepteur 802.11 (IEEE 802.11-2020,
10.3.2.14). Une trame à bit `retry` est une retransmission radio si, au
même point et en moins d'une seconde, une trame de même identité a déjà été
vue. L'identité regroupe l'adresse de l'émetteur radio TA, le numéro de
séquence et le numéro de fragment.

Une retransmission radio est fusionnée dans le paquet d'origine :

- elle est retirée du flux de paquets, en lot comme en live ;
- le compteur `Pkt.radio_retries` du paquet d'origine est incrémenté, pour
  les métriques radio ;
- un message de niveau INFO donne le nombre de fusions par point.

Une trame à bit `retry` dont l'original n'a pas été capté est conservée,
car c'est la seule copie vue.

## Métriques radio par client

Pour chaque point 802.11, le rapport (section « Wi-Fi : métriques radio par
client » du texte, clé `wifi_clients` du JSON) donne une fiche par station
cliente, identifiée par son adresse MAC. Comme les autres adresses, cette MAC
est anonymisée par `--redact` (le BSSID et l'émetteur radio aussi). La station
et le sens de la trame sont lus dans les bits ToDS/FromDS.

| Métrique | Calcul |
| --- | --- |
| RSSI médian | trames **émises** par la station (le signal d'une trame descendante est celui du point d'accès) |
| MCS, débit PHY | distribution sur les trames des deux sens, et débit médian |
| Taux de retransmission radio | copies *retry* fusionnées / transmissions totales |
| Itinérance | changements de BSSID datés, avec le nombre de flux vus avant et après |
| Temps d'antenne | somme de `longueur × 8 / débit PHY` par transmission, copies *retry* comprises |

Le temps d'antenne est un ordre de grandeur : il ne compte ni le préambule, ni
les intervalles entre trames, ni les acquittements.

Constats :

- **perte dans l'air** : un segment TCP du client est retransmis et sa
  transmission d'origine, au même point, porte des copies *retry*. La trame a
  peiné dans l'air.
- **perte après le point d'accès** : l'origine a été vue sans *retry*, donc
  acquittée au niveau 802.11. Le cas couvre aussi un segment descendant jamais
  vu dans l'air, perdu avant d'atteindre l'antenne. Un segment montant jamais
  vu reste « indéterminé », car la sonde a pu le manquer.
- **débit PHY bas** : débit PHY médian sous 24 Mbit/s
  (`netcross_core.wifi.SEUIL_DEBIT_PHY_BAS_MBPS`).
- **itinérance pendant le flux** : un flux du client est vu avant ET après un
  changement de BSSID.

## Non-fuite de la phrase de passe

La phrase de passe ne passe jamais sur la ligne de commande de tshark, qui
serait visible dans la liste des processus. Le mécanisme est le suivant :

- elle est écrite dans le fichier `80211_keys` d'un répertoire de
  configuration Wireshark temporaire (droits 0700, fichier 0600), en
  encodage pourcentage ;
- ce répertoire est désigné à tshark par `WIRESHARK_CONFIG_DIR` ;
- il est supprimé dès la fin du processus, même en cas d'erreur.

Seule la préférence `wlan.enable_decryption:TRUE` passe en `-o`.

Avec le déchiffrement actif, tshark ajoute aussi à chaque trame les clés
dérivées (`wlan.analysis.pmk`, `.kck`, `.kek`, `.tk`, `.gtk`). Elles valent
la phrase de passe pour qui les lit. Netcross les retire de chaque
enregistrement dès la lecture, avant toute autre exploitation. La phrase
n'apparaît ni dans les journaux, ni dans les messages d'erreur, ni dans le
`repr` des clés, ni dans les rapports. Les tests
`tests/test_wifi_dechiffrement.py` le vérifient sur argv, loguru, stdout,
stderr et le rapport JSON.

## Limites

- WPA3-SAE et WPA2-Entreprise (802.1X) ne sont pas pris en charge, car la
  clé de session n'est pas dérivable d'une phrase de passe.
- Le répertoire temporaire remplace la configuration personnelle de
  Wireshark le temps de la lecture. Les préférences de Netcross sont passées
  en `-o` et ne sont pas concernées.
- La capture de test `tests/data/wpa2-psk-reference.pcap` est synthétique.
  Elle est générée par `tests/wpa2_reference.py` à partir d'un réseau fictif,
  ce qui permet de la distribuer sous la licence du dépôt.
