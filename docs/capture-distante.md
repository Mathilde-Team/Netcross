# Capture distante

Issue #166. Partout où une interface de capture en direct est attendue
(`--live` de `netcross-analyze`, `--live-current` de `netcross-diff`, champ
« interface » du panneau de capture live de la GUI), une **URL de source**
peut remplacer le nom d'interface locale. Le flux distant passe par le même
pipeline de dissection que `eth0` : diff live, rapport temps réel, alertes…
fonctionnent à l'identique, et sources locales et distantes se mélangent
librement.

| Source | Syntaxe | Côté cible |
|---|---|---|
| rpcapd | `rpcap://[utilisateur@]hote[:port]/interface` | démon `rpcapd` (port 2002 par défaut) |
| SSH (sshdump) | `sshdump://[utilisateur@]hote[:port]/interface[?key=CLE&priv=sudo]` (alias `ssh://`) | `tcpdump` + serveur SSH |
| Sonde netcross (#1105) | `probe://hote[:9443][/nom-de-sonde]` | sonde `netcross-probe` en mTLS |
| Entrée standard | `pipe://-` ou `-` | n'importe quel producteur pcap |
| Tube nommé | `pipe:///chemin/fifo` | n'importe quel producteur pcap |

## Exemples

```bash
# Deux points : LAN local + DMZ via rpcapd, filtre BPF applique cote distant
netcross-analyze --live LAN:eth0 --live "DMZ:rpcap://10.0.0.5:2002/eth1:tcp port 443" --live-duration 60

# Routeur via SSH (cle dediee, tcpdump lance avec sudo)
netcross-analyze --live "GW:sshdump://capture@routeur.lan/br-lan?key=~/.ssh/netcross&priv=sudo"

# Sans extcap : tcpdump distant envoye sur l'entree standard
ssh routeur tcpdump -U -w - -i eth0 'not port 22' | netcross-analyze --live GW:-

# Tube nomme alimente par un autre processus
mkfifo /tmp/capteur && netcross-analyze --live CAPTEUR:pipe:///tmp/capteur

# Sonde netcross (#1105) : rien ne circule pendant la session, la fenetre
# est tiree a l'arret -- le nom de sonde du chemin porte le filtre BPF
netcross-analyze --live "GW:probe://sonde.lan:9443/ROUTEUR:tcp port 443"
```

Le filtre BPF optionnel suit l'URL (`LABEL:URL:FILTRE`) : les `:` de l'hôte, du
port ou d'une adresse IPv6 entre crochets ne comptent pas, seul le premier `:`
après `/interface` sépare le filtre.

## Sonde netcross `probe://` (#1105)

Une sonde `netcross-probe` (sous-commande `servir`, voir [la page de
l'agent](probe-agent.md)) remplace le flux tiré à travers le réseau : elle
écrit **localement** dans son propre tampon circulaire et le collecteur
tire la fenêtre [début de session, arrêt] **à la fin** — une coupure du
lien d'administration pendant la session ne fait perdre aucun paquet au
point de mesure. Le pcapng livré passe par le même pipeline que `eth0`.

- **Syntaxe** : `probe://hote[:9443][/nom-de-sonde]` — le port est celui
  du contrat (9443), le chemin est le nom de la sonde (informatif, mais
  nécessaire pour accoler un filtre BPF : même règle que `rpcap://`).
- **Aucun secret dans l'URL** : l'authentification est le TLS mutuel —
  identités du collecteur dans `NETCROSS_PROBE_CERT_PEM`,
  `NETCROSS_PROBE_KEY_PEM` et `NETCROSS_PROBE_CA_PEM` (chemin de fichier
  ou PEM en clair ; `NETCROSS_PROBE_TIMEOUT` pour le délai, 10 s par
  défaut). Un utilisateur (`utilisateur@`) est refusé.
- **Incompatibilités assumées** : pas de ring buffer local ni de rapport
  en continu sur un point `probe://` (la sonde tient déjà son tampon ; le
  rapport lit un flux, la sonde sert des fenêtres) — refus explicite.
- Une sonde injoignable ou refusante à l'arrêt fait échouer le point
  (erreur explicite), jamais une analyse silencieusement vide.

## Prérequis

- **rpcap** : tshark compilé avec la capture distante (l'option `-A` apparaît
  dans `tshark -h` ; c'est le cas des versions Windows, pas toujours des
  paquets Linux). Sur la cible : `rpcapd -n` (sans authentification, réseau de
  confiance uniquement) ou `rpcapd` avec comptes locaux.
- **sshdump** : l'extcap `sshdump` de Wireshark (paquet `wireshark` ou
  `wireshark-extcap`, visible dans `tshark -D`). Les paramètres sont transmis
  en préférences extcap (`-o extcap.sshdump.remotehost:…`, `remoteport`,
  `remoteusername`, `remoteinterface`, `sshkey`, `remotepriv`). Sur la cible :
  `tcpdump`, et `sudo`/`doas` sans mot de passe si `priv=` est utilisé.
  sshdump exclut par défaut sa propre session SSH de la capture.
- **pipe** : aucun ; une seule source par exécution peut lire l'entrée standard.

## Authentification et secrets

- Un mot de passe **dans l'URL est refusé** (historique du shell, liste des
  processus, journaux). Utiliser les variables d'environnement
  `NETCROSS_RPCAP_PASSWORD` (rpcap avec utilisateur, obligatoire dans ce cas)
  et `NETCROSS_SSH_PASSWORD` (sshdump, facultatif).
- Pour SSH, préférer une clé (`key=`) ou l'agent SSH à un mot de passe : le
  mot de passe est transmis à tshark en argument et reste donc visible des
  autres utilisateurs locaux via `ps`.
- Les journaux (`tshark args`) masquent `-A utilisateur:***` et les
  préférences `…password` / `…passphrase`.
- rpcap transporte les paquets **en clair** : à réserver à un réseau
  d'administration, ou à encapsuler dans un tunnel (préférer sshdump).

## Validation

Chaque URL est vérifiée avant de lancer tshark : schéma connu, hôte (nom DNS,
IPv4, `[IPv6]`), port 1-65535, interface et utilisateur sans espace ni `-`
initial (aucune valeur ne peut devenir une option de tshark), paramètres
sshdump connus (`key`, `priv`), clé SSH existante, tube nommé existant. Une
erreur arrête la CLI avec un message explicite ; la GUI l'affiche dans le
journal et n'ouvre aucune capture.

## API

```python
from pcap_parser import iter_live, iter_live_multi
from pcap_parser.remote import parse_source

parse_source("rpcap://10.0.0.5/eth0").interface  # 'rpcap://10.0.0.5:2002/eth0'
for pkt in iter_live("sshdump://capture@routeur/eth0", bpf_filter="udp"):
    ...
```
