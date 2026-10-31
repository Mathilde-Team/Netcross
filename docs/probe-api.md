# API agent `netcross-probe` ↔ collecteur (contrat v1)

Spécification issue de #1098, première sous-issue du chantier #1002 (sondes
distribuées). Elle **fige le contrat** avant d'écrire l'agent (#1099), la
sécurité (#1101), la remontée pertes/horloge (#1103) et le collecteur (#1105).

Le schéma OpenAPI 3.1 qui fait foi est [`probe-api-v1.yaml`](probe-api-v1.yaml).
La CI le valide contre le méta-schéma officiel OpenAPI 3.1 et vérifie que ses
exemples respectent ses propres schémas (`tests/test_probe_api_spec.py`).

Version du contrat : **1.0.0**.

## Rôles

| Rôle | Logiciel | Sert | Appelle |
|---|---|---|---|
| Sonde (agent) | `netcross-probe`, sur chaque point de capture | santé, métadonnées, fenêtres de trafic | l'inscription du collecteur |
| Collecteur | `netcross_api` | l'inscription | les routes de chaque sonde |

L'agent capture en local dans un tampon circulaire (dumpcap,
`ring_recorder_args`) : une coupure du lien d'administration ne fait perdre
aucun paquet au point de mesure. Le collecteur ne tire que les fenêtres utiles
à une analyse.

## Routes

| Méthode | Chemin | Serveur | Rôle | Authentification |
|---|---|---|---|---|
| `POST` | `/probe/v1/enrollments` | collecteur | inscription (`enroll_probe`) | jeton d'enrôlement |
| `GET` | `/probe/v1/health` | sonde | santé : capture, tampon, horloge, pertes (`probe_health`) | mTLS |
| `GET` | `/probe/v1/metadata` | sonde | identité, interfaces, tampon, capacités (`probe_metadata`) | mTLS |
| `POST` | `/probe/v1/windows` | sonde | demande de fenêtre [t1, t2] + BPF (`request_window`) | mTLS |
| `GET` | `/probe/v1/windows/{window_id}` | sonde | métadonnées de la fenêtre (`get_window`) | mTLS |
| `DELETE` | `/probe/v1/windows/{window_id}` | sonde | libération de la fenêtre (`delete_window`) | mTLS |
| `GET` | `/probe/v1/windows/{window_id}/pcapng` | sonde | téléchargement du pcapng (`download_window`) | mTLS |

### Inscription

1. L'administrateur crée un jeton d'enrôlement sur le collecteur et le remet
   à la sonde par un canal hors bande (fichier, variable d'environnement).
2. La sonde génère sa clé privée (qui ne la quitte jamais) et une CSR, puis
   appelle `POST /probe/v1/enrollments` sur TLS serveur, avec
   `Authorization: Bearer <jeton>`.
3. Le collecteur consomme le jeton, signe un certificat client (SAN URI
   `urn:netcross:probe:<probe_id>`) et renvoie `probe_id`, le certificat,
   la chaîne de l'autorité et la version de contrat retenue.

Un nom de sonde déjà inscrit renvoie `409` ; un jeton consommé, expiré ou
inconnu renvoie `401` ; sans version majeure commune, `426`.

### Fenêtre de trafic

`POST /probe/v1/windows` avec `{start, end, bpf, max_bytes}` (secondes Unix,
bornes incluses). La sonde :

1. sélectionne les fichiers du tampon qui chevauchent [start, end]
   (`pcap_parser.capture.select_ring_files`, #1086) ;
2. extrait les paquets de l'intervalle, applique le filtre BPF et écrit un
   pcapng dont les blocs ISB portent `ifdrop`/`osdrop` ;
3. répond `201` avec un objet `Window` : intervalle demandé et intervalle
   réellement couvert (`covered`), nombre de paquets, taille, SHA-256, pertes
   de capture et état d'horloge **au moment de la capture**.

Le collecteur télécharge ensuite `GET .../pcapng` (en-tête `Digest`
identique à `Window.sha256`), puis libère la fenêtre avec `DELETE`. Une
fenêtre non libérée expire à `expires_at`. Codes d'erreur : `400` (fenêtre
inversée, BPF refusé), `404` (rien dans le tampon), `413` (au-delà de
`max_bytes`).

`covered` peut être plus court que `requested` si le tampon a déjà tourné :
le collecteur doit le signaler dans le rapport plutôt que conclure à une
absence de trafic.

### Métadonnées de mesure

Chaque fenêtre et chaque réponse de santé portent :

- `capture_loss` : paquets reçus et perdus au point de capture (`ifdrop`
  interface, `osdrop` noyau) ;
- `clock` : source (`ptp`, `chrony`, `ntpd`, `systemd-timesyncd`, `none`,
  `unknown`), synchronisation, décalage et dispersion annoncés, référence.

Elles permettent au rapport de distinguer « le réseau a perdu » de « la
sonde a perdu », et alimentent l'estimation de décalage entre points.

## Versionnement et compatibilité

- **Semver** dans `info.version`. Le **majeur** figure dans le chemin
  (`/probe/v1/...`) ; chaque réponse porte l'en-tête
  `Netcross-Probe-Api: <majeur>.<mineur>`.
- **Négociation** à l'inscription : la sonde annonce `api_versions` ; le
  collecteur choisit la plus haute version commune et la renvoie dans
  `api_version`. Les capacités optionnelles passent par `capabilities` (une
  capacité inconnue est ignorée).
- **Mineur** (1.0 → 1.1) : uniquement additif. Nouveaux champs facultatifs,
  nouvelles routes, nouvelles valeurs de `capabilities`. Tous les objets
  acceptent des champs supplémentaires (`additionalProperties: true`, sauf
  `Interval`) : **un client ignore les champs qu'il ne connaît pas**.
- **Majeur** (v1 → v2) : toute suppression, tout renommage, tout changement
  de type ou de sémantique, ainsi que l'ajout d'une valeur à une énumération
  fermée (`ClockSource`, `Health.status`). Le nouveau majeur est servi sous
  `/probe/v2` **en parallèle** de `/probe/v1` pendant au moins une version
  mineure du collecteur, pour permettre une mise à jour progressive des
  sondes.
- Les codes `error` des réponses d'erreur sont stables dans un majeur.

## Modèle de sécurité

- **Aucune écoute sans authentification** : l'agent n'expose que TLS 1.3
  avec certificat client obligatoire ; une connexion sans certificat valide
  est refusée pendant la poignée de main.
- **mTLS** dans les deux sens : l'autorité du collecteur signe les
  certificats des sondes (SAN `urn:netcross:probe:<probe_id>`) et du
  collecteur (SAN `urn:netcross:collector:<id>`). La sonde épingle
  `ca_chain_pem` reçu à l'inscription.
- **Jeton d'enrôlement** : à usage unique, au moins 128 bits d'entropie,
  durée de vie courte, stocké haché côté collecteur ; seule la route
  d'inscription l'accepte.
- **Révocation** (#1101) : un certificat révoqué reçoit `401` ; la sonde
  doit alors être réinscrite avec un nouveau jeton.
- Aucun secret (jeton, clé privée) n'apparaît dans les réponses, les
  messages d'erreur ni les journaux.

## Limites de cette version

- Pas de flux continu (streaming) : seules des fenêtres bornées sont
  transférées.
- Pas de compression négociée en v1 (capacité réservée `compression_zstd`).
- La rotation des certificats avant expiration sera précisée avec #1101.
