# Non-fuite des secrets de déchiffrement

Issue #1047, chantier #997. Les secrets TLS / QUIC fournis à Netcross, par fichier de clés (`--tls-keylog`, API
`tls_keylog`, onglet avancé de l'interface) ou embarqués dans la capture (blocs DSB, `editcap --inject-secrets`),
servent uniquement à tshark pour déchiffrer. Ils ne doivent apparaître dans aucune sortie de l'analyse.

## Ce qui garantit l'absence de fuite

- Seul le **chemin** du fichier de clés est transmis à tshark (préférence `tls.keylog_file`) ; Netcross vérifie
  seulement que le fichier existe et est lisible, sans en lire le contenu.
- Un bloc DSB est **compté** (« secrets de déchiffrement embarqués : N bloc(s) DSB ») ; son contenu, son type et
  sa longueur ne sont ni lus ni journalisés.
- Les rapports et métadonnées ne gardent que les **noms des points** qui ont reçu une clé (`options.tls_keylogs`
  dans l'API), jamais le chemin ni le contenu.
- L'API copie le fichier téléversé en mode 0600 dans un fichier temporaire, supprimé à la fin de l'analyse.

## Ce que vérifie le test

`tests/test_non_fuite_secrets.py` lance un run complet, une fois avec `--tls-keylog` et une fois avec les mêmes
secrets dans un bloc DSB, puis cherche chaque secret (client_random et secrets de trafic) sous cinq formes :
hexadécimal minuscule et majuscule, hexadécimal séparé par « : », octets bruts et base64. Les sorties relues :

| Sortie | Option |
|---|---|
| Rapport texte, sortie d'erreur | sortie standard du CLI |
| Journaux loguru, tous niveaux (TRACE compris) | puits loguru ajouté pendant le run |
| Rapport JSON, Markdown, PDF (brut et texte extrait) | `--json-report`, `--md-report`, `--pdf-report` |
| Rapport de sécurité HTML | `--security-report --security-html` |
| Export SIEM | `--siem-export cef --siem-output` |
| Journal Zeek | `--zeek-conn` |
| Base d'historique SQLite | `--history-db` |
| Ticket de support | `--support-ticket --support-consent` |
| Contenus extraits (fichiers et manifeste) | `--extract-contents` |
| API : réponses et entrée du magasin d'analyses | `POST /captures`, `GET /analyses/{id}` et `/report` |

Un témoin vérifie que la recherche trouve bien les secrets dans le fichier de clés et dans la capture DSB.

## Limites

- Les **exports de capture** (`--export-pcap`, `--merge`, `--split`, `--convert`...) sont des copies de la capture
  d'entrée : comme Wireshark, ils gardent ses blocs DSB. Pour transmettre une capture sans ses secrets :
  `editcap --discard-all-secrets entree.pcapng sortie.pcapng`.
- Le contenu **déchiffré** (requêtes HTTP, fichiers extraits) n'est pas un secret de déchiffrement : il apparaît
  normalement dans les sorties. `--redact` (refusé avec un fichier de clés) reste l'outil pour masquer les données.
