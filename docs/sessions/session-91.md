# Session 91 : collecteur — inventaire, santé des sondes et schéma probe://

Date : 19/11/2026 (Paris). Issue #1105 (P1, sous-issue 5/6 du chantier
[sondes distribuées #1002](https://github.com/Mathilde-Team/Netcross/issues/1002)).
Le travail porte sur la branche `feature/issue-1105-collecteur-inventaire-sante`,
initialisée depuis dev (ce93dea, merge de la PR #1283 de l'enrôlement mTLS
#1101).

## Réalisation

Le contrat passe en **1.1.0**, purement additif : la sonde peut annoncer
`listen_base_url` à l'inscription. Une sonde 1.0 parle à un collecteur 1.1
sans changement — champ absent = comportement 1.0.

### Agent : servir les routes du contrat

`netcross_probe.serveur` (nouveau) : l'agent sert santé, métadonnées et
fenêtres sur TLS 1.3 mutuel (stdlib `http.server`, aucun framework — la
sonde reste légère). `ServeurSonde.demarrer(hote, port)` écoute en arrière-
plan, `arreter()` éteint le service sans toucher au tampon. Les erreurs du
contrat sont stables : `400 invalid_bpf` / `invalid_window`,
`404 window_not_buffered` / `window_unknown`, `413 window_too_large` ;
le pcapng porte un en-tête `Digest: sha-256=` conforme à `Window.sha256`.
La sous-commande `servir` enchaîne enrôlement (si l'identité n'existe pas
encore, clé privée jamais transmise), lecture de l'identité, capture en
tampon circulaire et service — jusqu'à SIGINT/SIGTERM.

`netcross_probe.client` (nouveau) : la moitié collecteur des mêmes appels
(`ClientSonde`, mTLS). Coupure réseau : les requêtes idempotentes
(`GET`/`DELETE`) sont rejouées une fois (« reprise »), le `POST` jamais
(rejouer créerait une seconde fenêtre : échec explicite). `client_depuis_env`
lit `NETCROSS_PROBE_CERT_PEM` / `NETCROSS_PROBE_KEY_PEM` /
`NETCROSS_PROBE_CA_PEM` (chemin ou PEM en clair) et `NETCROSS_PROBE_TIMEOUT`.

### Schéma probe://

`pcap_parser.remote` analyse `probe://hote[:9443][/nom-de-sonde]` : aucun
secret dans l'URL (utilisateur refusé, TLS mutuel), le chemin porte le nom
de sonde — seul moyen d'accoler un filtre BPF (même règle que `rpcap://`).
`netcross_core.probe_capture` est le point de branchement des trois
surfaces : `collecter_fenetre_sonde` tire la fenêtre [début de session,
arrêt] puis la lit par le pipeline habituel (`parse_capture`). Modèle
assumé : **aucun flux pendant la session** — « le collecteur ne tire que
les fenêtres utiles » ; une coupure du lien d'administration ne fait
perdre aucun paquet au point de mesure.

- **CLI** : `--live DMZ:probe://…` attend la fin de session puis collecte
  la fenêtre (`_worker_sonde`) ; une sonde muette est rapportée sur ce
  point sans arrêter les autres.
- **API** : `POST /live-captures` accepte les points `probe://` (hors
  liste blanche des interfaces — une sonde n'est pas une interface locale
  du serveur ; l'accès reste la clé API puis le mTLS). `ring_buffer` et
  `live_report` sont refusés explicitement (la sonde tient son tampon ; le
  rapport lit un flux, la sonde sert des fenêtres). Les fenêtres sont
  tirées à la fin de session par dépendance injectée
  (`fetch_probe_window`), écrites comme fichier du point, puis l'analyse
  habituelle suit.
- **GUI** : champ interface et panneau live acceptent `probe://` ; le
  thread d'un point sonde attend l'arrêt puis collecte la fenêtre dans le
  même pipeline ; les enregistreurs de rotation ignorent les points sonde
  (message au journal).

### Collecteur : inventaire et santé

`netcross_api.probe_routes` expose, derrière la clé API :

- `GET /probes` : chaque sonde inscrite — identité, adresse annoncée,
  révocation, expiration du certificat, dernière santé connue ;
- `GET /probes/{probe_id}/health` : la santé **actuelle**, lue en direct
  en mTLS avec le certificat client du collecteur (SAN
  `urn:netcross:collector:<id>`, forgé par l'autorité du collecteur).
  Refus explicites : `404 probe_unknown`, `401 probe_revoked`,
  `409 probe_address_unknown` (sonde 1.0 sans adresse), `502`
  `sonde_injoignable` / `sonde_refus` — jamais une santé inventée.

L'enrôlement accepte `listen_base_url` (obligatoirement `https://`) et
négocie la version (plus haute commune, 1.0/1.1).

## Vérifications

Nouveaux tests : `tests/test_issue_1105_collecteur.py` (serveur mTLS +
client bout à bout : santé, métadonnées, cycle de vie de fenêtre, Digest,
refus 400/404/413, refus de poignée de main sans certificat client,
coupures réseau avec reprise GET / POST jamais rejoué, inventaire et
santé collecteur 200/401/404/409/502, analyse d'URL `probe://`), étendus
à `tests/test_remote_capture.py` (analyse, filtre BPF, refus
`ring_recorder_args`), `tests/test_issue_1105_api_live.py` (points
`probe://` de `POST /live-captures`, sonde muette = échec explicite) et
la CLI `_worker_sonde`. Un défaut détecté par ces tests (dossier du point
sonde jamais créé avant l'écriture du pcapng) a été corrigé.

La suite complète et les contrôles finaux (ruff, format, import-linter,
mypy, `mkdocs build --strict`) sont consignés après leur exécution, avant
le premier push ; ils ne remplacent pas la CI du dernier head.

Résultats (Python 3.14, `PYTHONPATH=src python -m pytest tests/ -q`) :
7292 réussis, 107 ignorés, 0 échec (185 s) ; ruff check et format
propres ; import-linter : 1 contrat respecté ; audit des sorties
`logger.debug` : 4782/4782 conformes ; `docs/openapi.yaml` et
`docs/class-diagram.md` régénérés et à jour ; `mkdocs build --strict` :
succès ; mypy : 1 note résiduelle dans `netcross_gtk4/app.py`
(fonction non typée, hors périmètre).

## Limites

Pas de flux continu : seules des fenêtres bornées sont transférées (choix
assumé du contrat v1). La santé d'une sonde muette est une erreur
explicite, pas une extrapolation. `capture_loss`/`clock` valent `null`
quand la sonde n'a rien pu lire — jamais confondus avec zéro. Aucun
réseau externe : les tests d'intégration mTLS tournent sur localhost avec
des autorités générées dans le test. Les paquets de déploiement suivent
(#1107, dépend de cette issue).
