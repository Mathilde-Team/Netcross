# Changelog

Tous les changements notables du projet Netcross sont documentés dans ce fichier.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/),
et le projet adhère au [SemVer](https://semver.org/lang/fr/).

## [Unreleased]

### Ajouté
- Orchestration automatique de la chaîne d'incident (#1001) : `netcross_core.incident_chain.ChaineIncidents`,
  branchée sur `LiveDiffEngine(gel=chaine)` à la place du `GelManager` nu, enchaîne à chaque alarme le gel
  rétroactif (#1087), l'attente effective de la fin de fenêtre (calculée depuis l'horodatage du dernier paquet vu,
  en arrière-plan — le moteur live n'est jamais bloqué), l'archivage signé (#1090), l'analyse multi-points et la
  notification (#1091) — sans rien relancer à la main. `chaine_incidents_depuis_reglages()` raccorde les réglages
  partagés (gel_settings) au moteur live. Un gel sans fichier protégé est signalé sans archiver ; un échec à une
  étape est journalisé sans interrompre le moteur ni les autres incidents. Voir docs/incidents-gel.md
  (« L'orchestration automatique »).
- Seconde passe ciblée en flux (#1025, sous-issue 6/6 du chantier pipeline en flux #995) :
  la topologie est désormais déduite en mode `--streaming` comme en batch — un enregistrement
  compact par (flux, point) (horodatage et TTL du premier paquet) est collecté au fil de l'eau
  (ARP/STP exclus, doublons avec `--exclude-duplicates`, nat-tolerant identique à
  `correlate`), puis la même déduction que le mode batch s'exécute à la fermeture : mêmes
  seuils, mêmes arêtes/ambiguïtés/isolés/branchements/fusions. La mémoire est proportionnelle
  au nombre de flux (pas de paquets) et déportée sur disque avec `--spill-seuil` (#1024),
  sans changer les résultats. Exposé dans `streaming.seconde_passe` de `--json-report`.
  Voir docs/seconde-passe.md. Restent hors de cette passe : `clock_sync`,
  `detect_microbursts`, l'équivalence complète du rapport et le basculement du défaut
  vers `--streaming` (décision humaine, voir l'issue).
- Débordement sur disque des flux longs (#1024, chantier pipeline en flux #995) : `--spill-seuil N`
  borne en mémoire les structures de l'état par flux qui grandissent avec le nombre total de
  conversations vues (résumé TCP par clé du détecteur de coupure, coupures déjà comptées) ; au-delà
  du seuil, les entrées les moins récentes sont déportées dans une base SQLite temporaire, supprimée
  en fin d'analyse, et retrouvées (promues) à la lecture — résultats identiques avec ou sans
  débordement (mesure 10⁶ paquets : ~650 Mo en RAM contre ~10 Mo avec seuil 5 000). Voir
  docs/debordement-flux.md.
- État par flux avec expiration (#1023, chantier pipeline en flux #995) : `--flow-timeouts` (délais par
  protocole à la Zeek, format `TCP=3600,UDP=60,ICMP=60,AUTRE=60`) configure la table d'état de flux de
  `--streaming` — un flux inactif depuis son délai libère son état (mémoire bornée par les flux actifs),
  la réouverture après expiration est comptée, et le détecteur de coupure NAT/pare-feu silencieuse y est
  incrémental : mêmes constats que le détecteur batch, exposés dans `streaming.flow_state` de
  `--json-report` (clés `records`, `expired`, `reopened`, `peak_active`, `nat_cutoffs`…) et les lignes
  « État par flux » du rapport texte. Voir docs/etat-flux.md.
- Campagne de performance multi-cœurs documentée (#1018, banc de performance #994) :
  `docs/performance.md` présente les mesures du pipeline complet (`tshark` inclus) sur les jeux
  synthétiques — tables jeux × degré de parallélisme (2 à 10 points, 10⁴ à 10⁶ paquets par point,
  parallélisme 1 à 8), débits de 798 à 3 929 paquets/s, pics RSS ~2,4 à 3,1 Kio/paquet (2 points ×
  10⁶ paquets : 4,8 Gio), avec la description de la machine de mesure et les commandes de
  reproduction. Le lien README « Limites connues » renvoie désormais à cette page.
- `--redact-scope adresses|noms|tout` (#1153, chantier #1007) : `--redact` anonymise désormais aussi, par défaut, les
  noms DNS (`dns_qry_name`), la cible HTTP (`http_uri` : hôte pseudonymisé, chemin `/res-N`), le SAN (joker conservé),
  le sujet et l'émetteur des certificats TLS (`CN=dn-N`), le Call-ID (`call-N@example.invalid`), le User-Agent et le
  Server SIP (`agent-N`), avec la table de noms commune (#1151), ainsi que les IP du SAN. Les pseudonymes restent
  stables pendant le run (dialogues SIP, certificats auto-signés). `--redact-map` exporte ces tables ; la GUI, l'API et
  `cross_capture_diff_cli.py` appliquent la portée « tout ». `--redact-scope adresses` rend le comportement antérieur.
- Constats filtrables et preuves cliquables du rapport HTML (#1077) : filtres par sévérité, segment et protocole avec
  compteur, et pour chaque preuve un diagramme centré sur la trame (voisines de la même conversation, même trame aux
  autres points, transit corrigé du décalage d'horloge), avec ancre `#preuve-<point>-<trame>` et équivalent sans
  JavaScript. Clé `evidence_frames` du JSON quand `packet_flows` est fourni. Voir docs/preuves-cliquables.md.
- Débit crête multi-échelle en fenêtre glissante (#1133, chantier microrafales #1005) : `netcross_core.multiscale`
  cherche, pour chaque point et chaque échelle (100 µs, 1 ms, 10 ms par défaut), la fenêtre la plus chargée en octets.
  Le calcul est exact, incrémental (paquet par paquet, compatible avec `--streaming`) et à mémoire bornée par la
  fenêtre. Une échelle plus fine que la résolution d'horodatage du point (`if_tsresol`) ou que 1 µs est refusée
  explicitement, avec la raison. Voir docs/fenetres-multi-echelles.md.
- Échelle SIP multi-points (#1125) : pour chaque appel, une ligne par message SIP et une colonne par point de capture,
  dans le PDF, le rapport HTML (avec ou sans JavaScript) et le JSON (`sip_ladders`). Un message perdu entre deux
  points (« ABSENT »), retransmis ou réécrit (SDP, premier Via, Contact modifiés par un ALG ou un SBC) est mis en
  évidence ; les `100 Trying`, produits à chaque saut, ne sont jamais déclarés perdus. Les en-têtes Via et Contact
  sont désormais extraits, et `--redact` anonymise leurs adresses. Voir docs/echelle-sip.md.
- Appariement des flux RTP entre points (#1121) : le même flux est reconnu à plusieurs points malgré un NAT ou un SBC
  (ports, adresses, SSRC, séquence et horodatage RTP réécrits), par SSRC puis par couples (séquence, horodatage RTP)
  avec décalage constant. Clé `rtp_matches` de `--json-report` : jambes par point, méthode, `nat_rewritten`, pertes
  entre jambes. Voir docs/appariement-rtp.md.
- Corrélation en flux (#1022) : `--streaming` fusionne les points en k voies par temps (`heapq.merge`) et ferme
  chaque groupe après `--streaming-window` secondes ; la mémoire suit la fenêtre, pas le nombre de paquets. Paquets
  désordonnés rattachés dans la fenêtre, troncature (paquet arrivé après la fermeture de son groupe) signalée dans
  le rapport texte et la clé `streaming` de `--json-report`. Voir docs/correlation-en-flux.md.
- Vue « Chemin » du rapport HTML autonome (#1075) : les points de capture dans l'ordre du chemin, reliés par leurs
  segments. Le survol, le focus clavier ou le clic sur un segment affichent son détail (délai, P50/P95/P99, gigue,
  pertes, débit, sauts, horloge). Les flèches, Début et Fin passent d'un segment à l'autre. Un segment sans mesure est
  marqué « non mesurable » (en texte, avec une bordure pointillée). Le rendu sans JavaScript contient un tableau
  équivalent. Le JSON du rapport gagne la clé `path_metrics`, avec les mêmes chiffres que le PDF.
- `--prom-file` et `--openmetrics-file` (#1112) : métriques de l'analyse au format texte Prometheus (textfile
  collector de node_exporter, écriture atomique) et OpenMetrics 1.0 ; `--metrics-run` fixe l'étiquette `run` ;
  `--redact` anonymise les adresses présentes dans les étiquettes. Voir docs/metriques-prometheus.md.
- Client TWAMP-Light (#1066) : `netcross_core.active.twamp.mesurer` envoie des sondes RFC 5357 (annexe I, non
  authentifiées) à un réflecteur et rend délai aller-retour corrigé du temps de traitement, délais aller et retour,
  pertes, gigue et TTL reçu. Sans réflecteur (aucune réponse, port fermé, cible injoignable), le résultat l'indique
  au lieu d'échouer. 10 sondes/s au plus, chaque mesure journalisée. Voir docs/mesures-actives.md.
- Diagnostics sur le contenu déchiffré (#1045) : avec un fichier de clés, le certificat TLS 1.3 est lu (détection de
  substitution entre points), les paquets QUIC 1-RTT et leurs fermetures (CONNECTION_CLOSE) donnent des constats,
  et les signatures d'exploits sont aussi appliquées au contenu TLS en clair. Voir `docs/couverture-dechiffrement.md`.
- Couverture du déchiffrement TLS/QUIC (#1043) : le rapport texte, le PDF et le JSON (`decryption.by_point`)
  indiquent par point « 42/50 sessions TLS déchiffrées au point CLIENT » (et de même pour QUIC) dès qu'un fichier de
  clés ou des blocs DSB sont fournis. Voir docs/couverture-dechiffrement.md.
- Garde-fous de non-fuite des secrets (#1047) : un test de bout en bout cherche les secrets d'un fichier de clés et
  d'un bloc DSB (hexadécimal, octets bruts, base64) dans toutes les sorties d'un run : rapports texte, JSON,
  Markdown, PDF et HTML, journaux loguru, export SIEM, Zeek, base d'historique, ticket de support, contenus extraits
  et API. Voir docs/non-fuite-secrets.md.
- Non-régression de performance (#1019) : `scripts/bench.py --reference benchmarks/reference.json` compare le banc
  à une référence versionnée (durée totale et pics RSS, seuils `--seuil-duree`/`--seuil-memoire`, 20 % par défaut,
  code 3 sur régression ; `--resultat` pour comparer sans relancer, `--resume` pour le résumé du job). Workflow
  `bench.yml` hebdomadaire et à la demande (jamais sur les PR), résultat publié en artefact.
- Empreinte de paquet invariante (#1021) : `netcross_core.empreinte` projette la clé de corrélation sur 64 bits
  stables (BLAKE2b, indépendants de `PYTHONHASHSEED`), avec `apparier()` et `comparer_appariements()` pour vérifier
  l'équivalence avec `correlate()`. Limites (NAT, fragmentation, réécritures) dans docs/empreinte-paquet.md.
- Banc de performance (#1017) : `scripts/bench.py` (logique dans `netcross_core.testing.bench`) lance l'analyse complète sur les jeux synthétiques de #1015 et relève, par jeu et par degré de parallélisme (`--parallel 1,2,4,8`), la durée totale et par étape (#1016), le pic RSS du processus et de ses enfants et le débit en paquets/s ; environnement noté (cœurs logiques et utilisables, CPU, RAM, versions de tshark, Python et Netcross) ; sortie JSON au schéma versionné `netcross-bench` v1 et tableau Markdown ; `--repetitions` (médiane) ; `--mini` (2 points × 2 000 paquets) pour la CI. Voir `docs/quality/banc-performance.md`.
- Journaux de flux au format Zeek `conn.log` (#1115) : `--zeek-conn FICHIER` écrit une ligne par connexion et par point, colonnes Zeek standard (`#fields`/`#types`, lisible par `zeek-cut`) puis colonnes `netcross_*` (segment, latence et pertes par segment avec `--order`) ; `--zeek-format json` pour un objet par ligne. Respecte `--redact`. Voir docs/zeek-export.md.
- Image de CI préconstruite (#968, étape 1) : `.github/ci-image/Dockerfile` (paquets apt des jobs `quality`, `gtk4` et
  `packaging`) et workflow `ci-image.yml`. L'image est construite sur chaque PR qui la modifie, puis poussée vers
  `ghcr.io/mathilde-team/netcross-ci:26.04` à chaque modification fusionnée dans `dev`, chaque lundi (mises à jour de
  sécurité) et à la demande. `ci.yml` basculera dessus dans une seconde PR, une fois l'image publiée.

### Modifié
- Licence (#986) : passage de MIT à **GPL-3.0-or-later** — texte officiel
  GPLv3 dans `LICENSE`, déclaration `license = "GPL-3.0-or-later"` dans
  `pyproject.toml`, en-têtes `SPDX-License-Identifier` sur tous les
  fichiers source (Python, scripts shell, Dockerfile), `debian/copyright`
  ajouté (format machine-readable), spec RPM et README mis à jour
  (compatibilité des dépendances documentée).
- Guide utilisateur (#465) : captures d'écran de l'interface GTK4 à jour (les quatre onglets et la cartographie, plus quatre nouvelles pour les fenêtres Outils de capture, Analyse d'un dossier, Documentation Lua et Historique des runs), prises sur la vraie interface par `tools/captures_ecran_gui.py`, qui les régénère.
- CI (#966) : un nouveau commit sur une PR annule le run du commit précédent (`concurrency`), dans `ci.yml` et `pr-coverage.yml`. Les runs `push` sur dev et main ne sont jamais annulés.
- Seuil de couverture bloquant porté à 95 % (#953, règle Mathilde-Team/.github#9) :
  `fail_under = 95` est la seule déclaration. Le job Qualité l'applique hors
  `netcross_gtk4` (mesuré par le job GTK4), le job combiné au total réel, et le
  commentaire de couverture des PR compare le même périmètre que le job Qualité.

## [1.1.0] — 2026-10-18

### Ajouté
- Captures en direct par l'API (issues #902 à #908) :
  `POST /live-captures` lance une capture sur les interfaces du serveur avec
  un filtre BPF par point (#902), durée maximale configurable
  (`NETCROSS_API_LIVE_MAX_DURATION`, #903), arrêt avec analyse
  (`POST /live-captures/{id}/stop` renvoie l'`analysis_id`) et abandon sans
  analyse (`DELETE /live-captures/{id}`) (#904), ring buffer
  (`ring_buffer`, #905), rapport HTML rafraîchi en continu (#907) et
  comparaison avec le courant capturé en direct (#908)
- Bibliothèque de filtres BPF dans l'API : `GET/PUT/DELETE /bpf-filters`,
  champ `bpf_library` de chaque point de `POST /live-captures` (#906)
- Catalogue des dissecteurs Wireshark écrits en Lua (plus de 1 200 dépôts
  recensés par [wireshark-lua](https://github.com/Mathilde-Team/wireshark-lua))
  dans la banque Lua, en CLI, GUI et API (#917)
- Exploration et analyses en CLI et API : cartographie des communications
  (#909), exploration statistique (Top-N, tri, regroupement, drill-down,
  export CSV/JSON) (#912), dashboard analytique à sélection croisée (#911),
  annotations et signets sur les trames (#910)
- Parité GUI / CLI / API (série #330, issues #672 à #890) : outils de capture
  (fusion, découpage, conversion, export filtré, recalage temporel, rejeu),
  module IA local (`POST /analyses/{id}/ai`), plugins (`GET /plugins`,
  `NETCROSS_PLUGIN_PATH`), documentation Lua, historique des comparaisons et
  des analyses avec consultation filtrée, notifications, table d'anonymisation,
  export Markdown, Top-N appliqué aux graphiques du PDF, ticket de support
  (portées, marqueurs, correspondance), lots de captures (`POST /batches`,
  fenêtre « Analyse d'un dossier »), options d'analyse avancées
  (`parallel_workers`, base CVE, troncature annoncée)
- GUI : résultats de recherche forensic cliquables vers la trame (#675),
  sections d'expertise (#673), diagramme de séquence, SIEM et historique
  dans la fenêtre d'analyse (#674)
- CLAUDE.md : toute instruction reçue dans le chat devient une issue (#931)
- Plusieurs captures dans un seul fichier pcapng (#474, lot 1) :
  `--split-interfaces` fait de chaque interface (et de chaque section, pour
  des fichiers concaténés) un point distinct `NOM:INTERFACE`, analysé comme
  un fichier séparé. Nouvelles fonctions `pcap_parser.list_interfaces` et
  `pcap_parser.split_by_interface` ; la clé est le couple (section,
  interface), car l'identifiant d'interface repart de 0 à chaque section.
- Guide utilisateur (#465), `docs/guide/` : installation, préparation des
  captures, première analyse pas à pas, interface graphique (captures
  d'écran réelles), lecture du rapport et du score de santé, comparaison
  avant/après, dépannage. Il s'appuie sur des captures d'exemple versionnées
  (`docs/guide/exemples/`, 5 pertes connues entre LAN et WAN) et sur leur
  générateur reproductible : chaque sortie citée a été obtenue avec ces
  fichiers.
- Matrice de parité GUI / CLI / API (#330), `docs/parite-surfaces.md` :
  chaque fonction et sa disponibilité sur chaque surface, avec les écarts
  classés par impact. Le principal : le JSON de l'API n'est pas celui de
  `--json-report` (ni constats, ni triage, ni score de santé).
  `tests/test_parite_surfaces.py` extrait les options argparse des 6 CLI,
  les routes et paramètres FastAPI et les cases de la GUI (AST) : toute
  option ou route non classée dans la page, ou tout décompte périmé, fait
  échouer la CI.
- `netcross_gtk4/bpf_panel.py` — décisions du panneau de filtres BPF de la
  capture live extraites de `app.py` et couvertes à **100 %** (62 tests) :
  conversion indice de menu ↔ filtre, infobulle, désolidarisation du menu sur
  édition manuelle, validation d'enregistrement, bornes de déplacement (#285)
- `tests/test_history_cli.py` et `tests/test_cli_entrypoints.py` — première
  couverture des points d'entrée : `cross_history_cli.py` **0 % → 100 %**,
  analyzer 54,5 % → 61,3 %, diff 60,6 % → 62,4 %. Inventaire des codes de
  retour documenté dans le module de test (#287)
- `tests/test_pdf_report.py` et `tests/test_charts.py` — première couverture
  dédiée du rendu : `pdf.py` 63,1 % → 77,9 %, `charts.py` 41,2 % → 93,5 %. Le
  texte est réextrait des PDF produits (`pdftotext`) plutôt qu'inspecté avant
  rendu, et `generate_diff_pdf` — le rapport du mode comparaison — passe de
  zéro test à une couverture de bout en bout (#286)
- `netcross_gtk4/panel_state.py` — visibilité des panneaux, état du bouton
  Lancer, filtres de cartographie et sélection au tableau de bord, sortis de
  `app.py` (#285, troisième lot)
- Le bouton Lancer explique en infobulle pourquoi il est inactif — combien de
  captures manquent, et en mode live le compte porte sur les points **après**
  éclatement des interfaces, ce que l'utilisateur ne pouvait pas deviner (#285)
- `netcross_gtk4/run_outcome.py` — état de résultat de la GUI en structure
  unique et gelée : les quatorze champs `last_*` étaient réécrits séparément
  par l'analyse et par la comparaison, sans garantie qu'elles restent
  synchronisées, ce qui exposait à un affichage de données du run précédent
  (#285, deuxième lot)
- `netcross_gtk4/row_labels.py` — les douze fonctions de libellé et de clé de
  tri des lignes de la GUI, sorties de `app.py` pour devenir testables :
  elles étaient à 0 % non par difficulté mais parce que leur fichier
  `import gi` en tête, intestable en CI (#285, premier lot)
- Le rapport de sécurité alimente désormais le JSON (`security_report`), le
  PDF (section dédiée) et un nouveau rendu HTML autonome `--security-html` —
  il n'existait qu'en sortie texte (#218)
- `netcross_report/security_report.py::security_report_to_dict()` — socle de
  sérialisation unique des quatre rendus (#218)
- `netcross_report/security_html.py` — fichier HTML unique, sans ressource
  externe, tableaux filtrables, mode sombre et impression (#218)
- `--security-report`, `--cve-db` et `--security-html` documentés dans
  `CLAUDE.md`, avec les modules du pipeline de sécurité (#216)
- Les empreintes JA4/HASSH sont enfin affichées dans le rapport de sécurité
  (`JA4=…` / `HASSH=…` + forme lisible tronquée) : elles étaient calculées
  puis silencieusement jetées avant l'affichage (#259)
- `known_fingerprints.json` peuplé de 7 empreintes réelles (curl TLS 1.2 et
  1.3, wget, `openssl s_client`, `python ssl`, OpenSSH client et serveur),
  chacune vérifiée identique à celle calculée par Wireshark (#259)
- `scripts/capture_reference_fingerprints.py` — génère la base depuis du
  trafic réel en boucle locale et rejette toute empreinte en désaccord avec
  tshark (#259)
- `docs/fingerprints-ja4-hassh.md` (#259)

### Corrigé
- CI : la mesure de couverture par PR installe l'extra `api` (les tests de
  l'API étaient sautés et `netcross_api` comptait pour 0 % dans le delta),
  la base est mesurée avec les mêmes extras que la PR et aucune des deux
  mesures n'applique le seuil bloquant (réservé au job Qualité, PR #930)
- CI (release) : `softprops/action-gh-release` épinglé sur un SHA existant
  (PR #914)
- Rapport Markdown (`--md-report`, #761) : la section « Rapport de
  sécurité » lisait des clés que `security_report_to_dict()` ne produit pas
  (`global_score`, `critical_count`, `service_count`, `items`,
  `fingerprints`). Pour un Apache 2.4.49 porteur de 5 CVE, elle affichait
  « Score global : — », « Vulnérabilités critiques : 0 » et « Services
  analysés : 0 », sans lister aucune CVE. Elle reprend désormais le tableau
  de bord du rapport texte (score et niveau, services vulnérables,
  exploits, anomalies, CVE), un tableau des services (version, sévérité,
  CVE, empreinte) et un tableau des exploits, CVE et anomalies. La section
  « Expertise » lisait elle aussi des attributs inexistants (`group`,
  `verdict`, `framework`) : ses colonnes sont maintenant celles du PDF
  (cause probable, impact, référentiel, mesure et seuil). Les `|` et les
  sauts de ligne sont échappés dans les cellules. `_fmt_num`, jamais
  appelée, est supprimée. `tests/test_markdown_report_sections.py`
  (9 tests) porte le module à 100 % (lignes et branches ; il était à
  55,2 % sous GTK4).
- Premier démarrage (#468) : l'absence de `~/.netcross/bpf_filters.json` et
  de catalogue de traduction n'est plus journalisée en `ERROR` avec trace ;
  une capture introuvable ou illisible est signalée avant tshark avec la
  cause et la commande de correction ; si tshark (snap, AppArmor) refuse
  d'ouvrir un fichier pourtant lisible, il le reçoit sur son entrée
  standard ; la GUI lancée sans affichage accessible (root, SSH) affiche un
  message explicite et renvoie le code 2 au lieu d'une trace GTK.
- Page d'accueil de la documentation : la commande « Première analyse »
  (`--capture point_a.pcapng --analyze`) échouait, car `--analyze`
  n'existe pas et `--capture` exige `NOM=chemin`.
- `CONTRIBUTING.md` décrivait la branche `dev` comme protégée alors
  qu'aucune protection n'existait (`protected: false`) : c'est ce qui avait
  permis de fusionner les PR #316 à #327 avec une CI rouge (#334). La règle
  est désormais versionnée dans `.github/branch-protection/dev.json`, à
  appliquer par un administrateur, et le workflow « Protection de dev »
  (`scripts/check_branch_protection.py`) signale tout écart entre ce fichier
  et la protection réelle.
- Le workflow « Documentation » échouait à chaque push sur `main` (erreur
  404 au déploiement) : il publiait vers GitHub Pages, qui n'est pas activé
  sur le dépôt. La publication est retirée ; la construction
  `mkdocs build --strict` reste bloquante et le site HTML reste
  téléchargeable comme artefact du run. Permissions du workflow réduites
  à `contents: read`, `site_url` retiré de `mkdocs.yml`.
- Le tableau de bord analytique, la vue statistiques et la sélection de flux
  de la GUI plantaient silencieusement (`AttributeError` dans un callback
  `GLib.idle_add`) dès qu'un flux existait : les deux threads d'analyse
  transmettent le dict brut de `correlate()`, que ces vues orientées objets
  ne savent pas lire. `RunOutcome` porte désormais `flow_objects`, la
  `list[Flow]` dérivée du dict au seul point par lequel les deux chemins
  passent, et les vues concernées la consomment ; `last_flows` reste le dict
  brut pour le détail CSV, la cartographie et les objets de session, qui
  lisent les paquets (#453)
- Le bouton « Descendre » d'une ligne de capture n'avait pas la borne que
  « Monter » avait : il insérait au-delà de la fin sur la dernière ligne et ne
  restait en place que parce que GTK ajoute silencieusement en fin de liste.
  Les deux sens partagent désormais la même borne explicite (#285)
- Une base d'historique invalide (`--history-db` / `--db` pointant sur un
  fichier qui n'est pas du SQLite) faisait remonter `sqlite3.DatabaseError` en
  trace Python. Sur l'analyzer et le diff, l'historique étant écrit **à la fin**
  du run, toute l'analyse était perdue. Message nommant le chemin et code 1
  via `HistoryDatabaseError` (#287)
- Une capture introuvable n'était plus signalée sur la **branche de chargement
  par défaut** : `[A] 0 paquets chargés` était indistinguable d'une capture
  sans trafic IP, et l'avertissement « résultat incomplet » n'existait que sur
  `--parallel`. Les deux CLI rapportent désormais `ECHEC` par fichier dans les
  deux branches (#287)
- Un clic sur une vue du tableau de bord dont le type était mal orthographié
  n'avait aucun effet, sans message ni trace : la cascade de `elif` de
  `_dashboard_select` n'avait pas de branche finale. Un type inconnu lève
  désormais `UnknownViewTypeError` (#285)
- Avec les deux modes actifs, la page de configuration affichait le panneau de
  capture live **et** ceux de comparaison ; la priorité va au live, alignée sur
  l'ordre d'évaluation de `on_run_analysis` (#285)
- `CLAUDE.md` annonçait « 1150/1150 tests » et `mypy` intégré à l'outillage :
  la suite en compte 2958 et `mypy` n'est pas configuré dans le projet (#216)
- Le JSON écrit `security_report` dans tous les cas, avec le motif de
  l'absence : « non demandé », « rien trouvé » et « clé non produite par
  cette version » étaient indistinguables (#218)
- Journal de `apply_security_findings` : le compteur annoncé comme
  « fingerprints » comptait en réalité les incohérences de protocole (#259)
- Rapport texte : l'encapsulation au niveau fichier (lue par capinfos) est
  enfin affichée, et le code DLT par interface est traduit en nom lisible
  (`linktype 1 (Ethernet)`) (#263)
- `export_filtered()` : `bpf_filter` est replié dans le filtre d'affichage
  `-Y` au lieu de `-f`, que tshark refuse en relecture de fichier — tout
  appel avec ce paramètre échouait systématiquement (#261)
- `export_filtered()` et `adjust_timestamps()` imposent `-F pcap`/`-F pcapng`
  selon l'extension de sortie : sans cela tshark et editcap écrivaient du
  pcapng dans un fichier nommé `.pcap` (#262)
- CI : `tshark`/`editcap` sont installés et la CI échoue si un test
  `@requires_tshark` reste sauté — 6 tests n'avaient jamais pu s'exécuter (#262)
- 3 assertions de test erronées, révélées par leur première exécution réelle

### Ajouté
- Dockerfile et .dockerignore pour déploiement conteneurisé (#170)
- CONTRIBUTING.md — guide de contribution (#170)
- SECURITY.md — politique de sécurité et reporting CVE (#170)
- `netcross_core/config.py` — loader de configuration `.netcross.toml` (#170)
- `netcross_report/siem_export.py` — export CEF pour intégration SIEM (#170)
- `netcross_core/support/` — remontée de tickets anonymisés avec consentement
  explicite : crash, erreurs de traitement, journal et contexte (#269)
- `netcross_core/support/scrubber.py` — anonymisation de texte libre (IP, MAC,
  emails, URL, FQDN, noms de capture, répertoires personnels, secrets), en
  complément de `redact.py` qui ne traite que les champs structurés (#269)
- Options CLI `--support-ticket`, `--support-consent`, `--support-scope`,
  `--support-map`, `--support-marker` (#269)
- `docs/support-tickets.md` — documentation de la remontée de tickets (#269)
- `scripts/generate_openapi.py --check` + vérification en CI de la fraîcheur de
  `docs/openapi.yaml` (#209)

## [1.0.0] — 2026-09-22

### Ajouté
- Analyse croisée multi-points de captures Wireshark (.pcap/.pcapng)
- Corrélation de flux entre points (pertes, latence, QoS, retransmissions)
- Détection de signatures d'exploits (CVE-1 à CVE-5)
- Empreintes de services et versions (bannières, JA4, HASSH)
- Détection de tunneling DNS, beaconing C2, mouvements latéraux
- Détection DGA et fast flux DNS
- Extraction de fichiers (file carving) depuis captures
- Rapports PDF, JSON, CSV, texte
- Interface GTK4
- API REST FastAPI + spécification OpenAPI (#209)
- Logging structuré via loguru (#245)
- Pipeline CI/CD complet (lint, tests, coverage, guard main)
- Statistiques de flux et conversation (#145)
- Audit TLS (#153), découverte d'actifs (#151)
- Conversion de formats (#169), exfiltration de données (#148)

### Sécurité
- Politique de sécurité et procédure de reporting CVE (SECURITY.md)

---

Les versions antérieures ne sont pas trackées dans ce fichier.
Le projet utilisait des releases GitHub ad-hoc avant la version 1.0.0.
