# netcross — fonctionnalités, dette et priorisation

Document de référence pour mesurer l'état d'avancement du projet : ce qui
existe module par module, ce qui est réellement câblé dans une interface
utilisable (CLI/GUI/PDF), et ce qui ne l'est pas encore.

Généré en lisant le code source réel (pas la documentation existante) —
toute divergence avec le README reflète l'état effectif du code.

---

## 1. Vue d'ensemble des packages

| Package | Rôle | Dépendances externes |
|---|---|---|
| `pcap_parser` | Décodage bas niveau des captures via `tshark -T ek` (fichier ou live) | `tshark` (binaire système) |
| `netcross_core` | Moteur d'analyse : parsing (adaptateur), corrélation, analyse croisée, TLS, QUIC, texte, diff baseline | `cryptography` (QUIC uniquement) |
| `netcross_report` | Synthèse en constats, triage, graphiques, PDF | `reportlab`, `matplotlib`, `networkx`, `Pillow` |
| `netcross_gtk4` | Interface graphique GTK4 | `PyGObject`, `GTK4` |
| CLIs (`cross_capture_analyzer_cli.py`, `cross_capture_diff_cli.py`, `cross_history_cli.py`) | Points d'entrée ligne de commande | — |

### Outillage qualité (lint / format / architecture)

Introduit en Session 7 via `pyproject.toml` (`[tool.ruff]` /
`[tool.importlinter]`) et `.pre-commit-config.yaml`, tous deux à la racine.

| Outil | Rôle | Configuration clé |
|---|---|---|
| `ruff check` | Lint | `select = [E, W, F, I, B, C4, UP, SIM, N, PERF, RUF, TID]`, `line-length = 120`, `target-version = py39`, imports absolus obligatoires |
| `ruff format` | Formatage | même `line-length`/`target-version` |
| `import-linter` (`lint-imports`) | Architecture | contrat `layers` : `netcross_gtk4` → `netcross_report` → `netcross_core` → `pcap_parser` (une couche ne peut dépendre que de celles strictement en dessous) |
| `mypy --ignore-missing-imports` | Typage statique | ad hoc, pas encore dans `pre-commit` ; lancé uniquement sur les fichiers modifiés d'une session (voir note ci-dessous pour la limite que ça implique) |
| `pre-commit` | Orchestration | 3 hooks : `ruff --fix`, `ruff-format`, `import-linter` (local, `PYTHONPATH=src lint-imports`) |

Dépendances dev correspondantes dans `requirements-dev.txt` (`ruff==0.16.4`
épinglé sur la `rev` du hook, `import-linter>=2.13`, `pre-commit>=4.0`).

**Dette `mypy` — décompte corrigé à la Session 50** : 49 erreurs
préexistantes sur 9 fichiers (`analysis.py` 10, `tls_diagnostics.py` 18,
`triage.py` 9, `quic_diagnostics.py` 4, `packet.py` 2, `history.py` 2,
`netcross_report/__init__.py` 2, `ek_source.py` 1, `parsing.py` 1),
toutes de même nature (annotations de variable manquantes, `str | None`/
`int | None` remontant de `RawPacket` vers des dataclasses plus
strictes, `**dict` non typé passé à un constructeur typé) — pas des bugs
d'exécution, jamais reproduits par un test qui échoue. Le suivi tenu
depuis la Session 38 (27 erreurs, 7 fichiers) était sous-évalué : la
convention consistant à lancer `mypy` uniquement sur les fichiers
modifiés d'une session (voir `CLAUDE.md`, Commandes qualité) ne peut par
construction jamais détecter la dette d'un fichier qu'aucune session ne
retouche — c'est exactement le cas de `tls_diagnostics.py`/
`quic_diagnostics.py`, jamais modifiés depuis leur création et donc
jamais inclus dans un `mypy <fichiers modifiés>` ad hoc. Correction du
code toujours hors périmètre (décision reconduite depuis la Session 38,
non remise en cause par cette découverte) ; voir
`docs/sessions/session-50.md` pour le détail de l'audit.

**Comparaison avec les motifs non métier d'un autre projet** (`docs/
comparaison-patterns-project-skeleton.md`, Session 34) : revue section par
section de `PATTERNS.md` (catalogue de conventions d'architecture/tests/
packaging tenu par `project-skeleton`) contre le code réel de netcross —
chaque règle vérifiée par grep/lecture, jamais déduite par ressemblance.
Conclusion résumée : séparation des couches, packaging 3-méthodes et
journalisation de session sont implémentés et documentés ; l'absence de
cycles d'imports est assurée par `import-linter` plutôt que par un test
`ast` maison (rigueur équivalente) ; plusieurs motifs GTK4 du squelette
(SIGINT propre, préférences persistantes, icône, diagnostic sudo/RDP,
i18n, tracing entrée/sortie) sont absents et non documentés comme choix
délibérés ; toute la section « Secrets » du squelette est sans objet
(netcross n'accède à aucun système distant authentifié).

Écart corrigé dans le fichier fourni : `TID` absent du `select` rendait
`ban-relative-imports = "all"` inopérant (0 violation `TID252` remontée
sans, 76 avec, vérifié empiriquement) — `TID` ajouté, voir `docs/sessions/session-07.md` pour le détail complet des corrections apportées au code
(imports relatifs, `N806`, `E402`, `E741`, `E501`, `PERF401`...) et des
choix renommage-vs-`noqa` documentés au cas par cas.

Validation : `ruff check .` (0 erreur), `ruff format --check` (44 fichiers
conformes), `lint-imports` (contrat respecté), `pytest` (280/280),
`pre-commit run --all-files` exécuté réellement de bout en bout (3 hooks
passés).

### Organisation du suivi de projet (Session 42)

Jusqu'à la Session 41, le suivi tenait dans deux fichiers uniques à la
racine — `claude.md` (journal détaillé, une section par session,
7671 lignes/428 Ko après 41 sessions) et `FEATURES.md` (état fonctionnel
et backlog, 7230 lignes/384 Ko) — que chaque nouvelle session devait
reparcourir en entier pour retrouver le point courant. Restructuré en
Session 42 (voir `docs/sessions/session-42.md` pour le détail complet) :

- `CLAUDE.md`, court, à la racine : état courant, prochaine feature,
  commandes qualité — seul fichier à lire systématiquement en début de
  session, avec un import `@docs/features-backlog.md` pour recomposer le
  backlog sans le dupliquer.
- `docs/features-backlog.md` (ce fichier) : inchangé sur le fond, déplacé
  et renommé depuis `FEATURES.md` — reste le document de référence pour
  les fonctionnalités, la dette et la priorisation.
- `docs/sessions/session-NN.md` : historique détaillé (raisonnement,
  décisions de conception) éclaté depuis `claude.md`, un fichier par
  session — consulté à la demande, pas à chaque démarrage. La Session 22
  s'est révélée absente de l'archive livrée (gap pré-existant, documenté
  tel quel dans `docs/sessions/session-22.md` plutôt que reconstitué).

Toutes les références internes à `claude.md`/`FEATURES.md` (backlog,
`README.md`, `docs/comparaison-patterns-project-skeleton.md`) ont été mises
à jour vers les nouveaux chemins, à l'exception de
`docs/comparaison-patterns-project-skeleton.md` dont plusieurs numéros de
ligne cités (ex. `claude.md` lignes 409/492/537/2500) datent de l'ancien
fichier monolithique et ne sont plus vérifiables telles quelles — signalé
en tête de ce fichier plutôt que réécrit sans vérification.

---

## 2. Fonctionnalités par module

Légende : ✅ câblé dans au moins une interface utilisateur (CLI ou GUI) —
⚠️ code fonctionnel mais **non appelé par aucune interface** (mort du
point de vue de l'utilisateur final, sauf usage direct en bibliothèque).

### `pcap_parser` — décodage réseau (tshark)

- ✅ `parse_capture(path)` — décodage d'un fichier `.pcap`/`.pcapng`
- ✅ `parse_captures_parallel(captures)` — un processus tshark par fichier
- ✅ **Nouveau (Job 34, issue #154)** : `merge_captures(paths, output_path,
  dedup=False)` — fusionne plusieurs fichiers `.pcap`/`.pcapng` (formats
  mélangeables) en UN seul, ordonné par timestamp de paquet ; enveloppe
  de `mergecap` + `reordercap` (+ `editcap -w 0` si `dedup=True`), sans
  aucun décodage. Voir section 4, « fusion de captures PCAP — Job 34 ».
- ✅ `iter_live(interface, bpf_filter, stop_event=None)` — capture en
  direct sur interface ; câblé depuis la GUI (mode "Capture en direct",
  voir `netcross_gtk4.app`), depuis `cross_capture_analyzer_cli.py`
  (`--live LABEL:INTERFACE[:FILTRE_BPF]`, Session 5), **et depuis
  `cross_capture_diff_cli.py`** (`--live-current`, Session 16, pour le
  run courant uniquement — le baseline reste toujours un ou plusieurs
  fichiers, voir section 4 point 14) — cette dernière mention "toujours
  absent" était restée obsolète depuis la Session 16, corrigée en
  Session 37 (voir aussi la correction identique plus bas pour
  `parse_live`)
- ✅ **Nouveau** : paramètre `stop_event` (`threading.Event`) sur
  `iter_ek_records`/`iter_live`, pour un arrêt réactif même sur une
  interface sans trafic (un thread dédié termine le sous-processus
  tshark dès que l'événement est positionné, plutôt que d'attendre le
  prochain paquet pour vérifier un flag — voir `ek_source._terminate_on_event`)
- ✅ **Nouveau (Job 35, issue #155)** : `split_capture(path, output_dir,
  by="time"|"count"|"size", value)` — découpe une capture volumineuse en
  segments (durée, nombre de paquets ou taille maximale), format
  d'origine conservé (pcap, pcap nanoseconde, pcapng), renvoie la liste
  des segments dans l'ordre chronologique. `time` (`editcap -i`) et
  `count` (`editcap -c`) enveloppent `editcap` (livré avec tshark). `size`
  ne peut PAS s'appuyer sur `editcap` (aucune option de taille ; `tshark
  -b filesize:` refuse aussi de découper une lecture de fichier) : il est
  réalisé par `pcap_parser.capfile`, un cadrage binaire en une passe et
  mémoire constante (enregistrements pcap / blocs pcapng, **aucune
  dissection**), qui recopie en-tête global ou SHB+IDB+DSB dans chaque
  segment pour qu'il reste lisible seul. Points de conception : (1)
  `editcap` écrit du pcapng même pour une entrée pcap sans `-F` — le
  format détecté est donc toujours redemandé ; (2) `editcap -i` produit un
  fichier VIDE par intervalle sans paquet (silence de la capture) —
  supprimés, la numérotation des segments présente alors des trous ; (3)
  refus d'écraser ou de mélanger avec des segments déjà présents dans le
  répertoire de sortie (`FileExistsError`) ; (4) en mode `size`, un
  segment contient toujours au moins un paquet, donc un paquet plus gros
  que la limite dépasse seul sa limite. Tests : `tests/test_capfile.py`
  (sans outil externe), `tests/test_split_capture.py` (`editcap` simulé,
  plus les cas réels — 1000 paquets en 10 fichiers de 100, cohérence
  temporelle par intervalle de 10 s, silence sans segment vide — sautés si
  `editcap` est absent). Câblé sur `cross_capture_analyzer_cli.py`
  (`--split`, voir CLIs)
- ✅ Décapsulation native : VLAN (802.1Q, y compris empilé/QinQ), MPLS,
  GRE, VXLAN, GTP-U, ERSPAN, CAPWAP (canal data, avec détection du
  chiffrement DTLS)
- ✅ Extraction RTP (dissection tshark + repli heuristique par en-tête),
  DHCP, SIP (dissection tshark + repli heuristique)
- ✅ **Nouveau (Session 13)** : extraction DNS (`extract_dns`, dissection
  tshark native uniquement — **pas** de repli heuristique, voir section 4
  pour la justification). Reconnu sur UDP et TCP.
- ✅ **Nouveau (Session 17)** : extraction HTTP/1.x (`extract_http`,
  dissection tshark native uniquement, TCP seul — HTTP/2/3 hors périmètre,
  voir section 4). Nouveau helper `ek_fields.as_float()` pour `http.time`
  (durée requête→réponse **calculée nativement par tshark**, chaîne
  flottante de secondes — pas recomposée à la main comme pour DNS/DHCP/SIP).
- ✅ IPv4 et IPv6, ICMP
- ✅ Horodatage nanoseconde (`frame.time_epoch`)
- ✅ **Nouveau** : bit IPv4 `DF` (Don't Fragment) exposé (`RawPacket.df`,
  toujours `False` côté IPv6 — pas d'équivalent direct, la fragmentation
  y est uniquement faite par la source). Support pour la détection de
  noir PMTUD, voir `netcross_core.analysis` ci-dessous. Extraction via
  un nouveau helper `ek_fields.as_bool()`, qui **corrige au passage un
  bug réel** : `is_fragment` (MF) utilisait `bool(g(...))` nu, qui
  vaudrait `True` à tort si jamais ce champ était un jour rendu en
  chaîne `"0"`/`"1"` plutôt qu'en booléen JSON natif (`bool("0")` vaut
  `True` en Python) — trouvé en écrivant le test du nouveau champ `df`,
  jamais couvert par un test avant. Vérifié empiriquement contre un vrai
  tshark 4.2.2 (voir `docs/sessions/session-09.md`) que ces sous-champs de
  l'octet de flags IP sont bien rendus en booléen natif dans cette
  version — `as_bool` reste néanmoins tolérant à une représentation en
  chaîne par prudence (symétrique à `hex_or_dec_to_int` pour les
  champs numériques), au cas où une autre version de tshark diffère.
- ✅ **Nouveau (Session 21)** : fragmentation **IPv6** détectée
  (`RawPacket.is_fragment`/`ip_id` peuplés côté IPv6, en plus d'IPv4 déjà
  fait) — en-tête d'extension Fragment (RFC 8200 §4.5,
  `ipv6.fragment.ident`/`.offset`/`.more`), niché sous
  `ip6["ipv6_fraghdr"]` dans le layer EK (vérifié empiriquement contre un
  vrai tshark 4.2.2, pcap scapy fragmenté via `fragment6()`, voir
  `docs/sessions/session-21.md`) — normalisé liste/dict par prudence comme
  `layer()`/`innermost()`, bien que jamais observé en liste sur les
  captures de test (un seul en-tête Fragment possible par datagramme
  IPv6, RFC 8200 n'en autorise pas deux). Trou identifié dès la session
  qui avait introduit la détection PMTUD (Session 9, `is_fragment` restait
  toujours `False`/`ip_id` toujours `None` côté IPv6, jamais corrigé
  depuis) et listé en 🟢 urgence faible section 5.2 comme "non confirmé
  comme corrigé" — désormais fait.
  - **Limite protocolaire assumée, différente d'IPv4** (documentée dans
    `netcross_core.models`/`netcross_core.analysis`) : `ipv6.fragment.id`
    n'existe QUE sur un datagramme déjà fragmenté — un datagramme IPv6
    jamais fragmenté n'a par construction **aucun** identifiant à
    exposer, contrairement à `ip.id` en IPv4 qui est un champ ordinaire
    toujours présent. Conséquence directe sur `netcross_core.analysis`
    (bloc "fragmentation / MTU", inchangé, déjà générique sur `pk.ip_id`) :
    `r.frag_count` profite automatiquement de cet ajout (générique
    IPv4/IPv6 dès que `ip_id` est renseigné, aucune branche par famille
    d'adresse nécessaire dans `analyse()` elle-même) ; en revanche
    `r.frag_new`/`r.encap_frag_correlated` ("un datagramme non fragmenté
    en amont devient fragmenté en aval", appariement par
    `(src, dst, ip_id)`) ne peuvent détecter ce cas que si le datagramme
    est **déjà** fragmenté aux deux points — un datagramme non fragmenté
    au point amont n'a aucun `ip_id` pour l'appariement. Cohérent avec le
    fait que seule la source fragmente en IPv6 (jamais un routeur
    intermédiaire en cours de route, contrairement à IPv4) : le scénario
    "fragmentation qui apparaît en aval" que `frag_new` est censé
    détecter n'a de toute façon pas d'équivalent réaliste côté IPv6.
  - **Pas de changement côté ICMPv6** (hors périmètre de cette passe,
    volontairement) : ce projet ne décode pas encore ICMPv6 (pas de
    couche `icmpv6` sélectionnée dans `pcap_parser.tunnels`, contrairement
    à `icmp` pour IPv4) — la détection PMTUD IPv6 (ICMPv6 *Packet Too
    Big*, type 2) reste donc hors d'atteinte, comme déjà documenté dans
    `_analyse_pmtud`. Un paquet ICMPv6 est aujourd'hui classifié `proto="IP"`
    générique (repli par défaut), sans `icmp_type`/`icmp_code`. Décodage
    ICMPv6 non traité ici : nouvelle piste distincte, pas une extension
    mineure de celle-ci (nécessiterait une nouvelle couche EK, des champs
    `RawPacket` dédiés ou réutilisés, et une décision de conception sur le
    chevauchement avec `icmp_type`/`icmp_code` existants).
  - Automatique, sans nouveau flag CLI (même choix que PMTUD/DNS/HTTP/etc.
    en leur temps) : parité GUI/PDF/JSON gratuite via `r.frag_count`/
    `r.frag_new` déjà câblés partout (aucun code de `netcross_core.analysis`/
    `netcross_report` modifié, seule la production de `RawPacket` change).
  - Validation : 7 nouveaux tests (`tests/test_packet.py` : premier
    fragment, dernier fragment, non-fragmenté sans `ip_id`, normalisation
    liste défensive ; `tests/test_analysis.py` : `frag_count` générique
    IPv6, `frag_new` qui fonctionne quand déjà fragmenté aux deux points,
    cas limite non détecté documenté explicitement) — **439/439** au
    total, aucune régression sur les 432 hérités. Rejeu du **vrai CLI**
    (`cross_capture_analyzer_cli.py --pdf-report --json-report --triage`)
    sur un vrai scénario à 2 points (point A : datagramme IPv6 fragmenté
    en 3 par un vrai `tshark`/`fragment6()` scapy ; point B : même
    datagramme non fragmenté) : "3 paquets fragmentés vus" correctement
    remonté en console pour le point A, PDF et JSON générés sans erreur —
    confirme aussi empiriquement la limite documentée ci-dessus (aucune
    "nouvelle fragmentation" signalée entre A et B, comme attendu). `ruff
    check`, `ruff format --check`, `PYTHONPATH=src lint-imports`,
    `pre-commit run --all-files` tous rejoués réellement, tout passe.
- ✅ **Nouveau (Session 22)** : décodage **ICMPv6** (nouvelle couche
  `icmpv6` sélectionnée dans `pcap_parser.tunnels.select_innermost_layers`,
  miroir exact de `icmp` pour IPv4) — `RawPacket`/`Pkt.icmpv6_type`/
  `icmpv6_code` (`icmpv6.type`/`.code`), identifiant/séquence portés par
  `sport`/`dport` pour Echo Request/Reply uniquement (`icmpv6.echo.
  identifier`/`.sequence_number`, absents des autres types de message —
  vérifié empiriquement, `g()` renvoie `None` sans lever), `proto=
  "ICMPv6"` (nouvelle valeur, symétrique de `"ICMP"`). **Décision de
  conception** tranchée telle qu'identifiée en Session 21 ci-dessus :
  champs séparés de `icmp_type`/`icmp_code` plutôt que réutilisés — les
  espaces de valeurs ICMPv4/ICMPv6 ne se recouvrent pas numériquement
  (type 2 = *Redirect* côté v4, *Packet Too Big* côté v6 ; type 3 =
  *Destination Unreachable* côté v4, *Time Exceeded* côté v6), des champs
  distincts rendent la confusion structurellement impossible plutôt que
  de compter sur la discipline de chaque site d'appel à vérifier `proto`
  en plus du type.
  - Vérifié empiriquement contre un **vrai tshark 4.2.2** (pcap scapy
    synthétique : Echo Request/Reply, *Packet Too Big*, *Destination
    Unreachable*, *Time Exceeded*, Neighbor Solicitation/Advertisement) :
    noms de champs confirmés, et découverte notable — pour un message
    d'erreur ICMPv6 (qui embarque le datagramme original en cause),
    tshark **niche** les couches `ipv6`/`udp` de ce datagramme embarqué
    **sous la clé `icmpv6` elle-même**, pas au même niveau que la vraie
    couche IPv6 externe. `layer()`/`innermost()` ne recursent pas dans
    les sous-clés, donc aucun risque de confusion avec l'enveloppe
    externe (adresse du routeur qui émet l'erreur) — confirmé par un test
    dédié (`test_build_packet_icmpv6_ignore_couches_imbriquees_du_
    message_erreur`) plutôt que supposé.
  - **PMTUD IPv6 désormais détecté** (`_analyse_pmtud` étendu) : nouveau
    compteur `Report.icmpv6_too_big` (ICMPv6 *Packet Too Big*, type 2,
    RFC 4443 §3.2 — l'analogue IPv6 de *ICMP Fragmentation Needed*),
    compté **avant** le garde-fou `pk.ip_id is None` du bloc fragmentation/
    MTU (contrairement à *ICMP Fragmentation Needed* qui en profite
    passivement grâce à `ip.id` toujours présent côté IPv4, un message
    ICMPv6 n'a lui-même presque jamais d'en-tête d'extension Fragment —
    le compter seulement si `ip_id` est présent l'aurait fait passer
    inaperçu presque à chaque fois, piège identifié en croisant avec la
    Session 21). Deux branches dans `_analyse_pmtud` selon la famille
    d'adresse (`":" in key[1]`, `key[1]` = adresse source de la clé de
    flux) : IPv4 exige toujours le bit `DF` actif sur toutes les
    tentatives (inchangé) ; IPv6 n'a **aucune** vérification équivalente
    — le bit DF n'existe pas côté IPv6 et sa sémantique ("ne pas
    fragmenter CE paquet") y est de toute façon implicite pour **tout**
    paquet (seule la source fragmente, RFC 8200 §4.5), donc un noir est
    plausible dès que le reste des conditions (retransmissions répétées,
    jamais vu en aval, taille significative) est réuni. `r.pmtud_blackhole`
    reste un compteur unique générique IPv4/IPv6 (même principe que
    `r.frag_count` en Session 21) — messages de `synthesis.py`/
    `report_text.py`/`baseline_diff.py` généralisés pour ne plus
    présupposer IPv4 (« DF actif » devient « signal ICMP(v6) de MTU
    insuffisant », RFC 1191 IPv4 / RFC 8201 IPv6 cités ensemble),
    exemples par tentative (`pmtud_blackhole_examples`) précisant
    « DF actif » vs « IPv6, pas de bit DF » selon le cas.
  - Finding informatif dédié pour `icmpv6_too_big` (catégorie
    Fragmentation, même sévérité `info` que *ICMP Fragmentation Needed*) ;
    comparaison de baseline ajoutée (`higher_is_worse=False`, même
    raisonnement : plus de signal ICMPv6 observé = PMTUD qui fonctionne
    mieux, pas une régression).
  - Automatique, sans nouveau flag CLI — parité GUI/PDF/JSON gratuite
    (`netcross_report/charts.py`/`json_report.py`/la GUI sont déjà
    génériques sur `pk.proto`, confirmé par lecture de code : aucune
    liste de protocoles figée nulle part, aucun changement nécessaire).
  - Validation : 18 nouveaux tests (`test_packet.py` : Echo, *Packet Too
    Big* sans ident/seq, Neighbor Solicitation, non-confusion avec les
    couches imbriquées ; `test_tunnels.py` : sélection de couche avec/
    sans tunnel ; `test_analysis.py` : comptage `icmpv6_too_big`, noir
    PMTUD IPv6 détecté/supprimé/non-régression IPv4 ; `test_synthesis.py`,
    `test_report_text.py`, `test_baseline_diff.py`) — **457/457** au
    total, aucune régression sur les 439 hérités. Rejeu du **vrai CLI**
    sur trois scénarios avec un vrai `tshark`/pcap scapy synthétiques :
    (1) noir PMTUD IPv6 (3 segments retransmis en A, jamais vus en B,
    aucun ICMPv6) correctement détecté et remonté en console/JSON/PDF ;
    (2) même scénario **avec** un *Packet Too Big* intercalé en A —
    détection correctement supprimée ; (3) non-régression du scénario
    PMTUD IPv4 historique (`DF` actif, sans ICMPv6 en jeu) — toujours
    détecté à l'identique. `ruff check`, `ruff format --check`,
    `PYTHONPATH=src lint-imports` tous rejoués réellement, tout passe.
- ✅ **Nouveau (Session 24)** : décodage **ARP** (nouvelle couche `arp`
  sélectionnée dans `pcap_parser.tunnels.select_innermost_layers`, même
  picker générique que `icmp`/`icmpv6`) — première couche gérée par
  `build_packet()` **sans en-tête IP du tout** (RFC 826), via une
  branche `elif arp is not None:` dédiée avant le `return None` final.
  `src`/`dst` réutilisés pour porter les adresses IP *portées par ARP
  lui-même* (`arp.src.proto_ipv4`/`arp.dst.proto_ipv4`), cohérent avec
  le reste du pipeline. Nouveaux champs dédiés `RawPacket`/`Pkt.
  arp_opcode`/`arp_sender_mac`/`arp_is_gratuitous` (`arp.opcode`/`arp.
  src.hw_mac`/`arp.isgratuitous` — ce dernier une classification
  **native** tshark, sender IP == target IP, RFC 5227, lue telle quelle
  plutôt que recalculée, même discipline que `tcp.analysis.
  retransmission` en Session 10). `sport`/`dport` volontairement **pas**
  réutilisés pour ARP (contrairement à ICMP(v6) où ils portent
  ident/seq) : des champs dédiés évitent toute ambiguïté de lecture.
  `proto="ARP"` (nouvelle valeur). Vérifié empiriquement contre un vrai
  tshark 4.2.2 (pcap scapy synthétique : requête who-has, réponse
  is-at, annonce gratuite) — voir section 4 pour le détail complet
  (dont un piège de pollution des statistiques de perte/latence/
  topologie trouvé et corrigé côté `netcross_core.correlate`).
- ✅ **Nouveau (Session 25)** : décodage **STP** (nouvelle couche `stp`,
  même picker générique) — deuxième couche gérée par `build_packet()`
  sans en-tête IP (IEEE 802.1D), via `elif stp is not None:`.
  Contrairement à ARP, STP ne porte **aucune** adresse IP — `src`/`dst`
  réutilisent l'adresse MAC Ethernet de la trame (`eth.src`/`eth.dst`,
  récupérée directement via la couche `eth`, jamais tunnelée). Nouveaux
  champs dédiés `stp_bpdu_type`/`stp_flags_tc`/`stp_root_id`
  (`stp.type`/`stp.flags.tc` — classification **native** tshark, absente
  sur une TCN, pas juste `false`/`stp.root.prio`+`stp.root.hw`, absents
  eux aussi sur une TCN, trame BPDU minimale de 4 octets utiles).
  `proto="STP"`. Vérifié empiriquement contre un vrai tshark 4.2.2 (pcap
  scapy synthétique via `scapy.layers.l2.STP`, disponible nativement —
  la limitation `scapy.contrib.stp` documentée en Session 24 était une
  fausse piste, jamais cherché au bon endroit) — voir section 4 pour le
  détail complet.
- ✅ **Nouveau (Session 26)** : dissection **X.509 native** du
  certificat serveur présenté lors d'un handshake TLS
  (`pcap_parser.protocols.extract_tls_certificate`, même patron que
  `extract_dns`/`extract_http`/`extract_sip`/`extract_dhcp` — lit une
  dissection déjà faite par tshark, pas de parsing manuel). Nouveaux
  champs `RawPacket.tls_cert_not_before`/`tls_cert_not_after`/
  `tls_cert_san`/`tls_cert_serial` (`x509af.utcTime`/`x509ce.dNSName`/
  `x509af.serialNumber`), câblés sous `if proto == "TCP":`. Se limite
  **volontairement** au certificat feuille (RFC 5246 §7.4.2 garantit
  qu'il est toujours le premier de la chaîne) et **exclut** Subject/
  Issuer (positionnellement ambigus en `-T ek`, voir docstring de la
  fonction) — voir section 4 pour le détail complet de cette décision de
  conception, vérifiée empiriquement contre un **vrai handshake TLS**
  capturé en local (`openssl s_server`/`s_client` + `tshark -i lo`).
- ✅ **Nouveau** : classification native tshark d'une retransmission TCP
  (`RawPacket.is_retransmission`/`is_fast_retransmission`/
  `is_spurious_retransmission`, `tcp.analysis.retransmission`/
  `.fast_retransmission`/`.spurious_retransmission`). Champs d'expertise
  (pas des champs de protocole ordinaires) : nichés sous une sous-clé
  `_ws_expert` du layer EK, valeur toujours `None`, seule leur présence
  compte — nouveau helper générique `ek_fields.has_expert_flag()` pour
  ce type de champ, vérifié empiriquement contre un vrai tshark 4.2.2
  (voir `docs/sessions/session-10.md`). **Ne sont pas mutuellement exclusifs**
  au niveau des champs bruts eux-mêmes (`is_retransmission` reste actif
  même quand `fast`/`spurious` le sont aussi — contrairement à ce que
  suggère le mot "Supersedes" dans la documentation Wireshark, qui ne
  concerne que le message d'expertise affiché, pas les champs) ; la
  priorité (spurious > fast > simple) est appliquée côté
  `netcross_core.analysis`, voir ci-dessous.
- ✅ **Nouveau** : options TCP négociées au handshake exposées
  (`RawPacket.mss_val`/`wscale_shift`/`sack_permitted`,
  `tcp.options.mss_val`/`.wscale.shift`/`.sack_perm`). Contrairement aux
  champs d'expertise ci-dessus, ce sont des champs de protocole
  ORDINAIRES — vérifié empiriquement (tshark 4.2.2, voir `docs/sessions/session-11.md`) qu'ils sont simplement absents du layer quand l'option
  correspondante n'est pas présente dans le paquet (pas de niveau
  `_ws_expert`, pas de valeur vide à filtrer). `tcp.options.sack_perm`
  n'a pas de valeur numérique utile (option à longueur fixe) : seule sa
  présence compte, exposée comme `bool`. Support pour
  `_analyse_tcp_options`, voir `netcross_core.analysis` ci-dessous.
- ✅ **Nouveau (Session 19)** : `RawPacket` utilise désormais `__slots__`
  (plus de `__dict__` par instance) et interne (`sys.intern()`, nouveau
  helper `packet._intern()`) les champs catégoriels à forte duplication
  attendue (`src`/`dst`, `flags` TCP, `dhcp_msg_type`/`server_id`/
  `vendor_class`, `sip_msg_type`/`user_agent`/`server`, `dns_qry_name`,
  `http_method`/`http_uri`) — voir section 4 pour la mesure complète
  (piste "gestion mémoire des grosses captures").

### `netcross_core.parsing` — adaptateur `pcap_parser` → `Pkt`

- ✅ **Nouveau (Session 19)** : `Pkt` utilise aussi `__slots__` (même
  levier que `RawPacket` ci-dessus — c'est l'objet gardé le plus
  longtemps en mémoire, toute l'analyse tourne dessus). `parse_capture()`
  convertit désormais `RawPacket → Pkt` en libérant chaque `RawPacket`
  au fur et à mesure (`raw_packets[i] = None`) plutôt qu'avec une
  compréhension de liste qui gardait les deux listes complètement
  matérialisées en RAM simultanément jusqu'à la fin de la fonction —
  élimine un pic mémoire transitoire pendant le chargement. Voir section
  4 pour la mesure complète.

- ✅ `parse_capture(label, path)`, `parse_captures_parallel(captures)`
- ✅ `parse_live(label, interface, bpf_filter=None, stop_event=None)` —
  exporté par `netcross_core/__init__.py`, **câblé depuis la GUI**
  (mode "Capture en direct" : un thread par point, arrêt manuel ou
  durée max, affichage incrémental du compteur de paquets dans le
  journal) **et depuis `cross_capture_analyzer_cli.py`** (`--live`,
  Session 5 : même modèle un-thread-par-point, arrêt sur `SIGINT`
  (Ctrl+C) ou `--live-duration`, un point en échec n'interrompt pas les
  autres). **Câblé aussi par `cross_capture_diff_cli.py`** depuis la
  Session 16 (`--live-current`, pour le run courant uniquement — le
  baseline reste toujours un ou plusieurs fichiers, voir section 4 point
  14) : la mention "non exposé" ici était restée obsolète depuis cette
  session, jamais mise à jour alors que la section CLI plus bas la
  documentait déjà correctement — corrigé en Session 37.
- ✅ `parse_rtp(payload)`, `parse_sip(payload)` — heuristiques ré-exposées
  pour compat
- ✅ `parse_dhcp(pkt)`/`innermost_layer(...)` **supprimées de l'API
  publique** (n'existaient que pour planter avec `NotImplementedError` —
  vestiges de l'ancien décodeur sans équivalent tshark direct)

### `netcross_core.correlate` — corrélation multi-points

- ✅ `correlate(packets, nat_tolerant, nat_window_ms)` — 5-tuple strict ou
  hash de payload + fenêtre temporelle (mode NAT-tolérant). **Depuis la
  Session 24, étendu en Session 25** : exclut délibérément les paquets
  `proto in ("ARP", "STP")` avant construction de `flows` — les deux
  sont diffusés/multicast locaux par nature (RFC 826 pour ARP ; IEEE
  802.1D, adresse de groupe `01:80:c2:00:00:00`, pour STP), jamais
  relayés par un routeur, sans la sémantique requête/réponse-PAR-FLUX
  que suppose implicitement tout ce qui consomme `flows` ensuite dans
  `analyse()` (pertes, latence, QoS, saut de TTL, inférence de
  topologie). Sans cette exclusion, une requête ARP broadcast ou une
  BPDU STP qui n'atteint jamais un point en aval d'un routeur
  (comportement **normal** pour ces deux protocoles) aurait été comptée
  comme une perte réseau ; la même trame vue à plusieurs points aurait
  faussé l'inférence de topologie (recouvrement de flux artificiellement
  élevé entre points non adjacents). ARP et STP restent disponibles via
  `all_packets` pour les détecteurs qui les veulent explicitement
  (`_analyse_arp_ip_conflict`, `_analyse_stp_instability`, voir
  `netcross_core.analysis` ci-dessous) — même principe que DNS/SIP/DHCP/
  RTP, qui n'utilisent pas non plus `flows`. Voir section 4 pour le
  détail complet.
- ✅ `compute_throughput(packets, bucket_seconds)`
- ✅ **Nouveau (Session 20)** : `compute_topn_series(packets,
  bucket_seconds, dimension, top_n=5)` — débit par bucket ventilé par
  catégorie (`point -> catégorie -> bucket -> octets`), pour les
  graphiques temporels top-N (voir `netcross_report.charts` et
  `netcross_report.pdf` plus bas). 4 dimensions (`TOPN_DIMENSIONS`) :
  `protocol` (`pk.proto`), `port` (`PROTO/port`, port de **destination**
  uniquement), `ip` (IP de **destination** uniquement), `dscp` (`DSCP N`,
  `0` distingué explicitement de `non marque` — piège classique de
  tester `if pk.dscp` au lieu de `is not None`, `0`/best-effort étant une
  valeur légitime). Le choix "destination uniquement" pour `port`/`ip`
  (plutôt qu'une paire source/destination) garantit que la somme des
  catégories d'un point égale exactement son débit total, sans double
  comptage — propriété vérifiée par test
  (`test_topn_series_somme_des_categories_egale_le_debit_total_du_point`).
  Le classement top-N (et l'agrégat `"autres"` pour le reste) est calculé
  **indépendamment par point** : deux points peuvent avoir des catégories
  dominantes différentes, un classement global aurait fait disparaître
  la catégorie dominante d'un point minoritaire en volume.

### `netcross_core.analysis` — cœur analytique

- ✅ **Nouveau (Session 20)** : `analyse()` accepte un paramètre `topn=5`
  et peuple `Report.topn_timeseries` (`{"protocol": {...}, "port": {...},
  "ip": {...}, "dscp": {...}}`, un appel à `compute_topn_series` par
  dimension) juste après `r.throughput`. Toujours calculé (coût
  négligeable, même passe que les autres compteurs), même sans
  `--pdf-report` — cohérent avec `r.throughput` qui est lui aussi
  toujours calculé.
- ✅ Déduction automatique de topologie (delta TTL + Jaccard), y compris
  branchements/convergences/chemins isolés, sans `--order`
- ✅ Pertes par segment (avec exclusion des segments à faible couverture)
- ✅ Latence/gigue + décalage d'horloge estimé (formule NTP via handshake TCP)
- ✅ Sauts de routeur, instabilité de route (TTL variable intra-flux)
- ✅ QoS (DSCP) corrélé au TTL pour distinguer remarquage L2/L3, PCP 802.1p
- ✅ Fragmentation/MTU corrélée aux changements d'encapsulation
- ✅ **Nouveau** : détection de noir PMTUD (RFC 1191) — segment TCP `DF`
  actif, de taille significative (≥ 512 octets), retransmis plusieurs
  fois au point amont d'un segment réseau sans jamais atteindre le point
  aval, et sans aucun ICMP *Fragmentation Needed* observé au point amont
  sur toute la capture (`_analyse_pmtud`, `Report.pmtud_blackhole`/
  `pmtud_blackhole_examples`). Ancienne piste d'évolution priorité #1
  toujours ouverte (voir section 5.2), désormais faite. Automatique,
  sans nouveau flag CLI ; constat "PMTUD" (anomalie) dans
  `synthesis.build_findings`, section console dédiée, comparaison
  avant/après dans `baseline_diff` — parité GUI/PDF gratuite via le
  mécanisme générique existant (stdout redirigé + `Finding` générique).
  Limite assumée : rapprochement ICMP sur la capture entière au point
  amont, pas une fenêtre temporelle précise autour du segment (nécessite
  de décoder le paquet IP embarqué dans la charge utile ICMP pour un
  appariement par flux exact) ; IPv4 uniquement.
- ✅ Saturation/policing vs pertes non corrélées au débit ; indice de
  bufferbloat
- ✅ TCP avancé : fenêtre à zéro, ACK dupliqués, RST (dont détection
  d'injection locale), SYN sans réponse, SYN-ACK ne remontant pas
- ✅ **Nouveau** : classification des retransmissions TCP par cause
  probable (`_analyse_retransmission_types`, `Report.retrans_fast`/
  `retrans_rto`/`retrans_spurious`), en lisant directement la
  classification native de tshark (voir `pcap_parser` ci-dessus) plutôt
  que de réimplémenter une heuristique — le moteur d'état TCP complet de
  tshark (ACK dupliqués récents, fenêtre, ACK déjà vu en sens inverse...)
  fait déjà ce travail mieux que ce que ce projet pourrait reproduire
  simplement. Trois compteurs par point : `retrans_fast` (réaction à 3
  ACK dupliqués, récupération normale, sévérité "info"), `retrans_rto`
  (expiration de minuteur, récupération lente, "a_surveiller"),
  `retrans_spurious` (donnée déjà acquittée, renvoi inutile,
  "a_surveiller"). Complémentaire de `Report.retrans` (l'ancien compteur
  "même flux vu plusieurs fois à ce point", conservé inchangé pour
  compatibilité avec l'existant — notamment `baseline_diff`). Limite
  assumée : cette classification est calculée par tshark indépendamment
  pour chaque fichier de capture (un point = un fichier = un processus
  tshark) ; la condition "fast retransmission" de Wireshark exige
  notamment d'avoir vu le dernier ACK il y a moins de 20ms, donc un point
  de capture éloigné de l'émetteur peut classer différemment une même
  retransmission réelle sur le fil qu'un point plus proche — comportement
  de tshark lui-même, pas une approximation ajoutée ici. Bonus par
  rapport à la piste d'origine (qui ne mentionnait que fast/RTO) : la 3ᵉ
  catégorie `spurious` a été ajoutée au passage, quasi gratuite une fois
  les deux premières câblées et diagnostiquement utile (signale souvent
  un minuteur de retransmission mal calibré par rapport au RTT réel, ou
  un chemin de retour ACK asymétrique).
- ✅ **Nouveau** : négociation des options TCP au handshake
  (`_analyse_tcp_options`, `Report.mss_clamped`/`mss_clamped_examples`/
  `wscale_stripped`/`sack_stripped`) — compare MSS/Window Scale/SACK
  Permitted entre points adjacents pour le même paquet SYN ou SYN-ACK
  (même schéma de corrélation que `_analyse_pmtud`/`_analyse_handshake` :
  même 5-tuple + même `seq`). Trois signaux : `mss_clamped` (la valeur
  MSS change en cours de route — le plus souvent une adaptation
  délibérée d'un équipement intermédiaire pour compenser un tunnel/VPN,
  protège généralement contre un noir PMTUD, sévérité "info") ;
  `wscale_stripped` (l'option Window Scale disparaît en aval — désactive
  le window scaling pour toute la connexion dès qu'un seul côté ne le
  propose pas, plafonne la fenêtre TCP effective à 65535 octets, limite
  de débit classique sur un lien à fort produit débit × latence,
  "a_surveiller") ; `sack_stripped` (même logique pour SACK Permitted —
  récupération de perte moins efficace, renvoi de fenêtre entière plutôt
  que des seuls segments manquants, lien thématique direct avec la
  classification des retransmissions ci-dessus, "a_surveiller").
  Nécessite une corrélation stricte par 5-tuple (désactivé en mode
  `--nat-tolerant`, même contrainte que `_analyse_handshake`).
- ✅ VLAN : changement d'ID, bascule tagué/untagué, PCP
- ✅ RTP/voix : perte (déroulement de séquence), gigue RFC 3550, délai
  bout-en-bout, MOS/R-factor (E-model simplifié G.711)
- ✅ Décomposition temps réseau vs temps de traitement serveur
- ✅ DHCP : suivi par xid, messages manquants entre points, durée
  DISCOVER→ACK, NAK
- ✅ SIP : suivi par Call-ID, messages manquants, durée d'établissement
  (INVITE→200), appels en échec (4xx/5xx/6xx)
- ✅ **Nouveau (Session 13)** : DNS — suivi par identifiant de
  transaction (`dns.id`), messages manquants entre points, requêtes
  sans réponse observée nulle part (timeout), réponses NXDOMAIN/SERVFAIL,
  durée moyenne query→réponse. Voir section 4 pour le détail complet.
- ✅ **Nouveau (Session 23)** : timeout d'inactivité / coupure NAT-FW
  silencieuse (`_analyse_idle_timeout`, `Report.idle_timeout_dropped`/
  `idle_timeout_examples`) — une connexion TCP (5-tuple, **pas** un
  segment individuel via `flows`, voir section 4 pour le piège
  d'architecture identifié et corrigé cette session) déjà établie des
  deux côtés d'un segment réseau, dont le plus grand silence entre deux
  paquets consécutifs au point amont dépasse `_IDLE_TIMEOUT_SECONDS`
  (60s par défaut, **exposée en CLI depuis la Session 37** via
  `--idle-timeout-seconds` sur les deux CLI — voir section 4 ; reste la
  valeur par défaut de `analyse()` si l'option n'est pas fournie), et
  dont le trafic repris en amont après ce
  silence n'est plus jamais revu au point aval. Scope volontairement
  limité à TCP (comme PMTUD/options TCP/classification retransmissions).
  Automatique, sans nouveau flag CLI ; finding dédié (catégorie
  "NAT/Pare-feu") dans `synthesis.build_findings`, section console
  dédiée, comparaison avant/après dans `baseline_diff`
  (`higher_is_worse=True`) — parité GUI/PDF/JSON gratuite via le
  mécanisme générique existant. Voir section 4 pour le détail complet
  (deux pièges trouvés et corrigés par les tests avant livraison).
- ✅ **Nouveau (Session 24)** : conflit d'adresse IP via ARP
  (`_analyse_arp_ip_conflict`, `Report.arp_ip_conflict`/
  `arp_ip_conflict_examples`) — deux adresses MAC différentes qui
  revendiquent la même adresse IP source **au même point de capture**
  (chaque paquet ARP, requête ou réponse, porte une revendication
  implicite "sender IP ↔ sender MAC" utilisable de la même façon).
  Granularité **par point** (pas par paire) — même famille que
  `retrans_fast`/`retrans_rto`/`retrans_spurious` ci-dessus, contrairement
  à la plupart des autres détecteurs de ce module. Automatique, sans
  nouveau flag CLI ; finding dédié (catégorie "ARP") dans `synthesis.
  build_findings`, section console dédiée, comparaison avant/après dans
  `baseline_diff` (`higher_is_worse=True`) — parité GUI/PDF/JSON gratuite
  via le mécanisme générique existant. Voir section 4 pour le détail
  complet, dont un piège de pollution des statistiques de perte/latence/
  topologie trouvé et corrigé côté `netcross_core.correlate` (ARP
  désormais exclu de `flows`, voir ci-dessus).
- ✅ **Nouveau (Session 25)** : instabilité STP
  (`_analyse_stp_instability`, `Report.stp_topology_change`,
  `Report.stp_root_change`/`stp_root_change_examples`) — deux compteurs
  indépendants, granularité **par point** (même famille qu'ARP
  ci-dessus) : (1) événements de changement de topologie (BPDU TCN OU
  Configuration BPDU avec bit TC actif, comptés séparément même si les
  deux signalent le même phénomène réseau) ; (2) réélections du pont
  racine (comparaison "racine précédente → racine actuelle" **triée
  explicitement par horodatage par point**, ne suppose pas que
  `all_packets` est globalement chronologique entre points — même
  discipline défensive que `_analyse_idle_timeout` en Session 23).
  Automatique, sans nouveau flag CLI ; deux findings dédiés (catégorie
  "STP") dans `synthesis.build_findings`, section console dédiée,
  comparaison avant/après dans `baseline_diff` — parité GUI/PDF/JSON
  gratuite via le mécanisme générique existant. Limite architecturale
  honnête : le "flapping de port" au sens strict (état d'un port de
  commutateur) n'est pas observable depuis une capture de trafic, seule
  sa conséquence visible sur le fil (tempête de topologie, réélections)
  l'est. Voir section 4 pour le détail complet.
- ✅ **Nouveau (Session 26)** : diagnostics du certificat TLS
  (`_analyse_tls_certificate`, `Report.tls_cert_invalid_dates`/
  `Report.tls_cert_mismatch`) — deux compteurs de granularités
  différentes : (1) dates de validité hors fenêtre **par point** (comme
  ARP/STP) ; (2) numéro de série qui diffère entre deux points pour la
  même connexion (5-tuple) **par paire** (comme `pmtud_blackhole`/
  `idle_timeout_dropped`) — signature possible d'une interception/
  substitution TLS en cours de chemin, le diagnostic qui exploite le
  mieux l'identité multi-points propre à cet outil. Comparaison des
  dates effectuée contre l'horodatage du PAQUET (pas l'heure actuelle) :
  une analyse à froid d'une capture ancienne reste correcte. Automatique,
  sans nouveau flag CLI ; deux findings dédiés (catégorie "TLS") dans
  `synthesis.build_findings`, section console dédiée, comparaison
  avant/après dans `baseline_diff` — parité GUI/PDF/JSON gratuite via le
  mécanisme générique existant. Voir section 4 pour le détail complet.

### `netcross_core.report_text` — sortie texte/CSV

- ✅ `print_report(r)` — rapport console complet
- ✅ `write_detail_csv(path, flows, points)` — détail par flux

### `netcross_core.baseline_diff` — comparaison avant/après

- ✅ `diff_reports(baseline, current)` — régressions/améliorations sur
  pertes, TCP, fragmentation, DHCP, DNS, QoS/VLAN, routage, saturation,
  RTP/MOS, topologie
- ✅ `print_diff_report`, `write_diff_csv`
- ✅ Câblé via `cross_capture_diff_cli.py`
- ✅ Export PDF dédié (`netcross_report.generate_diff_pdf`, `--pdf-report`
  sur `cross_capture_diff_cli.py`)
- ✅ **Accessible depuis la GUI GTK4** : case "Mode comparaison", deux
  panneaux de captures (baseline/courant), seuils pertes/latence
  réglables, export PDF et CSV dédiés — voir section 4 point 4

### `netcross_core.client_diff` — comparaison client vs client (**nouveau, Session 14**)

- ✅ `group_packets_by_client(all_packets, client_group)` — répartit une
  même capture par poste (IP source ou destination) selon un groupement
  explicite `{nom: {ip1, ip2, ...}}` (pas d'auto-détection : voir
  discussion de conception ci-dessous et section 4)
- ✅ `build_client_report(client, ips, packets, points_order, ...)` —
  un `Report` par client, en réutilisant `analyse()` telle quelle (même
  schéma que `baseline_diff`, qui appelle déjà `analyse()` deux fois)
- ✅ `compare_clients(all_packets, client_group, reference=None, ...)` —
  point d'entrée principal : construit un `ClientReport` par client
  (référence incluse) puis diffe chaque **autre** client contre la
  référence en réutilisant `diff_reports()` en mode N-way (aucun
  nouveau moteur de diff — même fonction, un troisième axe de
  comparaison orthogonal à "point A vs point B" et "avant vs après").
  Référence par défaut : le premier client du groupement fourni.
- ✅ `ClientSignature` — agrégation (`Counter`) de `dhcp_vendor_class`/
  `sip_user_agent` par client, déjà partiellement captés ailleurs dans
  le projet, aucune nouvelle extraction de paquet. Objectif : transformer
  un "client B diverge" en "client B diverge, et son vendor DHCP/
  User-Agent SIP diffère" (signal plus proche d'une version logicielle
  différente qu'un pur écart réseau). Le JA3/version TLS mentionné dans
  le document de conception source (`idées.md`) n'existe pas encore dans
  `tls_diagnostics.py` — non repris ici (pas de champ fantôme), à
  ajouter le jour où ce champ existera réellement.
- ✅ `print_client_comparison`, `write_client_diff_csv`
- ✅ Câblé sur `cross_capture_analyzer_cli.py` : `--client-group
  NOM=IP1[,IP2,...]` (répétable, ≥ 2 requis), `--client-reference NOM`,
  `--client-diff-csv CHEMIN`. **Additif** à l'analyse principale (le
  `Report` combiné habituel est toujours calculé et affiché en premier) —
  n'affecte pas `--triage`/`--tls`/`--quic`/`--pdf-report`/
  `--json-report`, qui restent calculés sur l'ensemble des captures sans
  distinction de client (voir "Non traité dans cette passe" ci-dessous).
- **Décision de conception assumée** : pas d'auto-détection de client
  par IP unique. Le document source (`idées.md` §2) mentionne "filtrer
  `all_packets` par IP" en alternative au groupe explicite, mais sans
  préciser quelle heuristique choisirait les IP "clients" par opposition
  aux IP "serveurs" présentes dans la même capture — une IP unique
  choisie automatiquement produirait un client par IP source vue,
  serveurs compris, ce qui n'a pas de sens pour cet axe de comparaison.
  Le groupement explicite (`--client-group`) reste donc le seul mode
  supporté ; une auto-détection resterait à concevoir spécifiquement si
  le besoin se confirme (heuristique à documenter, pas un choix par
  défaut risqué).
- **Un paquet peut compter pour plusieurs clients** si du trafic direct
  existe entre deux postes tous deux dans le périmètre de comparaison
  (consequence assumée, documentée dans le docstring de
  `group_packets_by_client` — rare en pratique, l'usage visé est
  client → serveur).
- Validation : 14 nouveaux tests (`tests/test_client_diff.py`,
  325/325 au total), et — **premier rejeu de bout en bout contre un
  vrai `tshark` (4.2.2) et de vrais pcap scapy pour une fonctionnalité
  de ce projet depuis la Session 11** (accès réseau disponible cette
  session, comme les Sessions 9/10/11 mais contrairement aux Sessions
  1-8/12/13) : deux pcap scapy (PosteA vu aux 2 points, PosteB vu
  seulement au premier) rejoués via le vrai CLI
  (`cross_capture_analyzer_cli.py --client-group ... --client-diff-csv`)
  — régression "taux de pertes 0% -> 100%" correctement détectée et
  isolée sur PosteB, CSV relu et vérifié colonne par colonne. `ruff
  check`/`ruff format --check`/`lint-imports`/`pre-commit run
  --all-files` tous réellement exécutés et verts (pas de simulation
  manuelle cette fois, `pytest`/`ruff`/`tshark` tous installables dans
  cette session).

### `netcross_core.tls_diagnostics` — TLS (pipeline indépendant, via `pcap_parser`)

- ✅ Câblé via `--tls` sur `cross_capture_analyzer_cli.py`
- ✅ **Câblé aussi via `--tls` sur `cross_capture_diff_cli.py` (Session 8)** :
  exécuté séparément sur le baseline et sur le run courant (`parse_tls_capture`
  + `build_handshake_status` + `diagnose_tls` appelés deux fois, une fois par
  scénario) — ce module ne connaît qu'un état à un instant donné, pas de vraie
  diff sémantique possible entre les deux, donc affichés l'un après l'autre
  (console : bannières `-- TLS : BASELINE --`/`-- TLS : COURANT --` ; PDF :
  sous-sections dédiées dans `generate_diff_pdf`, voir plus bas)
- Capacités : ClientHello (SNI, version proposée), ServerHello (version
  négociée, cipher), Alerts (niveau + description IANA), détection du
  segment où un handshake qui aboutissait se met à échouer
- Limites assumées : pas de réassemblage TCP inter-segments, pas de
  décapsulation de tunnel, pas de QUIC, pas de chaîne de certificats
- ✅ **Câblé dans la GUI GTK4** (case "Diagnostic TLS", mode analyse
  simple sur fichiers uniquement — indisponible en capture live, ce
  diagnostic doit relire les fichiers passés en entrée). ✅ **Intégré au
  rapport PDF (Session 5)** : section dédiée dans `generate_pdf` (GUI et
  CLI) en plus d'être désormais mêlé au triage "par où commencer" en
  tête de rapport (voir `netcross_report.triage`, conçu pour un mélange
  `Finding`/`TlsFinding`).
- **scapy éliminé** (voir section 5) : relit désormais les captures via
  `pcap_parser.parse_capture()` (donc via tshark, comme le reste de
  l'outil) au lieu de `scapy.rdpcap()`. Plus aucun import scapy dans le
  projet, plus de fallback ni de message "nécessite scapy" nulle part.

### `netcross_core.quic_diagnostics` — QUIC/HTTP3 (pipeline indépendant, via `pcap_parser`)

- ✅ Câblé via `--quic` sur `cross_capture_analyzer_cli.py`
- ✅ **Câblé aussi via `--quic` sur `cross_capture_diff_cli.py` (Session 8)** :
  même principe que `--tls` ci-dessus, exécuté séparément sur baseline et
  courant et affiché côte à côte, pas de diff sémantique entre les deux
- Capacités : détection paquet Initial QUIC v1, dérivation des clés de
  protection initiale (HKDF, validé contre RFC 9001 Annexe A.2), levée de
  la protection d'en-tête, déchiffrement AEAD, extraction du SNI via le
  ClientHello transporté en frame CRYPTO ; comparaison multi-points par DCID
- Limites assumées : v1 uniquement, pas de 0-RTT/1-RTT (clés non
  publiques), pas de réassemblage CRYPTO multi-paquets
- ✅ Même constat que TLS : **câblé dans la GUI GTK4** (case "Diagnostic
  QUIC/HTTP3", mode analyse simple sur fichiers uniquement). ✅ **Intégré
  au rapport PDF (Session 5)**, même mécanisme que TLS ci-dessus.
- **scapy éliminé** (voir section 5) : relit désormais les captures via
  `pcap_parser.parse_capture()`. Dépendance restante propre à ce module :
  `cryptography` (HKDF/AES-GCM), gardée derrière un `try/except
  ImportError` explicite comme scapy l'était auparavant — mais ce garde
  n'est PAS un repli fonctionnel, juste un message d'erreur clair si le
  paquet manque ; import corrigé au passage (il n'était auparavant pas
  protégé du tout, un défaut préexistant repéré pendant ce nettoyage).

### `netcross_report.synthesis` — constats automatiques

- ✅ `build_findings(r)` — règles à seuils explicites sur pertes,
  saturation/bufferbloat, routage, QoS, fragmentation, VLAN, TCP,
  RTP/MOS, réseau vs serveur, DHCP, SIP, DNS
- ✅ Câblé dans `generate_pdf`

### `netcross_report.triage` — priorisation par segment

- ✅ Exporté par `netcross_report/__init__.py`, câblé dans `--triage` sur
  `cross_capture_analyzer_cli.py`, et intégré en tête de `generate_pdf`
  ET `generate_diff_pdf` (section "Par où commencer", table des segments
  convergents)
- Fonctionne indifféremment sur `Finding` et `DiffFinding` (duck-typing) —
  utilisé pour les deux rapports PDF avec le même code
- ✅ `health_score(ranked)`/`health_label(score)`/`format_health_line(score)`
  (**nouveau, Session 18**) — score de santé synthétique 0-100 dérivé de
  `rank_segments()` (jamais un recalcul indépendant), décroissance
  exponentielle bornée. Câblé partout où `rank_segments` l'est déjà :
  console (deux CLI + GUI GTK4), JSON (`health_score`/`health_label`),
  PDF (badge coloré). Voir section 4 pour le détail complet de la
  conception et de la validation.

### `netcross_report.charts` — graphiques matplotlib

- ✅ Topologie (networkx, disposée par générations), débit, latence,
  pertes, synthèse par gravité — tous câblés dans `generate_pdf`
- ✅ `chart_severity_summary` généralisé (paramètre `scheme`) pour aussi
  couvrir le vocabulaire `DiffFinding` (regression/a_verifier/amelioration)
  — réutilisé par `generate_diff_pdf`
- ✅ **Nouveau (Session 20)** : `chart_topn_timeseries(r, point, dimension,
  path)` — aire empilée (`ax.stackplot`) du débit par catégorie au fil du
  temps, pour **un seul point et une seule dimension** par appel.
  `generate_topn_charts(r, tmpdir, point=None)` génère les 4 graphiques
  (protocole/port/IP/DSCP) pour un point donné (par défaut `r.points[0]`)
  et les intègre dans `generate_all_charts()` sous les clés
  `topn_protocol`/`topn_port`/`topn_ip`/`topn_dscp`. Décision de
  conception (documentée aussi en section 5.2) : **un seul point tracé
  par graphique**, jamais plusieurs points superposés sur la même aire
  empilée — un même paquet physique peut être vu à plusieurs points de
  capture, l'additionner sur un même graphique donnerait un volume
  artificiellement gonflé (même raison que `compute_throughput` reste
  par point plutôt que globalisé). Axe temporel exprimé en secondes
  **relatives au premier bucket** de la série (`x = (bucket -
  bucket_min) * bucket_seconds`), et non en timestamp Unix absolu — bug
  réel rencontré et corrigé pendant cette session (le premier jet
  utilisait `bucket * bucket_seconds` directement, ce qui affichait un
  axe en `+1.788e9` avec l'annotation scientifique de matplotlib,
  contredisant la légende "secondes depuis le début de la capture").
  Catégorie `"autres"` toujours tracée en dernier (en haut de l'aire
  empilée) et en gris, distincte de la palette qualitative utilisée pour
  les vraies catégories. Non couvert par `pytest` (rendu visuel — même
  limitation assumée que le reste de `charts.py`, voir section 5.2) :
  validé par génération réelle d'un PDF (vrai `tshark`/`editcap`, scénario
  HTTP avec perte réelle) puis conversion en image (`pdf2image`) pour
  inspection visuelle, y compris pour repérer le bug d'axe ci-dessus.

### `netcross_report.pdf` — rapport PDF

- ✅ `generate_pdf(r, output_path, title, meta, findings=None,
  tls_findings=None, quic_findings=None)` — page de garde, **triage**
  (mêlé aux findings TLS/QUIC si fournis), synthèse + graphique de
  gravité, vue d'ensemble graphique, détail par module, tableau RTP,
  DHCP, SIP, **section dédiée Diagnostics TLS/QUIC (Session 5)**
- ✅ **Nouveau (Session 20)** : section "Évolution temporelle (top-N)"
  après la "Vue d'ensemble", une sous-section par dimension disponible
  (protocole/port/IP/DSCP), absente du PDF si `r.topn_timeseries` est
  vide (aucun paquet) — voir `netcross_report.charts` ci-dessus pour le
  détail des graphiques et la décision "un seul point". Le nom du point
  tracé est rappelé dans le texte d'introduction de la section.
- ✅ `generate_diff_pdf(findings, baseline, current, output_path, title,
  meta)` — nouveau : page de garde, triage, synthèse + graphique de
  gravité (vocabulaire diff), table des écarts
- ✅ **TLS/QUIC intégrés (Session 5)** : câblé depuis
  `cross_capture_analyzer_cli.py` (`--tls`/`--quic` + `--pdf-report`) et
  depuis la GUI (`self.last_tls_findings`/`self.last_quic_findings`
  transmis à `_generate_pdf_thread`). Testé de bout en bout (findings
  TLS/QUIC synthétiques → PDF généré → relu avec `pypdf` → section et
  messages bien présents).
- ✅ **`generate_diff_pdf` : TLS/QUIC intégrés (Session 8)** — nouveaux
  paramètres optionnels `tls_findings_baseline`/`tls_findings_current`/
  `quic_findings_baseline`/`quic_findings_current`, câblés depuis
  `cross_capture_diff_cli.py` (`--tls`/`--quic`). Rendus dans une
  section dédiée "Diagnostics TLS / QUIC — baseline vs courant"
  (sous-sections Baseline/Courant l'une sous l'autre) — **volontairement
  PAS fondus** dans le triage/la table de constats principale du diff
  (vocabulaire de sévérité différent — anomalie/a_surveiller/info contre
  regression/a_verifier/amelioration — les mélanger aurait faussé le
  comptage du graphique `chart_severity_summary` sans apporter de vraie
  sémantique de diff en échange). Testé de bout en bout : paquets
  TLS/QUIC synthétiques injectés via `pcap_parser.parse_capture`
  monkeypatché (scénario baseline OK partout / run courant où le point
  WAN casse — alert TLS fatal + disparition du ClientHello QUIC), PDF de
  4 pages généré, relu avec `pypdf` **et converti en image (`pdf2image`)
  pour vérification visuelle** de la mise en page de la nouvelle section
  — voir `docs/sessions/session-08.md` pour le détail complet.

### `netcross_report.json_report` — export JSON structuré (**nouveau, Session 12**)

- ✅ `generate_json_report(r, output_path, title, meta, findings=None,
  tls_findings=None, quic_findings=None)` — pendant JSON de `generate_pdf`,
  câblé via `--json-report CHEMIN` sur `cross_capture_analyzer_cli.py`.
  Réutilise exactement le même calcul (`build_findings`/`rank_segments`)
  que le PDF, pour que les deux formats s'accordent toujours sur les
  mêmes constats/le même triage pour un même `Report`. Sortie :
  `title`, `generated_at` (ISO 8601), `points`, `pairs`, `meta` (reportée
  telle quelle), `findings` (liste plate `severity`/`category`/`segment`/
  `message`), `triage` (liste de segments classés — `segment`/`score`/
  `categories`/`convergent`/`finding_count`, le détail des findings du
  segment n'étant pas ré-imbriqué : déjà présent dans `findings` ci-dessus).
  `tls_findings`/`quic_findings` : présents uniquement si fournis, mêlés
  au triage comme dans `generate_pdf`, exposés en plus dans leur propre
  clé de premier niveau.
- ✅ `generate_json_diff(findings, baseline, current, output_path, title,
  meta, tls_findings_baseline=None, tls_findings_current=None,
  quic_findings_baseline=None, quic_findings_current=None)` — pendant de
  `generate_diff_pdf`, câblé via `--json-report CHEMIN` sur
  `cross_capture_diff_cli.py`. TLS/QUIC baseline/courant **volontairement
  pas fondus** dans `findings`/`triage` — même décision de conception que
  `generate_diff_pdf` (vocabulaire de sévérité différent, pas de vraie
  diff sémantique disponible pour ces deux modules, voir section
  `netcross_report.pdf` ci-dessus et `docs/sessions/session-08.md`).
- **Aucune dépendance externe** (contrairement à `generate_pdf`/
  `generate_diff_pdf` qui ont besoin de `reportlab`/`matplotlib`/
  `networkx`) : `json`/`datetime` sont dans la bibliothèque standard —
  toujours disponible, y compris dans un environnement minimal sans les
  paquets de rendu PDF installés. Exporté sans garde `try/except
  ImportError` dans `netcross_report/__init__.py`, contrairement à
  `generate_pdf`/`generate_diff_pdf`.
- ✅ **Câblé côté GUI en Session 37** (bouton "Exporter en JSON" dans
  `netcross_gtk4/app.py`, mode simple et mode comparaison, sélecteur de
  fichier `Gtk.FileDialog` comme pour CSV/PDF) — voir section 4 pour le
  détail complet et la validation réelle (smoke test GTK4).
- ✅ **Parité `generate_json_diff()` avec `generate_json_report()` en
  Session 37** : les 5 objets de contrat de la Session 0 (`flows`/
  `conversations`/`expert_events`/`diagnoses`/`compliance`, posés en
  Session 36 côté analyzer) sont désormais exposables aussi côté diff
  CLI, toujours calculés sur le rapport **courant** uniquement (même
  décision que `DiffFinding.evidence`, Session 33) — voir section 4.
- Validation : 7 nouveaux tests (`tests/test_json_report.py`, 287/287 au total), + rejeu
  bout en bout des deux vrais CLI (`--json-report`) sur des paquets
  synthétiques, JSON relu et vérifié structurellement (voir `docs/sessions/session-12.md` pour le détail complet).

### `netcross_core.redact` — anonymisation des adresses (**nouveau, Session 28**)

- ✅ `AddressRedactor` — état partagé (mapping adresse réelle → pseudonyme,
  compteurs par type) permettant d'anonymiser une ou plusieurs listes de
  paquets avec un mapping **cohérent** (même adresse réelle -> même
  pseudonyme partout). `.redact(packets)` mute les paquets **en place**
  (`Pkt` ou `RawPacket` indifféremment — aucun `isinstance`, uniquement
  de l'accès par attribut sur des champs que les deux dataclasses
  partagent). Réutilisable sur plusieurs appels successifs — nécessaire
  pour `cross_capture_diff_cli.py` (baseline + courant doivent partager
  le même mapping, sans quoi le diff perdrait son sens).
- ✅ Pseudonymes **format-préservants**, jamais routables : IPv4 → RFC
  5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, 762
  adresses, débordement documenté sur `240.0.0.0/4` au-delà — jamais
  atteint en pratique) ; IPv6 → RFC 3849 (`2001:db8::/32`) ; MAC → OUI
  localement administré (`02:00:00:xx:xx:xx`).
- ✅ Champs couverts : `src`/`dst` (avec le cas piège des paquets **STP**,
  où ces deux champs portent en réalité une adresse MAC Ethernet et non
  une IP — repéré en lisant `pcap_parser.packet.build_packet` avant
  d'écrire le module, sans quoi une capture STP aurait laissé fuiter des
  MAC réelles sous couvert d'adresses "traitées"), `arp_sender_mac`,
  la partie MAC de `stp_root_id` (`"prio/mac"`, priorité préservée telle
  quelle), `dhcp_server_id`.
- ⚠️ **Ne couvre que les adresses**, volontairement : `dns_qry_name`,
  `http_uri`, `tls_cert_san`, `sip_call_id`/`sip_user_agent`/`sip_server`
  restent inchangés (ce sont des noms, pas des adresses) — voir la
  docstring de module pour le détail et `README.md` section "Limites
  connues".
- ✅ `redact_packets(packets)` — raccourci un seul appel/une seule liste
  (crée un `AddressRedactor`, l'applique, le renvoie). `entries()` —
  tuples `(adresse_reelle, pseudonyme, type)` triés, pour l'export.
  `write_redaction_map_csv(redactor, chemin)` — écrit la correspondance
  dans un CSV **local** (colonnes `adresse_reelle,pseudonyme,type`) —
  à conserver en privé, jamais transmis avec le rapport/la capture
  redigée.
- ✅ Câblé sur les deux CLI : `--redact`/`--redact-map CHEMIN` sur
  `cross_capture_analyzer_cli.py` et `cross_capture_diff_cli.py`
  (mapping partagé baseline+courant sur ce dernier). Appliqué au tout
  début du pipeline (juste après le chargement des paquets, avant
  `correlate`/`analyse`) : le reste du pipeline (analyse, `report_text`,
  `synthesis`, `triage`, `pdf`, `charts`, `json_report`) n'a **aucune
  modification à connaître** de cette fonctionnalité — il ne voit que
  des `Pkt` déjà pseudonymisés. Câblage à coût quasi nul, dans le même
  esprit que la fusion de captures segmentées de la Session 27.
  `meta={"Anonymisation": ...}` ajouté automatiquement aux exports PDF/
  JSON existants quand `--redact` est actif (plomberie déjà présente,
  `meta` étant déjà un paramètre optionnel de `generate_pdf`/
  `generate_json_report`/`generate_diff_pdf`/`generate_json_diff`).
- ⚠️ **Refusé explicitement** en combinaison avec `--tls`/`--quic`
  (relisent les fichiers via leur propre pipeline, indépendamment de la
  liste de paquets anonymisée) et `--client-group` (reçoit des adresses
  IP réelles directement en argument, affichées telles quelles dans
  `print_client_comparison`) — combiner aurait laissé filtrer des
  adresses réelles dans une partie du rapport sans le signaler. Même
  discipline que le refus déjà existant de `--live` avec
  `--tls`/`--quic`/`--parallel`. Détail dans `docs/sessions/session-28.md`.
- ✅ **Câblé côté GUI en Session 37** (case "Anonymiser les adresses IP/MAC
  (--redact)" dans `netcross_gtk4/app.py`, disponible en mode simple et
  comparaison, mutuellement exclusive avec Diagnostic TLS/QUIC des deux
  modes — cases automatiquement désactivées/décochées si `--redact` est
  actif, même garde-fou revérifié à l'exécution) — voir section 4 pour
  le détail complet et la validation réelle (smoke test GTK4).
- Validation : 27 nouveaux tests (`tests/test_redact.py`, 581/581 au
  total : générateurs de pseudonymes purs et leurs bornes de
  débordement, classification IP/MAC, cas STP, cohérence croisée entre
  champs, réutilisation du redacteur sur deux appels, export CSV,
  compatibilité `RawPacket`), + rejeu bout en bout des deux vrais CLI
  sur des pcaps synthétiques (scapy → vrai `tshark` 4.2.2) : absence de
  fuite vérifiée par `grep` sur stdout/`--detail-csv`/`--json-report`,
  mention `Anonymisation` vérifiée en page de garde du PDF via
  `pdftotext`, mapping partagé baseline/courant vérifié sur le CLI diff,
  les 3 refus vérifiés (exit 1), non-régression vérifiée sans `--redact`
  (voir `docs/sessions/session-28.md`, pour le détail complet).

### `netcross_report.history` — historique inter-runs SQLite (**nouveau, Session 29 ; étendu en Session 30**)

- ✅ Nouveau composant de stockage (pas un simple câblage, comme
  identifié en section 5.2) : une table SQLite locale (`runs`, créée à
  la volée) enregistre un **résumé compact** de chaque exécution des
  deux CLI — score de santé, nombre de constats par sévérité, points
  impliqués, étiquette libre optionnelle — pour observer une **tendance
  dans le temps** sur des runs successifs (ex : contrôle hebdomadaire du
  même lien). `sqlite3` est dans la bibliothèque standard, comme
  `json`/`datetime` pour `json_report.py` : toujours disponible, aucune
  dépendance supplémentaire.
- ⚠️ **Ne remplace pas** `--json-report`/`--pdf-report`/`--detail-csv` :
  ne conserve **pas** le détail des constats eux-mêmes, seulement un
  résumé par run. Répond à une question différente ("est-ce que ça
  s'améliore ou ça se dégrade ?") plutôt que "que s'est-il passé
  exactement cette fois-ci ?".
- ✅ `record_run(r, db_path, ...)` — résumé d'un run d'analyse simple.
  `findings`/`tls_findings`/`quic_findings` intégrés au même triage que
  `--json-report` (même cohérence de score entre les sorties). Lazy
  comme le reste : `build_findings(r)` déclenché aussi par `--history-db`
  seul (sans `--triage`/`--pdf-report`/`--json-report`), pas seulement
  quand l'un des trois est déjà demandé.
- ✅ `record_diff_run(findings, baseline, current, db_path, ...)` —
  pendant pour `cross_capture_diff_cli.py`. **Volontairement PAS** de
  paramètres `tls_findings_baseline/current`/`quic_findings_baseline/
  current`, contrairement à `record_run` : même asymétrie assumée
  qu'entre `generate_json_report` et `generate_json_diff` (TLS/QUIC ne
  connaissent qu'un état à un instant donné sur un diff, ne participent
  déjà à aucun score/triage nulle part ailleurs pour un diff — pas de
  raison de les y intégrer ici).
- ✅ `list_history(db_path, limit=None, label=None)` — lecture, plus
  récent d'abord (tri par id auto-incrémenté, pas par horodatage — robuste
  à une horloge système qui reculerait entre deux runs). Renvoie `[]`
  sans créer le fichier si `db_path` n'existe pas encore (évite un effet
  de bord surprenant sur une simple lecture). `print_history(entries)` —
  rendu console, même esprit que `triage.print_triage`.
- ✅ Câblé sur les deux CLI : `--history-db CHEMIN` (active
  l'enregistrement), `--history-label ÉTIQUETTE` (distingue plusieurs
  historiques dans un même fichier `.db` partagé — ex. plusieurs sites),
  `--history-show [N]` (affiche les N derniers runs après ce run, défaut
  10 ; filtré automatiquement sur `--history-label` si elle est fournie).
  `--history-label`/`--history-show` sans `--history-db` : refusés
  explicitement, même discipline que `--redact-map` sans `--redact`.
  Un même fichier `.db` peut mélanger runs `analyse` et `diff` (`run_type`
  distingue les deux). Compatible avec `--redact` (`meta.Anonymisation`
  reporté comme sur PDF/JSON) — aucune restriction de combinaison
  supplémentaire, contrairement à `--redact` + `--tls`/`--quic`/
  `--client-group`.
- Validation : 13 nouveaux tests (`tests/test_history.py`, 594/594 au
  total) : structure de base, cohérence du score avec un calcul
  indépendant via `triage.rank_segments`/`health_score`, intégration
  TLS/QUIC sur `record_run` et son absence volontaire sur
  `record_diff_run`, méta/étiquette reportées, ordre plus récent
  d'abord, filtre par étiquette, absence de fichier créé sur une lecture
  à vide, lecture brute via `sqlite3` (fichier réellement exploitable
  par un outil tiers). Rejeu bout en bout des deux vrais CLI (pcaps
  synthétiques scapy → vrai `tshark` 4.2.2, `--order` fourni pour que la
  corrélation de pertes s'active réellement) : plusieurs runs successifs
  accumulés dans une même base, mélange `analyse`/`diff`, filtre par
  étiquette vérifié, combinaison avec `--redact` vérifiée (méta présente
  dans la ligne SQLite), les 2 refus vérifiés (exit 1) sur les deux CLI
  (voir `docs/sessions/session-29.md`, pour le détail complet).
- ✅ **Session 30** : `list_history()` accepte désormais un filtre
  `run_type` (`"analyse"`/`"diff"`), combinable avec `label` (ET
  logique) — support de `cross_history_cli.py` (nouveau, voir section 1
  et ci-dessous), le CLI dédié à l'interrogation seule de l'historique
  sans relancer d'analyse (`--db`/`--label`/`--run-type`/`--limit`),
  piste laissée ouverte en Session 29. `--history-show` sur les deux CLI
  d'analyse n'expose volontairement pas ce filtre : inutile, chacun sait
  déjà de quel type est le run qu'il vient d'enregistrer.

### `cross_history_cli.py` — interrogation seule de l'historique (**nouveau, Session 30**)

- ✅ Point d'entrée dédié, indépendant de `--capture`/`--baseline`/
  `--current` (jamais requis ici, contrairement aux deux autres CLI) :
  `--db CHEMIN` (seul argument obligatoire), `--label ÉTIQUETTE`,
  `--run-type {analyse,diff}`, `--limit N`. Ne fait qu'appeler
  `netcross_report.history.list_history`/`print_history` — toute la
  logique vit déjà dans le module (Session 29), ce fichier ne fait que
  lire les arguments.
- ✅ Chemin `--db` inexistant : pas une erreur, affiche un historique
  vide (`list_history` ne crée jamais le fichier sur une simple
  lecture, voir `netcross_report.history`). `--limit` ≤ 0 refusé
  explicitement (message clair, exit 1). `--run-type` avec une valeur
  hors `{analyse, diff}` : refusé par `argparse` lui-même (`choices`).
- ✅ Aucun prérequis `tshark` : ce script ne lit jamais de capture,
  seulement une base `.db` déjà alimentée par les deux autres CLI.
- ✅ Câblage packaging complet : wrapper `netcross-history`
  (`build-deb/wrappers/`, `build-rpm/wrappers/netcross-history-wrapper`),
  ajouté à `debian/netcross.install`, `debian/control` (description),
  `netcross.spec` (`%install`/`%files`) et `build-rpm/build.sh` — même
  parité que `netcross`/`netcross-diff`/`netcross-gui`. Bit exécutable
  du script source oublié puis corrigé en cours de session (repéré en
  inspectant le contenu réel du `.deb` construit, pas en le supposant
  correct par analogie avec les deux autres CLI).
- Validation : 2 nouveaux tests sur le filtre `run_type` de
  `list_history` (seul, puis combiné avec `label`) dans
  `tests/test_history.py` — **596/596** au total. Le module CLI
  lui-même n'est pas couvert par `pytest`, même convention que
  `cross_capture_analyzer_cli.py`/`cross_capture_diff_cli.py` (voir
  section 5.2 et `tests/test_diff_cli_live.py`) : validé par un rejeu
  réel — base peuplée par 2 vrais runs `cross_capture_analyzer_cli.py`
  et 1 vrai run `cross_capture_diff_cli.py` (`--history-db` partagé,
  étiquettes différentes), puis interrogée avec toutes les combinaisons
  de filtres (`--label` seul, `--run-type` seul, combinés, `--limit`,
  base absente, `--limit 0`, `--run-type` invalide, `--db` manquant).
  **Paquet `.deb` réellement construit** (`dpkg-buildpackage`, disponible
  cette session) et son contenu inspecté (`dpkg-deb -c`) pour confirmer
  que `netcross-history` et `cross_history_cli.py` y figurent avec les
  bonnes permissions — `rpmbuild` indisponible dans cet environnement,
  `netcross.spec`/`build-rpm/build.sh` mis à jour par symétrie exacte
  avec le `.deb` mais non rejoués avec un vrai `rpmbuild` (voir
  `docs/sessions/session-30.md`).

### `netcross_gtk4.app` — interface graphique

- ✅ 3 pages (Configuration/Travail/Résultats), ajout de captures via
  sélecteur de fichiers, réordonnancement (haut/bas = ordre physique),
  réglages fenêtre temporelle + cadence RTP + mode NAT-tolérant, analyse
  en thread d'arrière-plan avec journal en direct, export PDF
- ✅ **Parité GUI/CLI (mode analyse simple) déjà atteinte au moment de
  lire ce document** — ce paragraphe corrige une divergence constatée
  entre ce fichier (qui affichait encore ce point comme non traité) et
  le code réel (déjà complet) avant le début de cette passe : mode
  `--parallel`, export CSV de détail, `--triage`, `--tls`/`--quic`, et
  déduction automatique de topologie (case "Déduire la topologie
  automatiquement", équivalent à ne pas passer `--order`) sont tous
  câblés et fonctionnels. Vérifié par lecture complète du fichier,
  `python -m compileall`, et vérification programmatique (import direct
  + `inspect.signature`) que chaque fonction appelée par `app.py` existe
  bien dans `netcross_core`/`netcross_report` avec la signature attendue
  — GTK4 lui-même n'étant pas disponible dans l'environnement où cette
  vérification a été faite, un test d'interface réel n'a pas pu être
  rejoué.
- ✅ **Mode comparaison baseline/courant** (équivalent de
  `cross_capture_diff_cli.py`) également déjà intégré : case à cocher
  dédiée, deux panneaux de captures (baseline/courant), seuils
  pertes/latence, export PDF et CSV dédiés.
- ✅ **Parité TLS/QUIC en mode comparaison — fait en Session 37** : le
  mode comparaison expose désormais ses propres cases (`self.
  diff_tls_check`/`self.diff_quic_check`, dans `diff_options_box`,
  distinctes de `tls_check`/`quic_check` du mode simple) — `tshark`
  relit séparément le baseline et le courant (comme le CLI de diff
  `--tls`/`--quic`), affiché en deux sections dans le journal/PDF/JSON.
  Voir section 4 pour le détail complet et la validation réelle (smoke
  test GTK4).
- ✅ **Capture en direct — fait dans cette passe** (seule brique
  réellement manquante trouvée après vérification du point ci-dessus,
  voir section 4 point 5) : case "Capture en direct", panneau dédié
  (nom/interface/filtre BPF par point), démarrage/arrêt manuel ou durée
  max, affichage incrémental (compteur de paquets par point dans le
  journal). Mode analyse simple uniquement (pas de comparaison) ;
  TLS/QUIC indisponibles dans ce mode (nécessitent un fichier à relire,
  qu'une capture live ne produit pas). Depuis Session 5, ce mode a un
  équivalent sur `cross_capture_analyzer_cli.py` (`--live`, même
  limitation TLS/QUIC/comparaison assumée côté CLI aussi).
- ✅ **Top N du triage réglable (Session 5)** : `Gtk.SpinButton` à côté
  de la case "Triage" (1 à 50, défaut 5, équivalent GUI de
  `--triage-top-n`), câblé sur le mode fichier et le mode live. Comblait
  la lacune mineure identifiée en Session 4.
- ✅ **Top-N des graphiques réglable — fait en Session 37** : `Gtk.
  SpinButton` dédié (`self.topn_spin`, 1 à 20, défaut 5, équivalent GUI
  de `--topn-charts`) à côté des cases TLS/QUIC en mode simple, câblé
  sur l'appel à `analyse()`. Comblait la lacune identifiée en Session 20
  (même principe que `--triage-top-n` en Session 5).

### CLIs

- ✅ **Nouveau (Job 35, issue #155)** : `cross_capture_analyzer_cli.py
  --split MODE:VALEUR [--split-output-dir REP]` (`time:60`, `count:10000`,
  `size:100M`) — mode utilitaire : découpe chaque fichier de `--capture`
  dans `REP/<NOM>/` (défaut `./captures_split`) puis s'arrête SANS lancer
  d'analyse, et indique la commande pour rejouer les segments comme un
  seul point via la syntaxe `NOM=seg1,seg2,...` ci-dessous. Tailles en
  unités DÉCIMALES (`100M` = `tcpdump -C 100` ; `MiB` refusé plutôt que lu
  en décimal). Les options d'analyse/rapport combinées à `--split` sont
  refusées plutôt qu'ignorées en silence ; un fichier en échec est
  rapporté et les suivants sont traités (code de sortie 1). Exclusif
  avec `--merge` (Job 34, l'opération inverse : fusionner plutôt que
  découper). Les erreurs d'outil (`editcap` absent ou en échec) suivent la
  convention de `merge_captures` : `TsharkNotFoundError` / `TsharkError`.
  Absent de `cross_capture_diff_cli.py` (hors périmètre de l'issue)
- ✅ **Nouveau (Session 27)** : `--capture`/`--baseline`/`--current`
  acceptent désormais `NOM=chemin1[,chemin2,...]` — plusieurs chemins
  séparés par des virgules pour un même point de capture rejouent une
  capture segmentée (rotation tcpdump/tshark, ex: `-C 100`) comme un
  seul point continu, sans fusion préalable (`mergecap` ou autre) :
  chaque chemin devient une entrée `(label, chemin)` distincte, lue
  séparément par `tshark` puis simplement concaténée dans
  `all_packets` — le mécanisme qui permet déjà de fournir plusieurs
  fois le même label existait implicitement (`captures` est une simple
  liste de tuples, jamais dédupliquée par label), cette session ne fait
  qu'exposer une syntaxe explicite dessus. Fonctionne aussi bien en mode
  séquentiel qu'avec `--parallel` (chaque segment devient son propre
  processus `tshark`, gain de parallélisme accru sur une capture très
  segmentée). Aucun tri par timestamp n'est effectué : les segments
  doivent être listés dans l'ordre chronologique — les quelques analyses
  qui ont besoin d'un ordre strict par point (STP, timeout d'inactivité)
  trient déjà explicitement en interne plutôt que de faire confiance à
  l'ordre de `all_packets`, voir `netcross_core.analysis`. Non applicable
  à `--live`/`--live-current` (pas de fichiers).
- ✅ **Nouveau (Job 34, issue #154)** : `cross_capture_analyzer_cli.py
  --merge SORTIE [--merge-dedup]` — fusionne tous les fichiers des
  `--capture` en un seul fichier ordonné par timestamp (voir
  `pcap_parser.capture.merge_captures`), puis s'arrête SANS lancer
  d'analyse ; les `NOM=` sont ignorés (une capture fusionnée n'a plus de
  notion de point). Refusé avec `--live` et avec les options
  d'analyse/de rapport (`--pdf-report`, `--json-report`, `--detail-csv`,
  `--history-db`, `--client-group`, `--redact`, `--triage`, `--tls`,
  `--quic`, `--parallel`) plutôt qu'ignoré en silence ; `--merge-dedup`
  exige `--merge`. Différent de `NOM=chemin1,chemin2` (Session 27) qui
  concatène à la lecture sans produire de fichier.
- ✅ `cross_capture_analyzer_cli.py` : `--capture`, `--order`,
  `--detail-csv`, `--nat-tolerant`, `--nat-window-ms`, `--bucket-ms`,
  `--rtp-clock-rate`, `--pdf-report`, `--parallel`, `--parallel-workers`,
  `--triage`, `--triage-top-n`, `--tls`, `--quic`,
  **`--live`, `--live-duration`** (Session 5 — mutuellement exclusifs
  avec `--capture`/`--parallel`/`--tls`/`--quic`, mêmes limitations
  assumées que la GUI), **`--json-report`** (nouveau, Session 12 — voir
  `netcross_report.json_report` ci-dessus), **`--client-group`,
  `--client-reference`, `--client-diff-csv`** (nouveau, Session 14 —
  additif, voir `netcross_core.client_diff` ci-dessus ; non exclusif
  avec `--live` contrairement à `--tls`/`--quic`, s'applique après
  l'obtention de `all_packets` quel que soit son origine fichier/live),
  **`--topn-charts`** (nouveau, Session 20 — nombre de catégories des
  graphiques temporels top-N dans `--pdf-report`, voir
  `netcross_core.correlate`/`netcross_report.charts` ci-dessus ; sans
  effet sans `--pdf-report`, mais toujours passé à `analyse()` qui
  calcule `r.topn_timeseries` dans tous les cas)
- ✅ `cross_capture_diff_cli.py` : `--baseline`, `--current`, `--order`,
  `--nat-tolerant`, `--bucket-ms`, `--rtp-clock-rate`, `--parallel`,
  `--loss-threshold-pp`, `--latency-threshold-ms`, `--diff-csv`,
  `--pdf-report`, code de sortie non nul si régression (exploitable en CI),
  **`--triage`/`--triage-top-n`, `--tls`, `--quic`** (Session 8 — voir
  section 4 point 13 pour le détail et la discussion du choix de
  conception TLS/QUIC), **`--json-report`** (nouveau, Session 12 —
  TLS/QUIC baseline/courant exposés séparément, même choix que le PDF
  de diff), **`--live-current`, `--live-duration`** (nouveau, Session 16
  — voir section 4 point 14 pour le détail et la décision de conception
  : seul le run **courant** peut être capturé en direct, le baseline
  reste toujours un ou plusieurs fichiers ; mutuellement exclusif avec
  `--current`/`--parallel`/`--tls`/`--quic`, mêmes limitations assumées
  que `--live` sur l'autre CLI)
- 🔍 **Réexaminé en Session 37, requalifié** : `cross_capture_diff_cli.py`
  n'a toujours pas de `--topn-charts`, mais l'examen du code réel
  (`netcross_report/pdf.py::generate_diff_pdf`) montre que ce n'est PAS
  une omission isolée — `generate_diff_pdf` exclut délibérément **TOUS**
  les graphiques propres à un `Report` (topologie, débit, latence,
  pertes, ET top-N), pas seulement top-N, par choix de conception
  documenté depuis l'origine du rapport PDF de diff ("pas de vue
  d'ensemble graphique... puisque c'est `baseline_diff` qui a déjà fait
  le travail de comparaison chiffré"). Ajouter *seulement* top-N aurait
  été incohérent avec ce choix plus large. Rouvrir cette piste
  supposerait de trancher une question de conception plus vaste (quels
  graphiques Report ajouter à un rapport de diff, superposés ou côte à
  côte) — hors périmètre d'un correctif ponctuel, candidat pour une
  session dédiée si le besoin se confirme (voir section 5.2, ligne
  "Graphiques temporels top-N").

---

## 3. Diagramme de classes complet

Le diagramme de classes n'est **plus maintenu ici** : il est devenu un fichier à part entière,
[`docs/class-diagram.md`](class-diagram.md), **généré depuis le code** (`src/`) par
`scripts/generate_class_diagram.py` et rafraîchi automatiquement par le hook pre-commit
`class-diagram` (voir `.pre-commit-config.yaml`) dès qu'un fichier `src/**/*.py` change
(issue #140).

L'ancienne version, écrite et régénérée à la main, dérivait de session en session (figée pendant 21
sessions, voir `docs/sessions/session-36.md`) ; la règle « la relire et la régénérer à chaque
session » n'a plus lieu d'être : `python3 scripts/generate_class_diagram.py --check` (et le test
`tests/test_class_diagram.py`) échouent si le fichier est en retard sur le code.

## 4. Dette identifiée / reste à faire

Classé par effort estimé (croissant), pour prioriser.

### 🔒 Suite PR #212 — Restes du rapport de sécurité (issues #216, #217, #218)

La PR #212 (merged) a clôturé l'issue #139 (CVE-5) : le rapport de sécurité
consolidé (`--security-report` / `--cve-db`) est câblé, testé sur de vrais PCAPs
tshark, et validé sans faux positif sur trafic légitime. Trois restes identifiés :

| Issue | Description | Difficulté |
|-------|-------------|------------|
| #216 | Documenter `--security-report` / `--cve-db` dans `CLAUDE.md` (README déjà fait par PR #214) | 1/5 |
| #217 | `close_db()` sans `try/finally` dans `cross_capture_analyzer_cli.py` | 1/5 |
| #218 | Rendu HTML/PDF du rapport de sécurité (sortie texte uniquement actuellement) | 3/5 |

### 🔒 Chantier CVE — détection passive de vulnérabilités (issue parente #133)

Le chantier CVE est en grande partie livré. Quatre des cinq sous-tâches sont
clos :

| Issue | Titre | Statut | Difficulté |
|-------|-------|--------|------------|
| #135 | CVE-1 — Extraction des bannières de versions (fingerprinting passif) | **Ouverte** — fondation pour #143 | 3/5 |
| #136 | CVE-2 — Détection de signatures d'exploits connus | Clos | — |
| #137 | CVE-3 — Exploitation des alertes Expert Info | Clos | — |
| #138 | CVE-4 — Base de données CVE locale et corrélation versions | Clos | — |
| #139 | CVE-5 — Rapport de vulnérabilités et tableau de bord sécurité | Clos (PR #212) | — |

Seule #135 (CVE-1) reste ouverte. Elle est la fondation pour #143 (JA4/HASSH).
Voir le tableau récapitulatif dans `docs/issues-summary.md` pour le plan
parallélisé complet.

### 🔒 Chantier flux cachés + scénarios (issue parente #141)

Détail dans `docs/issues-summary.md` (Track C → D → E). Issues ouvertes :

| Issue | Titre | Priorité | Difficulté |
|-------|-------|----------|------------|
| #142 | FLOW-1 — DPI léger (protocole sur port non standard) | P3 | 3/5 |
| #143 | FLOW-2 — Fingerprinting TLS (JA4) et SSH (HASSH) | P3 | 4/5 |
| #144 | FLOW-3 — Détection de tunneling DNS | P3 | 3/5 |
| #145 | FLOW-4 — Analyse statistique des flux (SPLT, entropie) | P3 | 4/5 |
| #146 | FLOW-5 — Module IA/ML optionnel | P4 | 5/5 |
| #147 | SCENARIO-1 — Beaconing C2 | P3 | 4/5 |
| #148 | SCENARIO-2 — Exfiltration de données | P3 | 3/5 |
| #149 | SCENARIO-3 — Mouvements latéraux | P3 | 4/5 |
| #150 | SCENARIO-4 — File carving | P4 | 4/5 |
| #151 | SCENARIO-5 — Cartographie passive des actifs | P3 | 3/5 |
| #152 | SCENARIO-6 — DGA et fast flux | P3 | 4/5 |
| #153 | SCENARIO-7 — Audit certificats TLS | P3 | 2/5 |

### 🔧 Gestion PCAP, sources de capture et qualité (Track A, B, F)

| Issue | Titre | Priorité | Difficulté |
|-------|-------|----------|------------|
| #155 | Job 35 — Découpage PCAP (split) | P1 | 2/5 |
| #156 | Job 36 — Export sous-ensemble PCAP | P1 | 2/5 |
| #158 | Job 38 — Métadonnées de capture (capinfos) | P1 | 1/5 |
| #161 | Job 41 — Doublons inter-captures | P1 | 3/5 |
| #163 | Job 43 — Validation des checksums | P2 | 2/5 |
| #164 | Job 44 — tcpreplay (rejeu) | P2 | 3/5 |
| #165 | Job 45 — Ajustement de timestamps | P1 | 2/5 |
| #166 | Job 46 — Capture distante (rpcap/sshdump) | P2 | 4/5 |
| #167 | Job 47 — Filtres BPF (sauvegarde/rechargement) | P2 | 2/5 |
| #168 | Job 48 — Multi-interfaces | P2 | 3/5 |
| #169 | Job 49 — Conversion de formats | P2 | 2/5 |
| #170 | Qualité app (CI/CD, Docker, coverage, SIEM...) | P3 | — |
| #209 | Job 50 — API REST + OpenAPI | P3 | 3/5 |

### 📋 Planifié — API REST FastAPI et spécification OpenAPI générée en CI (Job 50, issue #209)

- **Constat de départ** : Netcross s'utilise uniquement via la CLI
  (`cross_capture_analyzer_cli.py`) et l'interface GTK4. L'intégration
  externe s'arrête à `--json-report` (fichier écrit sur disque, jamais
  exposé en service) et à l'historique SQLite (`--history-db`).
- **Objectif** : exposer les analyses (chargement de captures,
  `analyse()`, rapport de sécurité) via un service REST documenté par
  une spécification OpenAPI tenue à jour automatiquement dans la CI —
  l'approche code-first (FastAPI déduit la spécification des annotations
  de types, elle ne peut pas diverger du code) plutôt que spec-first
  (OpenAPI Generator produit alors le serveur).
- **Contraintes d'architecture** (définies avec l'issue) :
  - nouvelle couche CONSOMMATRICE `netcross_api` au-dessus de
    `netcross_report` dans le contrat import-linter (`netcross_gtk4` →
    `netcross_api` → `netcross_report` → `netcross_core` → `pcap_parser`) :
    jamais de refactor du cœur, l'API appelle `parse_captures_parallel`/
    `correlate`/`analyse`/`apply_security_findings` tels quels ;
  - schémas de réponse pydantic DÉCOUPLÉS des modèles du cœur (mapping
    depuis `netcross_report.session_objects`) — le cœur reste sans
    dépendance web ;
  - `fastapi`/`uvicorn` en dépendance optionnelle (`[project.optional-
    dependencies] api`) — jamais obligatoire pour CLI/GUI ;
  - analyses asynchrones (`202 Accepted` + statut, le décodage tshark
    prend de secondes à minutes, jamais bloquant dans une requête).
- **Détail complet, tâches et référence CI** : issue #209.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (fusion de captures PCAP — Job 34, issue #154)

- **Constat de départ** : Netcross analysait des captures multi-points
  mais ne pouvait pas les fusionner en un seul fichier — l'analyste qui
  avait capturé à plusieurs endroits devait ouvrir chaque fichier
  séparément, ou passer par `mergecap` à la main (la Session 27 avait
  seulement rendu possible de *lire* plusieurs segments comme un point
  continu, sans jamais produire de fichier).
- **Livré** : `pcap_parser.capture.merge_captures(paths, output_path,
  dedup=False)`, réexportée par `pcap_parser` et `netcross_core` (import
  direct dans `netcross_core/__init__.py`, sans passer par l'adaptateur
  `parsing.py` — aucune notion de label ici), et `--merge`/`--merge-dedup`
  sur `cross_capture_analyzer_cli.py`.
- **Choix de conception** :
  - *Alignement temporel* : `mergecap` intercale par timestamp mais
    suppose chaque entrée déjà ordonnée — `reordercap` est donc passé
    systématiquement après, pour garantir l'ordre global (vérifié sur
    une entrée volontairement désordonnée). L'ordre des fichiers dans
    `paths` est sans effet.
  - *Déduplication* : `editcap -w 0` (fenêtre de temps nulle), et NON
    `editcap -d` — vérifié empiriquement : `-d` retire tout paquet de
    contenu identique parmi les 5 précédents quel que soit son
    timestamp, donc supprimerait de vraies retransmissions, exactement
    la donnée que l'analyse cherche (`test_fusion_dedup_conserve_une_
    retransmission_a_un_autre_instant` échoue avec `-d`). Limite
    assumée et documentée : une même trame vue à deux points de capture
    a des timestamps différents (horloges différentes) et n'est PAS
    dédupliquée — la déduplication vise un fichier fourni deux fois ou
    des segments qui se chevauchent sur la même horloge.
  - *Format de sortie* : pcap classique si le nom finit par `.pcap`
    (insensible à la casse), pcapng sinon (défaut de `mergecap`).
  - *Écriture atomique* : intermédiaires dans un répertoire temporaire
    du dossier de sortie, puis `os.replace` — un échec (outil absent,
    fichier corrompu) ne crée ni ne modifie la sortie et ne laisse
    aucun intermédiaire.
  - *Erreurs* : `ValueError` (liste vide, sortie == entrée),
    `FileNotFoundError` (entrée ou dossier de sortie absent),
    `TsharkNotFoundError`/`TsharkError` (mêmes types que le reste de
    `pcap_parser`) ; la CLI les convertit en message + code de sortie 1.
  - *CLI* : `--merge` ne lance aucune analyse (une capture fusionnée
    perd la notion de point) ; il est refusé avec `--live` et avec les
    options d'analyse/de rapport plutôt que de les ignorer en silence.
- **Validation** : `tests/test_merge_captures.py`, 35 tests — unitaires
  (outils simulés : séquence d'outils, arguments, format, erreurs,
  nettoyage) et d'intégration avec les vrais `mergecap`/`reordercap`/
  `editcap` (2 pcap fusionnés → 6 paquets, dédup → 5, ordre, formats
  mélangeables, fichier corrompu), ces derniers sautés si les outils
  sont absents du `PATH`. Trois mutations vérifiées détectées (retrait
  de `reordercap`, `-d` au lieu de `-w 0`, `mergecap -a`). `ruff`,
  `lint-imports` verts ; `mypy` : aucune erreur sur les fichiers
  modifiés. Échecs sans lien constatés sur `main` : `test_live_diff.py`
  (2) et `test_class_diagram.py` (3, `docs/class-diagram.md` absent).
- **Hors périmètre** : fenêtre de déduplication paramétrable (utile
  pour deux points partageant une horloge NTP à la milliseconde près) ;
  compte de paquets fusionnés/supprimés en retour de fonction ; câblage
  de la fusion à `cross_capture_diff_cli.py`/GTK4 ; mention dans le
  `README.md`.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (extension du moteur d'EXÉCUTION aux CINQ règles à corrélation, lot complet — Session 69)

- **Contexte** : à l'issue de la Session 68, `CLAUDE.md` « Prochaine
  feature » listait SEPT règles sans évaluateur — les CINQ à
  `correlation_rule` non `None` (jamais auditées) et DEUX règles sans
  corrélation déjà AUDITÉES par la Session 67 mais non pilotées faute
  de forme directement reproductible (`rtp_quality_mos`,
  `server_processing_dominant`). L'extension (a) la moins coûteuse
  nommée explicitement par « Prochaine feature » était d'auditer enfin
  les cinq règles à `correlation_rule` non `None`, jamais faites
  jusqu'ici.
- **Ce qui a été livré** : CINQ nouveaux évaluateurs d'un coup
  (`_EVALUATORS` passe de trente-quatre à **trente-neuf** entrées sur
  41) — `qos_dscp_remarking`, `fragmentation_new`, `saturation`,
  `bufferbloat`, `pmtud_blackhole`. Vérifiées bloc par bloc dans
  `synthesis.py`, `netcross_core/models.py` ET
  `netcross_core/analysis.py` avant rédaction (pas seulement les deux
  premiers comme les audits précédents — nécessaire pour trancher,
  règle par règle, si son ou ses seuils catalogue sont réellement
  consommés au point de construction du `Finding` ou déjà entièrement
  appliqués en amont). Contrairement à l'audit symétrique de la
  Session 67 (quatre candidats sur cinq exigeaient une forme nouvelle),
  les CINQ se révèlent ici directement reproductibles à partir de
  briques déjà en place :
  - `qos_dscp_remarking` et `pmtud_blackhole` reprennent une forme déjà
    pilotée (compteur par paire + sévérité UNIQUE lue depuis
    `rule.severity` ; `pmtud_blackhole` avec `evidence` à trois
    arguments, forme de `nat_fw_silent_drop`/`arp_ip_conflict`) ;
  - `bufferbloat` est la forme la PLUS SIMPLE rencontrée par ce pilote
    à ce jour : ses trois seuils catalogue sont déjà entièrement
    appliqués en amont par `_analyse_bufferbloat()`, donc AUCUNE garde
    dans la boucle — chaque entrée du dict produit un `Finding`, sans
    exception ;
  - `fragmentation_new` et `saturation` partagent le schéma à DEUX
    sévérités déjà introduit par `loss_per_segment` (Session 55), mais
    sont les PREMIÈRES règles de ce pilote à produire deux MESSAGES
    distincts (pas seulement une sévérité variable) selon la branche :
    `fragmentation_new` pilote réellement son seuil catalogue
    (`correlated_encap_change_min_count`, comme `loss_per_segment`),
    tandis que `saturation` décide sa branche par comparaison de
    SOUS-CHAÎNE sur un verdict déjà entièrement rédigé en amont par
    `_analyse_saturation()` (ses cinq seuils catalogue n'y sont donc
    pas consommés) — première fois que ce pilote lit un `dict` dont la
    valeur est une chaîne plutôt qu'un entier, une liste ou un tuple.
- **À l'issue de cette session** : les CINQ règles à `correlation_rule`
  non `None` sont TOUTES couvertes. Il ne reste plus que DEUX règles
  sans évaluateur, toutes deux déjà auditées par la Session 67 et
  confirmées de forme entièrement nouvelle : `rtp_quality_mos` (source
  liste de dicts, deux seuils, sévérité calculée dynamiquement) et
  `server_processing_dominant` (corrèle deux moyennes avec un ratio ET
  un seuil absolu).
- **Correction mineure, hors périmètre** : la docstring de la dataclass
  `Rule` (`expert_rules.py`) affirmait à tort que « quatre règles
  seulement » portent une valeur `correlation_rule` non `None` —
  toujours cinq depuis la Session 47 (PMTUD black hole), déjà vérifié
  par `test_catalogue_cinq_regles_seulement_ont_une_correlation`
  (`tests/test_expert_rules.py`) ; relevée en vérifiant ce champ avant
  rédaction, corrigée en « cinq ».
- **Validation** : `tests/test_rule_engine.py` : 25 nouveaux tests (5
  par règle en moyenne, adaptés à chaque forme — les DEUX branches de
  sévérité pour `fragmentation_new`/`saturation`, un test d'`evidence`
  dédié pour `pmtud_blackhole`, un test dédié aux compteurs compagnons
  pour `qos_dscp_remarking`, pas de test « nul » pour `bufferbloat`
  faute de garde), plus mise à jour de
  `test_available_rule_ids_ne_contient_que_les_regles_pilotees`
  (étendue aux cinq nouveaux ids) ; `test_regle_connue_sans_evaluateur_
  leve_not_implemented_error` passe de `saturation` (désormais pilotée)
  à `rtp_quality_mos`. `pytest` 1113/1113 → **1138/1138** (+25 net).
  `ruff check .` propre, `ruff format --check .` propre du premier
  coup. `PYTHONPATH=src lint-imports` : 66 fichiers inchangés, aucun
  nouvel import inter-packages (contrat de couches inchangé). `mypy`
  sur les trois fichiers modifiés (`rule_engine.py`, `expert_rules.py`,
  `test_rule_engine.py`) : 0 erreur imputable (27 erreurs
  préexistantes, même sous-ensemble de 7 fichiers, reproduites
  uniquement SANS `PYTHONPATH=src` — confirmé à nouveau) ; baseline
  `src/` entier re-décomptée par prudence malgré l'absence de
  modification des neuf fichiers concernés : inchangée (49 erreurs/9
  fichiers). Détail complet : `docs/sessions/session-69.md`.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (extension du moteur d'EXÉCUTION à une forme NOUVELLE, lot groupé — Session 68)

- **Contexte** : à l'issue de la Session 67, `CLAUDE.md` « Prochaine
  feature » listait NEUF règles sans évaluateur — les CINQ à
  `correlation_rule` non `None` (jamais auditées), et QUATRE règles
  sans corrélation déjà AUDITÉES par la Session 67 mais non pilotées
  faute de forme directement reproductible (`rtp_quality_mos`,
  `dns_slow_resolution`, `server_processing_dominant`,
  `http_slow_response`). L'extension (a) la moins coûteuse nommée
  explicitement par « Prochaine feature » était d'introduire la forme
  `statistics.mean()` sur liste plate — partagée par
  `dns_slow_resolution`/`http_slow_response`, seule paire de forme
  identique parmi les quatre.
- **Ce qui a été livré** : DEUX nouveaux évaluateurs (`_EVALUATORS`
  passe de trente-deux à **trente-quatre** entrées sur 41) —
  `dns_slow_resolution` et `http_slow_response`, PREMIÈRE forme
  ENTIÈREMENT NOUVELLE pour ce pilote depuis son ouverture Session 55 :
  les 32 évaluateurs précédents lisent tous un `dict` `Report.<compteur>`
  (par point ou par paire) ; ces deux-là lisent une LISTE BRUTE
  (`Report.dns_duration_ms`/`Report.http_response_time_ms`,
  `list[float]`), calculent une moyenne (`statistics.mean()`) comparée
  à `rule.thresholds["mean_duration_ms_min"]`, et produisent au plus UN
  seul `Finding` par `Report`, segment fixe `"global"` — aucune
  itération sur `report.points` ni sur un dict. Vérifiées bloc par bloc
  dans `synthesis.py` (blocs `-- DNS --`/`-- HTTP --`) ET
  `netcross_core/models.py` avant rédaction : garde `if report.<liste>:`
  reprise à l'identique (liste vide → aucune moyenne tentée,
  `statistics.mean([])` lèverait `StatisticsError`), comparaison
  stricte `avg > seuil` (200.0 pour DNS, 500.0 pour HTTP, tous deux lus
  depuis `rule.thresholds` plutôt que recopiés en dur — même discipline
  que `loss_per_segment`, seule autre règle à seuil pilotée à ce jour),
  `sample_size=len(<liste>)`. Forme confirmée IDENTIQUE entre les deux
  règles par l'audit de la Session 67, seules différences : le seuil
  chiffré et le domaine (`DNS` vs `HTTP`, lu depuis `rule.domain`).
  `import statistics` remonté en tête de module (import top-level,
  compatible `ruff`/import-linter) plutôt que l'import local à la
  fonction du bloc procédural source — seule différence délibérée, sans
  effet sur le comportement.
- **Choix du prochain candidat** : sept règles restent sans évaluateur —
  les CINQ à `correlation_rule` non `None` (`qos_dscp_remarking`,
  `fragmentation_new`, `saturation`, `bufferbloat`, `pmtud_blackhole`,
  toujours jamais auditées) et DEUX des quatre règles sans corrélation
  auditées par la Session 67 : `rtp_quality_mos` (forme nouvelle,
  source `r.rtp_streams` en liste de dicts, DEUX seuils, sévérité
  calculée dynamiquement — aucune brique commune avec ce lot) et
  `server_processing_dominant` (corrèle deux moyennes avec un ratio ET
  un seuil absolu, plus proche des cinq règles à `correlation_rule` non
  `None` que de la forme introduite ici).
- **Validation** : `tests/test_rule_engine.py` : 10 nouveaux tests (5
  par règle — déclenche au-dessus du seuil/silencieux au ou sous le
  seuil/liste vide/`sample_size`/équivalence ; PREMIÈRES règles de ce
  pilote sans test d'`evidence` dédié, le segment `"global"` n'étant
  associé à aucun point ni paire — vérifié `evidence == []` dans le
  test « déclenche » de chacune plutôt qu'omis silencieusement), plus
  mise à jour de `test_available_rule_ids_ne_contient_que_les_regles_
  pilotees` (étendue aux deux nouveaux ids) ; `test_regle_connue_sans_
  evaluateur_leve_not_implemented_error` reste sur `saturation` (rôle
  inchangé depuis la Session 63, ni `dns_slow_resolution` ni
  `http_slow_response` n'étant ce rôle). `pytest` 1103/1103 →
  **1113/1113** (+10 net). `ruff check .` propre, `ruff format --check .`
  propre du premier coup. `lint-imports` inchangé en fichiers (66),
  dépendances 169 → **170** (`import statistics`, ajout stdlib
  top-level du fichier modifié — aucun nouvel import inter-packages,
  contrat de couches inchangé). `mypy` sur les deux fichiers modifiés :
  0 erreur imputable (27 erreurs préexistantes, même sous-ensemble de 7
  fichiers, reproduites uniquement SANS `PYTHONPATH=src`) ; baseline
  `src/` entier non re-décomptée cette session (aucun des neuf fichiers
  concernés touché), reconfirmée inchangée par construction (49
  erreurs/9 fichiers). Détail complet : `docs/sessions/session-68.md`.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (extension du moteur d'EXÉCUTION à la quatrième règle sans corrélation auditée — Session 67)

- **Contexte** : à l'issue de la Session 66, `CLAUDE.md` « Prochaine
  feature » listait DIX règles sans évaluateur — les CINQ à
  `correlation_rule` non `None`, et CINQ règles sans corrélation
  jamais auditées (`rtp_quality_mos`, `dns_slow_resolution`,
  `nat_fw_silent_drop`, `server_processing_dominant`,
  `http_slow_response`), aucune n'étant a priori mieux connue qu'une
  autre.
- **Audit des cinq candidats** (bloc par bloc dans `synthesis.py` ET
  `netcross_core/models.py` avant toute rédaction) : `rtp_quality_mos`
  a pour source `r.rtp_streams`, une LISTE DE DICTS (jamais rencontrée
  par ce pilote), avec DEUX seuils et une sévérité calculée
  dynamiquement selon le seuil franchi (forme entièrement nouvelle) ;
  `dns_slow_resolution`/`http_slow_response` partagent une forme
  nouvelle mais IDENTIQUE entre elles (`statistics.mean()` sur une
  liste plate `Report`, seuil unique, segment fixe `"global"`,
  `sample_size=len(liste)`) ; `server_processing_dominant` corrèle
  deux moyennes (`Report.server_think_time` vs `Report.latency`,
  premier/dernier point) avec un ratio ET un seuil absolu combinés,
  plus proche des cinq règles à `correlation_rule` non `None` ;
  `nat_fw_silent_drop` (`Report.idle_timeout_dropped`,
  `dict[tuple[str, str], int]` PAR PAIRE, condition `n <= 0: continue`,
  `evidence` à TROIS arguments via `_evidence()`, sévérité UNIQUE)
  reproduit EXACTEMENT la forme déjà pilotée par `tcp_mss_clamped`
  (Session 59) — seul des cinq directement reproductible.
- **Ce qui a été livré** : UN nouvel évaluateur (`_EVALUATORS` passe de
  trente et une à **trente-deux** entrées sur 41) — `nat_fw_silent_drop`,
  copie du gabarit `tcp_mss_clamped`. **Point notable, troisième
  occurrence de ce constat** (après `arp_ip_conflict` Session 65,
  `stp_instability` Session 66) : le seuil `rule.thresholds[
  "idle_timeout_seconds"]` (60.0) déclaré au catalogue n'est PAS
  consommé par ce bloc — il documente un seuil déjà appliqué en amont,
  côté `analysis.py::_analyse_idle_timeout`, jamais relu par
  `synthesis.py`.
- **Choix du prochain candidat** : les QUATRE règles sans corrélation
  restantes sont désormais toutes AUDITÉES mais non pilotées, chacune
  pour une raison de forme documentée ci-dessus — `dns_slow_resolution`/
  `http_slow_response` sont les plus proches d'un futur pilotage
  groupé (forme nouvelle mais partagée). Les cinq règles à
  `correlation_rule` non `None` restent, elles, entièrement jamais
  auditées.
- **Validation** : `tests/test_rule_engine.py` : 5 nouveaux tests
  (déclenche/absent/nul/evidence/équivalence, même discipline que
  `tcp_mss_clamped`), plus mise à jour de
  `test_available_rule_ids_ne_contient_que_les_regles_pilotees`
  (étendue au nouvel id) ; `test_regle_connue_sans_evaluateur_leve_
  not_implemented_error` reste sur `saturation` (rôle inchangé depuis
  la Session 63, `nat_fw_silent_drop` n'étant pas ce rôle). `pytest`
  1098/1098 → **1103/1103** (+5 net). `ruff check .` propre, `ruff
  format --check .` propre du premier coup. `lint-imports` inchangé en
  fichiers (66) ET en dépendances (169 — aucun nouvel import, cet
  évaluateur ne consomme que `Report.idle_timeout_dropped`/
  `idle_timeout_examples`/`idle_timeout_frames`, déjà exposées).
  `mypy` sur les deux fichiers modifiés : 0 erreur imputable (27
  erreurs préexistantes, même sous-ensemble de 7 fichiers, reproduites
  uniquement SANS `PYTHONPATH=src`) ; baseline `src/` entier non
  re-décomptée cette session (aucun des neuf fichiers concernés
  touché), reconfirmée inchangée par construction (49 erreurs/9
  fichiers). Détail complet : `docs/sessions/session-67.md`.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (extension du moteur d'EXÉCUTION à la troisième règle jamais auditée — Session 66)

- **Contexte** : à l'issue de la Session 65, `CLAUDE.md` « Prochaine
  feature » listait ONZE règles sans évaluateur, toutes JAMAIS
  auditées bloc par bloc — cinq à `correlation_rule` non `None`, et six
  sans corrélation. `stp_instability` était nommée comme le candidat le
  mieux connu de ces six (survolée Sessions 64-65 en même temps que
  `vlan_change`/`arp_ip_conflict` : son entrée catalogue porte deux
  `Report.<champ>` distincts dans `required_metrics`, signe déjà repéré
  d'une fusion à deux compteurs).
- **Ce qui a été livré** : UN nouvel évaluateur (`_EVALUATORS` passe de
  trente à **trente et une** entrées sur 41) — `stp_instability`,
  confirmée QUATRIÈME règle de ce pilote à fusionner DEUX compteurs
  `Report` distincts sous un seul `rule_id` (après
  `tcp_options_stripped` — Session 59 —, `icmp_fragmentation_needed` —
  Session 60 — et `dhcp_issues` — Session 63). Vérifiée bloc par bloc
  dans `synthesis.py` (bloc `-- instabilité STP (Session 25) --`),
  `netcross_core/models.py` ET `expert_rules.py` avant rédaction :
  `Report.stp_topology_change` (`dict[str, int]` PAR POINT, condition
  `n <= 0: continue`, AUCUNE `evidence` — forme déjà pilotée par
  `icmp_fragmentation_needed`) et `Report.stp_root_change` (`dict[str,
  int]` également PAR POINT, même condition, mais `evidence` à TROIS
  arguments via `_evidence()` — forme déjà pilotée par
  `arp_ip_conflict`). **Nuance par rapport à `dhcp_issues`** (seule
  fusion précédente à compteurs de formes différentes) : ici les deux
  compteurs STP partagent la MÊME granularité (par point) et la MÊME
  condition de garde — seule la présence d'`evidence` diffère entre les
  deux boucles, aucune brique nouvelle n'a donc été nécessaire (les deux
  formes existaient déjà séparément dans ce pilote).
- **Choix du prochain candidat** : les cinq règles sans corrélation
  restantes (`rtp_quality_mos`, `dns_slow_resolution`,
  `nat_fw_silent_drop`, `server_processing_dominant`,
  `http_slow_response`) restent à auditer une par une, sans supposer de
  forme par ressemblance (enseignement des Sessions 64-65, confirmé par
  cette session). Les cinq règles à `correlation_rule` non `None`
  restent les plus éloignées de ce pilote.
- **Validation** : `tests/test_rule_engine.py` : 7 nouveaux tests
  (déclenche par compteur séparément/deux findings/absent/nuls/evidence/
  équivalence, même discipline que `dhcp_issues`), plus mise à jour de
  `test_available_rule_ids_ne_contient_que_les_regles_pilotees`
  (étendue au nouvel id) ; `test_regle_connue_sans_evaluateur_leve_
  not_implemented_error` reste sur `saturation` (rôle inchangé depuis
  la Session 63, `stp_instability` n'étant pas ce rôle). `pytest`
  1091/1091 → **1098/1098** (+7 net). `ruff check .` propre, `ruff
  format --check .` propre du premier coup. `lint-imports` inchangé en
  fichiers (66) ET en dépendances (169 — aucun nouvel import, cet
  évaluateur ne consomme que `Report.stp_topology_change`/
  `stp_root_change` et ses deux listes d'accompagnement, déjà
  exposées). `mypy` sur les deux fichiers modifiés : 0 erreur imputable
  (27 erreurs préexistantes, même sous-ensemble de 7 fichiers,
  reproduites uniquement SANS `PYTHONPATH=src`) ; baseline `src/` entier
  reconfirmée inchangée (49 erreurs/9 fichiers). Détail complet :
  `docs/sessions/session-66.md`.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (extension du moteur d'EXÉCUTION à la deuxième règle jamais auditée — Session 65)

- **Contexte** : à l'issue de la Session 64, `CLAUDE.md` « Prochaine
  feature » listait DOUZE règles sans évaluateur, toutes JAMAIS
  auditées bloc par bloc — cinq à `correlation_rule` non `None`, et
  sept sans corrélation. `arp_ip_conflict` et `stp_instability`
  avaient été survolées (pas auditées complètement) à la Session 64 en
  même temps que `vlan_change`.
- **Ce qui a été livré** : UN nouvel évaluateur (`_EVALUATORS` passe de
  vingt-neuf à **trente** entrées sur 41) — `arp_ip_conflict`, choisie
  parce que son entrée catalogue (`evidence` + seuil
  `min_distinct_macs`) la rapprochait déjà, avant lecture complète,
  d'un évaluateur existant (`tls_cert_invalid_dates`, Session 61)
  plutôt que de `vlan_change`. Vérifiée bloc par bloc dans
  `synthesis.py` (bloc `-- conflit d'adresse IP (ARP) --`),
  `netcross_core/models.py` ET
  `netcross_core/analysis.py::_analyse_arp_ip_conflict` avant
  rédaction : `Report.arp_ip_conflict` (`dict[str, int]` PAR POINT, PAS
  par paire — ARP n'est jamais relayé par un routeur) reproduit la même
  forme que `tls_cert_invalid_dates` — condition `n <= 0: continue`,
  `evidence` à TROIS arguments via `_evidence()`, sévérité UNIQUE lue
  depuis `rule.severity` (`anomalie`). **Découverte non anticipée** :
  le seuil `rule.thresholds["min_distinct_macs"]` (2.0) déclaré au
  catalogue n'est PAS consommé par ce bloc — il documente un seuil déjà
  appliqué en amont, côté `analysis.py` (`len(macs) < 2`), pas une
  comparaison que `synthesis.py`/l'évaluateur referaient eux-mêmes —
  première fois que ce pilote rencontre un seuil catalogue non
  consommé par son propre évaluateur, à la différence de
  `loss_per_segment` (Session 55) dont le bloc source lit bien son
  seuil ; documenté explicitement dans la docstring de fonction pour
  éviter qu'une session future généralise à tort la lecture
  systématique de `rule.thresholds`.
- **Choix du prochain candidat** : `stp_instability` reste le mieux
  connu parmi les six règles sans corrélation restantes (survolée en
  même temps qu'`arp_ip_conflict`, fusionne DEUX compteurs `Report` de
  formes différentes — plus proche de
  `dhcp_issues`/`icmp_fragmentation_needed`, décision de conception à
  trancher). Les cinq autres sans corrélation (`rtp_quality_mos`,
  `dns_slow_resolution`, `nat_fw_silent_drop`,
  `server_processing_dominant`, `http_slow_response`) restent à
  auditer une par une, sans supposer qu'un seuil catalogue soit
  systématiquement consommé par le bloc source (enseignement de cette
  session). Les cinq règles à `correlation_rule` non `None` restent les
  plus éloignées de ce pilote.
- **Validation** : `tests/test_rule_engine.py` : 5 nouveaux tests
  (déclenche/absent/nul/evidence/équivalence, même discipline que
  `tls_cert_invalid_dates`), plus mise à jour de
  `test_available_rule_ids_ne_contient_que_les_regles_pilotees`
  (étendue au nouvel id) ; `test_regle_connue_sans_evaluateur_leve_
  not_implemented_error` reste sur `saturation` (rôle inchangé depuis
  la Session 63, `arp_ip_conflict` n'étant pas ce rôle). `pytest`
  1086/1086 → **1091/1091** (+5 net). `ruff check .` propre, `ruff
  format --check .` propre du premier coup. `lint-imports` inchangé en
  fichiers (66) ET en dépendances (169 — aucun nouvel import). `mypy`
  sur les deux fichiers modifiés : 0 erreur imputable (27 erreurs
  préexistantes, même sous-ensemble de 7 fichiers, reproduites
  uniquement SANS `PYTHONPATH=src`) ; baseline `src/` entier
  reconfirmée inchangée (49 erreurs/9 fichiers). Détail complet :
  `docs/sessions/session-65.md`.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (extension du moteur d'EXÉCUTION à la première règle jamais auditée — Session 64)

- **Contexte** : à l'issue de la Session 63, `CLAUDE.md` « Prochaine
  feature » listait TREIZE règles sans évaluateur, toutes JAMAIS
  auditées bloc par bloc (contrairement aux lots précédents, qui
  partaient toujours d'un audit déjà fait) — cinq à `correlation_rule`
  non `None`, et huit sans corrélation portant pour la plupart un ou
  deux seuils dans `rule.thresholds`. L'audit devenait le coût
  dominant, pas l'écriture de l'évaluateur.
- **Ce qui a été livré** : UN nouvel évaluateur (`_EVALUATORS` passe de
  vingt-huit à **vingt-neuf** entrées sur 41) — `vlan_change`, choisie
  en priorité parmi les huit règles sans corrélation. Vérifiée bloc par
  bloc dans `synthesis.py` (bloc `-- VLAN --`) ET
  `netcross_core/models.py` avant rédaction, malgré l'absence
  apparente de seuil qui aurait pu la faire deviner simple sans
  lecture : `Report.vlan_change` (`dict[tuple[str, str], int]` PAR
  PAIRE de points adjacents) s'est révélée reproduire EXACTEMENT la
  forme déjà pilotée par `hop_delta_outliers` (Session 56) et
  `pcp_change` (Session 60) — condition `n > 0`, segment
  `f"{a} -> {b}"`, aucune `evidence`, aucun seuil dans
  `rule.thresholds` (dict vide, vérifié dans le catalogue), sévérité
  UNIQUE lue depuis `rule.severity` (`a_surveiller`). Aucune brique
  nouvelle nécessaire (ni fonction privée à copier, ni nouvelle forme
  de compteur) — c'est la règle la plus simple auditée à ce jour parmi
  les treize.
- **Choix du candidat** : les sept autres règles sans corrélation
  (`rtp_quality_mos`, `dns_slow_resolution`, `nat_fw_silent_drop`,
  `arp_ip_conflict`, `stp_instability`, `server_processing_dominant`,
  `http_slow_response`) portent pour la plupart un ou deux seuils dans
  `rule.thresholds` — plus proches de `loss_per_segment` (Session 55)
  que de `hop_delta_outliers`/`pcp_change` — et restent à auditer une
  par une avant toute rédaction. Les cinq règles à `correlation_rule`
  non `None` (`qos_dscp_remarking`, `fragmentation_new`, `saturation`,
  `bufferbloat`, `pmtud_blackhole`) fusionnent chacune deux signaux
  distincts, forme différente de tout évaluateur déjà écrit, et restent
  les plus éloignées de ce pilote.
- **Validation** : `tests/test_rule_engine.py` : 3 nouveaux tests
  (déclenche/silencieux/équivalence, même discipline que
  `hop_delta_outliers`/`pcp_change`), plus mise à jour de
  `test_available_rule_ids_ne_contient_que_les_regles_pilotees`
  (étendue au nouvel id) ; `test_regle_connue_sans_evaluateur_leve_
  not_implemented_error` reste sur `saturation` (rôle inchangé depuis
  la Session 63, `vlan_change` n'étant pas ce rôle). `pytest` 1083/1083
  → **1086/1086** (+3 net). `ruff check .` propre, `ruff format
  --check .` propre du premier coup. `lint-imports` inchangé en
  fichiers (66) ET en dépendances (169 — aucun nouvel import, cet
  évaluateur ne consomme que `Report.vlan_change` déjà exposé). `mypy`
  sur les deux fichiers modifiés : 0 erreur imputable (27 erreurs
  préexistantes visibles sur le même sous-ensemble de 7 fichiers
  atteint par le graphe d'import de `rule_engine.py`, reproduites
  uniquement SANS `PYTHONPATH=src` — même précision que la Session 63) ;
  baseline `src/` entier reconfirmée inchangée (49 erreurs/9 fichiers).
  Détail complet : `docs/sessions/session-64.md`.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (extension du moteur d'EXÉCUTION aux deux dernières règles auditées — Session 63)

- **Contexte** : à l'issue de la Session 62, `CLAUDE.md` « Prochaine
  feature » ne listait plus que DEUX candidats déjà audités bloc par
  bloc (audit Session 60, confirmé inchangé Sessions 61/62) —
  `dhcp_issues` et `sip_issues` —, écartés jusque-là parce qu'ils
  fusionnent sous un même `rule_id` des compteurs `Report` de formes
  DIFFÉRENTES entre eux (contrairement à `tcp_options_stripped`/
  `icmp_fragmentation_needed`, dont les compteurs fusionnés partagent la
  même forme). Leur coût réel était un **choix de conception** à
  trancher, pas une brique technique manquante : les deux formes que
  `dhcp_issues` fusionne sont chacune déjà pilotées ailleurs depuis les
  Sessions 56/57. Chaque bloc source re-vérifié dans `synthesis.py`,
  `netcross_core/models.py` ET `expert_rules.py` avant rédaction.
- **Ce qui a été livré** : DEUX nouveaux évaluateurs (`_EVALUATORS`
  passe de vingt-six à **vingt-huit** entrées sur 41), sans aucune
  brique nouvelle (`_evidence()` déjà copiée localement depuis la
  Session 57 suffit). `_evaluate_dhcp_issues` fusionne
  `Report.dhcp_nak_count` (`dict[str, int]` PAR POINT, `n > 0`, sans
  `evidence` — forme de `tcp_zero_window`) et `Report.dhcp_missing`
  (`dict[tuple[str, str], list[str]]` PAR PAIRE, `if missing:`,
  `evidence` à DEUX arguments — forme de `dns_missing` ; absence de
  `dhcp_missing_frames` sur `Report` vérifiée, volontaire côté source).
  `_evaluate_sip_issues` reprend cette dernière forme pour
  `Report.sip_missing` et introduit la **TROISIÈME forme de source de
  tout ce pilote**, jamais rencontrée en 26 règles :
  `Report.sip_failed_calls` est une `list[str]` de messages déjà
  formatés par `analysis.py::_analyse_sip()` — pas un `dict` compteur
  du tout —, un `Finding` par entrée via une compréhension, sur le
  segment littéral `"global"`, sans condition de garde (une liste vide
  ne produit rien par construction) ni `evidence` (choix commenté côté
  procédural : le message EST déjà la preuve — reproduit tel quel, ce
  pilote reproduit le chemin procédural, il ne l'améliore pas).
  Sévérité UNIQUE lue depuis `rule.severity` (`anomalie` pour les deux
  règles, sur TOUS leurs sites de construction), aucune des deux ne
  portant de seuil dans `rule.thresholds` (dict vide, vérifié).
- **Choix de conception tranché** (le seul restant, ouvert depuis la
  Session 60) : UN seul évaluateur par règle produisant les deux formes
  de `Finding`, plutôt que deux entrées `_EVALUATORS` distinctes.
  `_EVALUATORS` est clé par `Rule.id` et le catalogue ne porte qu'UNE
  `Rule` par id (vérifié par lecture directe des deux objets `Rule`,
  pas par grep) : scinder exigerait d'inventer un `rule_id` absent du
  catalogue, exactement ce que ce pilote s'interdit depuis la
  Session 55 — et côté procédural les deux boucles portent bien le même
  `rule_id`, qu'un test d'équivalence filtrant par `rule_id` ne pourrait
  de toute façon pas distinguer.
- **Découverte non anticipée** : le test d'équivalence de `sip_issues` a
  échoué au premier passage. Cause vérifiée dans le code (pas devinée) :
  `build_findings()` **trie** sa liste complète avant de la renvoyer
  (`findings.sort(key=(SEVERITY_ORDER, category, segment))`, dernière
  ligne), alors qu'`evaluate()` renvoie dans l'ordre de CONSTRUCTION.
  Pour les 26 règles précédentes les deux ordres coïncidaient **par
  hasard** (segments déjà triés, ou tous identiques — tri stable), ce
  qu'aucun test n'avait jamais explicité. `sip_issues` les sépare
  (`"global"` puis `"A -> B"`, que le tri inverse : `"A"` < `"g"`).
  Décision : `evaluate()` ne reproduit délibérément PAS ce tri — étape
  de PRÉSENTATION appliquée aux 41 règles à la fois, pas propriété
  d'une règle isolée. Le test d'équivalence compare donc par CONTENU
  (même clé de tri des deux côtés), un test dédié fige la divergence
  d'ordre, et la comparaison positionnelle restée possible pour
  `dhcp_issues` est annotée comme une coïncidence. À reprendre le jour
  où `build_findings()` basculera vers ce moteur : c'est ce tri final,
  et non les évaluateurs, qui devra rester le point unique
  d'ordonnancement.
- **Validation** : `tests/test_rule_engine.py` : 15 nouveaux tests (7
  pour `dhcp_issues`, 8 pour `sip_issues` — avec tests dédiés à CHAQUE
  compteur source séparément, même discipline que `tcp_options_stripped`/
  `icmp_fragmentation_needed`, plus le test d'ordre ci-dessus), plus
  mise à jour de `test_available_rule_ids_ne_contient_que_les_regles_
  pilotees` (étendue aux vingt-huit règles) et de
  `test_regle_connue_sans_evaluateur_leve_not_implemented_error`
  (`dhcp_issues` devenant pilotée, ce rôle passe à `saturation` — l'une
  des cinq règles à `correlation_rule` non `None`, donc le rôle le plus
  STABLE disponible, contrairement à ses deux titulaires précédents
  devenus pilotés dès la session suivante). `pytest` 1068/1068 →
  **1083/1083** (+15 net). `ruff check .` propre, `ruff format --check .`
  propre du premier coup sur le code et les tests (aucun reformatage,
  contrairement aux Sessions 58/59/62 ; seul `docs/sessions/session-63.md`
  a été reformaté — `ruff format` traite aussi les blocs Python inclus
  dans les fichiers Markdown, jamais relevé par une session précédente). `lint-imports` inchangé en fichiers (66) ET en
  dépendances (169 — aucun nouvel import). `mypy` sur les deux fichiers
  modifiés : 0 erreur imputable (27 erreurs préexistantes sur le même
  sous-ensemble de 7 fichiers que les sessions précédentes) ; baseline
  `src/` reconfirmée inchangée (49 erreurs, 9 fichiers, même
  répartition qu'à la Session 50). Précision méthodologique relevée au
  passage : le chiffre de 27 n'est reproductible que **sans**
  `PYTHONPATH=src` (avec, mypy renvoie `Success` sur ces deux fichiers)
  — les deux invocations s'accordent sur ce qui compte, l'écart est
  signalé pour que le chiffre reste reproductible.
- **Non traité dans cette passe** : avec ce lot, **plus aucun candidat
  audité ne reste en attente** — les 13 règles sans évaluateur sont
  toutes des règles JAMAIS auditées, dont les CINQ à `correlation_rule`
  non `None` (`saturation`, `bufferbloat`, `qos_dscp_remarking`,
  `fragmentation_new`, `pmtud_blackhole`). Câblage à un CLI ou au GTK4,
  bascule effective de `build_findings()` vers ce moteur (à laquelle
  s'ajoute désormais la question d'ordonnancement ci-dessus), nettoyage
  des 49 erreurs `mypy` préexistantes : toujours hors périmètre. Voir
  `docs/sessions/session-63.md` pour le détail complet.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (extension du moteur d'EXÉCUTION à deux règles supplémentaires — Session 62)

- **Contexte** : depuis la Session 60 (confirmée inchangée Session 61),
  CLAUDE.md « Prochaine feature » listait `http_client_error`/
  `http_server_error` comme les deux derniers candidats déjà confirmés
  de forme directement reproductible, écartés du lot de la Session 61
  parce qu'ils nécessitaient de copier une DEUXIÈME fonction privée de
  `synthesis.py` (`_http_error_evidence()`, filtrage des exemples par
  classe de statut HTTP), jamais fait jusque-là pour ce pilote (une
  seule fonction privée copiée jusqu'à la Session 61, `_evidence()`).
  Chacune re-vérifiée bloc par bloc dans `synthesis.py` ET
  `netcross_core/models.py` avant rédaction cette session.
- **Ce qui a été livré** : DEUX nouveaux évaluateurs (`_EVALUATORS`
  passe de vingt-quatre à vingt-six entrées) — `_evaluate_http_client_
  error` et `_evaluate_http_server_error` (`Report.http_client_error_
  count`/`Report.http_server_error_count`, `dict[str, int]` PAR POINT,
  condition `n > 0`), plus une copie locale de `_http_error_evidence()`
  (corps identique à l'original vérifié ligne à ligne) : les textes et
  frames passés à `_evidence()` sont d'abord filtrés par cette fonction
  depuis le champ PARTAGÉ `Report.http_error_examples`/`Report.
  http_error_frames` (mélange volontaire 4xx/5xx à la collecte côté
  `analysis.py`, distinction faite uniquement au filtrage sur le
  suffixe "-> NNN" de chaque exemple). Sévérité unique lue depuis
  `rule.severity` (`info` pour `http_client_error`, `anomalie` pour
  `http_server_error`), aucune des deux ne porte de seuil dans
  `rule.thresholds` (dict vide, vérifié dans le catalogue). Avec ce
  lot, le bloc source `-- HTTP --` de `synthesis.py` est ENTIÈREMENT
  pilotée (`http_client_error`, `http_server_error`, `http_timeout`,
  `http_missing` — les quatre règles qu'il contenait sont toutes
  couvertes), même complétude que `-- TCP avancé --` depuis la
  Session 59.
- **Validation** : `tests/test_rule_engine.py` : 10 nouveaux tests (5
  par règle — déclenchement, silence, compteur nul, `evidence` filtrée
  sur le champ partagé, équivalence avec `build_findings()`), plus mise
  à jour de `test_available_rule_ids_ne_contient_que_les_regles_
  pilotees` (étendue aux vingt-six règles) ; `test_regle_connue_sans_
  evaluateur_leve_not_implemented_error` utilisait déjà `dhcp_issues`
  comme exemple de « règle connue mais non pilotée » (toujours sans
  évaluateur), aucun changement nécessaire. `pytest` 1058/1058 →
  **1068/1068** (+10 net). `ruff check .` propre ; `ruff format .` a
  reformaté deux lignes d'appel à `_http_error_evidence()` dépassant
  120 caractères (repliées automatiquement, même type de reformatage
  occasionnel que les Sessions 58/59), `ruff format --check .` propre
  ensuite. `lint-imports` inchangé (66 fichiers, 169 dépendances —
  aucun nouvel import, ces deux évaluateurs ne consomment que des
  compteurs `Report` déjà exposés). `mypy` sur les deux fichiers
  modifiés : 0 erreur imputable (27 erreurs préexistantes visibles sur
  le même sous-ensemble de 7 fichiers que les sessions précédentes) ;
  baseline `src/` reconfirmée inchangée (49 erreurs, 9 fichiers).
- **Non traité dans cette passe** : `dhcp_issues`/`sip_issues` restent
  sans évaluateur (déjà audités bloc par bloc Session 60, formes
  hétérogènes fusionnées sous un même `rule_id`, `sip_issues` ajoutant
  une troisième forme jamais pilotée, une liste de chaînes déjà
  formatées) — voir CLAUDE.md « Prochaine feature » pour le détail
  complet. Au-delà, ~13 règles jamais auditées. Câblage à un CLI ou au
  GTK4, bascule effective de `build_findings()` vers ce moteur,
  nettoyage des 49 erreurs `mypy` préexistantes : toujours hors
  périmètre. Voir `docs/sessions/session-62.md` pour le détail complet.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (extension du moteur d'EXÉCUTION à six règles supplémentaires — Session 61)

- **Contexte** : depuis la Session 60, CLAUDE.md « Prochaine feature »
  listait SIX candidats déjà audités bloc par bloc et confirmés de
  forme directement reproductible avec les briques déjà en place
  (compteur PAR POINT ou PAR PAIRE, entier ou liste, `evidence` via
  `_evidence()` déjà copiée localement dans `rule_engine.py`). Chacun
  re-vérifié bloc par bloc dans `synthesis.py` ET
  `netcross_core/models.py` avant rédaction cette session (pas
  supposé reproductible par le seul fait d'avoir déjà été audité
  Session 60).
- **Ce qui a été livré** : SIX nouveaux évaluateurs (`_EVALUATORS`
  passe de dix-huit à vingt-quatre entrées) — `_evaluate_tls_cert_
  invalid_dates`, `_evaluate_tls_handshake_no_reply`,
  `_evaluate_tls_handshake_incomplete` (chacune `Report.<nom>`,
  `dict[str, int]` PAR POINT, même forme que `tcp_mss_clamped` —
  Session 59 —, compteur entier + `evidence` à trois arguments,
  sévérité unique `anomalie`), `_evaluate_tls_cert_mismatch`
  (`Report.tls_cert_mismatch`, `dict[tuple[str, str], int]` PAR PAIRE,
  même forme côté paire, sévérité unique `anomalie`),
  `_evaluate_http_timeout` (`Report.http_timeout`,
  `dict[str, list[str]]` PAR POINT — un compteur en LISTE, condition
  `if timeouts:` et non `n > 0`, même forme que `dns_timeout` —
  Session 57 —, sévérité unique `anomalie`) et `_evaluate_http_missing`
  (`Report.http_missing`, `dict[tuple[str, str], list[str]]` PAR PAIRE,
  condition `if missing:`, même forme que `dns_missing` — Session 57 —,
  y compris l'absence de troisième argument `frames` à `_evidence()`
  puisque `Report` n'expose pas de `http_missing_frames` — vérifié dans
  `models.py` —, sévérité unique `a_surveiller`, seule des six règles
  de ce lot à ne pas être `anomalie`).
- **Validation** : `tests/test_rule_engine.py` : 29 nouveaux tests (5
  par règle — déclenchement, silence, compteur nul ou liste vide,
  `evidence`, équivalence avec `build_findings()` — sauf
  `http_missing`, 4 tests, sans notion de compteur « nul » pour une
  liste), plus mise à jour de
  `test_available_rule_ids_ne_contient_que_les_regles_pilotees`
  (étendue aux vingt-quatre règles) ; `test_regle_connue_sans_
  evaluateur_leve_not_implemented_error` utilisait déjà `dhcp_issues`
  comme exemple de « règle connue mais non pilotée » (toujours sans
  évaluateur), aucun changement nécessaire. `pytest` 1029/1029 →
  **1058/1058** (+29 net). `ruff check .`/`ruff format --check .`
  propres du premier coup. `lint-imports` inchangé (66 fichiers, 169
  dépendances — aucun nouvel import, ces six évaluateurs ne
  consomment que des compteurs `Report` déjà exposés). `mypy` sur les
  deux fichiers modifiés : 0 erreur imputable (27 erreurs préexistantes
  visibles sur le même sous-ensemble de 7 fichiers atteint par le
  graphe d'import de `rule_engine.py` que les sessions précédentes) ;
  baseline `src/` reconfirmée inchangée (49 erreurs, 9 fichiers).
- **Non traité dans cette passe** : les QUATRE derniers candidats
  nommés depuis la Session 59 restent sans évaluateur (déjà audités
  bloc par bloc Session 60, forme plus éloignée) — `dhcp_issues`/
  `sip_issues` (compteurs de formes hétérogènes fusionnés sous un même
  `rule_id`, `sip_issues` ajoutant une troisième forme jamais pilotée,
  une liste de chaînes déjà formatées) et `http_client_error`/
  `http_server_error` (nécessitent de copier une deuxième fonction
  privée de `synthesis.py`, `_http_error_evidence()`) — voir CLAUDE.md
  « Prochaine feature » pour le détail complet. Câblage à un CLI ou au
  GTK4, bascule effective de `build_findings()` vers ce moteur,
  nettoyage des 49 erreurs `mypy` préexistantes : toujours hors
  périmètre. Voir `docs/sessions/session-61.md` pour le détail complet.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (extension du moteur d'EXÉCUTION à trois règles supplémentaires — Session 60)

- **Contexte** : depuis la Session 59, CLAUDE.md « Prochaine feature »
  listait TREIZE candidats « de forme simple mais NON vérifiés bloc par
  bloc » pour poursuivre l'extension de `_EVALUATORS`, le bloc source
  `-- TCP avance --` étant désormais entièrement pilotée. Les treize ont
  été audités un par un cette session dans `synthesis.py` ET
  `netcross_core/models.py` avant toute rédaction, comme demandé — pas
  supposés simples par ressemblance.
- **Ce qui a été livré** : TROIS nouveaux évaluateurs (`_EVALUATORS`
  passe de quinze à dix-huit entrées) — `_evaluate_ttl_variation`
  (`Report.ttl_unstable`, `dict[str, int]` PAR POINT, même forme que
  `tcp_zero_window` — Session 56 —, sévérité unique `a_surveiller`),
  `_evaluate_pcp_change` (`Report.pcp_change`, `dict[tuple[str, str],
  int]` PAR PAIRE, même forme que `hop_delta_outliers` — Session 56 —,
  sévérité unique `a_surveiller`) et `_evaluate_icmp_fragmentation_needed`
  (DEUXIÈME règle de ce pilote, après `tcp_options_stripped` — Session
  59 —, à fusionner DEUX compteurs `Report` distincts sous un seul
  `rule_id` : `Report.icmp_frag_needed` IPv4 et `Report.icmpv6_too_big`
  IPv6, tous deux `dict[str, int]` PAR POINT, une seule `Rule` du
  catalogue couvrant les deux, sévérité unique `info`, aucune
  `evidence` — plus simple que `tcp_options_stripped`, qui était clé
  par paire).
- **Validation** : `tests/test_rule_engine.py` : 11 nouveaux tests (3
  pour `ttl_variation` — déclenchement, silence, équivalence —, 3 pour
  `pcp_change` — même structure — et 5 pour `icmp_fragmentation_needed`
  — IPv4 seul, IPv6 seul, les deux ensemble, silence, équivalence),
  plus mise à jour de deux tests préexistants
  (`test_regle_connue_sans_evaluateur_leve_not_implemented_error`
  ciblait `ttl_variation`, désormais piloté — remplacé par
  `dhcp_issues`, toujours sans évaluateur ; liste
  `available_rule_ids` étendue aux dix-huit règles). `pytest`
  1018/1018 → **1029/1029** (+11 net). `ruff check .`/`ruff format
  --check .` propres du premier coup, aucun reformatage nécessaire
  (contrairement aux Sessions 58/59). `lint-imports` inchangé (66
  fichiers, 169 dépendances — aucun nouvel import, ces trois
  évaluateurs ne consomment que des compteurs `Report` déjà exposés).
  `mypy` sur les deux fichiers modifiés : 0 erreur imputable (27
  erreurs préexistantes visibles sur le sous-ensemble de 7 fichiers
  atteint par le graphe d'import de `rule_engine.py`, même
  sous-ensemble qu'aux Sessions 57/58) ; baseline `src/` reconfirmée
  inchangée (49 erreurs, 9 fichiers).
- **Non traité dans cette passe** : les DIX autres candidats nommés
  depuis la Session 59 restent sans évaluateur, mais sont désormais
  TOUS audités bloc par bloc (fait cette session, pas seulement
  repéré) : SIX confirmés de forme directement reproductible avec les
  briques déjà en place (`tls_cert_invalid_dates`, `tls_cert_mismatch`,
  `tls_handshake_no_reply`, `tls_handshake_incomplete` — même forme que
  `tcp_mss_clamped` —, `http_timeout` — même forme que `dns_timeout` —,
  `http_missing` — même forme que `dns_missing`) et QUATRE de forme
  plus éloignée (`dhcp_issues`/`sip_issues`, compteurs de formes
  hétérogènes fusionnés sous un même `rule_id` ; `http_client_error`/
  `http_server_error`, nécessitent de copier une deuxième fonction
  privée de `synthesis.py`, `_http_error_evidence()`) — voir CLAUDE.md
  « Prochaine feature » pour le détail complet. Câblage à un CLI ou au
  GTK4, bascule effective de `build_findings()` vers ce moteur,
  nettoyage des 49 erreurs `mypy` préexistantes : toujours hors
  périmètre. Voir `docs/sessions/session-60.md` pour le détail complet.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (extension du moteur d'EXÉCUTION aux deux dernières règles TCP — Session 59)

- **Demandes explicites re-vérifiées** : « passer sur `uv` pour
  remplacer `poetry` » et « corriger toutes les erreurs `ruff` »,
  redemandées telles quelles cette session. `grep -ril poetry .` (hors
  caches) ne remonte que des commentaires historiques (déjà présents
  avant cette session) documentant l'absence de `poetry` — aucune
  trace réelle, migration déjà effective depuis la Session 55, rien à
  refaire. `ruff check .`/`ruff format --check .` : 0 erreur avant
  tout nouveau code (inchangé depuis la Session 50). Vérification
  complémentaire, jamais faite avant : `ruff check --select ALL
  --statistics .` remonte 6495 signalements répartis sur ~63 règles
  hors du `select` configuré du projet (docstrings, en-tête de
  copyright, complexité cyclomatique, accès privé, etc.) — un ruleset
  bien plus large que celui choisi et documenté dans `pyproject.toml`
  ; ce ne sont pas des « erreurs ruff » au sens de la configuration
  actuelle du projet, et les activer serait un changement de politique
  de lint, pas une correction — hors périmètre de la demande, non
  traité.
- **Contexte** : depuis la Session 58, CLAUDE.md « Prochaine feature »
  nommait explicitement les deux derniers candidats du bloc source
  `-- TCP avance --` de `synthesis.py::build_findings()`, laissés de
  côté au tour précédent pour forme différente : `tcp_options_stripped`
  (fusionne deux compteurs `Report` distincts sous un seul `rule_id`)
  et `tcp_mss_clamped` (`evidence` non vide, clé par paire de points).
- **Ce qui a été livré** : DEUX nouveaux évaluateurs (`_EVALUATORS`
  passe de treize à quinze entrées, le bloc `-- TCP avance --` est
  désormais ENTIÈREMENT pilotée — ses huit règles sont toutes
  couvertes) — `_evaluate_tcp_options_stripped` (première règle de ce
  pilote à reproduire DEUX boucles sources consécutives partageant le
  même `rule_id`, sur `Report.wscale_stripped`/`sack_stripped`,
  sévérité unique `a_surveiller` pour les deux) et
  `_evaluate_tcp_mss_clamped` (`Report.mss_clamped`, clé par paire de
  points, `evidence` non vide via `_evidence()` — copie locale déjà en
  place depuis la Session 57 —, sévérité `info`).
- **Validation** : `tests/test_rule_engine.py` : 10 nouveaux tests (5
  pour `tcp_options_stripped` — wscale seul, sack seul, les deux
  ensemble, silence, équivalence — et 5 pour `tcp_mss_clamped` —
  déclenchement, silence, compteur nul, évidence, équivalence), plus
  correction de deux tests préexistants cassés par ce lot
  (`tcp_options_stripped` servait d'exemple de règle « connue mais non
  pilotée » — remplacé par `ttl_variation` ; liste `available_rule_ids`
  étendue). `pytest` 1008/1008 → **1018/1018** (+10 net). `ruff check
  .`/`ruff format --check .` propres après un reformatage mineur
  (ligne vide surnuméraire). `lint-imports` inchangé (66 fichiers, 169
  dépendances). `mypy` sur les deux fichiers modifiés : 0 erreur
  imputable ; baseline `src/` reconfirmée inchangée (49 erreurs, 9
  fichiers).
- **Outillage** : note ajoutée dans `CLAUDE.md` (section « Commandes
  qualité ») sur la disponibilité du connecteur MCP Context7 dans cet
  environnement, à interroger au besoin pour la documentation à jour
  de bibliothèques tierces — pas utilisé cette session, aucune tâche
  ne l'ayant rendu nécessaire (le pilote ne consomme que du code
  interne au projet).
- **Non traité dans cette passe** : les ~26 autres règles sans
  évaluateur — le bloc source qui guidait le choix depuis la Session
  56 est épuisé, aucun nouveau candidat nommément identifié ; quelques
  pistes de forme simple repérées mais NON vérifiées bloc par bloc
  (`ttl_variation`, `pcp_change`, `icmp_fragmentation_needed`,
  `dhcp_issues`, `sip_issues`, règles HTTP/TLS sans seuil ni
  corrélation) — voir CLAUDE.md « Prochaine feature ». Câblage à un
  CLI ou au GTK4, bascule effective de `build_findings()` vers ce
  moteur, nettoyage des 49 erreurs `mypy` préexistantes : toujours hors
  périmètre. Voir `docs/sessions/session-59.md` pour le détail complet.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (extension du moteur d'EXÉCUTION à six règles supplémentaires — Session 58)

- **Contexte** : depuis la Session 56, CLAUDE.md « Prochaine feature »
  demande de poursuivre l'extension de `_EVALUATORS` en auditant
  chaque candidat bloc par bloc dans `synthesis.py` plutôt que de
  supposer les ~31 règles restantes aussi directes que celles déjà
  pilotées. Le bloc `-- TCP avance --` de
  `synthesis.py::build_findings()` regroupe HUIT règles au total,
  toutes de forme « compteur `dict[str, int]` sur `Report`, itération
  directe (pas `report.points`), sévérité unique » — la même forme que
  `tcp_zero_window`, déjà pilotée depuis la Session 56. SIX d'entre
  elles sont retenues cette session ; les deux dernières
  (`tcp_options_stripped`, deux compteurs distincts fusionnés sous un
  seul `rule_id` ; `tcp_mss_clamped`, `evidence` non vide clée par
  paire) diffèrent de forme et restent hors périmètre.
- **Ce qui a été livré** : SIX nouveaux évaluateurs (`_EVALUATORS`
  passe de sept à treize entrées) — `tcp_retransmission_rto`
  (`Report.retrans_rto`, sévérité `a_surveiller`),
  `tcp_retransmission_spurious` (`Report.retrans_spurious`,
  `a_surveiller`), `tcp_retransmission_fast` (`Report.retrans_fast`,
  `info` — seule sévérité `info` du lot), `tcp_rst_localized`
  (`Report.rst_localized`, `anomalie`), `tcp_syn_no_synack`
  (`Report.syn_no_synack`, `anomalie`) et `syn_reply_missing`
  (`Report.syn_reply_missing`, `anomalie`). Chacun reproduit EXACTEMENT
  son bloc source dans `synthesis.py::build_findings()`, vérifié bloc
  par bloc avant rédaction (aucune des six ne porte de seuil dans
  `rule.thresholds` — dict vide, vérifié dans le catalogue), aucune
  `evidence`.
- **Validation** : `tests/test_rule_engine.py` : 18 nouveaux tests (3
  par règle — déclenchement avec sévérité du catalogue,
  silence/absence, équivalence avec `build_findings()` filtrée par
  `rule_id`), plus mise à jour du test
  `test_regle_connue_sans_evaluateur_leve_not_implemented_error` (ciblait
  `tcp_rst_localized`, désormais piloté — remplacé par
  `tcp_options_stripped`, toujours sans évaluateur) et de
  `test_available_rule_ids_ne_contient_que_les_regles_pilotees` (liste
  étendue aux treize règles). `pytest` 989/989 → **1008/1008** (+19
  net — 18 nouveaux tests, le remplacement de cible dans le test
  `NotImplementedError` ne change pas le compte). `ruff check .`/`ruff
  format --check .` propres (`ruff format .` a reformaté
  `tests/test_rule_engine.py`, une ligne vide surnuméraire en fin de
  fichier). `lint-imports` inchangé (66 fichiers, 169 dépendances —
  aucun nouveau module créé, aucun nouvel import ajouté : les six
  évaluateurs n'utilisent que `Rule`/`Report`/`Finding`, déjà importés
  par ce module). `mypy` sur les deux fichiers modifiés : 0 erreur
  imputable à `rule_engine.py` ; les erreurs préexistantes (Session 50)
  hors périmètre reconfirmées inchangées (sous-ensemble de 27 sur 7
  fichiers visible depuis le graphe d'import de `rule_engine.py`, qui
  n'atteint pas `tls_diagnostics.py`/`quic_diagnostics.py`).
- **Non traité dans cette passe** : les ~25 autres règles sans
  évaluateur, non auditées individuellement pour leur simplicité (même
  réserve documentée depuis la Session 56) — dont
  `tcp_options_stripped`/`tcp_mss_clamped`, écartées de ce lot pour
  forme différente (voir « Contexte » ci-dessus) ; câblage à un CLI ou
  au GTK4 ; bascule effective de `build_findings()` vers ce moteur
  (nécessiterait toujours de traiter d'abord les CINQ règles à
  `correlation_rule` non `None`). Voir CLAUDE.md « Prochaine feature »
  et `docs/sessions/session-58.md` pour le détail complet.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (extension du moteur d'EXÉCUTION à deux règles supplémentaires — Session 57)

- **Contexte** : la Session 56 avait identifié `dns_timeout`/
  `dns_missing` comme les « premiers candidats naturels » pour
  poursuivre l'extension du pilote (`netcross_report/rule_engine.py`),
  mais les avait écartés pour forme différente : leurs compteurs source
  (`Report.dns_timeout`, `dict[str, list[str]]` ; `Report.dns_missing`,
  `dict[tuple[str, str], list[str]]`) portent des LISTES, pas des
  entiers, et leur bloc procédural source passe par `_evidence()`
  (`synthesis.py`) pour construire un `Finding.evidence` non vide —
  jamais fait jusqu'ici par ce pilote.
- **Ce qui a été livré** : DEUX nouveaux évaluateurs (`_EVALUATORS`
  passe de cinq à sept entrées) — `dns_timeout` (par point, comme
  `dns_nxdomain`/`dns_servfail`) et `dns_missing` (par paire de points
  adjacents, comme `hop_delta_outliers`). Chacun reproduit EXACTEMENT
  son bloc source dans `synthesis.py::build_findings()`, `if
  timeouts`/`if missing` (troncation de liste) et `len(...)` dans le
  message plutôt qu'un entier comparé à 0. `_evidence()` est une
  fonction PRIVÉE de `synthesis.py` : copiée localement dans
  `rule_engine.py` (même discipline déjà appliquée à `_pct` depuis la
  Session 55 — jamais importée telle quelle à travers une frontière de
  module, corps vérifié ligne à ligne identique à l'original).
  `dns_timeout` porte en plus `frames` (`report.dns_timeout_frames`,
  liste parallèle produisant un `PacketEvidence` par preuve) ;
  `dns_missing` n'en porte PAS — vérifié dans `models.py` avant
  rédaction : aucun champ `dns_missing_frames` sur `Report`, absence
  volontaire côté source (le bloc procédural appelle `_evidence(seg,
  missing)` à deux arguments seulement), pas un oubli de ce pilote.
  Sévérité UNIQUE pour les deux règles (aucun seuil dans
  `rule.thresholds`), lue depuis `rule.severity` comme le lot de la
  Session 56.
- **Validation** : `tests/test_rule_engine.py` : 9 nouveaux tests
  (déclenchement avec sévérité du catalogue, silence si le compteur est
  absent ou porte une liste vide, contenu d'`evidence` — premières
  vérifications de ce champ pour ce pilote —, équivalence avec
  `build_findings()` incluant la comparaison de l'`evidence` terme à
  terme). `pytest` 980/980 → **989/989** (+9 net). `ruff
  check`/`ruff format --check` propres. `lint-imports` inchangé en
  nombre de fichiers (66), 169 dépendances (+1 : nouvel import
  `netcross_core.expert_model` dans `rule_engine.py` pour
  `EvidenceLink`/`PacketEvidence` — contrat de couches toujours
  respecté, import dans le sens autorisé `netcross_report ->
  netcross_core`). `mypy` sur les deux fichiers modifiés : 0 erreur
  imputable ; les erreurs préexistantes (Session 50, 49 sur 9 fichiers
  pour l'intégralité de `src/`) hors périmètre reconfirmées inchangées
  (sous-ensemble de 27 sur 7 fichiers visible depuis le graphe
  d'import de `rule_engine.py`, qui n'atteint pas
  `tls_diagnostics.py`/`quic_diagnostics.py`).
- **Non traité dans cette passe** : les ~31 autres règles sans
  évaluateur, non auditées individuellement pour leur simplicité (ne
  pas supposer qu'elles sont toutes aussi directes que les sept déjà
  pilotées — vérifier bloc par bloc dans `synthesis.py` avant d'en
  ajouter d'autres) ; câblage à un CLI ou au GTK4 ; bascule effective
  de `build_findings()` vers ce moteur (nécessiterait toujours de
  traiter d'abord les CINQ règles à `correlation_rule` non `None`).
  Voir CLAUDE.md « Prochaine feature » et `docs/sessions/session-57.md`
  pour le détail complet.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (extension du moteur d'EXÉCUTION à quatre règles supplémentaires — Session 56)

- **Contexte** : le premier pilote du moteur d'exécution
  (`netcross_report/rule_engine.py::evaluate()`) couvrait UNE seule
  règle depuis la Session 55 (`loss_per_segment`). CLAUDE.md
  « Prochaine feature » nommait explicitement trois candidats « à
  seuil unique simple, sans corrélation » pour l'étendre :
  `tcp_zero_window`, `hop_delta_outliers`, les compteurs DNS bruts.
- **Ce qui a été livré** : QUATRE nouveaux évaluateurs (`_EVALUATORS`
  passe de une à cinq entrées) — `tcp_zero_window`,
  `hop_delta_outliers`, `dns_nxdomain`, `dns_servfail`. Chacun
  reproduit EXACTEMENT son bloc source dans
  `synthesis.py::build_findings()`, vérifié bloc par bloc avant
  rédaction : les quatre itèrent directement
  `Report.<compteur>.items()`, contrairement à `loss_per_segment` qui
  itère `report.points`. Différence de conception assumée : aucune de
  ces quatre règles ne porte de seuil dans `rule.thresholds` (dict
  vide) — chaque évaluateur lit `rule.severity` directement plutôt que
  de recopier la sévérité en dur une seconde fois, la rendant PILOTÉE
  par le catalogue pour ce lot (égalité avec la constante procédurale
  vérifiée par le test d'équivalence de chaque règle). `hop_delta_outliers`
  est la seule des quatre clée par une paire de points adjacents
  (`(a, b)`) plutôt qu'un point seul ; le mode statistique qu'elle
  détecte est déjà précalculé en amont dans `Report.hop_delta_outliers`
  (`netcross_core.analysis`), donc pas plus complexe à reproduire ici.
- **Correction apportée cette session** : la note de la Session 55
  groupait « les compteurs DNS bruts » comme un candidat homogène
  unique. Vérifié dans `netcross_core/models.py` avant rédaction que ce
  n'est pas le cas : `dns_nxdomain_count`/`dns_servfail_count` sont de
  simples `dict[str, int]` (retenus dans ce lot), tandis que
  `dns_timeout` (`dict[str, list[str]]`) et `dns_missing`
  (`dict[tuple[str, str], list[str]]`) portent des LISTES et leur bloc
  procédural passe par `_evidence()` (synthesis.py) — forme différente,
  non retenue ici (voir Non traité ci-dessous).
- **Validation** : `tests/test_rule_engine.py` : 12 nouveaux tests (3
  par règle — déclenchement avec sévérité issue du catalogue, silence
  si le compteur est absent ou nul, équivalence avec
  `build_findings()`). L'équivalence est filtrée par `rule_id` et non
  par `category` cette fois : contrairement à « Pertes » (une seule
  règle dans toute la catégorie), les catégories TCP/DNS/Routage
  portent chacune plusieurs `rule_id` distincts — filtrer par seule
  catégorie aurait mélangé des `Finding` d'autres règles et faussé la
  comparaison. `pytest` 968/968 → **980/980** (+12 net). `ruff
  check`/`ruff format --check` propres. `lint-imports` inchangé (66
  fichiers, 168 dépendances — aucun nouveau module créé, contrat
  toujours respecté). `mypy` sur les deux fichiers modifiés : 0
  erreur ; les 49 erreurs préexistantes (Session 50) hors périmètre
  reconfirmées inchangées sur l'intégralité de `src/` (toujours 49/9).
- **Non traité dans cette passe** : `dns_timeout`/`dns_missing` (forme
  différente, nécessitent de reproduire `_evidence()` dans l'évaluateur
  — jamais fait jusqu'ici) ; les ~31 autres règles sans évaluateur, non
  auditées individuellement pour leur simplicité (ne pas supposer
  qu'elles sont toutes aussi directes que les cinq déjà pilotées) ;
  câblage à un CLI ou au GTK4 ; bascule effective de `build_findings()`
  vers ce moteur (nécessiterait toujours de traiter d'abord les CINQ
  règles à `correlation_rule` non `None`). Voir CLAUDE.md « Prochaine
  feature » et `docs/sessions/session-56.md` pour le détail complet.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (premier pilote du moteur d'EXÉCUTION de règles — Session 55)

- **Contexte** : la bibliothèque de règles déclarative (§6.2) est
  COMPLÈTE depuis la Session 54 (41 règles), mais `rule_id` se
  contentait jusqu'ici d'ANNOTER un `Finding` déjà construit par le
  code procédural (`synthesis.py::build_findings`) — jamais de moteur
  qui évaluerait une `Rule` du catalogue contre un `Report` pour
  PRODUIRE lui-même ce `Finding`. C'était l'un des deux chantiers
  laissés ouverts par la Session 54 (voir CLAUDE.md « Prochaine
  feature » à l'époque), retenu en Session 55 plutôt que la bascule
  vers la Session 3 (corrélation causale, difficulté 5/5, sans brique
  préalable).
- **Ce qui a été livré** : nouveau module
  `netcross_report/rule_engine.py`, fonction
  `evaluate(rule_id, report) -> list[Finding]`. Placé dans
  `netcross_report` et pas `netcross_core` : produire un `Finding`
  (type défini dans `netcross_report.synthesis`) depuis `netcross_core`
  violerait le contrat de couches ([tool.importlinter],
  `netcross_gtk4 -> netcross_report -> netcross_core -> pcap_parser`).
  Portée volontairement réduite à **une seule règle pilotée** :
  `loss_per_segment` (la plus simple du catalogue — un seul seuil
  numérique nommé dans `Rule.thresholds`, sans `correlation_rule`).
  Les 40 autres règles n'ont pas d'évaluateur enregistré :
  `evaluate()` lève `NotImplementedError` pour elles (distinct de
  `KeyError` pour un `rule_id` absent du catalogue). `build_findings()`
  reste inchangé et demeure l'unique chemin de production en CLI/GUI —
  ce module est un second consommateur indépendant du même `Report`,
  pas un remplacement.
- **Validation** : `tests/test_rule_engine.py` (9 tests), dont une
  vérification d'équivalence explicite avec `build_findings()` sur
  plusieurs points (mêmes `severity`/`category`/`segment`/`message`/
  `sample_size`/`rule_id`). `pytest` 959/959 → 968/968 (+9 net). `ruff
  check`/`ruff format --check` propres. `lint-imports` : 65→66
  fichiers, 164→168 dépendances, contrat toujours respecté (aucun
  cycle introduit par le nouveau module). `mypy` sur les deux fichiers
  ajoutés : 0 erreur imputable ; les 49 erreurs préexistantes (Session
  50) hors périmètre reconfirmées inchangées sur l'intégralité de
  `src/`.
- **Non traité dans cette passe** : extension à d'autres règles du
  catalogue (candidats à seuil simple sans corrélation : par exemple
  `tcp_zero_window`, `hop_delta_outliers`, les compteurs DNS bruts) ;
  câblage à un CLI ou au GTK4 (`evaluate()`/`available_rule_ids()` ne
  sont appelés aujourd'hui que par les tests) ; bascule effective de
  `build_findings()` vers ce moteur (nécessiterait d'abord de traiter
  les CINQ règles à `correlation_rule` non `None` — saturation,
  bufferbloat, remarquage QoS, fragmentation, PMTUD black hole — qui
  fusionnent deux signaux distincts, forme différente de
  `loss_per_segment`). Voir CLAUDE.md « Prochaine feature » et
  `docs/sessions/session-55.md` pour le détail complet.

### ✅ Migration de gestion des dépendances `pip` → `uv` (Session 55, hors feuille de route OmniPeek)

- **Demande explicite** : « passer sur `uv` pour remplacer `poetry` ».
  Recherche préalable dans le projet : **aucune trace de `poetry`**
  trouvée (`pyproject.toml` n'avait que `[tool.ruff]`/
  `[tool.importlinter]`, aucun `poetry.lock` livré) — la migration
  réellement en place à remplacer était `pip install -r
  requirements.txt(+ -dev.txt)`.
- **Ce qui a été livré** : `[project]` +
  `[project.optional-dependencies.dev]` + `[tool.uv] package = false`
  ajoutés à `pyproject.toml` (mêmes bornes de version que les
  `requirements*.txt` existants) ; `uv.lock` généré (49 paquets
  résolus) ; `uv sync --extra dev` opérationnel. `requires-python`
  relevé de `>=3.9` à `>=3.10` (`import-linter>=2.13`, dépendance dev,
  exige lui-même Python≥3.10 — `uv lock` échouait sinon sur la
  résolution de l'extra `dev` ; aucun changement de syntaxe nécessaire
  dans `src/`, le code applicatif reste compatible 3.9).
  `requirements.txt`/`requirements-dev.txt` conservés comme repli
  documenté (référencés par les messages d'erreur d'`install.sh`, qui
  privilégie de toute façon les paquets système et n'a pas changé
  cette session) mais volontairement non régénérés via `uv export`
  (pin transitif complet, style différent des bornes `>=` déjà en
  place) — à tenir à jour manuellement en miroir de `pyproject.toml`.
  `.gitignore` ajouté (absent avant cette session) couvrant `.venv/`
  et les caches d'outillage déjà présents.
- **Validation** : `pytest`/`ruff check`/`ruff format --check`/
  `lint-imports` rejoués via `uv run` après la migration, tous verts,
  aucune régression (959/959 à ce stade, avant l'ajout de la feature
  ci-dessus).
- **Non traité dans cette passe** : aucune erreur `ruff` trouvée à
  corriger (demande explicite de la session, vérifiée — état inchangé
  depuis la Session 50).

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (section 6.2, "négociations TLS incomplètes" — décision architecturale tranchée — Session 54)

- **Décision tranchée** : la question ouverte depuis la Session 49 —
  faire vivre « négociations TLS incomplètes » (§6.2) dans
  `Report`/`analysis.py` (option (a)), ou l'enrichir dans
  `tls_diagnostics.py` en acceptant qu'elle ne soit jamais cataloguable
  (option (b)) — est tranchée en faveur de **l'option (a)**.
- **Pourquoi (a)** : le coût redouté (soit dupliquer le parsing manuel
  de `tls_diagnostics.py` sur la charge utile TCP brute, soit casser
  son indépendance délibérée) a été vérifié dans le code AVANT
  d'écrire quoi que ce soit (même discipline que la correction de la
  Session 53) et s'est révélé ne pas exister. `pcap_parser.protocols`
  (déjà utilisé pour le certificat, Session 26/53) lit tshark en mode
  `-T ek` SANS restriction de champs -- toute la dissection TLS native
  de tshark (type d'enregistrement, sous-type Handshake) y est déjà
  présente. Confirmé EMPIRIQUEMENT (pas supposé) par une vraie capture
  TLS 1.2 generée sur loopback (`openssl s_server`/`s_client`/`curl`,
  `tshark` 4.2.2 -- tous réinstallés via `apt-get` dans cet
  environnement, voir Validation ci-dessous) : les champs
  `tls.record.content_type`/`tls.handshake.type` (`tls_tls_record_
  content_type`/`tls_tls_handshake_type` en notation EK) suffisent,
  exactement comme `x509af_x509af_*` le fait déjà pour le certificat.
  Aucune réutilisation de `tls_diagnostics.py` nécessaire : nouvelle
  fonction `extract_tls_handshake` totalement indépendante.
  `tls_diagnostics.py` reste inchangé, comme conçu à l'origine.
- **Détecteur entièrement nouveau** (pas une simple formalisation d'un
  détecteur existant, à la différence des Sessions 46-53) :
  - `pcap_parser/protocols.py::extract_tls_handshake()` -- lit les deux
    champs ci-dessus, renvoie trois booléens par paquet
    (`client_hello`/`server_hello`/`application_data`), gère le cas où
    tshark coalesce plusieurs enregistrements TLS dans un seul paquet
    (listes parallèles plutôt que valeurs scalaires -- même traitement
    que les dates de certificat).
  - Trois nouveaux champs bout-en-bout (`RawPacket` --
    `pcap_parser/packet.py` -- puis `Pkt` -- `netcross_core/models.py`
    -- via l'adaptateur `netcross_core/parsing.py`) :
    `tls_client_hello`/`tls_server_hello`/`tls_application_data`
    (booléens).
  - `netcross_core/analysis.py::_analyse_tls_handshake()` -- PAR POINT
    uniquement (comme `_analyse_tls_certificate` pour
    `tls_cert_invalid_dates`, aucune corrélation entre points
    nécessaire, à la différence de `tls_cert_mismatch`) : regroupe les
    paquets d'un même point par connexion NON orientée (les deux
    extrémités (ip, port) triées, pas un 5-tuple directionnel strict --
    ClientHello/ServerHello/application_data peuvent apparaître dans
    l'un ou l'autre sens), puis pour chaque connexion où un ClientHello
    est vu :
    - `Report.tls_handshake_no_reply` (PAR POINT) : aucun ServerHello
      jamais observé ensuite pour cette connexion à ce point --
      silence total après l'ouverture de la négociation.
    - `Report.tls_handshake_incomplete` (PAR POINT) : un ServerHello
      EST vu, mais aucun enregistrement `application_data` jamais
      observé ensuite pour cette connexion à ce point -- négociation
      démarrée puis interrompue avant son terme.
  - Limites assumées, documentées dans le code : ne distingue pas une
    négociation réellement bloquée d'une capture arrêtée avant que la
    suite n'arrive (limite structurelle de toute analyse PAR POINT,
    comme `dns_timeout`/`syn_no_synack`) ; TLS 1.3 déguise en
    `application_data` les messages de handshake qui suivent le
    ServerHello (compatibilité des intermédiaires), ce qui peut
    occasionnellement masquer une négociation TLS 1.3 réellement
    interrompue juste après ce déguisement -- même ambiguïté déjà
    documentée dans `netcross_core.tls_diagnostics`.
- **Deux nouvelles règles** ajoutées à `_RULE_CATALOG`
  (`netcross_core/expert_rules.py`, 39 → 41), domaine `"TLS"` partagé
  avec les deux règles certificat de la Session 53 (même
  `Finding.category`, quatre concepts désormais distincts sous la même
  étiquette naturelle -- exactement la situation que la correction de
  la Session 53 avait clarifiée comme sans risque technique) :
  - `tls_handshake_no_reply` -- sévérité `anomalie`, confiance `0.8`
    (correspondance par identifiant exact -- la connexion -- entre
    plusieurs paquets d'un MÊME point, même registre que
    `dhcp_issues`/`sip_issues` ; PAS le registre 0.7 de
    `syn_no_synack`, puisqu'aucun ordre de points n'est requis ici).
  - `tls_handshake_incomplete` -- mêmes sévérité et confiance.
  Les deux `rule_id` câblés DÈS LA CRÉATION des sites de `Finding`
  correspondants (contrairement au certificat, Session 26 → 53) :
  cette session connaît déjà le catalogue dans son intégralité, rien
  ne justifiait de rouvrir un écart déjà identifié et corrigé.
- **Câblage complet des consommateurs existants**, au-delà de
  `synthesis.py` (nouveau bloc « -- négociations TLS incomplètes -- »
  dans `build_findings()`) : `report_text.py` (nouvelle section
  « -- Negociations TLS incompletes -- ») et `baseline_diff.py` (deux
  nouveaux appels `_compare_count` dans la boucle par point).
- **Vingt-neuf tests nets** (930 → **959**), répartis sur cinq
  fichiers : `test_expert_rules.py` (+4 -- spot checks Session 54,
  plus renommages/réécritures neutres en nombre du comptage global,
  des domaines et du test de traçabilité `rule_id`/domaine) ;
  `test_analysis.py` (+8 -- unitaires sur `_analyse_tls_handshake` :
  handshake complet sans signal, `no_reply` détecté avec numéro de
  trame, `incomplete` détecté avec numéro de trame du ClientHello,
  ServerHello seul sans ClientHello ignoré, paquets sans signal TLS
  ignorés, indépendance stricte entre points) ; `test_synthesis.py`
  (+8 -- sévérité/segment, évidence avec et sans numéro de trame,
  rule_id, pour les deux signaux) ; `test_report_text.py` (+3 --
  rendu texte affiché/message par défaut) ; `test_baseline_diff.py`
  (+6 -- nouvelle occurrence signalée, évidence avec et sans numéro de
  trame, pour les deux signaux).
- Validation : suite complète rejouée avant (930/930, héritée de la
  Session 53) et après (**959/959**) ; `ruff check .`/`ruff format
  --check .` propres (1 fichier reformaté : `report_text.py`, limite
  de 120 caractères), vérifié avec la version épinglée `ruff==0.16.4` ;
  `lint-imports` (65 fichiers, 164 dépendances, contrat respecté --
  inchangé, aucun nouveau module créé) ; `mypy
  --ignore-missing-imports` sur les neuf fichiers source modifiés :
  UNE erreur introduite puis corrigée DANS LA MÊME session
  (`extract_tls_handshake` renvoyait `set[int | None]` au lieu de
  `set[int]` annoncé -- `hex_or_dec_to_int` peut renvoyer `None` sur un
  champ malformé ; corrigé en filtrant explicitement les `None`, aucun
  changement de comportement puisque les valeurs recherchées, 1/2/23,
  ne sont de toute façon jamais `None`), 0 erreur imputable au final ;
  les 49 erreurs préexistantes (Session 50) hors périmètre
  reconfirmées inchangées sur l'intégralité de `src/` (toujours 49
  erreurs sur 9 fichiers -- `pcap_parser/protocols.py`, seul fichier
  modifié qui aurait pu en hériter, n'en fait PAS partie).
  **Validation bout en bout avec une vraie capture TLS 1.2**,
  contrairement à la Session 53 (justifié ici car détecteur
  ENTIÈREMENT nouveau, même situation que la Session 52 pour HTTP) :
  `tshark`/`openssl` réinstallés via `apt-get` dans cet environnement ;
  capture générée sur loopback pour DEUX scénarios réels -- (1) un
  `ClientHello` seul sans réponse (`openssl s_client` contre un
  `s_server` qui n'a jamais complété son `SSL_accept()`) correctement
  détecté comme `tls_handshake_no_reply["A"] == 1`, zéro faux positif
  sur `tls_handshake_incomplete` ; (2) un handshake TLS 1.2 COMPLET
  réel (`curl` contre `openssl s_server -www`, échange HTTP effectif)
  ne déclenche NI L'UN NI L'AUTRE signal -- vérifié à la fois par appel
  direct du pipeline (`parse_capture`/`correlate`/`analyse`) et par le
  CLI complet (`cross_capture_analyzer_cli.py --capture A=...`, sortie
  texte confirmée affichant la nouvelle section). Non-régression
  vérifiée sur la détection de certificat (Session 26/53) avec la même
  capture réelle (`tls_cert_invalid_dates`/`tls_cert_mismatch` restent
  vides, comme attendu -- certificat valide, un seul point).
- **`README.md` à nouveau volontairement NON modifié** : le nouveau
  signal n'ajoute aucune capacité visible côté CLI/PDF/GUI qui ne soit
  déjà couverte par la description existante de l'analyse TLS ; seul le
  JSON gagne deux valeurs possibles pour un champ déjà exposé depuis la
  Session 48. Détail complet : `docs/sessions/session-54.md`.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (section 6.2, "bibliothèque de règles d'expertise réseau" — extension à "TLS" (certificat) — Session 53)

- **Périmètre choisi pour cette session** : la Session 52 laissait
  ouverte une seule catégorie entièrement sans règle (`"TLS"`), ainsi
  que les mêmes pistes plus larges (détecteur « négociations TLS
  incomplètes », moteur d'EXÉCUTION, bascule vers la Session 3). Les
  pistes plus larges restent hors calibre pour une session ponctuelle
  (même conclusion qu'aux Sessions 47-52). `"TLS"` (certificat hors
  validité/pas encore valide, certificat substitué, Session 26, DEUX
  sites de `Finding` dans `synthesis.py::build_findings()`, bloc
  « -- certificat TLS -- ») était la seule catégorie restante.
- **Correction apportée cette session**, avant toute écriture de code :
  CLAUDE.md et les docstrings des Sessions 49/51/52 affirmaient que
  cataloguer ce signal « recoupait » directement la décision
  architecturale en suspens sur « négociations TLS incomplètes »,
  donc que ce n'était « pas un simple geste mécanique » comme les
  Sessions 51/52. Vérifié dans le code avant rédaction (même discipline
  que le reste de ce catalogue) : cette affirmation était **inexacte**.
  Le signal « négociations incomplètes » ne produit **aucun**
  `synthesis.Finding` aujourd'hui — il vit exclusivement dans
  `TlsFinding` (`netcross_core.tls_diagnostics`, type jamais relié à
  `Finding.category`) — il n'a donc **jamais** été, et ne devient pas
  maintenant, un candidat à une entrée de ce catalogue, qui n'accepte
  comme `domain` que des valeurs réellement produites par
  `Finding.category`. Les deux signaux partagent la même étiquette
  « TLS » en langage naturel mais ne partageaient déjà aucun code,
  aucun type, aucun site de `Finding` commun : cataloguer l'un ne
  préjuge donc rigoureusement rien du sort de l'autre.
- **Deux nouvelles règles** ajoutées à `_RULE_CATALOG`
  (`netcross_core/expert_rules.py`, 37 → 39), toutes deux domaine
  `"TLS"`, même discipline de formalisation que les Sessions 46-52 (le
  détecteur existe déjà, `_analyse_tls_certificate` — Session 26 —
  n'est pas modifié) :
  - `tls_cert_invalid_dates` (`Report.tls_cert_invalid_dates`, PAR
    POINT) — sévérité `anomalie`, confiance `0.8` (lecture native du
    champ certificat, agrégation sur un seul point sans hypothèse de
    topologie, même registre que `stp_instability`).
  - `tls_cert_mismatch` (`Report.tls_cert_mismatch`, PAR PAIRE de
    points) — sévérité `anomalie`, confiance `0.8` (correspondance par
    identifiant exact — le 5-tuple de connexion — entre deux points,
    même registre que `vlan_change`).
  Les deux restent AUTONOMES (`correlation_rule=None`) et à seuils
  vides (se déclenchent sur toute occurrence, n > 0).
- **Câblage `rule_id`** sur les DEUX sites de `Finding` de cette
  catégorie dans `synthesis.py::build_findings()` (bloc
  « -- certificat TLS -- ») — code procédural non modifié dans sa
  logique, seulement annoté, même discipline que les Sessions 48-52.
- **Non traité, décision explicitement reportée** : « négociations TLS
  incomplètes » (§6.2) — toujours aucun détecteur réel dans le pipeline
  `Report`/`Finding`, décision architecturale identifiée en Session 49
  toujours ouverte (et désormais clairement DISTINCTE de la question
  de couverture du catalogue, voir correction ci-dessus) ; tout moteur
  d'EXÉCUTION ; cause probable/impact et Sessions 3 à 11 de la section
  13.3 : inchangé depuis la Session 49. Après cette session, **plus
  aucune catégorie de `Finding` n'est entièrement sans règle**.
- **Cinq tests nets** (925 → **930**) : dans `test_expert_rules.py` —
  nouvelle section « spot checks Session 53 »
  (`test_catalogue_deux_regles_tls`,
  `test_tls_cert_invalid_dates_et_mismatch_meme_severite_meme_confiance`,
  `test_regles_tls_toutes_autonomes_et_sans_seuil`,
  `test_tls_cert_invalid_dates_metriques_requises`,
  `test_tls_cert_mismatch_metriques_requises`, +5) ; comptage catalogue
  `37` → `39` (`test_catalogue_trente_neuf_regles`, renommé) ; domaines
  attendus étendus à `"TLS"` (dix-neuf familles au lieu de dix-huit,
  test renommé) ; `test_negociations_tls_incompletes_non_cataloguees`
  réécrit pour vérifier que le domaine `"TLS"` du catalogue ne contient
  QUE les deux règles certificat, jamais un id représentant les
  « négociations incomplètes » ; test d'agrégation `rule_id`
  (`test_rule_id_couvre_les_trente_neuf_regles_et_respecte_le_domaine`,
  renommé) déplace les deux champs `Report.tls_cert_*` du bloc
  « orphelins » (désormais vide) vers le bloc des signaux catalogués.
  Dans `test_synthesis.py`, les deux tests existants
  `test_tls_cert_{invalid_dates,mismatch}_rule_id_reste_none` convertis
  EN PLACE en versions positives (`rule_id` attendu non `None`, mêmes
  `Report` synthétiques réutilisés, neutres en nombre).
- Validation : suite complète rejouée avant (925/925, héritée de la
  Session 52) et après (**930/930**) ; `ruff check .`/`ruff format
  --check .` propres, vérifié avec la version épinglée `ruff==0.16.4` ;
  `lint-imports` (65 fichiers, 164 dépendances, contrat respecté —
  inchangé) ; `mypy --ignore-missing-imports` sur les quatre fichiers
  modifiés (`expert_rules.py`/`synthesis.py` + les deux fichiers de
  test) : 0 erreur imputable, les 49 erreurs préexistantes (Session 50)
  hors périmètre reconfirmées inchangées (revérifié aussi sur
  l'intégralité de `src/` : toujours 49 erreurs sur 9 fichiers). **Pas
  de validation avec capture réelle cette session** (contrairement à la
  Session 52) : le détecteur (`_analyse_tls_certificate`, Session 26)
  est déjà testé de longue date (`test_analysis.py`,
  `test_report_text.py`, `test_baseline_diff.py`) et n'est pas modifié
  par cette session — même situation que les Sessions 46-51, qui
  s'appuyaient elles aussi sur des détecteurs déjà testés ailleurs.
- **`README.md` à nouveau volontairement NON modifié**, même raison
  qu'aux Sessions 46-52. Détail complet : `docs/sessions/session-53.md`.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (section 6.2, "bibliothèque de règles d'expertise réseau" — extension à "HTTP" — Session 52)

- **Périmètre choisi pour cette session** : la Session 51 laissait
  ouvertes deux catégories entièrement sans règle (`"TLS"`, `"HTTP"`)
  ainsi que les mêmes pistes plus larges (détecteur « négociations TLS
  incomplètes », moteur d'EXÉCUTION, bascule vers la Session 3). Les
  pistes plus larges restent hors calibre pour une session ponctuelle
  (même conclusion qu'aux Sessions 47-51). Entre les deux catégories
  restantes, `"HTTP"` (codes de statut, Session 17, CINQ sites de
  `Finding` dans `synthesis.py::build_findings()`, bloc « -- HTTP --
  ») a été retenue avant `"TLS"` : comme `"Reseau/Serveur"` en Session
  51, elle ne nomme aucun concept architectural non tranché
  (contrairement à `"TLS"`, qui recoupe toujours la décision en
  suspens sur « négociations TLS incomplètes » identifiée en Session
  49) — son seul coût, le NOMBRE de sites (cinq, pas un), avait motivé
  son report en Session 51 mais n'est pas une difficulté de fond.
- **Cinq nouvelles règles** ajoutées à `_RULE_CATALOG`
  (`netcross_core/expert_rules.py`, 32 → 37), toutes domaine `"HTTP"`,
  calquées sur le même geste que les quatre compteurs DNS bruts +
  `dns_slow_resolution` (Sessions 47/49) :
  - `http_client_error` (4xx, `Report.http_client_error_count`) —
    sévérité `info`, confiance `0.9`, même registre que `dns_nxdomain`.
  - `http_server_error` (5xx, `Report.http_server_error_count`) —
    sévérité `anomalie`, confiance `0.9`, même registre que
    `dns_servfail`.
  - `http_timeout` (`Report.http_timeout`) — sévérité `anomalie`,
    confiance `0.8`, même registre que `dns_timeout` mais cle de
    transaction DIFFÉRENTE : `(connexion TCP, URI, Nième occurrence)`
    plutôt qu'un identifiant de transaction numérique (HTTP/1.x n'en
    porte pas), documenté dans `required_context` d'après la docstring
    de `_analyse_http`.
  - `http_missing` (`Report.http_missing`) — sévérité `a_surveiller`,
    confiance `0.8`, même registre que `dns_missing`, même clé de
    transaction que `http_timeout` ci-dessus.
  - `http_slow_response` (`Report.http_response_time_ms`, seuil moyenne
    > 500ms) — sévérité `a_surveiller`, confiance `0.8`, même registre
    que `dns_slow_resolution` mais source de mesure DIFFÉRENTE :
    `http.time`, calculé NATIVEMENT par tshark (pas recomposé à la main
    comme DNS/DHCP/SIP), vérifié empiriquement en Session 17.
  Les cinq restent AUTONOMES (`correlation_rule=None`), sans site de
  `Finding` partagé entre elles.
- **Câblage `rule_id`** sur les CINQ sites de `Finding` de cette
  catégorie dans `synthesis.py::build_findings()` (bloc « -- HTTP --
  ») — code procédural non modifié dans sa logique, seulement annoté,
  même discipline que les Sessions 48-51.
- **Non traité, décision explicitement reportée** : la DERNIÈRE
  catégorie encore entièrement sans règle (`"TLS"`) ; « négociations
  TLS incomplètes » (§6.2) — toujours aucun détecteur réel dans le
  pipeline `Report`/`Finding`, décision architecturale identifiée en
  Session 49 toujours ouverte ; tout moteur d'EXÉCUTION ; cause
  probable/impact et Sessions 3 à 11 de la section 13.3 : inchangé
  depuis la Session 49.
- **Six tests nets** (919 → **925**) : dans `test_expert_rules.py` —
  `test_catalogue_cinq_regles_http`,
  `test_http_client_error_est_info_http_server_error_est_anomalie`,
  `test_http_timeout_et_http_missing_severites`, `test_seuil_http_lent`,
  `test_regles_http_toutes_autonomes` (+5, `test_http_non_cataloguee`
  supprimé -1) ; dans `test_synthesis.py`, les trois tests existants
  `test_http_{4xx,5xx,duree_moyenne}_rule_id_reste_none` convertis EN
  PLACE en versions positives (`rule_id` attendu non `None`, mêmes
  Report synthétiques réutilisés, neutres en nombre), plus deux tests
  réellement nouveaux `test_http_timeout_rule_id_est_http_timeout`/
  `test_http_missing_rule_id_est_http_missing` (+2). Comptage catalogue
  `32` → `37` (`test_catalogue_trente_sept_regles`, renommé) ; domaines
  attendus étendus à `"HTTP"` (dix-huit familles au lieu de dix-sept,
  test renommé) ; test d'agrégation `rule_id`
  (`test_rule_id_couvre_les_trente_sept_regles_et_respecte_le_domaine`,
  renommé) déplace les cinq champs `Report.http_*` du bloc « orphelins
  » (qui ne garde plus que `"TLS"`) vers le bloc des signaux
  catalogués.
- Validation : suite complète rejouée avant (919/919, hérités de la
  Session 51) et après (**925/925**) ; `ruff check .` propre après
  reformulation de quatre lignes dépassant 120 caractères ; `ruff
  format --check .` propre (1 fichier reformaté), vérifié avec la
  version épinglée `ruff==0.16.4` ; `lint-imports` (65 fichiers, 164
  dépendances, contrat respecté — inchangé) ; `mypy
  --ignore-missing-imports` sur les quatre fichiers modifiés
  (`expert_rules.py`/`synthesis.py` + les deux fichiers de test) : 0
  erreur imputable, les 49 erreurs préexistantes (Session 50) hors
  périmètre reconfirmées inchangées. **Validation bout en bout avec un
  vrai `tshark`/serveur HTTP réel** (contrairement aux Sessions 46-51,
  qui s'appuyaient sur des détecteurs déjà testés ailleurs) : serveur
  `http.server` Python réel sur loopback, capturé en direct via
  `dumpcap` pendant trois requêtes `curl` réelles (200/404/500) ;
  `cross_capture_analyzer_cli.py --json-report` rejoué sur cette
  capture confirme `rule_id="http_client_error"`/`"http_server_error"`
  corrects à la fois sur les `findings` et les `expert_events`.
- **`README.md` à nouveau volontairement NON modifié**, même raison
  qu'aux Sessions 46-51. Détail complet : `docs/sessions/session-52.md`.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (section 6.2, "bibliothèque de règles d'expertise réseau" — extension à "Reseau/Serveur" — Session 51)

- **Périmètre choisi pour cette session** : la Session 50 (audit qualité,
  hors feuille de route OmniPeek) laissait intactes les trois pistes de
  la Session 49 dans `CLAUDE.md` — étendre le catalogue aux trois
  catégories entièrement sans règle (`"Reseau/Serveur"`, `"TLS"`,
  `"HTTP"`), construire un détecteur réel pour « négociations TLS
  incomplètes », amorcer un moteur d'EXÉCUTION, ou basculer vers la
  Session 3 (cause probable/impact, 5/5). Les deux dernières restent
  manifestement hors calibre pour une session ponctuelle (même
  conclusion qu'aux Sessions 47-49). Entre les trois catégories,
  `"Reseau/Serveur"` a été retenue : un seul site de construction de
  `Finding` (`synthesis.py`, bloc « -- decomposition reseau / serveur
  -- »), contre cinq pour `"HTTP"` (chacun avec sa propre gradation de
  sévérité par classe de code de statut — extension mécanique jugée
  trop large pour cette même passe) ; et aucun concept architectural non
  tranché, contrairement à `"TLS"` qui recoupe directement la décision
  en suspens sur « négociations TLS incomplètes » identifiée en Session
  49 (le signal certificat déjà existant, Session 26, reste un concept
  différent et non nommé par §6.2 — le cataloguer aurait nécessité de
  trancher cette même question en creux).
- **Une nouvelle règle** `server_processing_dominant` ajoutée à
  `_RULE_CATALOG` (`netcross_core/expert_rules.py`, 31 → 32) : domaine
  `"Reseau/Serveur"`, sévérité `a_surveiller`, confiance `0.7`
  (heuristique à seuil délibéré non calibré à un équipement précis —
  même palier que `nat_fw_silent_drop`/`arp_ip_conflict`), seuils
  `{"ratio_serveur_reseau": 3.0, "seuil_serveur_ms": 20.0}` recopiés
  directement du code de `synthesis.py`
  (`avg_server > 3 * avg_net and avg_server > 20`). `required_metrics`
  pointe `Report.server_think_time`/`Report.latency`/`Report.points` —
  précision documentée dans `required_context` : la latence référence
  toujours le PREMIER et le DERNIER point de `r.points`, pas une paire
  adjacente quelconque (contrairement à la plupart des autres règles du
  catalogue qui raisonnent par paire de points adjacents).
- **Câblage `rule_id`** sur l'unique site de `Finding` de cette
  catégorie dans `synthesis.py::build_findings()` — code procédural non
  modifié dans sa logique, seulement annoté, même discipline que les
  Sessions 48-49.
- **Non traité, décision explicitement reportée** : les DEUX catégories
  entières encore sans règle (`"TLS"`, `"HTTP"`) — aucune n'est nommée
  par §6.2 ; « négociations TLS incomplètes » (§6.2) — toujours aucun
  détecteur réel dans le pipeline `Report`/`Finding`, la décision
  architecturale identifiée en Session 49 (faire vivre le signal dans
  `analysis.py`/`Report` vs l'enrichir dans `tls_diagnostics.py` sans
  jamais le rendre cataloguable) reste entièrement ouverte ; tout moteur
  d'EXÉCUTION ; cause probable/impact et Sessions 3 à 11 de la section
  13.3 : inchangé depuis la Session 49.
- **Trois nouveaux tests nets** (916 → **919**) dans
  `test_expert_rules.py` : `test_http_non_cataloguee` (symétrique du
  test TLS existant, confirme que `"HTTP"` reste hors catalogue),
  `test_server_processing_dominant_domaine_et_severite`,
  `test_seuil_server_processing_dominant`. Le test existant
  `test_reseau_serveur_rule_id_reste_none` (`test_synthesis.py`)
  converti EN PLACE en `test_reseau_serveur_rule_id_est_
  server_processing_dominant` (même Report synthétique réutilisé,
  aucun test net ajouté par cette conversion) ; le test d'agrégation
  `rule_id` (`test_rule_id_couvre_les_trente_deux_regles_et_
  respecte_le_domaine`, renommé) et le test de comptage des dix-sept
  familles de domaines (renommé) mis à jour en conséquence.
- Validation : suite complète rejouée avant (916/916, hérités de la
  Session 50) et après (**919/919**) ; `ruff check .` propre ; `ruff
  format --check .` propre (116 fichiers), vérifié avec la version
  épinglée `ruff==0.16.4` ; `lint-imports` (65 fichiers, 164 dépendances,
  contrat respecté — inchangé, aucun nouveau fichier source) ; `mypy
  --ignore-missing-imports` sur les deux fichiers modifiés
  (`expert_rules.py`/`synthesis.py`) : 0 erreur imputable, les 49
  erreurs préexistantes (Session 50) hors périmètre reconfirmées
  inchangées. Pas de validation bout en bout via un pcap réel, même
  raison qu'aux Sessions 46-49 (détecteur déjà réel et déjà testé par
  ailleurs dans `analysis.py`/`test_analysis.py`, seule l'annotation
  `rule_id` est nouvelle) ; le test d'agrégation étendu appelle
  néanmoins la vraie `build_findings()`.
- **`README.md` à nouveau volontairement NON modifié**, même raison
  qu'aux Sessions 46-49 : l'ajout d'une règle au catalogue et son
  câblage `rule_id` ne change aucune capacité visible pour
  l'utilisateur final de l'outil (CLI/PDF/GUI inchangés, seul le JSON
  gagne une valeur possible pour un champ déjà exposé depuis la
  Session 48). Détail complet : `docs/sessions/session-51.md`.

### 🔍 Audit qualité — Context7, ruff, mypy (Session 50, hors feuille de route OmniPeek)

- **Demande** : auditer le projet avec Context7, corriger toute erreur
  `ruff`, faire évoluer les fichiers de suivi/tests/documentation —
  explicitement distincte de la consigne récurrente habituelle
  (« Continue les features... »), pas de nouvelle règle ni de nouveau
  détecteur cette session.
- **Ruff** : `ruff check .` et `ruff format --check .` propres, vérifié
  avec la version épinglée `ruff==0.16.4` (`requirements-dev.txt`/
  `.pre-commit-config.yaml`), pas seulement la dernière disponible
  (`0.16.7` au moment de l'audit). **Aucune erreur trouvée** — rien à
  corriger.
- **Audit Context7** (documentation à jour des bibliothèques externes
  les plus sensibles du projet, jamais fait explicitement avant) :
  - `cryptography` (`netcross_core/quic_diagnostics.py`) : `AESGCM`,
    `Cipher(algorithms.AES(...), modes.ECB())` et les primitives HKDF
    manuelles correspondent exactement aux exemples officiels
    `pyca/cryptography` (`docs/hazmat/primitives/aead.rst` et
    `symmetric-encryption.rst`). L'AES-ECB en levée de protection
    d'en-tête QUIC est la construction imposée par la RFC 9001 (pas un
    usage ECB générique, qui serait effectivement à proscrire) — déjà
    explicité dans la docstring du module, confirmé indépendamment ici.
  - PyGObject/GTK4 (`netcross_gtk4/app.py`) : déjà sur `Gtk.FileDialog`
    (les quatre occurrences du module), jamais `Gtk.FileChooserDialog`
    ni `Gtk.Dialog`, dépréciés depuis GTK 4.10 selon la documentation
    officielle `api.pygobject.gnome.org` ; aucun appel `.show()` sur un
    widget (déprécié aussi depuis 4.10 au profit de `set_visible`).
  - `networkx` (`netcross_report/charts.py`) : `topological_generations`
    et `NetworkXUnfeasible` sont l'API stable et documentée (`main`,
    dépôt `networkx/networkx`), rien de déprécié.
  - `matplotlib`/`reportlab` : relecture manuelle de `charts.py`/`pdf.py`
    sans appel Context7 dédié (usage standard de l'API orientée objet —
    `fig, ax = plt.subplots()`, `platypus` — sans motif suspect
    identifié à la lecture ; `ax.set_xticklabels()` toujours précédé de
    `ax.set_xticks()`, ce qui évite l'avertissement `FixedFormatter`
    des versions récentes de matplotlib).
- **Découverte non planifiée, documentée plutôt qu'ignorée** : premier
  passage `mypy --ignore-missing-imports` sur l'intégralité de `src/`
  depuis l'introduction de l'outil (Session 38) — jusqu'ici toujours
  limité aux fichiers modifiés d'une session, une convention qui ne peut
  par construction jamais détecter une dérive sur un fichier qu'aucune
  session ne retouche. Résultat : **49 erreurs sur 9 fichiers**, pas 27
  sur 7 comme suivi jusqu'ici — `tls_diagnostics.py` (18 erreurs) et
  `quic_diagnostics.py` (4 erreurs) n'avaient jamais été comptés, n'ayant
  jamais été modifiés par une session depuis leur création et donc
  jamais inclus dans un `mypy <fichiers modifiés>` ad hoc. Même nature
  d'erreurs que les 27 déjà connues (annotations de variable manquantes,
  `str | None`/`int | None` remontant de `RawPacket` vers des dataclasses
  plus strictes, `**dict` non typé passé à un constructeur typé) — pas
  une régression de code, un angle mort de suivi. Voir la table
  « Outillage qualité » ci-dessus pour le décompte détaillé par fichier,
  et `CLAUDE.md` (État courant + Commandes qualité) pour le résumé.
  Correction du code lui-même toujours hors périmètre (même décision que
  la Session 38, non remise en cause par cette découverte).
- **Validation** : `pytest` 916/916 (inchangé), `lint-imports` 65
  fichiers/164 dépendances/contrat respecté (inchangé) — aucune
  régression, seuls des fichiers de suivi/documentation modifiés cette
  session.
- **Non traité, explicitement hors périmètre de cette session** :
  correction des 49 erreurs `mypy` elles-mêmes ; poursuite de la feuille
  de route OmniPeek (`CLAUDE.md` § Prochaine feature, inchangée) — la
  demande précisait « sans passer à la suite ».

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (section 6.2, "bibliothèque de règles d'expertise réseau" — extension de couverture — Session 49)

- **Périmètre choisi pour cette session** : la Session 48 laissait
  quatre pistes ouvertes dans `CLAUDE.md` — étendre la couverture du
  catalogue aux signaux restés `rule_id=None`, construire un détecteur
  réel pour « négociations TLS incomplètes », amorcer un moteur
  d'EXÉCUTION, ou basculer vers la Session 3 (cause probable/impact,
  5/5). Les deux dernières sont manifestement hors calibre pour une
  session ponctuelle (même conclusion qu'aux Sessions 47-48). Entre les
  deux premières, l'extension de couverture a été retenue pour sa partie
  la plus tractable : les CINQ paires « signal isolé à côté d'une règle
  déjà existante », de nature « formalisation pure » (le détecteur
  existe déjà, non modifié), analogue en taille et en discipline aux
  Sessions 46-47 plutôt qu'une détection entièrement nouvelle à écrire.
- **Huit nouvelles règles** ajoutées à `_RULE_CATALOG`
  (`netcross_core/expert_rules.py`, 23 → 31) : `syn_reply_missing`
  (TCP, à côté de `tcp_syn_no_synack` — même fonction source
  `_analyse_handshake`), `hop_delta_outliers` (Routage, à côté de
  `ttl_variation`), `pcp_change` (QoS, à côté de `qos_dscp_remarking`),
  `icmp_fragmentation_needed` (Fragmentation — **fusionne** les deux
  sites `icmp_frag_needed`/`icmpv6_too_big`, IPv4 et IPv6 du même signal
  fonctionnel, même sévérité `info`, même discipline que
  `tcp_options_stripped` en Session 47), et **quatre** règles DNS
  distinctes `dns_nxdomain`/`dns_servfail`/`dns_timeout`/`dns_missing`
  (gardées séparées plutôt que fusionnées : leurs sévérités
  `info`/`anomalie`/`anomalie`/`a_surveiller` diffèrent, même
  raisonnement que les trois sous-types de retransmission TCP en
  Session 46 — fusionner masquerait la gradation). Chaque champ
  `required_metrics`/`confidence`/`severity` vérifié directement contre
  `analysis.py` avant rédaction (jamais supposé) ; `confidence` calée
  sur l'échelle à cinq paliers déjà documentée en comparant chaque
  nouveau détecteur à son mécanisme le plus proche parmi les 23 règles
  existantes (ex : `pcp_change` reprend exactement le mécanisme et la
  confiance de `vlan_change`, dont la docstring de règle citait déjà
  `pcp_change` par son nom comme signal voisin non exposé).
- **Câblage `rule_id`** sur les neuf sites de `Finding` correspondants
  dans `synthesis.py::build_findings()` — code procédural non modifié
  dans sa logique, seulement annoté, même discipline que la Session 48.
- **Découverte non planifiée, documentée plutôt qu'ignorée** :
  `netcross_core/tls_diagnostics.py` (module indépendant, déjà câblé aux
  trois CLI/GUI, déjà documenté en README) suit déjà un état de
  handshake TLS par flux et par point (`HandshakeStatus.verdict` :
  `"client_hello_no_reply"`/`"server_hello_no_data"`/`"complete"`/etc.)
  très proche en esprit de « négociations TLS incomplètes » — mais
  produit son propre type `TlsFinding`, jamais un `synthesis.Finding`,
  donc jamais cataloguable via `rule_id` tel que ce mécanisme fonctionne
  aujourd'hui. La conclusion de la Session 47 (« aucun détecteur réel »)
  reste exacte pour le pipeline `Report`/`Finding` spécifiquement, mais
  la décision à prendre pour ce point n'est plus la même : voir
  `CLAUDE.md`/section 13.3 ci-dessous.
- **Non traité, décision explicitement reportée** : les TROIS catégories
  entières encore sans règle (`"Reseau/Serveur"`, `"TLS"`, `"HTTP"`, 8
  sites au total) — aucune n'est nommée par la section 6.2, contrairement
  aux cinq paires traitées cette session qui formalisent chacune une
  extension directe d'un concept déjà cité ; extension mécanique jugée
  inappropriée, décision à prendre catégorie par catégorie dans une
  session future. « Négociations TLS incomplètes » : toujours pas de
  détecteur réel dans le pipeline `Report`/`Finding` (voir découverte
  ci-dessus — la décision porte maintenant sur QUEL pipeline doit porter
  ce signal, pas seulement sur l'écriture d'un détecteur). Tout moteur
  d'EXÉCUTION, cause probable/impact et Sessions 3 à 11 de la section
  13.3 : inchangé depuis la Session 48.
- **Quatre nouveaux tests nets** (912 → **916**) dans
  `test_expert_rules.py` : le test d'agrégation de la Session 48
  (`test_rule_id_couvre_...`) renommé et étendu en place (31 règles, les
  neuf signaux Session 49 déplacés du bloc « orphelins » au bloc
  « catalogués » — une seule fonction, ne change pas le total), plus
  quatre tests ciblés réellement nouveaux (fusion ICMP/ICMPv6, sévérités
  DNS distinctes, mécanisme partagé `syn_reply_missing`/
  `tcp_syn_no_synack`, domaines des paires Routage/QoS). Dans
  `test_synthesis.py`, les **neuf tests existants**
  `..._rule_id_reste_none` des signaux concernés convertis EN PLACE en
  `..._rule_id_est_<id>` (assertion et docstring mises à jour, même
  nombre de tests avant/après — aucun test net ajouté par cette
  conversion).
- Validation : suite complète rejouée avant (916 avec les 9 échecs
  attendus des tests pas encore convertis) et après (**916/916**) ;
  `ruff check .` propre après correction de trois dépassements de
  120 caractères introduits par les nouvelles chaînes de documentation
  de règles (repliées sur plusieurs lignes, aucun changement de
  contenu) ; `ruff format --check .` propre (114 fichiers) ;
  `lint-imports` (65 fichiers, 164 dépendances, contrat respecté —
  inchangé, aucun nouveau fichier source) ; `mypy
  --ignore-missing-imports` sur les deux fichiers modifiés
  (`expert_rules.py`/`synthesis.py`) : 0 erreur imputable, mêmes 27
  erreurs préexistantes reconfirmées inchangées ; `python -m compileall`
  propre sur tout `src/`. Diff complet contre le zip fourni en entrée de
  session vérifié (`diff -rq`, hors caches d'outils) : exactement les
  deux fichiers source et les deux fichiers de test attendus modifiés.
  Pas de validation bout en bout via un pcap réel, même raison qu'aux
  Sessions 46-48 (détecteurs déjà réels et déjà testés par ailleurs,
  seule l'annotation `rule_id` est nouvelle) ; le test d'agrégation
  étendu appelle néanmoins la vraie `build_findings()`.
- **`README.md` à nouveau volontairement NON modifié**, même raison
  qu'aux Sessions 46-48 : l'ajout de règles au catalogue et leur câblage
  `rule_id` ne change aucune capacité visible pour l'utilisateur final
  de l'outil (CLI/PDF/GUI inchangés, seul le JSON gagne des valeurs pour
  un champ déjà exposé depuis la Session 48).

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (section 6.2, "bibliothèque de règles d'expertise réseau" — câblage à un consommateur réel — Session 48)

- **Périmètre choisi pour cette session** : la Session 47 laissait trois
  pistes ouvertes dans `CLAUDE.md` — câbler le catalogue à un vrai
  consommateur, construire un détecteur réel pour « négociations TLS
  incomplètes », ou basculer vers la Session 3 (cause probable/impact,
  5/5). La première a été retenue : mieux calibrée pour une session
  (annotation d'un pipeline déjà réel plutôt qu'écriture d'une détection
  entièrement nouvelle ou d'un moteur de corrélation causale complet).
- **Champ `rule_id` (`str | None`, défaut `None`)** ajouté à `Finding`
  (`netcross_report/synthesis.py`) et `ExpertEvent`
  (`netcross_core/expert_model.py`), recopié de l'un à l'autre par
  `netcross_report/expert_events.py::build_expert_events()` (`getattr`
  défensif, `DiffFinding` ne déclare pas ce champ). Exact miroir de
  `remediation` (Session 45) mais dans l'autre sens : `remediation` est
  un texte rédigé, toujours `None` côté `"netcross"` ; `rule_id` est un
  identifiant lu, toujours `None` côté `"tshark"` (le catalogue décrit
  des détecteurs Netcross, pas les signaux bruts du dissecteur tshark).
- **Audit complet des ~44 sites de construction de `Finding`** dans
  `build_findings()` (pas seulement les 23 comptoirs déjà catalogués) :
  chaque site a été comparé au champ `required_metrics`/`domain` exact
  de la règle candidate (jamais une correspondance par seule
  `category` — huit domaines regroupent plusieurs signaux distincts,
  "TCP" à elle seule en compte huit). Résultat : les **23 règles du
  catalogue sont désormais toutes utilisées au moins une fois** (aucune
  regle orpheline de son côté, vérifié par une différence d'ensembles
  exacte avant rédaction des tests), et **~18 sites restent
  volontairement `rule_id=None`** malgré une catégorie par ailleurs
  couverte : `hop_delta_outliers` (à côté de `ttl_variation`),
  `pcp_change` (à côté de `qos_dscp_remarking`),
  `icmp_frag_needed`/`icmpv6_too_big` (à côté de `fragmentation_new`),
  `syn_reply_missing` (à côté de `tcp_syn_no_synack`, qui ne lit que
  `Report.syn_no_synack`), les quatre signaux DNS bruts
  `dns_nxdomain_count`/`dns_servfail_count`/`dns_timeout`/`dns_missing`
  (à côté de `dns_slow_resolution`, qui ne lit que
  `Report.dns_duration_ms`) — plus trois catégories ENTIÈRES encore sans
  aucune règle : `"Reseau/Serveur"`, `"TLS"` (signal certificat déjà
  existant, Session 26 — concept différent de « négociations
  incomplètes »), `"HTTP"`.
- **Exposition JSON** (`netcross_report/json_report.py`) : clé
  `"rule_id"` dans `_finding_dict` (absente plutôt que `None` explicite
  sur un `Finding` orphelin, même convention que `sample_size`/
  `evidence`) et dans `_expert_event_dict` (toujours présente, exposée
  telle quelle comme `cause`/`impact`/`confidence`, y compris `None`
  côté `"tshark"`). CLI `--triage`/PDF/GUI **inchangés** : `rule_id` est
  un identifiant technique destiné à un consommateur programmatique
  (dashboard, pipeline), pas à la table lisible par un humain déjà
  affichée par ces trois-là (même raisonnement que l'absence de
  `sample_size`/`evidence` dans le PDF aujourd'hui).
- **50 nouveaux tests** (862 → 912) : 42 dans `test_synthesis.py` (un
  par site de construction de `Finding` — les 26 sites couverts, un par
  identifiant, et les orphelins volontaires distingués un par un de la
  règle voisine de leur propre catégorie), 1 test d'agrégation dans
  `test_expert_rules.py` (construit un `Report` déclenchant l'ensemble
  des signaux à la fois, vérifie que chaque `rule_id` produit résout
  réellement via `get_rule()` avec le bon `domain`, et que les 23
  règles sont chacune utilisées), 3 dans `test_expert_events.py`
  (recopie, `None` par défaut, comportement avec `DiffFinding`), 4 dans
  `test_json_report.py` (exposé/absent côté `Finding`, exposé côté
  `"netcross"`/toujours `None` côté `"tshark"`).
- Validation : suite complète rejouée avant (862/862, hérités de la
  Session 47) et après (**912/912**, +50 net) ; `ruff check .`/`ruff
  format --check .` propres ; `lint-imports` (65 fichiers, 164
  dépendances, contrat respecté — inchangé, aucun nouveau fichier
  source) ; `mypy --ignore-missing-imports` sur les cinq fichiers
  modifiés (`synthesis.py`/`expert_model.py`/`expert_events.py`/
  `json_report.py`/`expert_rules.py` — docstring uniquement pour ce
  dernier) : 0 erreur imputable, mêmes 27 erreurs préexistantes
  reconfirmées inchangées. Pas de validation bout en bout via un pcap
  réel, même raison qu'aux Sessions 46-47 (nouveau champ annoté sur un
  pipeline qui reste piloté par du code procédural inchangé) ; le test
  d'agrégation appelle néanmoins la vraie `build_findings()`.
- Non traité : les trois catégories entières sans règle
  (`"Reseau/Serveur"`/`"TLS"`/`"HTTP"`) et les signaux isolés listés
  ci-dessus restent sans `rule_id` — extension de couverture explicitement
  reportée à une session future, pas une extension mécanique du même
  geste ; « négociations TLS incomplètes » (toujours aucun détecteur réel
  à formaliser) ; tout moteur d'EXÉCUTION qui évaluerait une `Rule`
  contre un `Report` pour produire lui-même un Finding/ExpertEvent (le
  sens reste inverse : `rule_id` annote un Finding déjà produit par le
  code procédural existant) ; README.md à nouveau non modifié, même
  raison qu'aux Sessions 46-47 (aucune capacité visible pour
  l'utilisateur final autre qu'un champ JSON supplémentaire). Cause
  probable/impact et Sessions 3 à 11 de la section 13.3 : entièrement à
  faire, inchangé.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (section 6.2, "bibliothèque de règles d'expertise réseau" — second lot — Session 47)

- **Périmètre choisi pour cette session** : la Session 46 laissait trois
  pistes ouvertes dans `CLAUDE.md`, dont « étendre
  `netcross_core/expert_rules.py` aux règles "nouvelles" de la section
  6.2 » — DNS lent, PMTUD black hole, NAT/FW silencieux, anomalies L2,
  options TCP incompatibles, négociations TLS incomplètes, etc. Avant de
  rédiger quoi que ce soit, chaque concept a été vérifié directement
  contre `analysis.py`/`synthesis.py` (recherche des noms de champs
  `Report`/fonctions `_analyse_*`, pas une supposition sur l'état du
  code) : **cinq des six sont en réalité déjà implémentés**, par des
  sessions antérieures et indépendantes de ce chantier de bibliothèque
  de règles — la section 6.2 les qualifiait de « nouvelles » à un moment
  où ces détecteurs n'existaient sans doute pas encore, mais le code a
  rattrapé le texte depuis. Seule « négociations TLS incomplètes » reste
  sans détecteur réel (recherche exhaustive des champs `tls_*` de
  `Report` : aucun ne suit l'état d'avancement d'une poignée de main,
  seulement des champs de certificat) — non cataloguée, volontairement,
  plutôt que d'inventer une règle sans donnée réelle derrière.
- **Huit nouvelles entrées de catalogue** (23 au total) :
  `dns_slow_resolution` (DNS, `_analyse_dns`, seuil 200ms de durée
  moyenne de résolution) ; `pmtud_blackhole` (PMTUD, `_analyse_pmtud`,
  seuil 512 octets / 2 tentatives, corrélation avec l'absence de signal
  ICMP(v6) sur toute la capture) ; `nat_fw_silent_drop` (NAT/Pare-feu,
  `_analyse_idle_timeout`, seuil 60s de silence) ; `arp_ip_conflict`
  (ARP, `_analyse_arp_ip_conflict`, seuil 2 MAC distinctes) ;
  `stp_instability` (STP, `_analyse_stp_instability`, regroupe
  topology-change et root-change, même sévérité) ; `vlan_change` (VLAN,
  boucle principale d'`analyse()`) ; `tcp_options_stripped` (TCP, Window
  Scale + SACK Permitted retirés, même sévérité, `_analyse_tcp_options`)
  et `tcp_mss_clamped` (TCP, même fonction source que le précédent mais
  sévérité `info` au lieu de `a_surveiller` — adaptation généralement
  délibérée et bénéfique, pas une entrée nommée par §6.2 mais ajoutée
  pour ne pas laisser un signal orphelin de son détecteur déjà
  catalogué). « Anomalies L2 » et « options TCP incompatibles »
  couvrent donc chacune plusieurs entrées, exactement comme
  « retransmissions TCP » en Session 46.
- Un signal « TLS » existant par ailleurs (certificat hors validité ou
  substitué entre points, Finding.category `"TLS"`, Session 26)
  n'est **pas** catalogué non plus cette session : c'est un problème
  différent de « négociation incomplète » (validité du certificat, pas
  achèvement de la poignée de main) et il n'est pas nommé par §6.2 —
  laissé à une décision explicite d'une session future plutôt
  qu'absorbé ici par extension implicite. Vérifié par un test dédié
  (`test_negociations_tls_incompletes_non_cataloguees` : aucune règle du
  catalogue ne porte le domaine `"TLS"`).
- Échelle de confiance (5 paliers, inchangée depuis la Session 46)
  élargie dans sa description pour couvrir les nouveaux mécanismes de
  détection (lecture native à un seul point sans hypothèse de topologie,
  ex. STP) sans changer les cinq valeurs numériques elles-mêmes. Une
  cinquième règle corrélée s'ajoute aux quatre de la Session 46 :
  `pmtud_blackhole` (retransmissions sans progression + absence de
  signal ICMP(v6) au point amont).
- 6 nouveaux tests dans `tests/test_expert_rules.py` (26 → 32) : quatre
  seuils numériques pinnés supplémentaires (DNS/PMTUD/NAT-FW/ARP), un
  test distinguant explicitement les deux règles issues de
  `_analyse_tcp_options`, un test documentant l'absence délibérée du
  domaine `"TLS"`. Les tests agrégés existants (comptage total,
  domaines couverts, règles corrélées, règles TCP, seuils vides) mis à
  jour en conséquence plutôt que dupliqués. Le test de traçabilité
  domaine ↔ `Finding.category` (Session 46) étendu pour exercer les six
  nouveaux domaines via une vraie `build_findings()`. Total **862/862**.
- Validation : suite complète rejouée avant (856/856, hérités de la
  Session 46) et après (862/862, +6 net) ; `ruff check .`/`ruff format
  --check .` propres ; `lint-imports` (65 fichiers, 164 dépendances,
  contrat respecté — inchangé, aucun nouveau fichier source) ; `mypy
  --ignore-missing-imports` sur `expert_rules.py` : 0 erreur imputable,
  mêmes 14 erreurs préexistantes reconfirmées inchangées. Pas de
  validation bout en bout via un pcap réel, même raison qu'en Session 46
  (catalogue non câblé au pipeline CLI/JSON/GUI) ; le test de
  traçabilité étendu appelle néanmoins la vraie `build_findings()`.
- Non traité : « négociations TLS incomplètes » (aucun détecteur réel à
  formaliser, construire ce détecteur serait une feature normale — code
  de détection dans `analysis.py` — pas un ajout au catalogue) ; le
  signal TLS certificat déjà existant (non nommé par §6.2) ; tout moteur
  d'exécution ; le câblage d'un `rule_id` sur `ExpertEvent` ;
  l'exposition du catalogue via `--json-report`/GUI ; README.md à
  nouveau non modifié, même raison qu'en Session 46 (aucune capacité
  visible pour l'utilisateur final). Cause probable/impact et Sessions 3
  à 11 de la section 13.3 : entièrement à faire, inchangé.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (section 6.2, "bibliothèque de règles d'expertise réseau" — premier jalon — Session 46)

- **Périmètre choisi pour cette session** : la Session 45 clôturait les
  onze champs cible d'`ExpertEvent` et ne laissait plus, dans la
  Session 2 (§13.3), que la bibliothèque de règles déclarative au sens
  strict décrite en §6.2 — explicitement qualifiée de « moteur à part
  entière, pas un champ » et « probablement la dernière feature de la
  Session 2, ou le premier jalon substantiel s'il s'avère trop large
  pour une seule session ». Ce lot traite le second cas : nouveau
  module `netcross_core/expert_rules.py` avec le contrat `Rule` (douze
  champs calqués EXACTEMENT sur le schéma de §6.2 — id, domaine,
  préconditions, métriques requises, fenêtre temporelle, seuils/
  percentiles, contexte requis, règle de corrélation, sévérité,
  confiance, explication, pistes de vérification) et un catalogue de
  **quinze règles** couvrant les **treize règles « déjà présentes »**
  nommées explicitement par §6.2 : « pertes par segment,
  retransmissions TCP, fenêtres à zéro, RST, SYN sans réponse,
  variation de TTL, remarking QoS, fragmentation, saturation,
  bufferbloat, RTP, DHCP et SIP ».
- Treize concepts nommés, quinze entrées de catalogue : les
  « retransmissions TCP » se décomposent en trois signatures déjà
  distinctes et déjà classées séparément par tshark
  (`_analyse_retransmission_types` — fast/RTO/spurious, trois sévérités
  différentes) plutôt qu'une seule entrée qui aurait masqué cette
  distinction ; les douze autres concepts correspondent chacun à une
  seule entrée (DHCP et SIP regroupent chacun deux signatures internes
  qui partagent déjà la même sévérité `"anomalie"`, donc une seule
  règle sans perte d'information).
- **Ce catalogue NE RÉIMPLÉMENTE AUCUNE détection** : chaque règle
  DÉCRIT un détecteur qui existe déjà et reste la seule source de
  vérité (`netcross_core.analysis` pour les compteurs de `Report`,
  `netcross_report.synthesis.build_findings` pour la transformation en
  `Finding`). Même discipline que `_KNOWN_FLAGS`/`_REMEDIATION`
  (`netcross_core.wireshark_expert`, Session 1/45) : une table de
  référence formalisée à partir de code déjà écrit et déjà testé,
  jamais une heuristique inventée. Chaque champ de chaque règle a été
  vérifié directement contre le code source (noms de champs `Report`/
  `Pkt`, valeurs de seuils numériques littérales) avant rédaction.
- `domain` reprend EXACTEMENT les valeurs de `Finding.category`
  (`netcross_report.synthesis`) — pas une nouvelle taxonomie — vérifié
  par un test qui construit un `Report` minimal, appelle
  `build_findings()` et confirme que les catégories réellement
  produites correspondent aux domaines du catalogue
  (`test_domaines_correspondent_a_des_finding_category_reels`).
- `confidence` : échelle à cinq paliers discrets documentée dans la
  docstring de module (0.9 lecture déterministe native ; 0.8
  correspondance déterministe multi-points par identifiant exact ; 0.75
  corrélation déterministe de deux signaux avec une hypothèse
  structurelle assumée ; 0.7 heuristique dépendant d'une hypothèse de
  topologie/ordre ; 0.6 estimation statistique) — PAS la même échelle
  que `ExpertEvent.confidence` (1.0/0.7/0.4, Session 40), volontairement
  distincte pour ne pas laisser croire aux deux qu'elles mesurent la
  même chose.
- `correlation_rule` : quatre règles seulement portent une valeur non
  `None` (saturation, bufferbloat, remarquage QoS, fragmentation) —
  celles qui croisent déjà réellement DEUX signaux bruts distincts dans
  le code existant, mais via un code figé entre deux compteurs précis,
  PAS un moteur générique capable de fusionner N `ExpertEvent`
  arbitraires selon une règle déclarée (ce moteur générique reste la
  Session 3, absente).
- 26 nouveaux tests (`tests/test_expert_rules.py`, nouveau fichier) :
  forme du contrat `Rule`, structure du catalogue (15 entrées, ids
  uniques, sévérités/confiances valides, quatre règles corrélées
  exactement), `get_rule`/`list_rules`, seuils numériques pinnés
  (recopiés depuis `analysis.py`/`synthesis.py` au moment de la
  rédaction), et le test de traçabilité domaine ↔ `Finding.category`
  ci-dessus. Total **856/856**.
- Validation : suite complète rejouée avant (830/830, hérités de la
  Session 45, confirmés intacts) et après (856/856, +26 net) ; `ruff
  check .`/`ruff format --check .` propres ; `lint-imports` (65
  fichiers, 164 dépendances, contrat respecté) ; `mypy
  --ignore-missing-imports` sur le fichier source modifié : 0 erreur
  imputable à `expert_rules.py`, les 14 erreurs préexistantes
  accessibles depuis `netcross_core` (sous-ensemble des 27 documentées)
  reconfirmées inchangées. Pas de validation bout en bout via un pcap
  réel cette fois : contrairement aux Sessions 40-45 qui ajoutaient un
  champ exposé dans `--json-report` (donc vérifiable sur une sortie CLI
  réelle), ce catalogue n'est câblé nulle part dans le pipeline CLI/
  JSON/GUI — rien de plus à observer sur une sortie réelle que ce que
  les tests unitaires (déjà réels, construits sur des `Report`
  directement peuplés, même méthode que `test_synthesis.py`) couvrent
  déjà.
- Non traité : les règles « nouvelles » de §6.2 (DNS lent, PMTUD noir,
  NAT/FW silencieux, anomalies L2, options TCP incompatibles,
  négociations TLS incomplètes) ; tout moteur d'EXÉCUTION qui
  évaluerait une `Rule` contre un `Report` pour PRODUIRE un
  `ExpertEvent`/`Finding` (ce catalogue reste descriptif) ; le câblage
  d'un `rule_id` sur `ExpertEvent` ; l'exposition du catalogue via
  `--json-report`/GUI. README.md non modifié cette session : le
  catalogue n'ajoute aucune capacité visible pour l'utilisateur final
  (rien ne change dans la sortie CLI/PDF/GUI), à la différence des
  sessions précédentes qui touchaient toutes `--json-report`. Cause
  probable/impact et Sessions 3 à 11 de la section 13.3 : entièrement à
  faire, inchangé.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (Session 2 de la section 13.3, "moteur d'événements d'expertise" — cinquième et dernier lot — Session 45)

- **Périmètre choisi pour ce lot** : la Session 44 laissait deux points
  dans la Session 2 avant de basculer sur la Session 3 : l'action de
  vérification/remédiation et la bibliothèque de règles déclarative
  (§6.2). Ce lot traite le premier : `ExpertEvent` gagne un nouveau
  champ `remediation: str | None` (défaut `None`, rétrocompatible) —
  dernier des onze champs du schéma cible de la section 6.1 accessible
  sans le moteur de corrélation causale de la Session 3.
- Contrairement à tous les champs des lots précédents de cette Session 2
  (`confidence`/`first_seen`/`last_seen`/`layer`/`protocol`/`flow_keys`/
  `packet_evidence` — tous LUS depuis une donnée déjà disponible, jamais
  devinés), `remediation` est un texte **rédigé** par ce projet : une
  piste de vérification technique courte (une à deux phrases, au
  conditionnel/à l'impératif de suggestion, jamais une affirmation de
  diagnostic définitif) associée au nom de flag EK connu ayant produit
  le signal.
- Nouvelle table `netcross_core.wireshark_expert._REMEDIATION` :
  volontairement restreinte aux onze flags déjà répertoriés dans
  `_KNOWN_FLAGS` (les seuls dont ce projet connaisse déjà le sens exact
  et la sévérité) — `_remediation_for()` retourne `None` pour tout flag
  absent de cette table, plutôt qu'un conseil générique inventé sans
  connaître la nature réelle du signal. Contrairement à `_flag_severity`
  (repli sur `_DEFAULT_SEVERITY` pour un flag inconnu), il n'existe pas
  d'équivalent « prudent » à une piste de vérification : soit le flag
  est déjà connu et documenté, soit aucun conseil n'est proposé.
  Calculé uniquement côté `netcross_core.wireshark_expert.
  build_wireshark_expert_events()` (source `"tshark"`), une seule fois
  par (point, flag) — constant pour un flag donné, comme `layer`/
  `protocol`, pas recalculé par occurrence.
- **Volontairement laissé à `None` côté source `"netcross"`**
  (`netcross_report.build_expert_events()`) — généraliser `remediation`
  aux `Finding` Netcross supposerait une bibliothèque de textes par
  CATÉGORIE (pas par flag EK — `Finding` n'expose aucun flag EK), un
  chantier de rédaction bien plus large portant sur les ~20 catégories
  de `Finding.category` (Pertes, Saturation, Routage, QoS, Fragmentation,
  VLAN, TCP, RTP/MOS, Réseau/Serveur, DHCP, SIP, PMTUD, NAT/FW, ARP, STP,
  TLS x2, MSS, DNS, HTTP) — non cadré ni rédigé dans cette passe, hors
  périmètre explicite plutôt qu'un oubli silencieux.
- `netcross_report/json_report.py` : `_expert_event_dict()` sérialise la
  nouvelle clé `remediation` (chaîne ou `null`).
- 10 nouveaux tests (`test_expert_model.py` +2, `test_wireshark_expert.py`
  +5, `test_json_report.py` +3). Total **830/830**.
- Validation bout en bout avec un vrai `tshark`/pcap `scapy` (voir
  `docs/sessions/session-45.md`) : un pcap synthétique (handshake TCP +
  retransmission d'un segment applicatif + ACK à fenêtre nulle) confirme
  `remediation` renseignée avec le texte attendu de `_REMEDIATION` pour
  `tcp.analysis.retransmission` et `tcp.analysis.zero_window`, et `None`
  pour les flags de suivi de connexion TCP (`tcp.completeness`, hors
  `_KNOWN_FLAGS`) — vérifié à la fois sur `cross_capture_analyzer_cli.py
  --json-report` et sur `cross_capture_diff_cli.py --json-report`
  (même fonction de sérialisation partagée), tshark 4.2.2.
- Non traité : la bibliothèque de règles déclarative au sens strict
  décrite en 6.2 (un moteur à part entière — préconditions, fenêtre
  temporelle, corrélation —, pas un champ), cause probable/impact
  (bascule vers la Session 3). Avec ce lot, les DIX champs du schéma
  cible de la section 6.1 accessibles sans le moteur de corrélation
  causale de la Session 3 sont désormais tous portés par `ExpertEvent`
  (seuls `cause`/`impact` restent `None`) ; il ne reste dans la
  Session 2 que la bibliothèque de règles déclarative (§6.2). Sessions 3
  à 11 de la section 13.3 : entièrement à faire, inchangé.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (Session 2 de la section 13.3, "moteur d'événements d'expertise" — quatrième lot — Session 44)

- **Périmètre choisi pour ce lot** : la Session 43 laissait explicitement
  « points/paquets concernés comme listes structurées » en tête des
  points restants (deuxième des deux points listés après `flow_keys`).
  Ce lot le traite : `ExpertEvent` gagne un nouveau champ
  `packet_evidence: list[PacketEvidence]` (défaut `[]`, rétrocompatible).
- `packet_evidence` réutilise l'objet de contrat `PacketEvidence` déjà
  introduit en Session 35 (via `EvidenceLink.packet`) — PAS une nouvelle
  notion, seulement une seconde exposition du même objet, mais couvrant
  ici la TOTALITÉ des occurrences d'un (point, flag) au lieu des
  `_MAX_EXAMPLES` (5) exemples plafonnés déjà portés par `evidence` :
  un flux avec des centaines de retransmissions n'expose aujourd'hui que
  5 numéros de trame via `evidence`, ce champ expose tous les numéros
  réels.
- Calculé uniquement côté `netcross_core.wireshark_expert.
  build_wireshark_expert_events()` (source `"tshark"`), un
  `PacketEvidence(point, frame_number)` par occurrence dont `pk.
  frame_number` est disponible — même garde défensive (`None` toléré,
  jamais deviné) que pour `evidence`. Aucune déduplication nécessaire :
  `pk.expert_flags` ne répète jamais le même nom de flag pour un même
  paquet, donc chaque (point, flag) ne visite un `pk` donné qu'une seule
  fois — chaque numéro de trame n'apparaît donc naturellement qu'une
  fois.
- **Volontairement laissé à `[]` côté source `"netcross"`**
  (`netcross_report.build_expert_events()`) — même discipline que
  `flow_keys` : `Finding`/`EvidenceLink` ne portent un `PacketEvidence`
  que pour la seule catégorie PMTUD déjà câblée (Session 35), et
  seulement pour les exemples plafonnés conservés dans `evidence` —
  aucune liste de LA TOTALITÉ des numéros de trame n'existe côté
  `Finding` aujourd'hui, quelle que soit la catégorie ; l'inventer
  aurait été relire `evidence` en prétendant qu'elle est complète alors
  qu'elle ne l'est pas.
- `netcross_report/json_report.py` : `_expert_event_dict()` sérialise la
  nouvelle clé (`[{"point": ..., "frame_number": ...}, ...]`, même
  format que la clé `frame_number` optionnelle déjà portée par
  `evidence`).
- 9 nouveaux tests (`test_expert_model.py` +2, `test_wireshark_expert.py`
  +5, `test_json_report.py` +2). Total **820/820**.
- Validation bout en bout avec un vrai `tshark`/pcap `scapy` (voir
  `docs/sessions/session-44.md`) : un pcap synthétique de 8 retransmissions
  du même segment (au-delà du plafond de 5) confirme `evidence` limitée à
  5 exemples et `packet_evidence` portant bien les 7 numéros de trame
  réels (frames 4 à 10), tshark 4.2.2.
- Non traité : action de vérification/remédiation, la bibliothèque de
  règles déclarative au sens strict décrite en 6.2, cause probable/
  impact (bascule vers la Session 3). Généralisation de
  `packet_evidence` aux événements de source `"netcross"` : non traitée
  pour la même raison que `flow_keys` (donnée absente de `Finding`, pas
  une simple omission). Restent donc dans la Session 2 : action de
  vérification/remédiation et la bibliothèque de règles déclarative
  (§6.2) — les autres points du schéma cible de la section 6.1 sont
  désormais tous traités ou explicitement basculés vers la Session 3.
  Sessions 3 à 11 de la section 13.3 : entièrement à faire, inchangé.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (Session 2 de la section 13.3, "moteur d'événements d'expertise" — troisième lot — Session 43)

- **Périmètre choisi pour ce lot** : la Session 41 laissait explicitement
  « flux/paquets concernés comme listes structurées » en tête des points
  restants. Ce lot traite le premier des deux : `ExpertEvent` gagne un
  nouveau champ `flow_keys: list[tuple]` (défaut `[]`, rétrocompatible)
  — les paquets concernés (au-delà des exemples plafonnés d'`evidence`)
  restent non traités, voir « Non traité » ci-dessous.
- `flow_keys` reprend au sens EXACT `netcross_core.correlate.
  flow_key()` — `(proto, src, sport, dst, dport, key_id)` en mode strict
  — PAS une nouvelle notion d'identité de flux : un consommateur
  retrouve directement le `Flow` correspondant en comparant `Flow.key` à
  un élément de cette liste, sans relire de paquet brut.
- Calculé uniquement côté `netcross_core.wireshark_expert.
  build_wireshark_expert_events()` (source `"tshark"`), en réutilisant
  `flow_key()` sans aucune nouvelle logique de corrélation. Appliqué à
  la TOTALITÉ des occurrences d'un (point, flag) — pas seulement aux
  `_MAX_EXAMPLES` exemples plafonnés conservés dans `evidence`, même
  discipline que `first_seen`/`last_seen` (Session 40) — dédoublonné
  dans l'ordre de première rencontre.
- **Délibérément non trié** : `key_id`/`sport`/`dport` mélangent `int`
  et `None` selon le protocole du paquet (ARP/STP notamment) ; un tri
  naïf (`sorted()`) lèverait `TypeError` en comparant les deux types à
  la même position de tuple. L'ordre d'insertion (déterministe tant que
  l'itération sur `all_packets` l'est, déjà le cas ailleurs dans ce
  module) est la seule option sûre sans introduire une clé de tri
  artificielle.
- **Volontairement laissé à `[]` côté source `"netcross"`**
  (`netcross_report.build_expert_events()`) — même discipline que
  `confidence`/`layer`/`protocol` : `Finding`/`EvidenceLink` ne portent
  aujourd'hui qu'un numéro de trame optionnel (`PacketEvidence.
  frame_number`), pas les autres champs du 5-tuple (`sport`/`dport`/
  `key_id`...) nécessaires pour reconstruire un `flow_key()` exact — le
  déduire depuis le seul point/texte d'`evidence` aurait été une
  supposition, pas une lecture.
- `netcross_report/json_report.py` : `_expert_event_dict()` sérialise la
  nouvelle clé (tuples convertis en listes, même convention que
  `Conversation.flow_keys` juste au-dessus dans le même fichier).
- 9 nouveaux tests (`test_expert_model.py` +2, `test_wireshark_expert.py`
  +5, `test_json_report.py` +2). Total **811/811**.
- Non traité : points/paquets concernés comme listes structurées
  au-delà des exemples plafonnés (deuxième point restant), cause
  probable/impact (Session 3), action de vérification/remédiation, et
  la bibliothèque de règles déclarative au sens strict décrite en 6.2.
  Généralisation de `flow_keys` aux événements de source `"netcross"` :
  non traitée pour la même raison que `confidence`/`layer`/`protocol`
  (donnée absente de `Finding`, pas une simple omission). Sessions 3 à
  11 de la section 13.3 : entièrement à faire, inchangé.

### Contrainte d'environnement de cette session

Ni `tshark` ni accès `apt`/`sudo` disponibles dans cet environnement
(le réseau est restreint aux dépôts de paquets PyPI/npm/crates/GitHub,
pas aux dépôts système Ubuntu) — contrairement à ce que rapportent les
Sessions 39-41. `pytest`/`ruff`/`import-linter`/`pre-commit` en revanche
tous disponibles et exécutés réellement (installés via `pip`) : suite
complète, lint, format et contrat de couches vérifiés pour de vrai,
seule la validation empirique bout en bout avec un `tshark` réel (comme
les sessions précédentes de cette même feature) n'a pas pu être
reconduite ici. Le test unitaire équivalent
(`test_build_wireshark_expert_events_flow_keys_*`, données synthétiques
via `conftest.make_pkt`) reste la seule validation disponible pour ce
lot dans cet environnement.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (Session 2 de la section 13.3, "moteur d'événements d'expertise" — deuxième lot — Session 41)

- **Périmètre choisi pour ce lot** : la Session 40 laissait explicitement
  de côté « couche réseau/protocole explicites » comme « question de
  conception non triviale, mieux traitée seule ». Ce lot la traite :
  `ExpertEvent` gagne deux nouveaux champs optionnels du schéma cible de
  la section 6.1, `layer: str | None` (couche OSI : `"liaison"`/
  `"reseau"`/`"transport"`) et `protocol: str | None` (`"ARP"`/`"STP"`/
  `"IPv4"`/`"IPv6"`/`"ICMP"`/`"ICMPv6"`/`"TCP"`/`"UDP"`) — `None` par
  défaut, rétrocompatible.
- Calculés uniquement côté `netcross_core.wireshark_expert.
  build_wireshark_expert_events()` (source `"tshark"`), via une nouvelle
  fonction `_layer_and_protocol_for()` : un nom de flag EK brut est
  TOUJOURS construit comme `"{clé_couche}_{nom_de_champ}"` (ex :
  `tcp_tcp_analysis_retransmission`), et aucune des huit clés EK
  réellement lues par `pcap_parser.packet` (`ip`/`ipv6`/`arp`/`stp`/
  `tcp`/`udp`/`icmp`/`icmpv6`) ne contient elle-même de underscore —
  `flag_name.split("_", 1)[0]` isole donc TOUJOURS la clé exactement,
  une propriété structurelle de la convention EK, jamais une déduction.
  Nouvelle table `_LAYER_AND_PROTOCOL` traduit cette clé en (couche,
  protocole) ; repli `(None, None)` pour un préfixe inconnu (ne devrait
  jamais arriver en pratique, ensemble fermé), jamais une supposition.
- **Volontairement laissés à `None` côté source `"netcross"`**
  (`netcross_report.build_expert_events()`) — et PAS par manque de
  temps : `Finding.category` est un regroupement MÉTIER (`"Pertes"`,
  `"Saturation"`, `"Routage"`, `"Réseau/Serveur"`...) qui ne correspond
  pas à un protocole ni une couche unique pour plusieurs de ces
  catégories (`"Pertes"`/`"Saturation"` s'appliquent à n'importe quel
  protocole transporté). Inventer l'association aurait été une
  supposition fabriquée, pas une donnée lue — même discipline que
  `cause`/`impact` (Session 3, absente) et `confidence`/`first_seen`/
  `last_seen` côté `"netcross"` (Session 40).
- `netcross_report/json_report.py` : `_expert_event_dict()` sérialise
  les deux nouvelles clés (`layer`/`protocol`).
- 15 nouveaux tests (`test_expert_model.py` +2, `test_wireshark_expert.
  py` +10, `test_expert_events.py` +1, `test_json_report.py` +2). Total
  **802/802**.
- Validation bout en bout avec un vrai `tshark` 4.2.2/pcap `scapy`
  (réseau disponible dans cet environnement) : pcap synthétique
  handshake TCP + retransmission rejoué via
  `cross_capture_analyzer_cli.py --json-report` réel — les trois
  `wireshark_expert_events` produits (`tcp_tcp_connection_syn`/
  `synack`, `tcp.analysis.retransmission`) portent tous
  `layer="transport"`/`protocol="TCP"` ; côté `expert_events` (source
  `"netcross"`), `layer`/`protocol` bien `null`, confirmant l'étanchéité
  de la distinction source `"tshark"`/`"netcross"`.
- Non traité : les sept autres champs du schéma cible section 6.1 (flux
  concernés, points/paquets concernés comme listes structurées au-delà
  de `evidence`, cause probable, impact, action de vérification/
  remédiation), la généralisation de `layer`/`protocol`/`confidence`/
  `first_seen`/`last_seen` aux événements de source `"netcross"`, et le
  reste de la Session 2 (le « moteur de règles d'expertise » au sens
  strict — préconditions, fenêtre temporelle, corrélation, décrit en
  section 6.2). Sessions 3 à 11 de la section 13.3 : entièrement à
  faire, inchangé.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (Session 2 de la section 13.3, "moteur d'événements d'expertise" — premier lot — Session 40)

- **Périmètre choisi pour ce premier lot** : la Session 2 (difficulté
  5/5) vise, d'après le schéma cible de la section 6.1, un `ExpertEvent`
  portant catégorie / couche réseau / protocole / sévérité / confiance /
  première-dernière occurrence / points concernés / flux concernés /
  paquets concernés / cause probable / impact / action de vérification.
  Plutôt que d'esquisser les onze champs à la fois (plusieurs supposent
  des décisions de conception non triviales — lien vers `Flow`, notion
  d'"action de remédiation"...), ce premier lot traite les DEUX champs
  les plus directement calculables sur la donnée déjà disponible :
  **confiance** et **première/dernière occurrence** — même discipline
  que les sessions précédentes (Session 32/35 : un cablage réel et
  testé sur un périmètre serré, plutôt qu'une esquisse partout).
- `ExpertEvent` (`netcross_core.expert_model`) gagne trois nouveaux
  champs optionnels : `confidence: float | None`, `first_seen: float |
  None`, `last_seen: float | None` — `None` par défaut, rétrocompatible
  avec tout `ExpertEvent` déjà construit (même convention que `source`
  ajouté en Session 1).
- Calculés uniquement côté `netcross_core.wireshark_expert.
  build_wireshark_expert_events()` (source `"tshark"`) : `confidence`
  reflète la nature de la donnée, pas une probabilité calibrée — 1.0 si
  la sévérité est NATIVE tshark pour ce (point, flag), 0.7 si le flag
  est seulement connu de la table `_KNOWN_FLAGS` maintenue à la main par
  ce projet, 0.4 sinon (nom EK brut jamais vu). `first_seen`/`last_seen`
  sont le min/max de `pk.ts` sur la TOTALITÉ des occurrences d'un
  (point, flag), pas seulement les `_MAX_EXAMPLES` exemples plafonnés
  conservés dans `evidence` — même parcours que le compteur
  d'occurrences déjà existant, aucun coût supplémentaire.
- **Volontairement laissés à `None` côté source `"netcross"`**
  (`netcross_report.build_expert_events()`, à partir d'un `Finding`) :
  `Finding` ne porte aujourd'hui aucune notion de confiance ni de
  timestamp — ni directement, ni via `EvidenceLink`/`PacketEvidence`
  (qui n'exposent qu'un numéro de trame, pas un instant). Les y ajouter
  aurait exigé soit de deviner une valeur non mesurée, soit de faire
  remonter des timestamps depuis `Report`/`analysis.py` jusqu'à
  `Finding` — une extension distincte, hors périmètre de ce premier lot.
- `json_report.py` (`_expert_event_dict`) sérialise les trois nouvelles
  clés, `null` côté `expert_events`/`diagnoses` comme documenté.
- 13 nouveaux tests (`test_expert_model.py` +2, `test_wireshark_expert.
  py` +8, `test_expert_events.py` +1, `test_json_report.py` +2). Total
  **787/787**.
- Validation bout en bout avec un vrai `tshark`/pcap `scapy` (réseau
  disponible dans cet environnement, comme en Session 39) : pcap
  synthétique avec une vraie retransmission TCP rejoué via
  `cross_capture_analyzer_cli.py --json-report` réel — `confidence=1.0`
  et `first_seen`/`last_seen` corrects sur les trois signaux tshark
  produits (`tcp_tcp_connection_syn`/`synack`, `tcp.analysis.
  retransmission`), `confidence`/`first_seen` bien `null` côté
  `expert_events` (source `"netcross"`).
- Non traité : les neuf autres champs du schéma cible section 6.1
  (couche réseau/protocole explicites, points/flux/paquets concernés
  comme listes structurées, cause probable, impact, action de
  vérification/remédiation), la généralisation de `confidence`/
  `first_seen`/`last_seen` aux événements de source `"netcross"`, et le
  reste de la Session 2 (le "moteur de règles d'expertise" au sens
  strict — préconditions, fenêtre temporelle, corrélation, décrit en
  section 6.2). Sessions 3 à 11 de la section 13.3 : entièrement à
  faire, inchangé.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (Session 1 de la section 13.3, "exploitation de l'expertise Wireshark/TShark" — second lot, clôture — Session 39)

- **Changement d'environnement notable** : contrairement à **toutes**
  les sessions depuis la Session 3 (voir leurs sections "Contrainte
  d'environnement"), cette session dispose d'un accès réseau réel
  (`archive.ubuntu.com`/`pypi.org` atteignables) : `tshark` 4.2.2 (la
  version exacte déjà citée dans tout ce fichier) a pu être installé
  via `apt-get`, ainsi que `pytest`/`ruff`/`import-linter`/`mypy`/
  `scapy` via `pip`. Détaillé dans "Validation" ci-dessous ; mentionné
  ici en tête parce que c'est ce qui a rendu possible le second point
  ci-dessous (impossible à vérifier sans tshark réel) et le bug trouvé
  juste après (invisible sans lui). Un pcap scapy synthétique
  (handshake + retransmission réelle, puis variantes avec checksum TCP/
  IP volontairement invalide pour déclencher des conditions
  d'expertise multiples) a été rejoué avec ce vrai tshark pour vérifier
  empiriquement, plutôt que supposer, la structure exacte de `_ws_expert`
  une fois `_ws.expert.severity`/`.group`/`.message` en jeu — jamais
  fait auparavant (la Session 38, qui a posé `_ws_expert__ws_expert_
  message` dans ses fixtures de test, l'avait anticipé sans jamais
  pouvoir le vérifier ni voir son effet une fois combiné à severité/
  groupe, tous deux alors inconnus de ce projet).
- **Piste retenue** : la Session 38 a explicitement laissé deux items
  ouverts pour clore la Session 1 : "sévérité/groupe/message natifs
  tshark" et "couches autres que TCP" (Console/PDF/GUI restent hors
  scope, cohérent avec les cinq objets de la Session 0 jamais câblés là
  non plus — voir section 13.3, inchangé). Les deux sont traités
  ensemble dans cette session : ils touchent le même calcul dans
  `pcap_parser/packet.py` (autant le refactorer une seule fois), et
  leur combinaison clôt entièrement la Session 1 plutôt que de la
  laisser fractionnée sur encore une session. Contrairement à la
  Session 38, la sévérité/le groupe/le message natifs ne sont **plus**
  une extension non vérifiable : voir ci-dessus.
- **Bug de conception trouvé et corrigé avant livraison** (même
  discipline que le bug de la Session 38 sur le libellé reconstruit) :
  `expert_flag_names()` ne filtrait pas les trois champs descriptifs
  génériques (`_ws_expert__ws_expert_severity`/`.group`/`.message`) qui
  accompagnent TOUJOURS un nom de condition dans une occurrence
  `_ws_expert` réelle — vérifié seulement dans cette session, faute de
  tshark réel avant. Résultat concret avec un vrai tshark : **chaque**
  signal d'expertise réel aurait fait remonter ces trois clés comme si
  elles étaient elles-mêmes des noms de flag indépendants dans
  `RawPacket.expert_flags`, et `build_wireshark_expert_events()` (qui
  itère ce tuple sans distinction) aurait donc construit, en plus du
  vrai événement, jusqu'à trois `ExpertEvent` parasites par (point,
  signal) — ex: un "événement" `_ws_expert__ws_expert_message : 1
  occurrence(s)..." dans le rapport JSON, sans aucun rapport avec un
  signal réseau. Jamais détecté en Session 38 : son test le plus
  proche (`test_expert_flag_names_plusieurs_flags_tries`) posait déjà
  la clé message dans sa fixture mais ne vérifiait que la présence des
  DEUX noms de condition attendus dans un tuple plus long, sans
  assertion d'égalité stricte qui aurait révélé la clé en trop, et sans
  jamais combiner ce test à `build_wireshark_expert_events()`. Corrigé
  en excluant ces trois clés connues (`_META_KEYS`) dans
  `expert_flag_names()` ; le test existant est mis à jour (assertion
  stricte, désormais sans la clé message) et un nouveau test dédié
  (`test_expert_flag_names_exclut_les_champs_meta_severite_groupe_
  message`) verrouille la régression. Voir "Ce qui a été livré".
- **Décisions de conception sur la richesse native** :
  - Sévérité/groupe sont rendus par tshark comme des **codes entiers**
    en sortie EK (chaîne décimale, ex: `"4194304"`), jamais le libellé
    affiché dans l'IHM Wireshark — traduits via deux tables
    (`_SEVERITY_LABELS`/`_GROUP_LABELS` dans `ek_fields.py`) générées
    depuis `tshark -G values` (sortie authentique du binaire, pas une
    supposition ni une reconstruction depuis les constantes `PI_*`/
    `GROUP_*` internes à Wireshark de mémoire). Un code absent de ces
    tables (nouvelle valeur d'une future version de tshark) retombe sur
    sa représentation brute en chaîne, jamais un libellé deviné — même
    discipline que `_KNOWN_FLAGS`/`_flag_label` pour les noms de
    condition eux-mêmes.
  - Sévérité NATIVE tshark (`Error`/`Warning`/`Note`/`Chat`/`Comment`)
    → vocabulaire Netcross (`anomalie`/`a_surveiller`/`info`, déjà
    utilisé par `Finding.severity` ailleurs dans ce projet) : mapping
    direct par ordre de gravité (`_NATIVE_TO_NETCROSS_SEVERITY` dans
    `wireshark_expert.py`), PRIORITAIRE sur la table `_KNOWN_FLAGS`
    dès qu'elle est disponible pour au moins un exemple du (point,
    flag) — y compris pour un flag **déjà connu** de cette table (la
    native l'emporte toujours, pas seulement en repli sur les flags
    inconnus). `_KNOWN_FLAGS` reste le repli pour tout paquet sans
    `expert_details` (format d'avant cette session). Bénéfice concret
    mesuré en session : `tcp.checksum_bad` (absent de `_KNOWN_FLAGS`)
    retombait auparavant sur `_DEFAULT_SEVERITY = "info"`, sous-estimant
    clairement une vraie erreur de checksum — la sévérité native
    (`Error` → `anomalie`, vérifié empiriquement) corrige ce point sans
    devoir cataloguer chaque nouveau flag à la main.
  - Le message natif, à l'inverse, peut être **paramétré par paquet**
    (ex: `"Bad checksum [should be 0x8cfa]"`, la valeur attendue variant
    d'un paquet à l'autre pour un même flag) — contrairement à sévérité/
    groupe, propriétés constantes du TYPE de condition (définies une
    fois pour toutes côté dissecteur tshark, jamais par paquet). Ajouté
    à l'`evidence` de CHAQUE exemple individuellement (texte enrichi,
    jamais un remplacement du format existant), jamais au message agrégé
    de l'`ExpertEvent` (qui reste construit à partir du seul nom de flag
    comme avant cette session) : agréger un message potentiellement
    différent par occurrence sous un unique message aurait été trompeur
    pour un (point, flag) à plusieurs occurrences.
  - `expert_flag_details()` (nouvelle fonction publique, `ek_fields.py`)
    renvoie un 4-uplet `(name, severity, group, message)` par nom de
    condition — jamais un dict/objet dédié : cohérent avec le choix de
    la Session 1 initiale de garder `RawPacket`/`Pkt` construits
    uniquement de types primitifs/tuples (`Pkt` ne dépend toujours
    d'aucun type `pcap_parser`, voir sa docstring "aucune
    transformation" déjà en place). Vérifié empiriquement (voir premier
    point) qu'une occurrence `_ws_expert` porte en pratique EXACTEMENT
    un nom de condition, y compris avec deux conditions SIMULTANÉES sur
    un même paquet (`_ws_expert` devient alors une LISTE de deux
    occurrences INDÉPENDANTES, chacune avec sa propre sévérité/son
    propre groupe/message — jamais un mélange ambigu entre les deux).
- **Couches autres que TCP** : `expert_flags`/`expert_details` sont
  désormais l'union des signaux sur TOUTES les couches déjà extraites
  par `build_packet()` (L3 : `ip4`/`ip6`/`arp`/`stp`, une seule active à
  la fois pour un paquet donné ; L4 : `tcp`/`udp`/`icmp`/`icmpv6`, idem)
  plutôt que la seule couche TCP. Vérifié empiriquement (checksum IP
  invalide → `ip_ip_checksum_bad_expert` correctement capté, rejoué via
  `build_packet()` sur la sortie réelle de tshark) — pas seulement en
  théorie. Aucune connaissance protocolaire nouvelle requise : les huit
  variables de couche existaient déjà comme locales dans `build_packet`,
  `expert_flag_names(None)`/`expert_flag_details(None)` renvoient déjà
  un résultat vide, donc les couches non actives pour un paquet donné ne
  coûtent qu'un appel sans effet.

### Ce qui a été livré

- `pcap_parser/ek_fields.py` : `expert_flag_names()` corrigée (exclut
  `_META_KEYS`, voir bug ci-dessus) ; nouvelles constantes `_SEVERITY_
  KEY`/`_GROUP_KEY`/`_MESSAGE_KEY`/`_META_KEYS`, tables `_SEVERITY_
  LABELS`/`_GROUP_LABELS` (14+5 entrées, `tshark -G values` 4.2.2),
  fonction privée `_expert_label()`, nouvelle fonction publique
  `expert_flag_details(layer) -> tuple[tuple[str, str|None, str|None,
  str|None], ...]`.
- `pcap_parser/packet.py` : le calcul de `expert_flags` quitte la
  branche `if tcp is not None` pour devenir un calcul unique, après
  détermination de toutes les couches, unionnant `expert_flag_names()`/
  `expert_flag_details()` sur les huit couches (`ip4`, `ip6`, `arp`,
  `stp`, `tcp`, `udp`, `icmp`, `icmpv6`). Nouveau champ `RawPacket.
  expert_details : tuple[tuple[str, str|None, str|None, str|None],
  ...]`, `__slots__` mis à jour, docstrings de `expert_flags`/
  `expert_details` réécrites (la limite "TCP uniquement" est levée).
- `netcross_core/models.py`/`parsing.py` : `Pkt.expert_details` miroir
  (`__slots__` mis à jour), câblé dans `_to_pkt()` — couvert
  automatiquement par le test générique existant qui compare tous les
  champs de `RawPacket` à `Pkt` (`test_parsing_adapter.py`, comme pour
  `expert_flags` en Session 38).
- `netcross_core/wireshark_expert.py` : nouvelle table
  `_NATIVE_TO_NETCROSS_SEVERITY`, nouvelle fonction privée
  `_lookup_native_detail(pk, flag_name)`. `build_wireshark_expert_
  events()` : sévérité native prioritaire (repli `_flag_severity`
  inchangé), message natif ajouté à chaque ligne d'`evidence`, groupe
  natif ajouté au message agrégé (`"[groupe tshark : Sequence]"`).
  Docstring de module réécrite (les deux limites "pas la sévérité
  native"/"TCP uniquement" sont levées).
- `tests/conftest.py`/`test_parsing_adapter.py`/`test_redact.py` :
  `"expert_details": ()` ajouté aux fabriques `make_pkt()`/`_raw()`/
  `RawPacket(...)` locale (champ désormais obligatoire, même mise à
  jour mécanique qu'en Session 38 pour `expert_flags`).
- `README.md` : section `--json-report` de l'analyzer CLI, paragraphe
  `wireshark_expert_events` complété (sévérité native + message natif
  en evidence).

### Validation

**Environnement réseau/outils réel cette session** (voir premier point
ci-dessus) — première fois depuis le début de ce projet que la suite
complète est rejouée avec de vrais `pytest`/`ruff`/`import-linter`/
`mypy`, plutôt qu'un harnais de secours ou une relecture manuelle.

- `pytest` réel, suite complète : **750 → 774 (+24)**, tous verts.
  Répartition des 24 nouveaux/modifiés : `test_ek_fields.py` (+7 nets :
  1 test existant corrigé pour le bug ci-dessus + 1 nouveau test de
  régression dédié + 6 nouveaux tests `expert_flag_details`) ;
  `test_packet.py` (+7 nets : 1 test existant remplacé, qui affirmait
  l'ancienne limite TCP-only devenue fausse, par 2 nouveaux [signal
  non-TCP capté, union L3+L4 simultanée] + 5 nouveaux tests
  `expert_details` [natifs reconnus, code inconnu, occurrences
  multiples indépendantes, couche non-TCP, cas vide]) ;
  `test_wireshark_expert.py` (+9 : priorité native même sur flag connu,
  repli table inchangé, `Note`/`Chat`/`Comment` → `info` avec un flag
  choisi pour ne pas coïncider avec le repli, message natif dans
  l'evidence, message agrégé inchangé par le natif, groupe natif dans
  le message agrégé, non-régression stricte sans détail natif, lookup
  défensif sur un flag sans rapport).
- `ruff check .` / `ruff format --diff` (config `pyproject.toml`
  existante) : un dépassement de 120 caractères trouvé et corrigé dans
  `test_wireshark_expert.py`, sinon propre sur l'ensemble du projet, pas
  seulement les fichiers touchés.
- `lint-imports` (contrat `netcross_gtk4 → netcross_report →
  netcross_core → pcap_parser`) : 64 fichiers analysés, contrat
  respecté — `wireshark_expert.py` n'importe toujours que
  `netcross_core.expert_model`.
- `mypy --ignore-missing-imports` sur les 5 fichiers source modifiés :
  3 erreurs préexistantes (non liées à cette session, confirmées
  identiques en relisant l'archive originale non modifiée :
  `RawPacket.src`/`dst` potentiellement `None`, `netcross_core/
  parsing.py` ligne ~143) — aucune **nouvelle** erreur introduite.
  Corriger ces trois erreurs préexistantes est hors du périmètre de
  cette session (ne concerne pas la comparaison OmniPeek).
- Validation de bout en bout **avec un vrai `tshark`/pcap `scapy`**
  (impossible depuis la Session 3, voir premier point) : pcaps
  synthétiques (handshake + retransmission réelle ; variantes avec
  checksum TCP et IP volontairement invalides) rejoués via les deux
  CLI réels (`cross_capture_analyzer_cli.py --json-report`,
  `cross_capture_diff_cli.py --json-report`) — `wireshark_expert_events`
  produit correctement `severity="info"` (mapping natif `Chat`/`Note` →
  `info`, cohérent avec la table pour ces flags), message natif dans
  `evidence[].text` (ex: `"This frame is a (suspected) retransmission"`)
  et groupe natif dans `message` (`"[groupe tshark : Sequence]"`),
  `frame_number` correctement propagé. Deux flags de connexion inédits
  découverts au passage (`tcp.analysis.connection.syn`/`.synack`,
  sévérité native `Chat` → `info`) : ce projet ne les connaissait pas
  explicitement avant (absents de `_KNOWN_FLAGS`) mais sont désormais
  correctement classés grâce à la sévérité native, sans devoir les
  ajouter à la table à la main — illustration concrète du bénéfice de
  cette session.

### Non traité dans cette passe

- Sessions 2 à 11 de la section 13.3 (moteur d'événements d'expertise,
  corrélation causale, nuance `DEVIATION`...) — entièrement à faire,
  inchangé depuis la Session 37/38. La Session 1 elle-même est
  désormais complète (les deux items laissés ouverts par la Session 38
  sont traités ici).
- Console/PDF pour `wireshark_expert_events` et export JSON de la GUI
  — cohérent avec les cinq objets de la Session 0, jamais câblés là non
  plus (voir section 13.3) : question architecturale plus large
  touchant les six objets ensemble, pas spécifique à la Session 1.
- Les trois erreurs `mypy` préexistantes relevées en Validation
  (non liées à la comparaison OmniPeek).

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (Session 1 de la section 13.3, "exploitation de l'expertise Wireshark/TShark" — premier lot — Session 38)

- **Piste retenue** : la Session 37 avait explicitement noté que "la
  suite des Sessions 1 à 11 de la section 13.3 reste entièrement à
  faire". Cette session reprend au premier item non traité du
  découpage recommandé : la Session 1 ("exploitation de l'expertise
  Wireshark/TShark", difficulté 3/5). Même leçon méthodologique que la
  Session 0 (voir section 13.3) : "exploiter l'expertise Wireshark/
  TShark" ne veut pas dire couvrir toute la spécification d'un coup
  (sévérité/groupe/message natifs tshark, toutes les couches
  protocolaires, statistiques globales) — un premier lot, réel et
  testé, plutôt qu'une tentative incomplète sur tout le périmètre.
  Scope retenu : généraliser la détection d'expertise TCP déjà
  existante (`has_expert_flag`, qui ne testait qu'un flag connu à la
  fois pour les trois retransmissions), puis convertir cette vue brute
  en `ExpertEvent` — objet déjà posé par la Session 0/36 — plutôt que
  d'inventer un nouveau type. Voir section 13.3 pour le détail complet
  de ce qui est traité et volontairement laissé de côté dans ce
  premier lot.
- **Distinction centrale** : la consigne de la section 13.3 est
  explicite — "il ne faut pas considérer les signaux Wireshark comme
  des diagnostics définitifs, ils constituent des preuves
  supplémentaires". `ExpertEvent` gagne donc un champ `source`
  (`"netcross"` par défaut, rétrocompatible avec tout `ExpertEvent`
  construit avant cette session — `"tshark"` pour les événements bruts
  de cette session) : un signal tshark déjà exploité par un détecteur
  Netcross dédié (ex: `tcp.analysis.retransmission`, déjà classifié
  fast/RTO/spurious par `_analyse_retransmission_types`) continue
  d'apparaître aussi sous sa forme brute — volontaire, pas une
  duplication à corriger : le `Finding`/`ExpertEvent` Netcross
  (`source="netcross"`) est un diagnostic déjà catégorisé et
  priorisé ; l'`ExpertEvent` tshark brut (`source="tshark"`) est la
  preuve source, moins interprétée. Cle JSON dédiée
  `wireshark_expert_events`, jamais fondue avec `expert_events`.
- **Bug de conception trouvé et corrigé avant livraison** : une
  première version tentait de reconstruire le libellé lisible d'un nom
  de champ EK brut algorithmiquement (`tcp_tcp_analysis_fast_
  retransmission` → retirer le premier segment, rejoindre le reste par
  des points). Faux en général : plusieurs noms de champ tshark
  contiennent eux-mêmes un underscore dans leur dernier segment
  (`tcp.analysis.fast_retransmission`, `.zero_window`...) — rien dans
  le nom EK ne distingue un underscore qui était un point de celui qui
  appartenait déjà au nom. `test_wireshark_expert.py` l'a détecté avant
  toute livraison (reconstruction produisait `tcp.analysis.fast.
  retransmission`, un point en trop). Corrigé par une table explicite
  (`_KNOWN_FLAGS`, flag connu par flag connu, libellé ET sévérité
  ensemble) plutôt qu'une reconstruction générique : un flag inconnu de
  la table garde son nom EK brut, moins lisible mais jamais trompeur.
- **Câblage réel** : les deux CLI calculent `wireshark_expert_events`
  (`build_wireshark_expert_events(all_packets)`/`(current_packets)`,
  déjà disponible depuis les paquets déjà parsés plus haut) et le
  transmettent à `generate_json_report()`/`generate_json_diff()`, qui
  exposent une sixième clé JSON optionnelle (absente si non fournie,
  même convention que les cinq clés de la Session 0). **Câblé dans les
  deux CLI dès cette première passe** — contrairement à la Session 0
  où la parité diff CLI avait dû attendre une session dédiée
  (Session 37), leçon retenue.

### Ce qui a été livré

- `pcap_parser/ek_fields.py` : `expert_flag_names(layer)` — généralise
  `has_expert_flag()` : renvoie TOUS les noms de champs présents sous
  `_ws_expert` pour une couche, triés, plutôt que de tester un nom
  connu à la fois. Tolère `_ws_expert` en liste (plusieurs conditions
  simultanées) comme `has_expert_flag()` le fait déjà.
- `pcap_parser/packet.py` : nouveau champ `RawPacket.expert_flags:
  tuple[str, ...]`, peuplé sur la couche TCP (seule couche où ce projet
  lit déjà `_ws_expert`) via `expert_flag_names(tcp)` ; tuple vide sur
  tout paquet non-TCP ou sans aucune condition d'expertise active (cas
  le plus fréquent).
- `netcross_core/models.py`/`parsing.py` : `Pkt.expert_flags` miroir,
  câblé dans `_to_pkt()` — couvert automatiquement par le test générique
  existant qui compare tous les champs de `RawPacket` à `Pkt`
  (`test_parsing_adapter.py`).
- `netcross_core/expert_model.py` : `ExpertEvent` gagne `source: str =
  "netcross"` (voir "Distinction centrale" ci-dessus). Docstring
  étendue avec le detail complet.
- `netcross_core/wireshark_expert.py` (nouveau module, ~90 lignes utiles)
  : `build_wireshark_expert_events(all_packets) -> list[ExpertEvent]` —
  regroupe par (point, flag) distinct, `evidence` plafonnée à 5
  exemples (même plafond que les `*_examples` de `Report` ailleurs dans
  ce projet), table `_KNOWN_FLAGS` (11 flags TCP déjà connus de ce
  projet : les trois retransmissions + duplicate_ack/zero_window/
  window_full/keep_alive/out_of_order/lost_segment/ack_lost_segment/
  reused_ports) avec libellé lisible ET sévérité Netcross estimée.
  Exporté depuis `netcross_core/__init__.py`.
- `netcross_report/json_report.py` : `_expert_event_dict()` expose
  désormais `source` ; `generate_json_report()`/`generate_json_diff()`
  gagnent un paramètre optionnel `wireshark_expert_events=None` → clé
  JSON `wireshark_expert_events` (absente si non fourni).
- `cross_capture_analyzer_cli.py`/`cross_capture_diff_cli.py` : import +
  calcul + transmission de `wireshark_expert_events` dans le bloc
  `--json-report` des deux CLI.
- `tests/conftest.py` : `make_pkt()` gagne `"expert_flags": ()` dans ses
  valeurs par défaut (champ `Pkt` désormais obligatoire) ; même mise à
  jour dans les fabriques locales de `test_parsing_adapter.py` et
  `test_redact.py` qui construisent directement `RawPacket`.
- `README.md` : section `--json-report` de l'analyzer CLI étendue avec
  la sixième clé.

### Validation

**`pytest`/`ruff`/`lint-imports` non disponibles dans cet environnement**
(pas d'accès réseau pour les installer — même contrainte que la
Session 8, contrainte différente des sessions qui semblent avoir eu
accès à ces outils, ex: Sessions 36/37). Un petit harnais de secours a
été écrit (`run_tests_fallback.py`, resté hors du zip livré, même choix
que le harnais de la Session 8) réimplémentant uniquement ce dont la
suite a réellement besoin (vérifié par grep avant d'écrire quoi que ce
soit sur tout `tests/*.py`) : les fixtures intégrées `capsys`/
`monkeypatch`/`tmp_path` et `pytest.approx`/`pytest.raises` — aucune
classe de test, aucun `pytest.mark.parametrize`, aucun `pytest.fixture`
custom, aucun `pytest.skip` dans toute la suite existante, donc non
implémentés (auraient été du code mort).

Premier run (avant tout nouveau code) : **720/720** — confirme la
suite héritée intacte et confirme au passage le harnais lui-même
(compte identique à celui documenté en fin de Session 37 avec un vrai
`pytest`). Un bug du harnais a été trouvé et corrigé en cours de route
(forme à 2 arguments de `monkeypatch.setattr("module.attr", valeur)`
mal gérée, valeur silencieusement écrasée par `None` — confirmé
propre au harnais, pas au code du projet, en relisant `tests/
test_ek_source.py` où le symptôme est apparu). Après le nouveau champ
`Pkt.expert_flags` (obligatoire, sans valeur par défaut — voir
"Ce qui a été livré"), premier run a révélé **206 échecs en cascade**,
tous de la même cause : `conftest.make_pkt()` et les deux fabriques
locales `RawPacket` ne fournissaient pas ce nouveau champ — corrigé
(voir "Ce qui a été livré"), pas une régression du projet lui-même,
maintenance normale attendue en ajoutant un champ `Pkt` obligatoire.

30 nouveaux tests, tous rejoués réellement via le harnais :
- `test_ek_fields.py` (+5) : `expert_flag_names()` — plusieurs flags
  triés, absence, couche `None`, `_ws_expert` en liste, éléments non
  dict ignorés sans lever.
- `test_packet.py` (+4) : `expert_flags` reflète un flag présent, vide
  sans expertise, plusieurs flags simultanés sur un même paquet,
  toujours vide sur un paquet non-TCP (ARP).
- `test_expert_model.py` (+2) : `source` vaut `"netcross"` par défaut,
  `"tshark"` explicite.
- `test_wireshark_expert.py` (+16, nouveau fichier) : un événement par
  (point, flag), regroupement par point/flag distincts, un paquet
  portant plusieurs flags produit plusieurs événements, sévérité connue
  et sévérité par défaut si flag inconnu, catégorie fixe, `source`
  toujours `"tshark"`, `cause`/`impact` toujours `None`, libellé
  restauré correctement (voir "bug de conception" ci-dessus), preuve
  plafonnée à 5 exemples avec compteur exact dans le message,
  `PacketEvidence` présent/absent selon `frame_number`, texte de preuve
  mentionnant src/dst.
- `test_json_report.py` (+3) : nouvelle clé absente par défaut (report
  ET diff), exposée avec `source="tshark"` (report ET diff),
  `expert_events`/`wireshark_expert_events` bien séparés par `source`
  dans le même document.

Total : **750/750**.

**Style/lint** : `ruff`/`lint-imports` indisponibles (voir ci-dessus) —
relecture manuelle ciblée sur les règles de `pyproject.toml` (même
méthode que la Session 8) : aucune ligne > 120 caractères dans les 18
fichiers touchés (2 dépassements trouvés et corrigés dans
`wireshark_expert.py`/`test_wireshark_expert.py`), imports triés
alphabétiquement dans chaque bloc modifié (vérifié champ par champ,
pas seulement visuellement), aucun import relatif, `__all__` de
`netcross_core/__init__.py` : nouvelle entrée `build_wireshark_expert_
events` placée dans le groupe alphabétique des noms commençant par une
minuscule (convention déjà en place dans ce fichier, pas un tri global
strict). Contrat `import-linter` (couches `netcross_gtk4 →
netcross_report → netcross_core → pcap_parser`) : `netcross_core/
wireshark_expert.py` n'importe que `netcross_core.expert_model` — même
couche, aucune dépendance vers une couche supérieure. Motif de boucle
`liste = []` + `liste.append(...)` avec logique intermédiaire (calcul
de `label`/`count`/`severity`/`evidence` avant l'ajout) : déjà présent
tel quel dans `netcross_report/expert_events.py::build_expert_events`
et `netcross_core/correlate.py::build_flows`, tous deux confirmés
propres par un `ruff check` réel en Session 36/37 — cohérence retenue
plutôt qu'une réécriture en compréhension de liste non confirmée.

`python -m compileall`/`py_compile` sur les 10 fichiers source modifiés
ou créés : propre. `netcross_gtk4/app.py` non touché par cette session
et non plombé sur `wireshark_expert_events` (voir section 13.3, "non
traité") — sites d'appel `generate_json_report`/`generate_json_diff`
relus et confirmés compatibles (nouveau paramètre optionnel en dernière
position, toujours appelés par mots-clés dans ce projet, jamais par
position).

Validation de bout en bout avec un **vrai `tshark`/pcap `scapy` non
réalisable** cette session (binaire absent de cet environnement, comme
toutes les sessions depuis la Session 3). Le pipeline complet
(`build_packet()` → `RawPacket.expert_flags` → `_to_pkt()` →
`Pkt.expert_flags` → `build_wireshark_expert_events()` →
`generate_json_report()`/`generate_json_diff()`) reste vérifié de bout
en bout par les tests unitaires ci-dessus, qui exercent les mêmes
fonctions réelles que les CLI utilisent, seule la source des couches EK
étant synthétique (comme pour toute la suite existante, voir
`tests/conftest.py`).

### Contrainte d'environnement de cette session

Ni `tshark` ni `sudo`/réseau disponibles (même contournement que les
Sessions 8/35/36/37 : aucun outil externe installable). `pytest`/
`ruff`/`lint-imports` indisponibles également (contrainte de la
Session 8, pas de celle des Sessions 36/37 qui semblent y avoir eu
accès) — suppléés par le harnais de secours et la relecture manuelle
décrits dans Validation ci-dessus, à ré-exécuter avec les vrais outils
dès qu'un environnement avec accès réseau est disponible.

### Non traité dans cette passe

- Le reste de la Session 1 (sévérité/groupe/message natifs tshark,
  couches autres que TCP) — voir section 13.3 pour le détail complet
  de ce qui est volontairement laissé de côté et pourquoi.
- Sessions 2 à 11 de la section 13.3 (moteur d'événements d'expertise,
  corrélation causale, nuance `DEVIATION`...) — entièrement à faire,
  inchangé depuis la Session 37.
- Console/PDF pour `wireshark_expert_events` et export JSON de la GUI
  — cohérent avec les cinq objets de la Session 0, jamais câblés là non
  plus (voir section 13.3).

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (nettoyage des mentions "non câblé"/"non traité"/"non exposé"/"absent" — Session 37)

- **Demande** : l'utilisateur a demandé de retrouver toutes les mentions
  "non câblé"/"non traité"/"non exposé"/"absent" laissées par les
  sessions précédentes dans `docs/features-backlog.md`/`docs/sessions/` et de les finir.
  Inventaire fait par grep exhaustif (`⚠️`, "non câblé", "non traité",
  "non exposé") : la plupart des occurrences historiques dans les
  entrées de session passées décrivaient des décisions de conception
  **déjà tranchées et closes en leur temps** (ex: `sip_failed_calls`
  volontairement sans evidence, catégorie "Pertes" volontairement sans
  evidence) — non touchées ici, ce ne sont pas des lacunes. Les vraies
  lacunes encore ouvertes (marquées `⚠️` en section 2, la partie de ce
  document censée refléter l'état actuel) ont été traitées une par une :
- **`--idle-timeout-seconds` exposé en CLI** (les deux CLI) : la
  constante `_IDLE_TIMEOUT_SECONDS` (60s) de `_analyse_idle_timeout`
  restait figée depuis la Session 23. `analyse()` gagne un paramètre
  optionnel `idle_timeout_seconds=None` (défaut = comportement inchangé
  via le défaut de `_analyse_idle_timeout`), câblé sur les deux CLI. Au
  passage, une définition **morte** de `_analyse_idle_timeout` (un
  docstring sans corps, immédiatement écrasée par la vraie définition
  juste après) trouvée et supprimée dans `analysis.py` — vestige d'un
  refactor antérieur (Session 23) jamais nettoyé.
- **Parité JSON du diff CLI (Session 0)** : `generate_json_diff()` gagne
  les 5 paramètres optionnels posés en Session 36 pour
  `generate_json_report()` (`flows`/`conversations`/`expert_events`/
  `diagnoses`/`compliance`), toujours côté rapport **courant**
  uniquement (même décision que `evidence` en Session 33).
  `cross_capture_diff_cli.py` les calcule désormais dans le bloc
  `--json-report` — nécessitait de faire remonter `all_packets` du
  scénario courant hors de `_run_scenario()` (qui ne renvoyait
  auparavant que le `Report`, jamais les paquets bruts) : la fonction
  renvoie maintenant `(Report, all_packets)`.
- **`PacketEvidence` étendu aux 8 catégories restantes** (+ `DiffFinding`
  pour PMTUD, resté pilote-`Finding`-seulement depuis la Session 35) :
  NAT/Pare-feu (`idle_timeout_dropped`), ARP (`arp_ip_conflict`), STP
  (`stp_root_change`), TLS (`tls_cert_invalid_dates`,
  `tls_cert_mismatch`), TCP (`mss_clamped`), DNS (`dns_timeout`), HTTP
  (4xx/5xx/timeout) — les 9 catégories qui portaient déjà un
  `EvidenceLink` textuel portent désormais aussi un numéro de trame
  quand disponible, sur `Finding` **et** `DiffFinding`. Pour chaque
  catégorie, un `Report.<champ>_frames` parallèle au `<champ>_examples`
  existant a été ajouté (`netcross_core/models.py`), peuplé au même
  index dans `analysis.py` en réutilisant le `Pkt` déjà présent au point
  de collecte (aucune nouvelle donnée créée) — sauf pour NAT/Pare-feu
  (il fallait retenir `(ts, frame_number)` au lieu de seulement `ts`
  dans `_analyse_idle_timeout`) et ARP (retenir le dernier `Pkt` par
  IP/point). `_http_error_evidence()` (dupliquée entre `synthesis.py` et
  `baseline_diff.py`) renvoie désormais `(textes, frames)` filtrés
  ensemble par classe de statut, pour rester alignés. `_evidence()` (les
  deux copies) gagne un paramètre `frames` optionnel depuis la Session
  35 côté `synthesis.py` — désormais aussi côté `baseline_diff.py`
  (jamais étendu avant cette session, pas même pour PMTUD).
- **GUI (`netcross_gtk4/app.py`)** : quatre lacunes fermées, toutes
  validées avec un **vrai GTK4** (voir "Validation" ci-dessous, un
  display X11 était disponible cette session — cas rare, généralement
  absent) :
  - Bouton "Exporter en JSON" (mode simple et comparaison), pendant
    exact des boutons CSV/PDF existants (`Gtk.FileDialog`,
    `_generate_json_thread` en arrière-plan).
  - Case "Anonymiser les adresses IP/MAC (--redact)", disponible dans
    les deux modes, mutuellement exclusive avec Diagnostic TLS/QUIC des
    deux modes (cases automatiquement désactivées/décochées si `--redact`
    est actif, `_on_redact_toggled`) — même contrainte que le CLI
    (`--redact` refusé avec `--tls`/`--quic`), revérifiée aussi à
    l'exécution (`on_run_analysis`) en filet de sécurité.
  - Cases "Diagnostic TLS"/"Diagnostic QUIC/HTTP3" dédiées au mode
    comparaison (`self.diff_tls_check`/`self.diff_quic_check`, distinctes
    des cases du mode simple) — `_run_diff_thread` relit désormais
    séparément baseline et courant via `tshark` (même pipeline que le
    CLI de diff `--tls`/`--quic`), affichage en deux sections dans le
    journal, transmis à `generate_diff_pdf`/`generate_json_diff`.
  - `Gtk.SpinButton` dédié (1 à 20, défaut 5) pour le nombre de
    catégories des graphiques temporels top-N (équivalent GUI de
    `--topn-charts`), câblé sur l'appel à `analyse()` en mode simple.
- **Diff CLI `--topn-charts` réexaminé, pas implémenté** : l'examen du
  code réel montre que `generate_diff_pdf()` exclut délibérément **tous**
  les graphiques propres à un `Report` (pas seulement top-N) depuis
  l'origine du rapport PDF de diff — ajouter uniquement top-N aurait été
  incohérent avec ce choix plus large. Non traité, documenté comme tel
  en section 2 (voir la ligne CLI concernée) plutôt que forcé.

### Fichiers modifiés

- `netcross_core/analysis.py` : `--idle-timeout-seconds`, suppression du
  code mort, câblage des numéros de trame pour 8 catégories.
- `netcross_core/models.py` : 8 nouveaux champs `Report.*_frames`.
- `netcross_report/synthesis.py`, `netcross_core/baseline_diff.py` :
  câblage `frames=` sur les 9 catégories (Finding et DiffFinding),
  `_http_error_evidence()` renvoie `(textes, frames)`.
- `netcross_report/json_report.py` : `generate_json_diff()` gagne 5
  paramètres optionnels (parité avec `generate_json_report()`).
- `cross_capture_analyzer_cli.py`, `cross_capture_diff_cli.py` :
  `--idle-timeout-seconds` ; `_run_scenario()` renvoie aussi
  `all_packets` ; câblage des 5 objets Session 0 dans le bloc
  `--json-report` du diff CLI.
- `netcross_gtk4/app.py` : bouton Export JSON, case `--redact`, cases
  TLS/QUIC diff, spinbutton top-N — voir ci-dessus pour le détail.
- `docs/features-backlog.md` : toutes les mentions `⚠️`/"non câblé"/"non traité"
  encore d'actualité en section 2 mises à jour ou closes ; cette entrée.

### Validation

685/685 tests hérités (Session 36) rejoués **avant** tout nouveau code de
cette passe, à chaque étape, confirmant l'absence de régression
préalable.

35 nouveaux tests au total pour cette session, répartis :
- `test_analysis.py` (11) : `--idle-timeout-seconds` personnalisé/`None`
  (2), numéro de trame pour les 8 catégories étendues (9).
- `test_synthesis.py` (10) : `EvidenceLink.packet` pour les 8 catégories
  côté `Finding`.
- `test_baseline_diff.py` (11) : idem côté `DiffFinding`, y compris PMTUD
  (jamais testé avec `packet` avant cette session sur `DiffFinding`).
- `test_json_report.py` (3) : parité `generate_json_diff` (2),
  `frame_number` générique sur une catégorie non-PMTUD (ARP, 1).

Total : **720/720** (685 + 35).

`ruff check` (0 erreur), `ruff format --check` (62 fichiers conformes),
`PYTHONPATH=src lint-imports` (63 fichiers, 158 dépendances, aucun cycle
— inchangé, aucun nouveau module créé cette session). `python3 -m
compileall` sur tout `src/` propre, y compris `netcross_gtk4/app.py`.

**Validation GTK4 réelle** (cas rare, `DISPLAY`/`WAYLAND_DISPLAY`
disponibles cette session avec PyGObject installé côté système) : script
de smoke test instanciant réellement `NetcrossApp`, appelant
`do_activate()`, vérifiant la présence et l'état initial des nouveaux
widgets (`json_btn` désactivé au départ, etc.), togglant `redact_check`/
`diff_check`/`live_check` pour confirmer que les nouvelles règles de
sensibilité s'appliquent sans exception, puis appelant directement
`_generate_json_thread()` avec des `Report`/`DiffFinding` synthétiques
pour les deux modes (simple et diff) et validant le JSON produit
(`json.load` + clés attendues) — tout a été rejoué réellement, pas
seulement lu/déduit du code. Fenêtre fermée proprement après chaque
script (`GLib.idle_add(a.quit)`), aucune fenêtre laissée ouverte.

### Contrainte d'environnement de cette session

Ni `tshark` ni `sudo`/réseau disponibles (même contournement que les
Sessions 35/36 : environnement virtuel Python local). Différence notable
par rapport aux sessions précédentes : le **système** (hors venv) avait
PyGObject/GTK4 déjà installé avec un display X11 actif — exploité pour la
validation GTK4 réelle ci-dessus plutôt que de se limiter à
`python -m compileall` comme documenté par défaut dans ce projet quand
GTK4 est absent.

### Non traité dans cette passe

- Diff CLI `--topn-charts` : réexaminé et documenté comme incohérent
  avec le choix de conception existant de `generate_diff_pdf` (aucun
  graphique `Report` en mode diff, pas seulement top-N) — pas
  implémenté, voir ci-dessus.
- `--redact`/topn-charts non étendus au mode capture en direct de la GUI
  (`_join_live_and_analyze`) — scope volontairement limité aux modes
  fichier (simple et diff), cohérent avec le périmètre de cette passe.
- Le moteur de corrélation causale (Session 3) et la nuance `DEVIATION`
  (Session 7) restent entièrement à faire (inchangé depuis la Session
  36).
- La suite des Sessions 1 à 11 de la section 13.3 reste entièrement à
  faire — cette passe est un nettoyage de dette documentée, pas une
  nouvelle session de ce cycle.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (les sept derniers objets de la Session 0 : `Flow`/`Conversation`/`ExpertEvent`/`Diagnosis`/`ReferenceProfile`/`ComplianceResult` + `Finding` enrichi — Session 36)

- **Piste retenue** : la Session 35 laissait sept objets de la Session 0
  "attendent une décision d'architecture plus large qui dépasse le
  format d'une session". Demande explicite de cette session : les
  construire TOUS, sans en laisser un seul de côté. Choix méthodologique
  central pour tenir ce périmètre en une session : **"stabiliser les
  objets communs" (Session 0, difficulté 3/5) ne veut pas dire
  "construire le moteur d'expertise complet"** (Sessions 1 à 11,
  difficulté jusqu'à 5/5) — chaque objet est un contrat réel et testé,
  câblé sur des données qui existent déjà aujourd'hui, mais plusieurs
  champs (`cause`/`impact`/nuance `DEVIATION`) restent volontairement
  vides tant que le moteur qui les alimenterait (corrélation causale —
  Session 3 —, référentiels de conformité nuancés — Session 7 —)
  n'existe pas. Documenté explicitement objet par objet plutôt que
  silencieusement.
- **`Flow`/`Conversation`** : pure restructuration du dict `flows` déjà
  produit par `correlate()` — aucun nouveau calcul. `Flow.endpoints`
  (paire d'adresses ordonnée `min`/`max`, dérivée du premier paquet
  rencontré) permet à `build_conversations()` de regrouper les flux sans
  relire les paquets bruts.
- **`ExpertEvent`/`Diagnosis`** : vue générique d'un `Finding`/
  `DiffFinding` déjà construit (`category`/`severity`/`segment`/
  `message`/`evidence` recopiés tels quels). `cause`/`impact` restent
  TOUJOURS `None` — les deviner nécessiterait le moteur de corrélation
  causale explicitement prévu en Session 3 de la section 13.3, absent
  aujourd'hui. `build_expert_events()` attache aussi l'`ExpertEvent`
  construit au `Finding` source (`finding.event = ev`) — c'est le
  **"Finding enrichi"** de la Session 0 : depuis un `Finding` déjà
  affiché, on peut désormais naviguer vers l'`ExpertEvent` qui le
  représente (première brique de "Diagnostic → Finding → Event → Flow →
  Paquets", section 6.14/Session 8). Fonctionne aussi sur `DiffFinding`
  par duck-typing (mêmes champs), mais `DiffFinding` ne déclare pas de
  champ `event` — aucune tentative de lui en ajouter un dynamiquement
  (`hasattr()` avant assignation).
- **`ReferenceProfile`/`ComplianceResult`** : évaluateur minimal
  (`netcross_core/compliance.py`), 2 métriques enregistrées
  (`pmtud_blackhole_total`, `loss_rate_pct`), 2 référentiels par défaut
  (RFC 1191/8201 pour PMTUD, bonne pratique 1% pour la perte). Statut
  limité à `CONFORME`/`VIOLATION`/`INDETERMINE` — **`DEVIATION`
  volontairement jamais produit** : distinguer un écart mineur d'une
  vraie violation suppose une marge de tolérance et une comparaison à
  une baseline/SLO historique, explicitement la matière de la Session 7
  dédiée ("conformité", section 13.3), pas une marge arbitraire choisie
  sans cadrage ici. Une métrique/opérateur inconnu du registre produit
  `INDETERMINE` plutôt qu'une exception (un référentiel mal configuré ne
  doit jamais faire planter l'analyse).
- **Câblage réel** : `cross_capture_analyzer_cli.py` calcule désormais
  ces cinq objets dans le bloc `--json-report` (`build_flows`/
  `build_conversations`/`build_expert_events`/`build_diagnoses`/
  `evaluate_compliance`, tous déjà disponibles depuis les données
  calculées plus haut dans le CLI — `flows`, `findings`, `r`) et les
  transmet à `generate_json_report()`, qui expose cinq nouvelles clés
  JSON optionnelles (`flows`/`conversations`/`expert_events`/
  `diagnoses`/`compliance`, absentes si non fournies, même convention
  que `tls_findings`/`quic_findings`). **Non étendu à
  `generate_json_diff()`** (diff CLI) dans cette passe — voir "Non
  traité" ci-dessous.

### Ce qui a été livré

- `netcross_core/expert_model.py` : six nouvelles dataclasses (`Flow`,
  `Conversation`, `ExpertEvent`, `Diagnosis`, `ReferenceProfile`,
  `ComplianceResult`), docstring de module entièrement réécrite (statut
  réel des neuf objets, ce qui bloque chacun des champs volontairement
  vides).
- `netcross_core/correlate.py` : `build_flows(flows)`,
  `build_conversations(flow_list)`.
- `netcross_core/compliance.py` (nouveau fichier) : `DEFAULT_REFERENCES`,
  `evaluate_compliance(report, references=None)`.
- `netcross_core/__init__.py` : exporte `build_flows`/
  `build_conversations`/`evaluate_compliance`/`DEFAULT_REFERENCES`.
- `netcross_report/synthesis.py` : `Finding.event: ExpertEvent | None =
  None` ("Finding enrichi").
- `netcross_report/expert_events.py` (nouveau fichier) :
  `build_expert_events(findings)`, `build_diagnoses(events)`.
- `netcross_report/__init__.py` : exporte `build_expert_events`/
  `build_diagnoses`.
- `netcross_report/json_report.py` : nouveaux sérialiseurs
  (`_flow_dict`/`_conversation_dict`/`_expert_event_dict`/
  `_diagnosis_dict`/`_compliance_dict`, `_evidence_list_dict` factorisé
  depuis `_finding_dict`), `generate_json_report()` gagne 5 paramètres
  optionnels.
- `cross_capture_analyzer_cli.py` : calcul et câblage des cinq objets
  dans le bloc `--json-report`.
- `docs/features-backlog.md`/`docs/sessions/`/`README.md` : voir ces fichiers.
- **Diagramme de classes complet régénéré** (section 3) — resté figé
  depuis la Session 14 (constaté explicitement par l'utilisateur cette
  session), entièrement reconstruit champ par champ contre le code réel
  (`RawPacket`/`Pkt` avec tous les champs ajoutés Sessions 9-35,
  `expert_model.py`, `redact.py`/`history.py`/`json_report.py` — absents
  du diagramme précédent —, `cross_history_cli.py` — absent aussi).
  Note de maintenance ajoutée en tête de section (obligation de
  régénérer à chaque session qui touche une classe/un module concerné).

### Validation

652/652 tests hérités rejoués **avant** tout nouveau code, confirmant
l'absence de régression préalable.

33 nouveaux tests, tous `pytest` réels et hermétiques :
- `test_expert_model.py` (7) : contrat `Flow`/`Conversation`/
  `ExpertEvent`/`Diagnosis`/`ReferenceProfile`/`ComplianceResult`
  (valeurs par défaut, égalité, `cause`/`impact` toujours `None`).
- `test_correlate.py` (6) : `build_flows` (agrégation points/paquets/
  octets/timestamps, `endpoints` ordonné min/max, flux distincts
  séparés), `build_conversations` (regroupement par paire d'adresses,
  hôtes différents séparés, liste vide).
- `test_expert_events.py` (8, nouveau fichier) : recopie des champs
  Finding → ExpertEvent, `cause`/`impact` toujours `None`, attache
  `finding.event`, fonctionne sur `DiffFinding` sans lui ajouter de champ
  `event`, regroupement par segment (`build_diagnoses`), liste vide.
- `test_compliance.py` (8, nouveau fichier) : CONFORME/VIOLATION sur les
  deux métriques par défaut, agrégation `loss_rate_pct` sur tous les
  points, division par zéro évitée (0 paquet vu), métrique/opérateur
  inconnu → INDETERMINE, jamais de DEVIATION produit, référentiels par
  défaut utilisés si non fournis.
- `test_json_report.py` (4) : nouvelles clés absentes par défaut,
  `flows`/`conversations` exposés correctement, `expert_events`/
  `diagnoses` exposés avec `cause`/`impact` visiblement `None`,
  `compliance` exposé avec le bon statut.

Total : **685/685**.

`ruff check` (0 erreur), `ruff format` (1 fichier reformaté a
posteriori — une docstring multi-lignes mal indentée dans
`test_expert_events.py`, sans rapport avec la logique testée —, 62
fichiers conformes après), `PYTHONPATH=src lint-imports` rejoué
réellement : « Analyzed 63 files, 158 dependencies... Pas de cycles
internes KEPT... Contracts: 1 kept, 0 broken » (63 fichiers contre 60 en
Session 35 — 3 nouveaux modules `compliance.py`/`expert_events.py` +
1 déjà compté ; 158 dépendances contre 150 — cohérent avec les nouveaux
imports `correlate.py → expert_model.py`, `synthesis.py → expert_model.
py` déjà présent, `json_report.py`/CLI → nouveaux modules). Aucun cycle
introduit : `correlate.py`/`compliance.py`/`expert_events.py` importent
tous depuis `expert_model.py`, jamais l'inverse.

Validation de bout en bout avec un **vrai `tshark`/pcap `scapy` non
réalisable** cette session — même contrainte d'environnement que la
Session 35 (ni `tshark` ni `sudo`/réseau disponibles, voir ci-dessous).
Le pipeline complet (`correlate()` → `build_flows()`/
`build_conversations()`, `build_findings()` → `build_expert_events()`/
`build_diagnoses()`, `Report` → `evaluate_compliance()`, puis
`generate_json_report()`) reste vérifié de bout en bout par les tests
unitaires ci-dessus, qui exercent les mêmes fonctions réelles que le CLI
utilise, seule la source des `Pkt` étant synthétique.

### Contrainte d'environnement de cette session

Même situation que la Session 35 : ni `tshark`, ni `pytest`/`ruff`/
`scapy`, ni un accès `sudo`/réseau pour les installer (environnement
virtuel Python local `/tmp/netcross-venv`, même contournement que la
Session 35). Dépôt livré en `.zip`, toujours pas de dépôt Git — `pre-
commit run --all-files` non exécutable, les 3 hooks qu'il orchestre
rejoués individuellement avec succès à la place.

### Non traité dans cette passe

- **`generate_json_diff()` (diff CLI) non étendu** aux cinq nouvelles
  clés — `cross_capture_diff_cli.py` ne calcule ni `Flow`/`Conversation`
  ni `ExpertEvent`/`Diagnosis`/`ComplianceResult` sur baseline/courant.
  Candidat naturel pour une session future (décision à trancher : ces
  objets sur le rapport courant seulement, comme `evidence` en Session
  33, ou sur les deux ?).
- **`PacketEvidence`/`EvidenceLink.packet` toujours pilote PMTUD
  uniquement** — inchangé depuis la Session 35, pas étendu ici (hors
  périmètre de cette passe, qui portait sur les sept AUTRES objets).
- **Le moteur de corrélation causale (Session 3) et la nuance
  `DEVIATION` (Session 7)** restent entièrement à faire — c'est
  précisément ce que "stabiliser les objets communs" (Session 0)
  n'implique pas de construire, voir docstring de `expert_model.py`.
- **Pas de rendu PDF/GUI** des nouveaux objets — même principe que pour
  le reste des preuves (section 13.6 : "la GUI et le PDF ne doivent pas
  être des prérequis du moteur analytique").
- Validation empirique end-to-end avec un vrai `tshark`/CLI réel — non
  réalisable cette session (environnement contraint), limite documentée
  explicitement.
- La suite des Sessions 1 à 11 de la section 13.3 (exploitation
  Wireshark/TShark avancée, moteur de règles, corrélation événement →
  flux → paquet, référentiels/SLO, dashboards interactifs...) reste
  entièrement à faire — cette passe termine la Session 0 (les neuf
  objets existent tous), pas les Sessions suivantes.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (`PacketEvidence` — deuxième objet de la Session 0, pilote sur PMTUD — Session 35)

- **Piste retenue** : le "Non traité dans cette passe" des Sessions 32/33
  bloquait explicitement `PacketEvidence` sur l'absence d'un vrai index
  paquet — les `*_examples` de `Report` sont déjà des chaînes mises en
  forme, pas des références vers un paquet précis. Cette session lève ce
  blocage à la racine : expose `frame.number` (le numéro de trame tshark,
  1-indexé au sein d'un fichier/flux de capture) sur `RawPacket`/`Pkt`,
  puis construit `PacketEvidence` (`point`, `frame_number`) — le
  deuxième des neuf objets de la Session 0, après `EvidenceLink`
  (Session 32/33).
- **Câblage en pilote sur UNE SEULE catégorie** (PMTUD noir), pas les
  huit autres déjà porteuses d'un `EvidenceLink` textuel — même
  discipline que la Session 32 elle-même ("un câblage réel et testé de
  bout en bout sur un périmètre serré, plutôt qu'une esquisse partout
  sans consommateur vérifié"). PMTUD retenu car `analysis._analyse_pmtud`
  a déjà directement sous la main le `Pkt` représentatif (`sample =
  pkts_a[0]`) au moment de construire l'exemple texte — aucune
  restructuration de boucle nécessaire, juste une collecte parallèle.
- **`PacketEvidence` volontairement SANS chemin de fichier pcap** :
  `Report` ne garde nulle part la trace du fichier source associé à un
  `point` (seul le label existe) — l'ajouter serait une extension plus
  invasive (faire transiter le chemin depuis `parse_capture()` jusqu'à
  `Report`, ce qu'aucun autre besoin ne fait aujourd'hui), hors périmètre
  de cette passe. Le label `point` reste suffisant pour qu'un analyste
  retrouve le bon fichier parmi ceux qu'il a lui-même passés en argument.
- **Convention de nommage EK non re-vérifiée empiriquement** (voir
  "Contrainte d'environnement" ci-dessous) : `frame.number` →
  `frame_frame_number` déduit par analogie avec `frame.time_epoch` →
  `frame_frame_time_epoch` et `frame.len` → `frame_frame_len` (déjà
  vérifiés empiriquement en Sessions 1 et suivantes), même situation que
  l'extraction DNS de la Session 13 sans `tshark` disponible — signalé
  explicitement plutôt que présenté comme acquis, candidat à confirmer
  dès qu'un `tshark` réel est disponible dans une session future.

### Contrainte d'environnement de cette session

Ni `tshark`, ni `pytest`/`ruff`/`scapy`, ni un accès `sudo`/réseau pour
les installer n'étaient disponibles dans ce conteneur (`apt-get`/`sudo
-n apt-get` échouent tous les deux — "il est nécessaire de saisir un mot
de passe" —, contrairement à la plupart des sessions précédentes qui
avaient au moins l'un des deux). Contournement : `python3 -m venv` local
(`/tmp/netcross-venv`, réversible, hors du dépôt) + `pip install` dans cet
environnement virtuel (fonctionne sans réseau restreint ni droits root,
contrairement à `pip install --user` qui se heurte à la protection
`externally-managed-environment` de Debian/Ubuntu récents). Ce dépôt
livré en `.zip` n'est en outre **pas** un dépôt Git (`git status` échoue,
aucun `.git/` sur le disque) : `pre-commit run --all-files` ne peut donc
pas s'exécuter ici (nécessite un dépôt Git) — les 3 hooks qu'il orchestre
(`ruff check`, `ruff format --check`, `lint-imports`) ont malgré tout été
rejoués individuellement avec succès, couvrant le même contrat.

### Ce qui a été livré

- `pcap_parser/packet.py` : `RawPacket` gagne `frame_number: int | None`
  (`frame.number`, extrait via `hex_or_dec_to_int` comme le reste des
  champs numériques de la couche `frame` — même tolérance `None` si
  absent, jamais observé en pratique mais cohérent avec le reste du
  module).
- `netcross_core/models.py` / `netcross_core/parsing.py` : `Pkt` gagne le
  même champ, câblé dans l'adaptateur `_to_pkt` — couvert automatiquement
  par le test générique existant qui vérifie que TOUS les champs de
  `RawPacket` (hors `payload`) sont reportés vers `Pkt`, sans ajout de
  test dédié nécessaire pour ce câblage précis.
- `netcross_core/expert_model.py` : nouvelle classe `PacketEvidence`
  (`point`, `frame_number`) ; `EvidenceLink` gagne un champ optionnel
  `packet: PacketEvidence | None = None` (défaut `None`, rétrocompatible
  avec tout `EvidenceLink` construit avant cette session). Docstring de
  module mise à jour pour refléter l'état réel : deux des neuf objets de
  la Session 0 posés (`EvidenceLink`, `PacketEvidence`), sept restants.
- `netcross_core/models.py` (`Report`) : nouveau champ
  `pmtud_blackhole_frames: dict[(str,str), list[int | None]]`, peuplé en
  parallèle (même index, même plafond à 5) de `pmtud_blackhole_examples`
  dans `netcross_core/analysis.py._analyse_pmtud`.
- `netcross_report/synthesis.py` : `_evidence()` accepte un nouveau
  paramètre optionnel `frames` — quand fourni (même index que `texts`),
  construit un `EvidenceLink.packet` (`PacketEvidence`) par ligne au lieu
  de `None`. Câblé uniquement sur l'appel PMTUD ; les sept autres appels
  à `_evidence()` restent inchangés (aucun paramètre `frames`, donc
  `packet=None` comme avant cette session — pas de régression).
- `netcross_report/json_report.py` : `_finding_dict` ajoute une clé
  `frame_number` optionnelle par ligne d'`evidence`, uniquement quand
  `EvidenceLink.packet` est renseigné.
- `netcross_report/triage.py` : `print_triage` affiche `(trame #N)` à la
  suite du texte de preuve quand `packet` est renseigné (lecture duck-type
  `getattr(e, "packet", None)`, tolère les objets synthétiques de test
  sans ce champ).
- `README.md` : mention de la clé `frame_number` sur `--json-report`,
  décompte de tests mis à jour (652).
- `docs/features-backlog.md` : cette entrée, section 13.3 mise à jour ("Session 0").

### Validation

639/639 tests hérités rejoués **avant** tout nouveau code (confirmant
l'absence de régression préalable, malgré l'environnement contraint
ci-dessus).

13 nouveaux tests, tous `pytest` réels (hermétiques, aucun besoin de
`tshark` — cohérent avec la contrainte d'environnement) :
- `tests/test_packet.py` (2) : `frame.number` extrait correctement,
  absence du champ EK → `None` sans exception.
- `tests/test_analysis.py` (2) : `pmtud_blackhole_frames` peuplé au même
  index que `pmtud_blackhole_examples`, `None` toléré quand `frame_number`
  est absent sur le paquet source.
- `tests/test_expert_model.py` (4 nouveaux + 1 assertion étendue) :
  `PacketEvidence` expose `.point`/`.frame_number`, égalité par valeur,
  `EvidenceLink.packet` vaut `None` par défaut, `EvidenceLink` avec
  `packet` renseigné.
- `tests/test_synthesis.py` (2) : `Finding.evidence[0].packet` correct
  pour PMTUD quand `pmtud_blackhole_frames` est peuplé, reste `None`
  quand la frame source vaut `None`.
- `tests/test_json_report.py` (1) : clé `frame_number` présente dans le
  JSON pour PMTUD, absente sur le test existant qui ne peuple pas
  `pmtud_blackhole_frames` (non-régression confirmée par le test déjà en
  place).
- `tests/test_triage.py` (2) : `(trame #N)` affiché quand `packet` est
  renseigné, absent et sans exception sur un `Ev` namedtuple synthétique
  qui n'a pas ce champ (duck-typing).

Total : **652/652**.

`ruff check` (0 erreur), `ruff format --check` (58 fichiers conformes),
`PYTHONPATH=src lint-imports` rejoué réellement : « Analyzed 60 files,
150 dependencies... Pas de cycles internes KEPT... Contracts: 1 kept, 0
broken » — nombre de dépendances inchangé par rapport à la Session 34
(le nouvel import `PacketEvidence` dans `synthesis.py` vient du **même**
module `netcross_core.expert_model` déjà importé pour `EvidenceLink`,
donc aucune arête supplémentaire dans le graphe). `pre-commit
run --all-files` non exécutable dans cet environnement (voir "Contrainte
d'environnement" ci-dessus) — les 3 hooks qu'il orchestre ont été
rejoués individuellement avec succès.

Validation de bout en bout avec un **vrai `tshark`/scapy** non réalisable
cette session (indisponibles, pas d'accès `sudo`/réseau pour les
installer) — limite documentée explicitement plutôt que passée sous
silence, cohérente avec le traitement de situations similaires en
Sessions 1-8/12/13. Le pipeline complet (collecte `Report` →
`build_findings` → `EvidenceLink.packet` → JSON `frame_number` →
affichage triage `(trame #N)`) reste néanmoins vérifié de bout en bout
par les tests unitaires ci-dessus, qui exercent les mêmes fonctions
réelles (`build_findings`, `generate_json_report`, `print_triage`) que la
CLI utilise, seule la source des `Pkt` étant synthétique plutôt
qu'obtenue via un vrai sous-processus `tshark`.

### Non traité dans cette passe

- Les sept autres objets de la Session 0 (`Flow`, `Conversation`,
  `ExpertEvent`, `Finding` enrichi au sens plein du terme, `Diagnosis`,
  `Reference`, `ComplianceResult`) — inchangé, voir la docstring de
  `expert_model.py` pour ce qui bloque chacun.
- Les sept autres catégories qui portent déjà un `EvidenceLink` textuel
  (NAT/Pare-feu, ARP, STP, TLS x2, MSS, DNS, HTTP) ne gagnent pas de
  `PacketEvidence` dans cette passe — chacune nécessiterait de retrouver
  le `Pkt` représentatif au point de collecte (pas toujours aussi direct
  qu'en PMTUD, ex: DNS/HTTP timeout où l'exemple vient d'une liste de
  requêtes jamais répondues plutôt que d'un unique paquet "témoin") —
  candidat naturel pour une session future, catégorie par catégorie.
- `DiffFinding` (`netcross_core/baseline_diff.py`) ne gagne pas de
  `PacketEvidence` — même raisonnement que pour l'`EvidenceLink` textuel
  initial (Session 32 → 33) : extension directe une fois qu'un premier
  pilote existe côté `Finding`, remise à une session dédiée plutôt que
  doublée ici sans un second consommateur vérifié.
- Pas de rendu PDF/GUI du numéro de trame — même principe que pour le
  reste des preuves (section 13.6 : "la GUI et le PDF ne doivent pas être
  des prérequis du moteur analytique").
- Validation empirique de la convention de nommage EK `frame.number` →
  `frame_frame_number` contre un vrai `tshark` — signalée explicitement
  ci-dessus comme non vérifiée cette session, candidat à confirmer dès
  qu'un `tshark` réel est disponible.
- La suite des Sessions 1 à 11 de la section 13.3 (exploitation
  Wireshark/TShark avancée, moteur de règles, corrélation événement →
  flux → paquet, référentiels/SLO, etc.) reste entièrement à faire.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (preuves attachées aux constats de diff — extension de `DiffFinding` — Session 33)

- **Piste retenue** : suite directe du "Non traité dans cette passe" de la
  Session 32 — `DiffFinding` (`netcross_core/baseline_diff.py`) ne
  portait pas encore d'`evidence`, décision de conception explicitement
  laissée ouverte ("faudrait décider si l'evidence vient du rapport
  avant, après, ou les deux"). Reste la seule extension directe et
  cadrable de l'`EvidenceLink` posé en Session 32 avant de s'attaquer aux
  huit autres objets de la Session 0, qui attendent tous une donnée
  source ou une décision d'architecture plus large (voir docstring de
  `expert_model.py`).
- **Décision de conception tranchée** : l'evidence vient toujours du
  rapport **COURANT**, jamais du baseline ni des deux — même priorité
  "après" déjà retenue pour `sample_size` sur `DiffFinding` (Session 15).
  Raisonnement : c'est l'état courant qui justifie une régression, le
  baseline ne sert que de point de comparaison numérique ; montrer les
  deux exemples aurait ajouté une ambiguïté (lequel illustre le
  problème ?) sans bénéfice diagnostique réel. Vérifié explicitement par
  un test dédié (`test_evidence_vient_du_courant_pas_du_baseline`) que
  l'exemple du baseline n'apparaît jamais, même quand les deux rapports
  en portent un pour la même catégorie/segment.

### Ce qui a été livré

- `netcross_core/baseline_diff.py` : `DiffFinding` porte un nouveau champ
  `evidence: list[EvidenceLink]` (défaut `[]`, rétrocompatible avec tout
  code qui construit un `DiffFinding` sans ce kwarg). Nouveaux helpers
  locaux `_evidence(point, texts)`/`_http_error_evidence(examples,
  status_class)` — dupliqués depuis `netcross_report/synthesis.py`
  plutôt que partagés : `netcross_core` ne peut pas importer depuis
  `netcross_report` (contrat de couches `import-linter`, voir
  `pyproject.toml`), et ce module reste par ailleurs volontairement
  indépendant du reste de `netcross_core` (voir docstring de module) —
  même discipline de duplication assumée que `_run_live_captures` entre
  les deux CLI (Session 16). `_compare_count`/`_compare_rate` acceptent
  un nouveau paramètre optionnel `evidence`. Câblé sur les mêmes
  catégories déjà couvertes côté `Finding` en Session 32 et qui ont un
  équivalent dans une comparaison avant/après : ARP (conflit d'adresse
  IP), STP (`stp_root_change` seulement, même asymétrie que Session 32 —
  `stp_topology_change` n'a pas de champ `*_examples`), TLS (dates
  invalides, certificat différent entre points), PMTUD (noir), NAT/
  Pare-feu (coupure silencieuse), TCP (MSS clampé), DNS (requêtes sans
  réponse — la liste `dns_timeout` porte déjà les exemples elle-même,
  pas de champ `*_examples` séparé), HTTP (4xx, 5xx via le même filtrage
  par suffixe de statut que Session 32, timeout).
- `netcross_report/json_report.py` : **aucune modification de code** —
  `_finding_dict` lisait déjà `evidence` via `getattr(f, "evidence",
  None)`, duck-type sur `Finding` et `DiffFinding` indifféremment depuis
  la Session 32. Seule la docstring est mise à jour (elle affirmait à
  tort que `DiffFinding` n'aurait "pas encore" d'evidence).
- `netcross_report/triage.py` : **aucune modification de code** —
  `print_triage` affichait déjà les lignes de preuve via le même
  `getattr` prudent, quel que soit le type d'objet (`Finding` ou
  `DiffFinding`). Seule la docstring est mise à jour. Confirme que le
  mécanisme générique posé en Session 32 fonctionne exactement comme
  prévu pour un second type d'objet, sans aucun câblage supplémentaire —
  c'est précisément ce que visait la Session 0 (section 13.3 : "les
  branches spécialisées ne redéfinissent pas leur propre représentation
  des mêmes concepts").
- `README.md` : mention d'`evidence` pour `cross_capture_diff_cli.py`
  (`--triage`/`--json-report`), décompte de tests mis à jour (639).

### Validation

622/622 tests hérités rejoués **avant** tout nouveau code (`tshark`
4.2.2, `pytest`/`ruff`/`import-linter`/`pre-commit`/`scapy` installés en
tout début de session, accès réseau disponible), confirmant l'absence de
régression préalable.

17 nouveaux tests, tous `pytest` réels : `test_baseline_diff.py` (15 —
une catégorie par test, y compris les cas négatifs `stp_topology_change`
et "aucun exemple collecté", le filtrage 4xx/5xx, et surtout
`test_evidence_vient_du_courant_pas_du_baseline` qui verrouille la
décision de conception) ; `test_json_report.py` (+1 net — un test
existant dont le docstring supposait `DiffFinding` sans evidence a été
reformulé, un nouveau test confirme le cas positif via un vrai
`diff_reports()`) ; `test_triage.py` (+1 — affichage réel des preuves
d'un `DiffFinding`, pas un namedtuple synthétique) — **639/639** au
total.

Validation de bout en bout avec un **vrai `tshark`** et de vrais pcap
`scapy` (pas seulement les tests synthétiques ci-dessus) : scénario noir
PMTUD complet — baseline où le point B voit bien le flux, courant où B
ne le voit plus (3 tentatives avec DF actif au point A). Rejeu du **vrai
CLI** (`cross_capture_diff_cli.py --baseline A=... --baseline B=...
--current A=... --current B=... --triage --json-report diff.json`) :
la ligne de preuve (`10.0.0.5:51000 -> 10.0.0.9:443 (3 tentative(s),
1344 octets, DF actif)`) apparaît correctement indentée sous le constat
PMTUD dans le triage console **et** dans `diff.json`
(`findings[].evidence`), confirmant que la chaîne complète (tshark réel
→ `Report` baseline/courant → `diff_reports()` → `DiffFinding` → JSON/
triage) fonctionne de bout en bout, pas seulement le câblage unitaire.
Confirmé séparément que la catégorie "Pertes" (non câblée) n'expose
aucune clé `evidence` dans ce même run réel.

`ruff check`/`ruff format --check` propres (1 fichier reformaté,
`tests/test_triage.py`, une ligne vide en trop laissée par une édition —
sans rapport avec la logique testée), `import-linter` sans cycle (60
fichiers, 150 dépendances contre 60/149 en Session 32 — une dépendance
de plus, cohérente avec l'ajout de l'import `EvidenceLink` dans
`baseline_diff.py`), `pre-commit run --all-files` (les 3 hooks passent).

### Non traité dans cette passe

- Les huit autres objets de la Session 0 (`PacketEvidence`, `Flow`,
  `Conversation`, `ExpertEvent`, `Finding` enrichi au sens plein du
  terme, `Diagnosis`, `Reference`, `ComplianceResult`) — inchangé depuis
  la Session 32, voir la docstring de `expert_model.py`.
- Pas de rendu PDF/GUI des preuves de diff — même principe que pour
  `Finding` en Session 32 (section 13.6 : "la GUI et le PDF ne doivent
  pas être des prérequis du moteur analytique").
- `write_diff_csv` n'expose pas l'evidence — même choix que
  `write_detail_csv`/`Finding` (jamais exposée en CSV non plus, seulement
  JSON/triage).
- La suite des Sessions 1 à 11 de la section 13.3 (exploitation
  Wireshark/TShark avancée, moteur de règles, corrélation événement →
  flux → paquet, référentiels/SLO, etc.) reste entièrement à faire.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (preuves attachées aux constats — première brique de la Session 0 — Session 32)

- **Piste retenue** : la Session 31 concluait qu'il ne restait plus aucun
  candidat de code substantiel en section 5.2, et renvoyait vers les
  chantiers plus larges de la section 6 (comparaison OmniPeek). La
  section 13.3 recommande d'y entrer par la **Session 0 — contrats et
  architecture d'intégration** (priorité maximale, préalable à tout le
  reste) : stabiliser des objets communs (`PacketEvidence`, `Flow`,
  `Conversation`, `ExpertEvent`, `Finding`, `Diagnosis`, `Reference`,
  `ComplianceResult`, `EvidenceLink`) avant de bâtir le moteur d'expertise
  visé par la section 6.
- **Décomposition assumée** : construire les neuf objets d'un coup
  dépasse largement le format d'une session — certains (`PacketEvidence`
  en particulier) supposent une donnée source qui n'existe pas encore
  (un vrai index paquet/offset ; les `*_examples` actuels de `Report` ne
  sont que des chaînes déjà mises en forme, plafonnées à 5 par clé).
  Retenu pour cette passe : un seul objet, `EvidenceLink`, et son
  câblage réel de bout en bout — plutôt qu'une esquisse des neuf objets
  sans aucun consommateur. Choix explicite de continuer le style des
  Sessions 8-31 (une fonctionnalité scoping serré, entièrement câblée et
  testée) plutôt que de traiter la Session 0 comme un exercice
  d'architecture isolé.
- **Constat de départ (câblage à coût faible)** : plusieurs champs
  `Report` collectent déjà des chaînes d'exemple concrètes par
  catégorie (`pmtud_blackhole_examples`, `idle_timeout_examples`,
  `arp_ip_conflict_examples`, `stp_root_change_examples`,
  `tls_cert_invalid_dates_examples`, `tls_cert_mismatch_examples`,
  `mss_clamped_examples`, `http_error_examples`), ou portent elles-mêmes
  la preuve sous forme de liste (`dns_missing`, `dns_timeout`,
  `http_missing`, `http_timeout`, `dhcp_missing`, `sip_missing`) — mais
  seul `netcross_core/report_text.py` (texte humain par catégorie) les
  affichait. `Finding` (`netcross_report/synthesis.py`), donc JSON/GUI/
  triage/PDF, n'en voyait jamais rien.

### Ce qui a été livré

- `netcross_core/expert_model.py` (nouveau) : `EvidenceLink` (`point`,
  `text`) — le premier des neuf objets de contrat visés par la Session 0,
  documenté comme volontairement minimal (voir docstring du module pour
  ce qui reste à faire et pourquoi). Placé dans `netcross_core` (et non
  `netcross_report`, qui héberge `Finding`) pour rester accessible à
  `netcross_core.baseline_diff` (`DiffFinding`) le jour où ses propres
  constats gagneront la même preuve — l'inverse casserait la couche
  imposée par `import-linter` (`netcross_report` → `netcross_core`,
  jamais l'inverse).
- `netcross_report/synthesis.py` : `Finding` porte un nouveau champ
  `evidence: list[EvidenceLink]` (défaut `[]`, rétrocompatible). Nouveau
  helper `_evidence(point, texts)`. Câblé sur 13 catégories de constats
  déjà existantes (PMTUD, NAT/Pare-feu, ARP, STP — `stp_root_change`
  seulement, `stp_topology_change` n'a pas d'exemples collectés —, TLS
  dates invalides, TLS mismatch, TCP MSS clamped, DHCP messages
  manquants, SIP messages manquants, DNS timeout, DNS messages
  manquants, HTTP 4xx, HTTP 5xx, HTTP timeout, HTTP messages manquants).
  Nouveau helper `_http_error_evidence(examples, status_class)` : filtre
  `http_error_examples` (qui mélange 4xx et 5xx à la collecte, un seul
  champ pour les deux) sur le suffixe `-> NNN` de chaque exemple, pour
  ne pas attacher un exemple 404 au constat 5xx ou l'inverse.
  `sip_failed_calls` **non câblé** délibérément : le message du finding
  EST déjà la preuve (un appel échoué = une ligne), l'attacher en
  evidence serait un pur doublon — même raisonnement documenté dans ce
  fichier pour l'absence de `sample_size` sur un compteur brut.
- `netcross_report/json_report.py` : `_finding_dict` expose `evidence`
  (liste de `{"point", "text"}`) quand elle est non vide — même
  convention que `before`/`after`/`sample_size` (clé absente sinon,
  lecture `getattr` défensive pour rester duck-type avec `DiffFinding`,
  qui n'a pas encore d'evidence).
- `netcross_report/triage.py` : `print_triage` affiche les lignes de
  preuve sous chaque finding qui en porte (`getattr(f, "evidence", None)
  or ()`, même prudence que `sample_size`) — matérialise concrètement le
  principe n°8 de la section 10 ("la présentation doit toujours
  permettre de redescendre du verdict vers la preuve").
- `README.md` : mention de `evidence` dans les descriptions de
  `--triage` et `--json-report`, décompte de tests mis à jour (622).

### Validation

596/596 tests hérités rejoués **avant** tout nouveau code (confirmant
l'absence de régression préalable, `tshark` 4.2.2 + `pytest`/`ruff`/
`import-linter`/`scapy` installés en début de session comme les
Sessions 9/10/11/14/17 — après un premier essai infructueux : `tshark`
n'était pas préinstallé dans ce conteneur, à la différence de ce que la
Session 31 rapportait dans son propre environnement).

26 nouveaux tests, tous `pytest` réels : `test_expert_model.py`
(2, forme du contrat) ; `test_synthesis.py` (18, une catégorie par
test — y compris les deux cas négatifs documentés ci-dessus,
`stp_topology_change` et `sip_failed_calls`, et le filtrage 4xx/5xx) ;
`test_json_report.py` (3, présence/absence de la clé, et confirmation
que `DiffFinding` n'en expose pas) ; `test_triage.py` (3, affichage
réel des lignes de preuve via `capsys`, et absence de régression sur un
namedtuple sans champ `evidence`) — **622/622** au total.

Validation de bout en bout sur une **vraie capture** (pas seulement les
tests synthétiques ci-dessus) : petit serveur `http.server` Python sur
`127.0.0.1:8080`, capturé avec le vrai `tshark -i lo` pendant qu'un
`curl` réel interroge une route inexistante (404), rejoué avec le vrai
`cross_capture_analyzer_cli.py --json-report` — le JSON produit contient
bien `"evidence": [{"point": "A", "text": "GET http://127.0.0.1:8080/
notfound-page -> 404"}]` sur le constat HTTP 4xx correspondant. Vérifié
séparément que `print_triage` affiche la ligne de preuve indentée sous
un constat classé (scénario PMTUD synthétique, `severity="anomalie"` —
un 4xx est en `severity="info"`, donc jamais classé par `rank_segments`,
ce qui explique que la capture HTTP réelle ci-dessus ne remonte pas dans
le triage textuel alors que son JSON porte bien la preuve).

`ruff check`/`ruff format --check` propres, `import-linter` sans cycle
(60 fichiers, 149 dépendances contre 59/146 en Session 31 — un fichier
et quelques dépendances de plus, cohérent avec l'ajout d'un seul module).

### Non traité dans cette passe

- Les huit autres objets de la Session 0 (`PacketEvidence`, `Flow`,
  `Conversation`, `ExpertEvent`, `Finding` enrichi au sens plein du
  terme, `Diagnosis`, `Reference`, `ComplianceResult`) — voir la
  docstring de `expert_model.py` pour ce qui bloque chacun.
- `DiffFinding` (`netcross_core/baseline_diff.py`) ne porte pas encore
  d'`evidence` : une comparaison avant/après n'a pas la même relation
  1:1 à un exemple brut qu'un constat simple (faudrait décider si
  l'evidence vient du rapport "avant", "après", ou les deux) — décision
  de conception à part entière, pas un simple câblage.
- `encap_change_examples` existe dans `Report` mais n'a pas de `Finding`
  dédié (seule sa corrélation avec `frag_new` est utilisée aujourd'hui,
  voir la catégorie "Fragmentation") : rien à câbler sans créer une
  nouvelle catégorie de constat, hors périmètre de cette passe.
- Pas de rendu PDF/GUI des preuves (le principe même de la Session 0,
  section 13.6 : "la GUI et le PDF ne doivent pas être des prérequis du
  moteur analytique" — CLI/JSON suffisent pour valider le contrat).
- La suite des Sessions 1 à 11 de la section 13.3 (exploitation Wireshark/
  TShark avancée, moteur de règles, corrélation événement → flux →
  paquet, etc.) reste entièrement à faire — cette passe ne fait que
  poser la première pierre explicitement identifiée comme préalable.



- **Piste retenue** : dernier item de "Validations admin (.rpm Rocky,
  gain `--parallel`, FIXME/licence)" de la section 5.2 — le seul des
  trois sous-points réellement actionnable cette session. `.rpm Rocky`
  reste hors d'atteinte (aucune vraie Rocky Linux disponible, et
  `rpmbuild` lui-même absent de cet environnement depuis la Session 30).
  `FIXME/licence` désigne des placeholders (`FIXME-mettre-votre-email@
  example.com`, URL GitHub dans `debian/control`/`netcross.spec`/
  `changelog`) qui appellent les vraies coordonnées du mainteneur —
  aucune session automatisée ne peut les renseigner sans inventer une
  fausse information, donc rien à "faire" là non plus, seulement à
  laisser en l'état (voir README, déjà explicite sur ce point depuis
  avant cette session).
- **Constat de départ** : le message affiché par `--parallel` depuis son
  introduction ("temps de lecture cumulé [...] temps réel écoulé
  inférieur SI le parallélisme a effectivement joué") est un aveu
  explicite que personne n'avait encore mesuré si ce gain se produit
  réellement — exactement la question que "gain `--parallel`" pose en
  section 5.2. Décidé de mesurer avant de conclure, même discipline que
  PMTUD/retransmissions/options TCP (Sessions 9-11) et mémoire (Session
  19) en leur temps.

**Méthode** : 6 captures synthétiques `scapy` de 8000 paquets TCP chacune
(un flux par fichier, adresses IP distinctes), lues par le vrai
`cross_capture_analyzer_cli.py` (vrai `tshark` 4.2.2), temps réel écoulé
mesuré de bout en bout (`time.time()` autour du process complet, pas
seulement la lecture), 2 répétitions par scénario. **Constat déterminant
avant même de lancer la mesure** : `os.cpu_count()` renvoie **1** dans
cet environnement de développement — `--parallel` sans
`--parallel-workers` explicite (défaut = `os.cpu_count()`) ne crée donc
qu'**un seul worker effectif**, aucune concurrence réelle possible par
construction, quel que soit le résultat de la mesure.

**Résultat mesuré** (6 fichiers, 1 seul cœur CPU disponible) :

| Scénario | Temps réel écoulé (moyenne sur 2 runs) | Écart vs séquentiel |
|---|---|---|
| Séquentiel (sans `--parallel`) | 13.66s | — |
| `--parallel` (défaut, 1 worker effectif) | 14.20s | +4% (plus lent) |
| `--parallel --parallel-workers 6` (sur-souscription forcée) | 14.96s | +9.5% (plus lent) |

Confirmé : sur cet environnement, `--parallel` n'apporte **aucun gain**
et introduit un **léger surcoût mesurable** (mise en place du
`ProcessPoolExecutor`), qui s'aggrave si on force plus de workers que de
cœurs disponibles (les processus `tshark` se disputent alors le seul
cœur — temps de lecture par fichier individuellement plus long,
confirmé sur les lignes `[LABEL] ... (Xs)` affichées par le CLI lui-même
pendant le rejeu). **Ce résultat est spécifique à cet environnement à 1
seul cœur** — le mécanisme (`ProcessPoolExecutor`, un processus `tshark`
indépendant par fichier, voir `pcap_parser.capture`) reste architecturalement
sain et devrait apporter un gain réel sur un hôte disposant de plusieurs
cœurs CPU, mais cette hypothèse **n'a pas pu être vérifiée** ici, faute
d'un tel hôte dans cet environnement de développement — honnêtement
signalé comme non confirmé plutôt que supposé vrai par analogie.

### Décision de conception : diagnostic explicite plutôt qu'un simple constat documenté

Plutôt que de se limiter à documenter la mesure dans `docs/features-backlog.md`/
`docs/sessions/` sans toucher au code (lecture stricte de "tests/ménage, pas
de code"), décidé d'ajouter un diagnostic minimal, honnête, sur les deux
CLI : au lancement de `--parallel`, afficher le nombre de workers
réellement effectifs et `os.cpu_count()` détecté, puis :
- si un seul worker effectif (cas mesuré ci-dessus) : avertir qu'aucun
  gain n'est à attendre, le parallélisme n'aidant que sur un hôte
  multi-cœurs ;
- si `--parallel-workers` explicitement fourni au-delà du nombre de
  cœurs détectés (sur-souscription) : avertir que les processus
  `tshark` vont se disputer le CPU, ce qui peut ralentir la lecture de
  chaque fichier plutôt que l'accélérer (deuxième ligne du tableau
  ci-dessus, reproduite avec `--parallel-workers 4` sur seulement 2
  fichiers pendant la validation : temps individuel par fichier passé
  de ~2.3s à ~4.4s).

Justification : la mesure a révélé une information directement utile à
quiconque lance `--parallel` sur un hôte contraint (conteneur, VM à 1-2
vCPU — de plus en plus courant), et rester silencieux dessus aurait
laissé le message existant ("temps réel écoulé inférieur SI...")
insuffisant pour la comprendre. Reste volontairement minimal : pas de
détection automatique pour désactiver `--parallel-workers` au-delà du
nombre de cœurs (l'utilisateur reste libre d'ignorer l'avertissement,
ex. s'il sait que son I/O est plus contraignant que son CPU), seulement
un avertissement informatif.

### Ce qui a été livré

- **`cross_capture_analyzer_cli.py`** / **`cross_capture_diff_cli.py`** :
  au lancement de `--parallel`, affichage du nombre de workers effectifs
  et de `os.cpu_count()`, puis l'un des deux avertissements ci-dessus
  selon le cas (aucun avertissement si plusieurs workers effectifs et
  pas de sur-souscription détectée). `import os` ajouté aux deux
  fichiers (absent jusqu'ici). Comportement sans `--parallel` strictement
  inchangé (revérifié).
- **Aucune modification** dans `pcap_parser.capture`
  (`parse_captures_parallel`) : le mécanisme lui-même n'a pas changé,
  seul le message affiché avant de l'appeler.

### Validation

596/596 tests hérités toujours verts (aucun test dédié à ce diagnostic :
il ne fait qu'imprimer sur stdout selon `os.cpu_count()`/
`args.parallel_workers`, déjà à la limite de ce que ce projet couvre par
`pytest` pour les CLI eux-mêmes — voir section 5.2, seuls
`pcap_parser`/`netcross_core`/`netcross_report` sont couverts). `ruff
check`/`ruff format --check`/`PYTHONPATH=src lint-imports` réexécutés,
tout passe (59 fichiers dans les 4 packages sous contrat, 146
dépendances, aucun cycle).

Les trois messages rejoués réellement sur les deux CLI (vrai `tshark`,
vrais pcap `scapy`) : `--parallel` seul (1 worker effectif, avertissement
"aucun gain" affiché) ; `--parallel --parallel-workers 4` sur l'analyzer
et `--parallel-workers 3` sur le diff (sur-souscription, avertissement
"se disputent le CPU" affiché, temps individuels par fichier confirmés
dégradés) ; cas normal sans avertissement non retesté explicitement
(couvert par construction : les deux `elif` ne se déclenchent que sur
les deux conditions ci-dessus, absentes dans le cas normal).

### Non traité dans cette passe

- **`.rpm Rocky`** — nécessite une vraie Rocky Linux, indisponible dans
  cet environnement ; `rpmbuild` lui-même absent depuis la Session 30.
- **`FIXME`/licence** — placeholders nécessitant les vraies coordonnées
  du mainteneur (email, compte GitHub), non renseignables sans inventer
  une fausse information. `LICENSE` était alors complète (MIT, nom et
  année présents, aucun placeholder) ; le projet est passé en
  **GPL-3.0-or-later** (PR #989) et plus aucun FIXME de licence ne
  subsiste dans `LICENSE`, `debian/control` ou `netcross.spec`.
- **Mesure du gain `--parallel` sur un hôte multi-cœurs réel** — le
  mécanisme reste architecturalement sain (voir "Résultat mesuré"
  ci-dessus) mais aucun hôte de ce type n'était disponible cette
  session pour le confirmer empiriquement.
- **Validation CAPWAP sur vraie capture (Aruba/Cisco/Fortinet)** — seul
  candidat 🟠 restant, toujours hors d'atteinte sans matériel/trafic
  vendeur réel.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (CLI d'interrogation de l'historique — `cross_history_cli.py` — Session 30)

- **Piste retenue** : "CLI d'interrogation de l'historique sans capture"
  de la section 5.2 — entrée ajoutée par la Session 29 elle-même en
  laissant volontairement ce point de côté ("Une vraie interrogation
  seule [...] demanderait un sous-commande ou un script dédié, pas juste
  un nouveau flag"). Seul candidat 🟢 qui soit à la fois un vrai
  chantier de code et isolé/cadrable en une seule passe : CAPWAP
  Fortinet (hors d'atteinte sans trafic vendeur réel), NetFlow/sFlow
  ("chantier plus large, architecture à part"), capture continue
  ("plus gros chantier [...] à cadrer avant de coder") et pistes GitHub
  (exploratoire, aucun engagement) tous écartés pour les mêmes raisons
  qu'en Session 29. Les "validations admin" restent hors du type de
  tâche visé (tests/ménage, pas de code). Le candidat 🟠 (validation
  CAPWAP vendeur réel) reste hors d'atteinte sans matériel, comme
  depuis plusieurs sessions.
- **Périmètre volontairement étroit** : un script de lecture seule,
  aucune nouvelle logique métier — toute la mécanique (`list_history`/
  `print_history`) existait déjà depuis la Session 29. La seule vraie
  addition de code est le filtre `run_type` sur `list_history()`
  (absent jusqu'ici : les deux CLI d'analyse n'en avaient pas besoin,
  chacun connaissant déjà le type du run qu'il vient d'enregistrer).
  Décidé de l'ajouter au niveau de la bibliothèque (`netcross_report.
  history`) plutôt que de filtrer côté script : cohérent avec `label`,
  déjà un paramètre de `list_history()` et pas une étape de post-
  traitement séparée.
- **Piège trouvé en construisant réellement le paquet `.deb`** : le bit
  exécutable du fichier source `cross_history_cli.py` avait été oublié
  (`chmod 644` par défaut à la création, jamais aligné sur les deux
  autres CLI). Repéré non pas en le supposant correct par analogie, mais
  en inspectant le contenu réel du `.deb` construit avec
  `dpkg-buildpackage` (disponible cette session, jamais tenté lors d'une
  session précédente) : `dpkg-deb -c` montrait `-rw-r--r--` sur ce
  fichier contre `-rwxr-xr-x` sur `cross_capture_analyzer_cli.py`/
  `cross_capture_diff_cli.py`. Corrigé (`chmod 755`), `.deb` reconstruit,
  contenu revérifié.
- **Parité de packaging complète, pas seulement le script** : wrapper
  `netcross-history` (`build-deb/wrappers/` + `build-rpm/wrappers/
  netcross-history-wrapper`, contenu identique aux deux fichiers près du
  nom, même convention que les wrappers `netcross-diff` existants),
  `debian/netcross.install` (script + wrapper), `debian/control`
  (description — corrige au passage un oubli préexistant : `netcross-
  diff` n'y était déjà pas mentionné), `netcross.spec` (`%install`/
  `%files`) et `build-rpm/build.sh` (copie du script + du wrapper dans
  l'arborescence de build). Décision : traiter ce script comme un
  citoyen de première classe (troisième CLI packagé), pas comme un
  utilitaire annexe — cohérent avec le fait qu'il installe un vrai
  binaire `/usr/bin/netcross-history`, au même titre que les trois
  autres commandes existantes.

**Validation** : `tshark`/`pytest`/`ruff`/`import-linter`/`scapy`
toujours disponibles cette session (même environnement qu'en Session
29). Suite héritée rejouée avant tout changement : 594/594 verts. 2
nouveaux tests (`tests/test_history.py`, filtre `run_type` seul puis
combiné avec `label`) → **596/596** au total, aucune régression. `ruff
check`/`ruff format --check` et `PYTHONPATH=src lint-imports` (toujours
59 fichiers dans les 4 packages sous contrat — les CLI de premier
niveau n'en font pas partie, voir section 1 — 146 dépendances, aucun
cycle) réexécutés après modification, tout passe.

Validation bout-en-bout du script lui-même (même discipline que les
deux autres CLI, jamais couverts par `pytest` — voir section 5.2 et
`tests/test_diff_cli_live.py`) : base peuplée par 2 runs réels de
`cross_capture_analyzer_cli.py --history-db` (étiquettes `Site-A`/
`Site-B`) et 1 run réel de `cross_capture_diff_cli.py --history-db`
(étiquette `Site-A`, même fichier `.db` partagé) — vrai `tshark`, vrais
pcap `scapy`. `cross_history_cli.py --db` ensuite rejoué avec : aucun
filtre (3 runs, plus récent d'abord) ; `--label Site-A` (2 runs, analyse
+ diff) ; `--run-type diff` (1 run) ; `--label Site-A --run-type
analyse` combinés (1 run, le bon) ; `--limit 1` (1 seul, le plus
récent). Cas limites vérifiés : `--db` sur un chemin qui n'existe pas
encore (historique vide affiché, fichier confirmé non créé après coup) ;
`--limit 0` (refusé, message clair, exit 1) ; `--run-type bogus`
(refusé par `argparse`, exit 2) ; `--db` omis (refusé par `argparse`,
exit 2, `required=True`).

Packaging validé réellement pour le `.deb` : `debhelper`/`dpkg-dev`
installés cette session (absents jusqu'ici, jamais tenté lors d'une
session précédente), `build-deb/build.sh` exécuté de bout en bout sans
erreur, `.deb` généré inspecté avec `dpkg-deb -c` — `netcross-history`
présent dans `/usr/bin/` (`rwxr-xr-x`), `cross_history_cli.py` présent
dans `/usr/share/netcross/` avec les bonnes permissions après la
correction du bit exécutable (voir piège ci-dessus). `netcross.spec`/
`build-rpm/build.sh` mis à jour par la même symétrie exacte mais **non
rejoués** : `rpmbuild` absent de cet environnement (vérifié explicitement,
`which rpmbuild` sans résultat) — reste une dette de validation assumée,
notée dans "Non traité dans cette passe" de `docs/sessions/`. Artefacts de
build (`build-deb/_build/`, `build-deb/dist/`) supprimés après
validation, non inclus dans la livraison — ce projet n'a pas de
`.gitignore` (vérifié : fichier absent), donc nettoyage manuel explicite
plutôt qu'une règle qui l'aurait fait pour cette session.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (historique inter-runs SQLite — Session 29)

- **Piste retenue** : "Historique inter-sessions (SQLite)" de la section
  5.2 — seul candidat 🟢 restant qui soit à la fois un vrai chantier de
  code (contrairement aux "validations admin", tests/ménage sans code)
  et isolé/cadrable en une seule passe (contrairement à CAPWAP Fortinet,
  NetFlow/sFlow, ou la capture continue — respectivement hors d'atteinte
  sans matériel réel, chantier à architecture propre, et explicitement
  "à cadrer avant de coder" dans la section 5.2 elle-même). Le seul
  candidat 🟠 restant (validation CAPWAP vendeur réel) reste, comme en
  Session 28, hors d'atteinte sans matériel.
- **Désambiguïsation faite avant d'écrire le code** : le mot "session"
  est employé avec deux sens sans rapport dans ce projet. Dans
  "historique inter-**sessions**" (nom de la piste en section 5.2), une
  session désigne une **exécution de la CLI** (un point dans le temps où
  l'outil a été lancé) — pas une session de développement Claude
  (vocabulaire de ce fichier, "Session 29"). D'où le nom de fonction
  retenu, `record_run`/`record_diff_run` plutôt que `record_session`,
  pour ne pas entretenir la confusion dans le code lui-même — seule la
  docstring de module explicite le rapprochement avec le nom de la piste
  d'origine.
- **Périmètre décidé avant d'écrire le code** : un **résumé compact**
  par run (score de santé, nombre de constats par sévérité, points,
  étiquette libre), pas le détail des constats — déjà couvert par
  `--json-report`/`--pdf-report`/`--detail-csv`, qui restent la source
  de vérité pour un run donné. L'historique répond à une question
  différente ("tendance dans le temps") que ces trois-là ("détail d'un
  run"). Décision qui a aussi simplifié le câblage CLI : pas de nouveau
  mode "interrogation seule sans capture" (aurait demandé de retravailler
  le parsing d'arguments des deux CLI, `--capture`/`--baseline`/
  `--current` étant `required`) — `--history-show` affiche l'historique
  **après** un run normal, jamais à la place d'un run. Une CLI dédiée à
  l'interrogation pure de la base, indépendante d'une analyse, est
  laissée pour une session future si le besoin s'en fait sentir (voir
  section 5.2, nouvelle entrée).
- **Décision de conception — asymétrie `record_run`/`record_diff_run`
  assumée, pas un oubli** : `record_run` intègre `tls_findings`/
  `quic_findings` au même triage que `--json-report`
  (`generate_json_report`) sur un run d'analyse simple. `record_diff_run`
  n'accepte **volontairement pas** de paramètres `tls_findings_baseline/
  current` ni `quic_findings_baseline/current` : sur un diff, TLS/QUIC ne
  connaissent qu'un état à un instant donné (pas de vraie diff sémantique
  entre baseline et courant, voir `--tls`/`--quic` sur
  `cross_capture_diff_cli.py`), donc ne participent déjà à aucun
  `rank_segments`/`health_score` sur le PDF/JSON de diff
  (`generate_json_diff`/`generate_diff_pdf`) — reproduire cette même
  asymétrie ici plutôt que d'inventer un comportement différent pour
  l'historique.
- **Schéma SQLite volontairement minimal** : une seule table `runs`,
  colonnes scalaires + JSON sérialisé pour les champs structurés
  (`points`, `finding_counts`, `meta`) plutôt que plusieurs tables
  reliées par clé étrangère — le volume attendu (un résumé par
  exécution manuelle de CLI, pas un flux continu) ne justifie pas un
  schéma normalisé, et une table unique reste trivialement lisible par
  un outil tiers (`sqlite3`, DBeaver, etc.) sans documentation
  supplémentaire. `CREATE TABLE IF NOT EXISTS` exécuté à chaque
  connexion (écriture **et** lecture) : idempotent, pas de migration à
  gérer pour une v1.
- **`list_history` sur un fichier absent renvoie `[]` sans le créer** :
  `sqlite3.connect()` crée le fichier dès la connexion, y compris pour
  une lecture seule — sans vérification explicite (`os.path.exists`
  avant de se connecter), un simple `--history-show` sur un chemin qui
  n'existe pas encore aurait créé un fichier `.db` vide comme effet de
  bord surprenant. Repéré en écrivant le test correspondant avant
  l'implémentation, pas après coup.
- **Câblage CLI symétrique sur les deux outils** : `--history-db CHEMIN`
  (active l'enregistrement), `--history-label ÉTIQUETTE` (distingue
  plusieurs historiques dans un même fichier `.db` partagé, ex.
  plusieurs sites suivis dans la même base), `--history-show [N]`
  (`nargs="?"`/`const=10`, affiche les N derniers runs après celui-ci,
  filtré automatiquement sur `--history-label` si elle est fournie —
  décision : un run étiqueté n'a normalement d'intérêt à comparer que
  vis-à-vis de runs de la même étiquette). `--history-label`/
  `--history-show` sans `--history-db` : refusés explicitement, même
  discipline que `--redact-map` sans `--redact` (Session 28). Sur
  `cross_capture_analyzer_cli.py`, la condition qui déclenche le calcul
  (déjà paresseux) de `findings` a été étendue à `args.history_db` (elle
  ne couvrait jusqu'ici que `--triage`/`--pdf-report`/`--json-report`) :
  sans cet ajout, `--history-db` seul (sans aucun de ces trois) aurait
  enregistré un résumé toujours à 0 constat, quel que soit le contenu
  réel de la capture. Sur `cross_capture_diff_cli.py`, `findings` n'est
  jamais paresseux (`diff_reports()` toujours appelé) : aucun ajustement
  équivalent nécessaire de ce côté.
- **Compatible avec `--redact` sans restriction** : contrairement à
  `--tls`/`--quic`/`--client-group`, l'historique ne lit/réaffiche aucune
  adresse — seulement un score et des compteurs. `meta={"Anonymisation":
  ...}` reporté automatiquement dans la ligne SQLite quand `--redact` est
  actif, même plomberie `meta` déjà réutilisée pour PDF/JSON depuis la
  Session 28.

**Validation** : `tshark` (4.2.2), `pytest`, `ruff`, `import-linter`,
`scapy`, `reportlab`/`matplotlib`/`networkx`/`cryptography` tous
installés/disponibles cette session (accès réseau disponible). Suite
héritée rejouée avant tout changement : 581/581 verts, `ruff check`/
`ruff format --check`/`PYTHONPATH=src lint-imports` propres. 13 nouveaux
tests dans `tests/test_history.py` (structure de base de `record_run`/
`record_diff_run`, cohérence du score avec un calcul indépendant via
`triage.rank_segments`/`health_score`, `findings` précalculé non
recalculé — même garde que `generate_json_report`/`json_report.py` —,
intégration TLS/QUIC sur `record_run` et son absence volontaire sur
`record_diff_run` vérifiée par introspection de signature, méta/
étiquette reportées, ordre plus récent d'abord et `limit`, filtre par
étiquette, absence de fichier créé sur une lecture à vide, lecture brute
via `sqlite3` d'un fichier réellement exploitable par un outil tiers,
`print_history` sur liste vide et sur un run diff) — **594/594** au
total, aucune régression. `ruff check`/`ruff format --check` et
`PYTHONPATH=src lint-imports` (59 fichiers, 146 dépendances, aucun
cycle) réexécutés après modification, tout passe.

Validation bout-en-bout **avec un vrai `tshark`** et de vrais pcap
`scapy` (flux TCP de 40 segments entre deux IP réelles, vu à deux points
LAN/WAN, pertes introduites côté WAN — `--order` fourni pour que la
corrélation de pertes s'active réellement, absente sans lui) : trois
runs successifs de `cross_capture_analyzer_cli.py --history-db` sur le
même fichier (étiquettes `Site-A`, `Site-B`, puis sans étiquette) —
score de santé et compteurs de constats confirmés cohérents avec le
triage affiché sur stdout, `--history-show` confirmé filtré sur
`Site-A` seul quand l'étiquette est fournie, confirmé montrant tous les
runs (mélange d'étiquettes) sinon. Un run de
`cross_capture_diff_cli.py --history-db` sur le **même fichier** que les
runs d'analyse : lecture brute `sqlite3` confirme les deux `run_type`
(`analyse`/`diff`) coexistants dans la même table, `--history-show`
confirmé mélangeant les deux types dans l'ordre plus récent d'abord.
Combinaison avec `--redact` vérifiée : `meta.Anonymisation` présent dans
la ligne SQLite insérée. Code de sortie du CLI diff vérifié inchangé
(`exit 1` sur régression détectée) malgré l'ajout du bloc `--history-db`
juste avant. Les 2 refus (`--history-label`/`--history-show` sans
`--history-db`) vérifiés avec le vrai CLI sur les deux outils (message
clair, code de sortie 1, 3 invocations testées au total).

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (anonymisation des adresses — `--redact` — Session 28)

- **Piste retenue** : "Anonymisation (`--redact`)" de la section 5.2 —
  seconde moitié de la piste "Anonymisation / fusion de captures
  segmentées" scindée en Session 27 (voir son entrée ci-dessous),
  laissée ouverte à l'époque. Seul autre candidat 🟠 restant
  (validation CAPWAP sur une vraie capture Aruba/Cisco) hors d'atteinte
  sans matériel vendeur réel — `--redact` était donc le candidat le
  plus isolé/rapide à cadrer correctement en une seule passe.
- **Périmètre décidé avant d'écrire le code** : "adresses" au sens
  strict (IP + MAC), pas "tout ce qui identifie". Noms DNS/URI HTTP/SAN
  TLS/identifiants SIP explicitement laissés inchangés — assumé et
  documenté (docstring de module, README "Limites connues") plutôt
  qu'une couverture partielle non signalée qui aurait donné une fausse
  impression de sécurité.
- **Piège trouvé en lisant `pcap_parser.packet.build_packet` avant
  d'écrire quoi que ce soit** : sur un paquet **STP**, les champs
  `src`/`dst` portent `eth.src`/`eth.dst` — une adresse **MAC**, pas une
  IP — contrairement à tous les autres protocoles où ces deux champs
  sont des IP. Une anonymisation naïve (traiter `src`/`dst` comme des IP
  partout) aurait planté ou, pire, laissé les vraies MAC intactes en
  silence sur ce protocole précis. Traité explicitement via `pk.proto
  == "STP"` dans `AddressRedactor._redact_one`.
- **Décision de conception — mapping partagé, pas par-flux** : une même
  adresse réelle produit toujours le même pseudonyme sur tout l'appel à
  `AddressRedactor`, y compris à travers plusieurs listes de paquets
  (nécessaire pour `cross_capture_diff_cli.py` : baseline et courant
  doivent partager le même mapping, sans quoi une adresse commune aux
  deux runs obtiendrait deux pseudonymes différents et casserait la
  lisibilité du diff). Vérifié bout en bout (voir Validation).
- **Décision de conception — refus explicite plutôt que redaction
  partielle silencieuse** : `--tls`/`--quic` relisent les fichiers
  d'origine avec leur propre pipeline de décodage (voir
  `netcross_core.tls_diagnostics`/`quic_diagnostics`, pipeline
  indépendant de `netcross_core.parsing`) — les adresses qui y
  apparaissent ne passent jamais par la liste `all_packets` anonymisée.
  `--client-group` reçoit des adresses IP réelles **directement en
  argument de commande** et les réaffiche telles quelles dans
  `print_client_comparison` (`IP(s) : {ips}`) — aucun lien avec les
  paquets anonymisés non plus. Combiner `--redact` avec l'un de ces
  trois flags aurait donc produit un rapport *partiellement* anonymisé
  sans le signaler : refusé explicitement (`sys.exit(1)`, message
  explicatif), même discipline que le refus déjà existant de `--live`
  avec `--tls`/`--quic`/`--parallel` (Sessions 5/10/16). Un vrai support
  de ces trois combinaisons demanderait de retravailler ces pipelines
  indépendants pour qu'ils passent eux aussi par le mapping partagé —
  chantier distinct, non entamé ici (voir section 5.2 pour un futur
  candidat si le besoin se confirme).
- **Câblage à coût quasi nul** : la redaction s'applique une seule fois,
  juste après le chargement des paquets et avant `correlate`/`analyse` —
  tout le reste du pipeline (`analysis.py`, `report_text.py`,
  `synthesis.py`, `triage.py`, `pdf.py`, `charts.py`, `json_report.py`)
  n'a **aucune ligne modifiée** : il ne voit que des `Pkt` déjà
  pseudonymisés, y compris dans les chaînes d'exemples formatées
  (`pmtud_blackhole_examples`, etc.) puisqu'elles sont construites par
  `analysis.py` à partir des champs déjà réécrits. Même esprit que la
  fusion de captures segmentées de la Session 27. Seul ajout hors
  `redact.py` lui-même : le paramètre `meta` — déjà présent sur les
  quatre fonctions d'export (`generate_pdf`/`generate_diff_pdf`/
  `generate_json_report`/`generate_json_diff`) mais jamais utilisé par
  les CLI jusqu'ici — récupéré pour signaler `{"Anonymisation": ...}`
  en page de garde du PDF et dans le JSON quand `--redact` est actif.
- **Pseudonymes format-préservants et non routables** : IPv4 → RFC 5737
  (`192.0.2.0/24`/`198.51.100.0/24`/`203.0.113.0/24`, plages de
  documentation, jamais assignées sur le vrai Internet), IPv6 → RFC 3849
  (`2001:db8::/32`), MAC → OUI localement administré
  (`02:00:00:xx:xx:xx`, bit "locally administered" actif — jamais une
  vraie adresse issue d'un constructeur). Choisi plutôt que des
  placeholders opaques (`REDACTED-1`) pour que le résultat reste un
  paquet syntaxiquement valide et lisible (versions IPv4/IPv6
  distinguables), et pour que le caractère anonymisé soit reconnaissable
  sans ambiguïté par quiconque relit le rapport.
- **GUI GTK4 câblée en Session 37** (non câblée à l'origine en Session 28
  — décision assumée à l'époque : PyGObject/GTK4 indisponible dans
  l'environnement de développement pour valider visuellement/
  fonctionnellement un câblage, contrairement aux deux CLI) — une case
  "Anonymiser les adresses IP/MAC (--redact)" dans la grille d'options
  déjà partagée entre mode simple et mode diff (comme `--nat-tolerant`/
  `--parallel` envisagé à l'époque), mutuellement exclusive avec
  Diagnostic TLS/QUIC des deux modes. Validée avec un vrai GTK4 cette
  fois (smoke test réel, voir section 4, Session 37).

**Validation** : `tshark` (4.2.2), `pytest`, `ruff`, `import-linter` et
`scapy` tous disponibles simultanément cette session (accès réseau
disponible ; `reportlab`/`matplotlib`/`networkx`/`cryptography`
installés en plus pour couvrir `--pdf-report`/`--quic`). Suite héritée
rejouée avant tout changement : 554/554 verts, `ruff check`/`ruff
format --check` et `PYTHONPATH=src lint-imports` propres. 27 nouveaux
tests dans `tests/test_redact.py` (générateurs de pseudonymes purs et
leurs bornes de débordement IPv4 exactes — 253/254/507/508/761/762 —,
classification IP v4/v6/MAC, cas STP, cohérence croisée entre champs —
une même MAC vue en `src` STP et en `arp_sender_mac` ailleurs obtient le
même pseudonyme —, réutilisation du même `AddressRedactor` sur deux
appels successifs, tri/format de `entries()`, export CSV, compatibilité
`RawPacket` par duck typing) — **581/581** au total, aucune régression.
`ruff check`/`ruff format --check` et `PYTHONPATH=src lint-imports` (57
fichiers, 136 dépendances, aucun cycle) réexécutés après modification,
tout passe.

Validation bout-en-bout **avec un vrai `tshark`** et de vrais pcap
`scapy` (flux TCP entre deux IP réelles vu à deux points LAN/WAN + une
requête ARP, rejoués via le **vrai CLI**, pas de mock) : `--redact
--redact-map map.csv --detail-csv detail.csv` sur
`cross_capture_analyzer_cli.py` — `grep` sur stdout et sur
`detail.csv` confirme zéro occurrence des adresses réelles, `map.csv`
contient la correspondance exacte (3 IP + 1 MAC), `detail.csv` contient
bien les pseudonymes attendus. `--redact --json-report --pdf-report` :
`meta.Anonymisation` présent dans le JSON, zéro occurrence des adresses
réelles dans le JSON, mention "Anonymisation" confirmée en page de
garde du PDF via `pdftotext`. `cross_capture_diff_cli.py --baseline
... --current ... --redact --redact-map` : mapping strictement
identique des deux côtés (même 3 IP + 1 MAC, mêmes pseudonymes),
confirmant le partage baseline/courant. Les 3 refus testés avec le vrai
CLI (`--redact --tls`, `--redact --client-group ...`, `--redact-map`
sans `--redact`) : message clair, code de sortie 1 dans les 3 cas, sur
les deux CLI pour les combinaisons qui s'y appliquent. Non-régression
confirmée : sans `--redact`, `detail.csv` contient bien les adresses
réelles (comportement strictement inchangé).

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (fusion de captures segmentées — Session 27)

- **Piste retenue** : "Anonymisation (`--redact`) / fusion de captures
  segmentées" de la section 5.2, scindée en deux — seule la seconde
  moitié (fusion) est traitée cette session, `--redact` reste ouvert et
  distinct (rien de commun techniquement : l'un réécrit des adresses
  dans les paquets déjà chargés, l'autre change uniquement la façon de
  les charger).
- **Constat de départ** : `--capture NOM=chemin` (et son pendant
  `--baseline`/`--current` sur le CLI de diff) n'acceptait qu'un seul
  fichier par point. Une capture segmentée par rotation (`tcpdump -C`/
  `tshark -b`) obligeait donc soit à fusionner les segments au préalable
  avec un outil externe (`mergecap`), soit à perdre les segments
  suivants.
- **Découverte en lisant le code avant d'écrire quoi que ce soit** : le
  mécanisme qui rend cette fonctionnalité "quasi gratuite" existait déjà
  sans le savoir. `captures` (la liste intermédiaire construite par les
  deux CLI à partir de `--capture`/`--baseline`/`--current`) est une
  simple liste de tuples `(label, chemin)`, jamais dédupliquée ni
  indexée par label — et le chemin non-`--parallel`/non-`--live` de
  `main()` (`for label, path in captures: ... all_packets.extend(pkts)`)
  concatène déjà tout ce qu'elle contient, quel que soit le nombre
  d'entrées portant le même label. Fournir deux fois le même label
  aurait donc déjà "fonctionné" avant cette session (comportement jamais
  testé ni documenté comme un cas d'usage). Cette session n'ajoute donc
  aucune nouvelle machinerie de décodage/corrélation : elle expose une
  syntaxe explicite (`NOM=chemin1,chemin2,...`, virgules) sur un
  mécanisme déjà présent, avec la validation qui allait avec (segment
  vide refusé, ex: virgule en trop).
- **`--parallel` en profite automatiquement** : chaque segment devient
  sa propre entrée `(label, chemin)`, donc son propre processus `tshark`
  dans `parse_captures_parallel` — une capture très segmentée gagne
  potentiellement plus de parallélisme qu'un seul gros fichier par
  point, sans aucune modification de cette fonction.
- **Décision assumée** : aucun tri par timestamp des paquets fusionnés.
  Les segments doivent être listés par l'appelant dans l'ordre
  chronologique (ordre naturel d'une rotation tcpdump). Vérifié avant de
  faire ce choix que les quelques analyses sensibles à l'ordre au sein
  d'un point (`_analyse_stp_instability`, `_analyse_idle_timeout`, voir
  Sessions 23/25) trient déjà explicitement en interne plutôt que de
  faire confiance à l'ordre de `all_packets` — un tri global aurait donc
  été un coût (O(n log n) sur potentiellement toute la capture) sans
  bénéfice réel.
- **Câblage** : `_parse_capture_spec` (nouvelle fonction pure,
  `cross_capture_analyzer_cli.py`) et `_parse_capture_args` (fonction
  existante étendue, `cross_capture_diff_cli.py`, partagée par
  `--baseline`/`--current`) — chaque CLI garde sa propre copie de cette
  logique de parsing, même choix d'indépendance que pour `--live`/
  `--live-current` (Sessions 5/16, voir leurs docstrings de module).
  `--live`/`--live-current` eux-mêmes non concernés (pas de fichiers).

**Validation** : `tshark`, `pytest`, `ruff`, `import-linter`,
`pre-commit`, `scapy` tous disponibles simultanément cette session
(accès réseau disponible). Suite héritée rejouée avant tout changement :
540/540 verts. 14 nouveaux tests dans `tests/test_capture_segments.py`
(fonctions de parsing pures des deux CLI, formats valides/invalides,
segment vide au milieu/en fin de liste ; deux scénarios bout-en-bout par
CLI avec `parse_capture` monkeypatché selon le chemin reçu, pour
confirmer que les segments sont bien concaténés dans le `Report` final
et pas seulement dans la liste intermédiaire `captures`) — **554/554**
au total, aucune régression. `ruff check`/`ruff format --check` (3
corrections `PERF401`/`RUF059` appliquées avant validation finale),
`PYTHONPATH=src lint-imports` (55 fichiers, 131 dépendances, aucun
cycle) et `pre-commit run --all-files` (les 3 hooks) tous réellement
exécutés, tout passe.

Validation bout-en-bout **avec un vrai `tshark`** et de vrais pcap
`scapy` : un flux TCP de 6 paquets généré en un seul fichier
(`lan_full.pcap`) puis rejoué une seconde fois découpé en deux fichiers
de 3 paquets chacun (`lan_seg1.pcap`/`lan_seg2.pcap`, simulant une
rotation `tcpdump -C`). Rejeu du **vrai CLI**
(`cross_capture_analyzer_cli.py --capture LAN=lan_seg1.pcap,lan_seg2.pcap`)
: `6` paquets comptés au point LAN, identique au fichier unique — chaque
segment rapporté séparément en console (`[LAN] 3 paquets ... depuis
lan_seg1.pcap`, puis `lan_seg2.pcap`). Confirmé aussi avec `--parallel`
(deux lignes de timing distinctes, une par segment) et côté CLI de diff
(`--baseline LAN=base1.pcap,base2.pcap --current LAN=full.pcap`, les
deux segments du baseline bien rapportés `[baseline/LAN]` séparément).
Erreur de format (virgule en trop) testée avec le vrai CLI : message
d'erreur clair, code de sortie 1.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (TLS approfondi — certificat serveur — Session 26)

- **Piste retenue** : "TLS approfondi (chaîne de certs, réassemblage)"
  de la section 5.2, dernier candidat 🟢 substantiel restant. Suggestion
  initiale de `docs/features-backlog.md` suivie à la lettre : "passerait par le
  dissecteur TLS de tshark plutôt que `scapy.layers.tls`" — cette
  session lit la dissection X.509 **déjà faite par tshark** (`-T ek`,
  même pipeline que tout le reste), plutôt que d'étendre le parseur TLS
  binaire fait main de `netcross_core/tls_diagnostics.py` (qui, lui,
  n'est pas touché cette session — reste dédié au suivi d'état du
  handshake lui-même : SNI, version, cipher, alertes, réussi/bloqué).
- **Exploration empirique nettement plus lourde que d'habitude** :

  génération d'un **vrai handshake TLS** sur boucle locale (`openssl
  s_server`/`s_client`), capturé avec `tshark -i lo` — la capture réseau
  réelle s'est révélée possible dans cet environnement (contrairement à
  une hypothèse implicite des sessions précédentes, qui n'avaient
  jamais tenté). Deux découvertes structurantes pour la conception :
  1. **TLS 1.3 chiffre le message Certificate** (RFC 8446) — invisible
     en capture passive sans les clés de session. Une première capture
     en TLS 1.3 (négocié par défaut par `openssl s_client` récent) l'a
     confirmé concrètement ; forcé TLS 1.2 pour obtenir un Certificate
     en clair, cas réaliste pour un outil de capture passive sur le
     terrain (beaucoup de trafic d'entreprise reste en 1.2, et même en
     1.3 un tap passif sans `SSLKEYLOGFILE` ne verrait rien).
  2. **Subject/Issuer (Distinguished Name) sont positionnellement
     ambigus en EK** : tshark aplatit `x509if.oid`/`x509sat.
     uTF8String`/`x509sat.CountryName`/... en tableaux **partagés entre
     TOUTES les RDN de TOUS les certificats de la chaîne**, sans moyen
     fiable de déterminer par position laquelle des deux RDN (Issuer ou
     Subject, du même certificat OU d'un autre de la chaîne) correspond
     à quel attribut. Décision de conception prise **avant d'écrire le
     moindre code** : Subject/Issuer explicitement **exclus** du
     périmètre (reconstruction fiable demanderait `-T json`/`-T pdml`,
     pas le flux EK aplati utilisé partout ailleurs dans ce pipeline —
     chantier à part). En revanche `x509ce.dNSName` (SAN) et
     `x509af.utcTime` (dates de validité) se sont révélés être des
     champs à plat SANS cette ambiguïté, le premier élément
     correspondant TOUJOURS au certificat feuille (RFC 5246 §7.4.2 :
     "the sender's certificate MUST come first") — d'où le périmètre
     finalement retenu.
- **Nouvelle fonction `pcap_parser.protocols.extract_tls_certificate`**,
  même patron que `extract_dns`/`extract_http`/`extract_sip`/
  `extract_dhcp` (lit une dissection déjà faite par tshark, pas de
  parsing manuel). Nouveaux champs `RawPacket`/`Pkt.tls_cert_not_
  before`/`tls_cert_not_after`/`tls_cert_san`/`tls_cert_serial`. Câblée
  dans `build_packet()` sous `if proto == "TCP":` (TLS est TCP
  uniquement — TLS-sur-UDP/QUIC déjà couvert séparément par
  `quic_diagnostics.py`).
- **Deux diagnostics indépendants** (`_analyse_tls_certificate`,
  `netcross_core.analysis`) :
  1. `tls_cert_invalid_dates` (**par point**, comme ARP/STP) — le
     certificat feuille est présenté hors de sa fenêtre de validité au
     moment de la capture (déjà expiré, ou plus rarement pas encore
     valide — horloge serveur désynchronisée). Comparaison contre
     l'horodatage du PAQUET lui-même (pas l'heure actuelle) — une
     analyse à froid d'une capture ancienne reste correcte, un
     certificat valide au moment de la capture mais expiré depuis
     aujourd'hui n'est **pas** signalé à tort.
  2. `tls_cert_mismatch` (**par paire de points**, comme
     `pmtud_blackhole`/`idle_timeout_dropped`) — pour une même connexion
     (5-tuple), le numéro de série du certificat diffère entre l'amont
     et l'aval : signature possible d'une interception/substitution TLS
     en cours de chemin (proxy d'inspection, dispositif MITM), ou plus
     bénin un load-balancer qui termine le TLS avec un certificat
     différent du serveur réel en amont. C'est ce second diagnostic qui
     exploite le mieux l'identité propre de l'outil (comparaison
     multi-points), au-delà de ce qu'un simple `openssl x509 -checkend`
     ou Wireshark mono-capture pourrait déjà dire.
- **Câblage entièrement générique confirmé par lecture de code** :
  `netcross_report/synthesis.py` (deux `Finding` distincts, catégorie
  "TLS", sévérité `anomalie`), `netcross_core/report_text.py` (section
  console dédiée), `netcross_core/baseline_diff.py` (comparaison par
  point pour les dates, par paire pour la substitution) — aucune
  modification nécessaire dans `json_report.py`, `pdf.py`, `charts.py`,
  ni la GUI GTK4.
- **Limites assumées, documentées explicitement** (docstring de
  `extract_tls_certificate` et de `_analyse_tls_certificate`) : pas de
  vérification de la chaîne de confiance PKI (autorité, révocation —
  hors de portée d'une capture passive, qui n'a pas accès au magasin de
  confiance du client) ; une seule paire de dates par connexion et par
  point (le dernier handshake observé écrase le précédent en cas de
  reprise de session/renégociation) ; invisible en TLS 1.3 sans
  `SSLKEYLOGFILE` (voir plus haut).
- **Validé de bout en bout** : suite `pytest` complète rejouée avant
  toute modification (514/514 hérités de la Session 25, aucune
  régression préalable). 26 nouveaux tests : `tests/test_protocols.py` (champs réels, un seul SAN
  pas en liste, SAN absent, plusieurs certificats de la chaîne — prend
  le premier, absence de certificat, moins de deux dates) ; `tests/
  test_packet.py` (certificat présent, absent, ignoré sur UDP) ;
  `tests/test_analysis.py` (certificat valide, expiré, pas encore
  valide, sans certificat, date illisible sans planter, substitution
  détectée, pas de substitution si même série, pas de substitution si
  vu à un seul point, indépendance par connexion) ; `tests/
  test_synthesis.py`, `tests/test_report_text.py`, `tests/
  test_baseline_diff.py` (finding, affichage texte y compris message
  par défaut, comparaison de baseline pour les deux compteurs) —
  **540/540** au total, aucune régression. `tshark`/`pytest`/`ruff`/
  `import-linter`/`pre-commit`/`scapy`/`openssl` tous disponibles cette
  session. Rejeu du **vrai CLI**
  (`cross_capture_analyzer_cli.py --order A,B --triage --json-report`)
  sur des pcaps construits à partir de VRAIS handshakes TLS 1.2 capturés
  en local (pas seulement des couches EK synthétiques) : (1) certificat
  présenté avec un horodatage de capture décalé ~5 ans dans le futur
  (au-delà de sa validité de 365 jours) au point A, second certificat
  (numéro de série différent) au point B pour le même 5-tuple —
  correctement détecté et remonté en console/JSON/triage, les deux
  findings "TLS" distincts, avec le numéro de série complet dans chaque
  exemple ; (2) même certificat aux deux points, horodatage dans sa
  fenêtre de validité : aucun faux positif, message par défaut affiché.
  `ruff check`, `ruff format --check` (49 fichiers conformes après une
  correction automatique d'import trop long), `PYTHONPATH=src
  lint-imports` (aucun cycle introduit, 1 contrat respecté), `pre-commit
  run --all-files` (3 hooks) tous rejoués réellement, tout passe.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (Analyse L2 — instabilité STP — Session 25)

- **Piste retenue** : dernier reliquat de "Analyse L2 (ARP/STP)"
  (section 5.2), laissé explicitement ouvert en Session 24 faute de
  module `scapy.contrib.stp` détecté à l'époque. **Correction en tout
  début de session** : ce module contrib n'existe effectivement pas,
  mais `scapy.layers.l2.STP` existe nativement dans `scapy` 2.7.0
  (jamais cherché dans le bon module en Session 24) — la limitation
  d'environnement documentée n'était donc pas réelle, STP est
  pleinement réalisable.
- **Exploration empirique préalable** : pcap STP synthétique construit
  avec `scapy.layers.l2.STP` (Configuration BPDU normale, Configuration
  BPDU avec bit TC actif, TCN construite en bytes bruts car scapy n'a
  pas de classe dédiée pour ce type minimal), inspecté via un vrai
  `tshark -T ek` 4.2.2. Champs confirmés : `stp.type`→`stp_stp_type`,
  `stp.flags.tc`→`stp_stp_flags_tc` (booléen **natif** tshark),
  `stp.root.prio`→`stp_stp_root_prio`, `stp.root.hw`→`stp_stp_root_hw`.
  **Découverte empirique clé** : sur une TCN (type 0x80, trame BPDU
  minimale de 4 octets utiles par construction, IEEE 802.1D), les
  champs `stp.flags.tc` et `stp.root.*` sont **absents** du layer EK
  (pas juste vides) — cohérent avec le format du protocole (une TCN n'a
  structurellement ni champ flags, ni champs root/bridge).
- **Signal recherché — deux compteurs indépendants, par point** (pas
  par paire, même raisonnement qu'ARP en Session 24 — STP n'est jamais
  relayé par un routeur, une corrélation amont/aval n'aurait pas de
  sens) : (1) `stp_topology_change` — un événement de changement de
  topologie, signalé de façon équivalente par une BPDU TCN **ou** une
  Configuration BPDU avec le bit TC actif (les deux comptent séparément
  s'ils apparaissent tous les deux, ce sont deux trames distinctes même
  si elles signalent le même phénomène réseau) ; (2) `stp_root_change`
  — le pont racine annoncé (priorité + MAC) change de valeur d'une
  Configuration BPDU à la suivante, au même point. Nouveaux champs
  `Report.stp_topology_change`, `Report.stp_root_change`/
  `stp_root_change_examples`, détecteur `_analyse_stp_instability`
  (`netcross_core.analysis`).
- **Piège potentiel anticipé et neutralisé avant tout test** (pas
  découvert après coup) : la comparaison "racine précédente → racine
  actuelle" pour `stp_root_change` ne doit **pas** supposer que
  `all_packets` est globalement trié par horodatage entre points — le
  CLI concatène les paquets point par point (voir
  `cross_capture_analyzer_cli.py`), pas un merge chronologique global.
  Le détecteur trie explicitement chaque point avant comparaison
  (`pkts.sort(key=lambda p: p.ts)`), même discipline défensive que
  `_analyse_idle_timeout` en Session 23. Testé explicitement par
  `test_stp_root_change_trie_par_timestamp_avant_comparaison` (paquets
  fournis dans le désordre).
- **Changement de pipeline** : nouvelle branche `elif stp is not None:`
  dans `build_packet()` (STP, comme ARP, n'a pas d'en-tête IP — IEEE
  802.1D). Contrairement à ARP (qui porte ses propres adresses IP,
  réutilisées pour `src`/`dst`), STP ne porte **aucune** adresse IP —
  `src`/`dst` réutilisent donc l'adresse MAC Ethernet de la trame
  (`eth.src`/`eth.dst`, cette dernière toujours l'adresse de groupe bien
  connue `01:80:c2:00:00:00`), récupérée directement via la couche `eth`
  (jamais tunnelée, pas besoin de logique `innermost`). Trois nouveaux
  champs dédiés `RawPacket`/`Pkt.stp_bpdu_type`/`stp_flags_tc`/
  `stp_root_id`. Nouvelle valeur `proto = "STP"`.
- **`netcross_core.correlate.correlate()` étendu** : l'exclusion de
  `flows` introduite pour ARP en Session 24 est généralisée
  (`pk.proto in ("ARP", "STP")`) — même raisonnement exact (diffusion/
  multicast local au segment, jamais relayé par un routeur, pas de
  sémantique requête/réponse par flux). Sans cette extension, le même
  risque de pollution des statistiques de perte/latence/topologie
  identifié pour ARP en Session 24 se serait reproduit à l'identique
  pour STP (trafic périodique multicast, typiquement toutes les 2s).
- **Câblage entièrement générique confirmé par lecture de code** :
  `netcross_report/synthesis.py` (deux `Finding` distincts, catégorie
  "STP", sévérité `anomalie`), `netcross_core/report_text.py` (section
  console dédiée), `netcross_core/baseline_diff.py` (deux comparaisons
  par point via `_compare_count`, `higher_is_worse=True`) — aucune
  modification nécessaire dans `json_report.py`, `pdf.py`, `charts.py`,
  ni la GUI GTK4.
- **Limite architecturale honnête documentée** : le "flapping de port"
  au sens strict (un port de commutateur qui bascule haut/bas) n'est
  **pas** directement observable depuis une capture réseau — cette
  information vit dans la table d'état interne du commutateur (SNMP/
  syslog), pas sur le fil. Ce détecteur observe la conséquence visible
  sur le fil (tempête de changements de topologie, réélections de
  racine) plutôt que la cause exacte (quel port, sur quel commutateur).
  Avec cette session, la piste "Analyse L2 (ARP/STP)" de la section 5.2
  est désormais entièrement traitée dans les limites de ce qu'une
  capture de trafic peut observer.
- **Validé de bout en bout** : suite `pytest` complète rejouée avant
  toute modification (490/490 hérités de la Session 24, aucune
  régression préalable). 16 nouveaux tests, 2 tests existants corrigés
  (`test_build_packet_sans_ip_ni_arp_renvoie_none` et
  `test_parse_capture_ignore_les_paquets_non_decodables` supposaient que
  STP retournait `None` — désormais faux, remplacés par un scénario LLDP
  toujours hors périmètre) : `tests/test_tunnels.py` (sélection de
  couche `stp`, avec et sans tunnel) ; `tests/test_packet.py`
  (Configuration BPDU normale/avec TC, TCN avec champs root absents,
  `src`/`dst` = adresse MAC Ethernet) ; `tests/test_correlate.py`
  (exclusion de STP de `flows`) ; `tests/test_analysis.py` (détection
  via TCN, détection via bit TC, pas de signal sur Configuration
  normale, TCN et bit TC comptés séparément, détection de changement de
  racine, pas de changement si racine stable, TCN sans champ root
  ignorée sans casser la comparaison, indépendance stricte par point,
  tri explicite par horodatage, ignore les paquets non-STP) ;
  `tests/test_synthesis.py`, `tests/test_report_text.py`, `tests/
  test_baseline_diff.py` (deux findings distincts, affichage texte y
  compris message par défaut, comparaison de baseline) — **514/514** au
  total, aucune régression. `tshark`/`pytest`/`ruff`/`import-linter`/
  `pre-commit`/`scapy` tous installables cette session (accès réseau
  disponible). Rejeu du **vrai CLI**
  (`cross_capture_analyzer_cli.py --order A,B --triage --json-report`)
  sur deux scénarios à 2 points construits avec scapy et un vrai
  `tshark -T ek` 4.2.2 : (1) réseau instable au point A (une TCN, une
  Configuration BPDU avec bit TC, une réélection de racine), point B
  stable et sans lien — correctement détecté et remonté en console
  (« 2 changement(s) de topologie, 1 reelection(s) de racine »), dans le
  triage et dans le JSON (deux findings catégorie "STP" distincts).
  **Section "Pertes" du rapport texte : "aucune détectée"** malgré du
  trafic STP multicast présent uniquement au point A — confirme
  concrètement que l'extension du correctif `correlate()` fonctionne ;
  (2) trafic STP stable et périodique uniquement : aucun faux positif,
  message par défaut affiché. `ruff check`, `ruff format --check` (49
  fichiers conformes), `PYTHONPATH=src lint-imports` (aucun cycle
  introduit, 1 contrat respecté), `pre-commit run --all-files` (3 hooks)
  tous rejoués réellement, tout passe.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (Analyse L2 — conflit d'adresse IP via ARP — Session 24)

- **Piste retenue** : candidat 🟢 urgence faible "Analyse L2 (ARP/STP)" de
  la section 5.2 ("Angle mort réel : IP dupliquée, boucle, flapping de
  port — mais cas d'usage restreint au LAN pur"). **Scope volontairement
  restreint à ARP seul cette session** — `scapy` 2.7.0 (seule version
  disponible avec accès réseau cette session) n'a pas de module
  `scapy.contrib.stp` pour construire des trames BPDU de test, et le
  couple ARP+STP est trop large pour une seule passe disciplinée. STP
  (boucle, flapping de port via TCN/topology-change) explicitement
  reporté à une session future — voir section 5.2.
- **Exploration empirique préalable** (même discipline qu'en Session 22
  pour ICMPv6) : pcap ARP synthétique construit avec `scapy` (requête
  who-has, réponse is-at, annonce gratuite), inspecté via un vrai
  `tshark -T ek` 4.2.2. Noms de champs EK confirmés :
  `arp.opcode`→`arp_arp_opcode`, `arp.src.hw_mac`→
  `arp_arp_src_hw_mac`, `arp.src.proto_ipv4`→`arp_arp_src_proto_ipv4`,
  `arp.dst.proto_ipv4`→`arp_arp_dst_proto_ipv4`. **Découverte utile** :
  tshark calcule nativement `arp.isgratuitous`/`arp.isannouncement`
  (sender IP == target IP, RFC 5227) — inutile de recalculer cette
  comparaison à la main, même discipline que la classification native
  des retransmissions TCP en Session 10 (lire ce que le dissecteur a
  déjà déterminé, pas le refaire soi-même).
- **Signal recherché** : deux adresses MAC différentes qui revendiquent
  la même adresse IP source sur un même point de capture (traité par
  chaque paquet ARP, requête ou réponse, chacun portant une revendication
  implicite "je suis cette IP, voici ma MAC" via son propre champ
  sender) — signature classique d'un conflit d'adresse IP (double
  affectation statique, ou bascule d'IP flottante VRRP/HA en cours de
  capture). Nouveau couple de compteurs `Report.arp_ip_conflict`/
  `arp_ip_conflict_examples`, détecteur `_analyse_arp_ip_conflict`
  (`netcross_core.analysis`). **Granularité PAR POINT** (pas par paire
  de points comme la plupart des autres détecteurs de ce module) : un
  conflit d'adresse se voit déjà au sein d'un seul point de capture,
  une corrélation inter-points n'apporte rien de plus ici — même
  granularité que `retrans_fast`/`retrans_rto`/`retrans_spurious`.
- **Changement de pipeline nécessaire, plus profond qu'anticipé** : ARP
  n'a structurellement pas d'en-tête IP (RFC 826), et `pcap_parser.
  packet.build_packet()` retournait jusqu'ici `None` pour tout paquet
  sans IPv4 ni IPv6 (`return None # ARP, STP, etc. -- hors perimetre`).
  Ajout d'une branche `elif arp is not None:` dédiée, qui réutilise les
  champs génériques `src`/`dst` existants pour porter les adresses IP
  *portées par le protocole ARP lui-même* (`arp.src.proto_ipv4`/
  `arp.dst.proto_ipv4`) — cohérent avec le reste du pipeline, qui traite
  déjà `src`/`dst` comme des adresses IP génériques quel que soit le
  protocole (TCP/UDP/ICMP/ICMPv6). Trois nouveaux champs dédiés sur
  `RawPacket`/`Pkt` : `arp_opcode`, `arp_sender_mac`, `arp_is_gratuitous`
  (`sport`/`dport` **volontairement pas réutilisés** pour ARP,
  contrairement à ICMP(v6) où ils portent ident/seq — des champs dédiés
  évitent toute ambiguïté de lecture).
- **Piège sérieux repéré et corrigé AVANT tout test, par relecture
  attentive du code existant** (pas par un test cette fois) : la boucle
  principale de `analyse()` itère sur `flows` (produit par
  `netcross_core.correlate.correlate()`) **sans filtrer par protocole**
  pour calculer pertes (`loss_count`), latence, changements QoS, saut de
  TTL (`hop_delta`) et inférence de topologie (recouvrement de flux
  entre points). Une trame ARP qui y serait entrée aurait faussé ces
  métriques de façon trompeuse : (1) une requête ARP broadcast qui
  n'atteint jamais un point en aval d'un routeur (comportement **normal**
  pour ARP, RFC 826 — jamais routé) aurait été comptée comme une
  **perte réseau**, un faux signal d'anomalie ; (2) la même trame ARP
  broadcast vue à plusieurs points aurait ressemblé à un recouvrement de
  flux quasi parfait entre eux, faussant l'inférence de topologie (deux
  points non adjacents auraient pu sembler directement reliés). **Corrigé
  en excluant ARP de `correlate()`** avant construction de `flows` — ARP
  reste disponible via `all_packets` pour les détecteurs qui le veulent
  explicitement (`_analyse_arp_ip_conflict`), même principe que DNS/SIP/
  DHCP/RTP, déjà tous analysés depuis `all_packets` plutôt que `flows`.
  Documenté en détail dans le commentaire de `correlate()` et testé par
  `test_correlate_exclut_arp`.
- **Câblage entièrement générique confirmé par lecture de code**, comme
  les sessions précédentes : `netcross_report/synthesis.py` (nouveau
  `Finding`, catégorie "ARP", sévérité `anomalie`, `segment` = nom du
  point comme pour `retrans_fast`), `netcross_core/report_text.py`
  (nouvelle section console dédiée), `netcross_core/baseline_diff.py`
  (comparaison par point via `_compare_count`, `higher_is_worse=True`
  par défaut) — **aucune modification nécessaire** dans
  `json_report.py`, `pdf.py`, `charts.py`, ni la GUI GTK4.
  `compute_throughput`/`compute_topn_series` (qui, eux, opèrent
  directement sur `all_packets` et non sur `flows`) incluent
  légitimement le trafic ARP dans le débit et la répartition par
  protocole — bonus cohérent, pas une fuite du même problème que
  `flows` (ces deux fonctions n'ont pas la même hypothèse de sémantique
  requête/réponse par flux).
- **Validé de bout en bout** : suite `pytest` complète rejouée avant
  toute modification (471/471 hérités de la Session 23, aucune
  régression préalable). 19 nouveaux tests, 2 tests existants corrigés
  (`test_build_packet_sans_ip_renvoie_none` et
  `test_parse_capture_ignore_les_paquets_non_decodables` supposaient
  qu'ARP retournait `None` — désormais faux, remplacés par un scénario
  STP toujours hors périmètre) : `tests/test_tunnels.py` (sélection de
  couche `arp`, avec et sans tunnel) ; `tests/test_packet.py` (requête,
  réponse, annonce gratuite, `arp.isgratuitous` absent → False, champs
  IP neutres pour une trame sans en-tête IP) ; `tests/test_correlate.py`
  (exclusion d'ARP de `flows`) ; `tests/test_analysis.py` (détection
  nominale, pas de conflit à une seule MAC, détection indépendante du
  type de paquet requête/réponse, ignore les paquets non-ARP,
  indépendance stricte par point, plusieurs IP comptées séparément,
  exemples plafonnés à 5) ; `tests/test_synthesis.py`,
  `tests/test_report_text.py`, `tests/test_baseline_diff.py` (finding,
  affichage texte y compris message par défaut, comparaison de
  baseline) — **490/490** au total, aucune régression.
  `tshark`/`pytest`/`ruff`/`import-linter`/`pre-commit`/`scapy` tous
  installables cette session (accès réseau disponible). Rejeu du **vrai
  CLI** (`cross_capture_analyzer_cli.py --order A,B --triage
  --json-report`) sur deux scénarios à 2 points construits avec scapy et
  un vrai `tshark -T ek` 4.2.2 : (1) conflit d'adresse IP au point A
  (10.0.0.9 revendiquée par deux MAC différentes), point B avec un
  trafic ARP normal sans lien — correctement détecté et remonté en
  console/JSON/triage, catégorie "ARP" cohérente, **aucune pollution de
  la section Pertes** (confirmant le correctif `correlate()` ci-dessus,
  "Pertes : aucune détectée" malgré une requête ARP broadcast présente
  à un seul point) ; (2) même schéma mais avec une seule MAC stable dans
  le temps par IP — aucun faux positif, message par défaut affiché.
  `ruff check`, `ruff format --check` (49 fichiers conformes),
  `PYTHONPATH=src lint-imports` (aucun cycle introduit, 1 contrat
  respecté), `pre-commit run --all-files` (3 hooks) tous rejoués
  réellement, tout passe.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (Timeout d'inactivité / coupure NAT-FW silencieuse — Session 23)

- **Piste retenue** : candidat 🟢 urgence faible de la section 5.2, explicitement
  annoté "Demande un détecteur temporel neuf, absent du moteur actuel" — le seul
  candidat 🟠 urgence moyenne restant (validation CAPWAP sur vraie capture
  Aruba/Cisco/Fortinet) reste hors d'atteinte sans matériel vendeur réel, comme
  déjà constaté en Session 22.
- **Signal recherché** : une connexion TCP déjà établie et vue des deux côtés
  d'un segment réseau (`a`, `b`), qui traverse un silence prolongé côté amont,
  puis reprend avec de la donnée nouvelle qui n'atteint plus jamais l'aval —
  signature typique d'une table d'état NAT/pare-feu purgée pendant
  l'inactivité, sans RST (d'où « silencieuse » : ni le client ni le serveur ne
  sont explicitement notifiés de la rupture). Nouveau couple de compteurs
  `Report.idle_timeout_dropped`/`idle_timeout_examples` (par segment `(a, b)`),
  détecteur `_analyse_idle_timeout` (`netcross_core.analysis`).
- **Bug d'architecture trouvé et corrigé en cours de session, avant toute
  livraison** (piège documenté dans le docstring de `_analyse_idle_timeout`,
  section "Note de conception", et dans un test de non-régression dédié) :
  la première version itérait sur `flows` (le dict déjà construit par
  `netcross_core.correlate`, réutilisé tel quel par `_analyse_pmtud`) —
  or `flows` est indexé par 5-tuple **+ `key_id`, qui vaut le numéro de
  séquence TCP** (voir `pcap_parser.packet::build_packet`, `key_id = seq if
  proto == "TCP" else ip_id`). Chaque entrée de `flows` représente donc un
  **segment précis** (et ses éventuelles retransmissions, qui partagent le
  même `seq`), jamais une connexion entière qui enchaîne des segments à `seq`
  croissant. Une vraie reprise après coupure envoie forcément de la donnée
  **nouvelle** (`seq` différent du dernier segment avant le silence) : avec
  `flows`, le paquet d'avant-silence et celui d'après tombaient dans deux
  entrées séparées, chacune avec un seul paquet au point amont — la condition
  "au moins 2 paquets pour mesurer un écart" ne pouvait donc **jamais** être
  remplie, quel que soit le scénario réel. Le détecteur aurait été
  silencieusement inopérant en production. Corrigé en reconstruisant une vue
  par **connexion** directement depuis `all_packets` (5-tuple, sans `seq`),
  même technique que `_analyse_rtp` pour ses propres flux (5-tuple + SSRC,
  également hors du périmètre naturel de `flows`) — testé par
  `test_idle_timeout_detecte_meme_avec_seq_differente_apres_la_reprise`, qui
  aurait échoué avec la première version.
- **Second bug trouvé par un test, corrigé avant livraison** : la comparaison
  initiale du "dernier paquet vu en aval avant le silence" utilisait le début
  du trou (`gap_start`, timestamp du dernier paquet amont avant le silence)
  au lieu de sa fin (`gap_end`, début de la reprise en amont). Or le point
  aval voit toujours le trafic un peu **après** le point amont (délai de
  propagation normal du réseau) : son dernier paquet "avant le trou" a donc un
  timestamp *supérieur* à `gap_start` dans le cas général, ce qui aurait fait
  manquer la quasi-totalité des cas réels. Repéré par
  `test_idle_timeout_coupure_detectee` (délai de propagation de 0,1 s
  volontairement introduit entre A et B dans le jeu de données du test).
- **Seuil** `_IDLE_TIMEOUT_SECONDS = 60.0`, constante de module qui restait non
  exposée en CLI jusqu'à la Session 37 (**exposée depuis via
  `--idle-timeout-seconds` sur les deux CLI**, `analyse(idle_timeout_seconds=
  None)` par défaut = comportement inchangé) — au moment de cette session
  (23), même statut que `_PMTUD_MIN_SEGMENT_BYTES` dans `_analyse_pmtud` —
  contrairement à `rtp_clock_rate`/`bucket_seconds`/`topn`, qui eux sont des
  paramètres traversant `analyse()` jusqu'au CLI. Choix documenté dans le
  code : largement au-dessus d'un keepalive TCP applicatif classique (20-30 s,
  HTTP keep-alive/SSH `ServerAliveInterval`), largement en-deçà du minimum
  recommandé par la RFC 5382 §5 pour un NAT conforme (≥ 2h04) — de nombreux
  équipements NAT/pare-feu grand public ou d'entrée de gamme appliquent en
  pratique un timeout d'état TCP établi bien plus court que cette
  recommandation, sans jamais le publier ; ce seuil ne vise pas à identifier
  *le* timeout exact d'un équipement précis (impossible à déduire d'une seule
  capture) mais à filtrer les silences applicatifs courants pour ne retenir
  que les silences longs, seuls compatibles avec l'hypothèse "table d'état
  expirée".
- **Périmètre volontairement limité à TCP** (comme `_analyse_pmtud`,
  `mss_clamped`, `wscale_stripped`, la classification des retransmissions) :
  la notion de "session avec établissement/silence/reprise" n'a de sens direct
  que pour un protocole avec état. Un équivalent UDP (timeout NAT sur un flux
  RTP par exemple) resterait un chantier à part, déjà partiellement couvert
  côté perte/gigue par `r.rtp_streams` (`_analyse_rtp`) sans notion explicite
  de silence prolongé — piste possible pour une session future.
- **Câblage entièrement générique confirmé par lecture de code**, comme les
  Sessions 21/22 : `netcross_report/synthesis.py` (nouveau `Finding`,
  catégorie "NAT/Pare-feu", sévérité `anomalie`), `netcross_core/report_
  text.py` (nouvelle section console dédiée), `netcross_core/baseline_diff.py`
  (comparaison via `_compare_count`, `higher_is_worse=True` par défaut — plus
  de coupures détectées entre deux captures = régression, à la différence
  d'`icmpv6_too_big`) — **aucune modification nécessaire** dans
  `json_report.py`, `pdf.py`, `charts.py`, ni la GUI GTK4, tous génériques sur
  `Finding`/`build_findings`.
- **Validé de bout en bout** : suite `pytest` complète rejouée avant toute
  modification (457/457 hérités de la Session 22, aucune régression
  préalable). 11 nouveaux tests : `tests/test_analysis.py` (détection
  nominale avec délai de propagation réaliste, non-détection si le trafic
  repris est bien revu en aval, silence trop court, frontière stricte du
  seuil à 59 s, connexion jamais établie en aval avant la reprise, moins de 2
  paquets en amont, flux non-TCP ignoré, un seul trou compté par connexion
  même avec plusieurs silences successifs, non-régression explicite sur le
  bug `seq` différent décrit plus haut) ; `tests/test_synthesis.py`,
  `tests/test_report_text.py`, `tests/test_baseline_diff.py` (finding,
  affichage texte y compris message par défaut "aucune coupure détectée",
  comparaison de baseline) — **471/471** au total, aucune régression.
  `tshark`/`pytest`/`ruff`/`import-linter`/`pre-commit`/`scapy` tous
  installables cette session (accès réseau disponible). Rejeu du **vrai CLI**
  (`cross_capture_analyzer_cli.py --order A,B --triage --json-report`) sur
  deux scénarios à 2 points construits avec scapy et un vrai `tshark -T ek`
  4.2.2 (pas seulement les objets `Pkt` synthétiques des tests unitaires) :
  (1) connexion établie des deux côtés, silence de 94 s en A (`seq` différent
  entre avant et après, comme une vraie reprise), jamais revue en B —
  correctement détectée et remontée en console/JSON/triage avec le bon
  libellé, score de santé et catégorie "NAT/Pare-feu" cohérents ; (2) même
  scénario mais avec le trafic repris **bien revu** en B — aucun faux
  positif, message par défaut affiché. `ruff check`, `ruff format --check`
  (49 fichiers conformes), `PYTHONPATH=src lint-imports` (aucun cycle
  introduit, 1 contrat respecté), `pre-commit run --all-files` (3 hooks : ruff,
  ruff-format, import-linter) tous rejoués réellement, tout passe. **Effet de
  bord incident, sans rapport avec cette feature** : `ruff` 0.16.5 inclut
  désormais les fichiers `.md` dans son périmètre de formatage par défaut
  (nouveau comportement par rapport aux sessions précédentes) — un bloc de
  code Python exemple dans `docs/sessions/session-22.md` (import multi-lignes
  `scapy.layers.inet6`) ne respectait plus le style attendu ; reformaté par
  `ruff format .` pour repartir sur une base propre, aucun fichier source
  concerné.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (Décodage ICMPv6 + PMTUD IPv6 — Session 22)

- **Piste retenue** : seule piste "câblage/évolution ciblée" encore
  ouverte en section 5.2 (le seul autre point restant, validation CAPWAP
  sur vraie capture Aruba/Cisco/Fortinet, reste hors d'atteinte sans
  matériel vendeur réel) — identifiée explicitement comme piste distincte
  à la fin de la Session 21 en creusant la fragmentation IPv6 (voir
  ci-dessous, "ICMPv6 volontairement hors périmètre").
- **Ce qui existait déjà et a été réutilisé sans modification** :
  `_topn_category_label` (`netcross_core.correlate`) était déjà générique
  sur `pk.proto` ("TCP/UDP/ICMP/ICMPv6..." explicitement dans son propre
  docstring, anticipé avant même que ce décodage existe) — confirmé par
  lecture de code que `netcross_report/charts.py`, `json_report.py` et la
  GUI n'ont eu besoin d'aucune modification : la nouvelle valeur
  `proto="ICMPv6"` s'intègre automatiquement partout où `pk.proto` est
  déjà consommé génériquement.
- **Décision de conception tranchée** (documentée dans
  `pcap_parser.packet`/`netcross_core.models`) : `RawPacket`/`Pkt`
  reçoivent des champs `icmpv6_type`/`icmpv6_code` **séparés** de
  `icmp_type`/`icmp_code`, plutôt que réutilisés tels quels — les espaces
  de valeurs ICMPv4 et ICMPv6 ne se recouvrent pas numériquement (type 2 =
  *Redirect* côté v4, *Packet Too Big* côté v6 ; type 3 = *Destination
  Unreachable* côté v4, *Time Exceeded* côté v6), les réutiliser aurait
  fait courir le risque qu'un code appelant vérifie `icmp_type` sans
  vérifier `proto` en plus et confonde les deux protocoles. Champs
  séparés + `proto="ICMPv6"` (nouvelle valeur, symétrique de `"ICMP"`,
  déjà le discriminant utilisé partout dans ce projet pour TCP/UDP/ICMP)
  rendent cette confusion structurellement impossible plutôt que de
  compter sur la discipline de chaque site d'appel.
- **Découverte empirique notable** (tshark 4.2.2, pcap scapy
  synthétique) : pour un message d'erreur ICMPv6 (*Packet Too Big*,
  *Destination Unreachable*, *Time Exceeded*...) qui embarque le
  datagramme original en cause, tshark niche les couches `ipv6`/`udp` de
  ce datagramme embarqué **sous la clé `icmpv6` elle-même**, pas au même
  niveau que la vraie couche IPv6 externe. `layer()`/`innermost()` ne
  recursent que sur le niveau racine de `layers`, donc pas de risque
  d'écraser ou de confondre l'adresse de l'enveloppe externe (le routeur
  qui émet l'erreur) avec celle du datagramme embarqué (le vrai client) —
  vérifié par un test dédié plutôt que supposé sur la seule lecture du
  code (`test_build_packet_icmpv6_ignore_couches_imbriquees_du_message_
  erreur`).
- **PMTUD IPv6 désormais détecté** — extension de `_analyse_pmtud`
  (`netcross_core.analysis`), le point qui motivait cette session depuis
  le départ (Session 9 pour la version IPv4, Session 21 pour l'avoir
  identifié comme hors périmètre) :
  1. Nouveau compteur `Report.icmpv6_too_big` (ICMPv6 *Packet Too Big*,
     type 2, RFC 4443 §3.2 — l'analogue IPv6 de *ICMP Fragmentation
     Needed*), peuplé dans le même bloc "fragmentation / MTU" que ce
     dernier. **Piège identifié en croisant avec la Session 21** : ce
     comptage doit s'exécuter **avant** le garde-fou `pk.ip_id is None`
     du bloc, pas dedans — contrairement à un message ICMP(v4) qui hérite
     passivement d'un `ip.id` toujours présent (champ ordinaire IPv4, peu
     importe la fragmentation), un message ICMPv6 n'a lui-même presque
     jamais d'en-tête d'extension Fragment (petit message de contrôle,
     pas un gros datagramme) : le compter seulement si `ip_id` est
     renseigné l'aurait fait passer inaperçu dans l'immense majorité des
     cas.
  2. Deux branches dans `_analyse_pmtud` selon la famille d'adresse du
     flux (`":" in key[1]`, `key[1]` = adresse source de la clé de flux,
     voir `netcross_core.correlate.flow_key`) : IPv4 exige toujours le
     bit `DF` actif sur toutes les tentatives observées (inchangé, aucune
     régression) ; IPv6 **n'a aucune vérification équivalente** — le bit
     DF n'existe pas côté IPv6, et la sémantique qu'il exprime côté IPv4
     ("ne pas fragmenter CE paquet", par opposition à un paquet qui
     autoriserait un routeur à le fragmenter) est de toute façon
     **implicite pour tout paquet IPv6** : seule la source peut fragmenter
     en IPv6, jamais un routeur intermédiaire en cours de route (RFC 8200
     §4.5) — un routeur qui ne peut pas transmettre un segment IPv6 trop
     gros n'a categoriquement aucune autre option que de le rejeter,
     qu'un bit DF soit présent ou non. Un noir PMTUD IPv6 est donc
     plausible dès que le reste des conditions (retransmissions répétées,
     jamais vues en aval, taille significative) est réuni.
  3. `r.pmtud_blackhole` reste un **compteur unique générique** IPv4/IPv6
     (même principe que `r.frag_count` en Session 21, pas de duplication
     par famille d'adresse) — messages de `synthesis.py`/`report_text.py`/
     `baseline_diff.py` généralisés pour ne plus présupposer IPv4 seul
     (« DF actif » devient « signal ICMP(v6) de MTU insuffisant », RFC
     1191 IPv4 / RFC 8201 IPv6 citées ensemble) ; le détail par tentative
     (`pmtud_blackhole_examples`) précise « DF actif » vs « IPv6, pas de
     bit DF » selon le cas, pour ne pas perdre l'information utile au
     diagnostic dans la généralisation du message principal.
- **Finding informatif dédié** pour `icmpv6_too_big` (catégorie
  Fragmentation, sévérité `info`, même niveau que *ICMP Fragmentation
  Needed*) ; comparaison de baseline symétrique ajoutée
  (`higher_is_worse=False` : plus de signal ICMPv6 observé entre deux
  captures = PMTUD qui fonctionne mieux, pas une régression — même
  raisonnement déjà appliqué à *ICMP Fragmentation Needed*).
- **Non traité, volontairement** : la valeur de MTU annoncée par un
  message *Packet Too Big* (`icmpv6.mtu`) n'est pas conservée — seule
  son occurrence (type 2) est comptée, au même niveau de détail que
  *ICMP Fragmentation Needed* côté IPv4 (qui ne conserve pas non plus le
  détail du message). Aurait été une information diagnostique
  supplémentaire utile (le lien exact qui limite le chemin), mais aurait
  cassé la symétrie avec le pendant IPv4 sans bénéfice proportionné pour
  cette passe — piste possible pour une session future si le besoin se
  confirme.
- **Validé de bout en bout** : suite `pytest` complète rejouée avant
  toute modification (439/439 hérités de la Session 21, aucune
  régression préalable). 18 nouveaux tests : `tests/test_packet.py` (Echo
  Request/Reply avec identifiant/séquence, *Packet Too Big* sans
  identifiant/séquence, Neighbor Solicitation générique, non-confusion
  avec les couches imbriquées d'un message d'erreur) ; `tests/test_
  tunnels.py` (sélection de la couche `icmpv6` avec et sans tunnel) ;
  `tests/test_analysis.py` (comptage `icmpv6_too_big` y compris sans
  `ip_id`, noir PMTUD IPv6 détecté sans bit DF, supprimé par un *Packet
  Too Big* en amont, non-régression explicite du comportement IPv4 avec
  `DF` non actif) ; `tests/test_synthesis.py`, `tests/test_report_text.py`,
  `tests/test_baseline_diff.py` (finding informatif, affichage texte,
  comparaison de baseline) — **457/457** au total, aucune régression.
  `tshark`/`pytest`/`ruff`/`import-linter`/`scapy` tous installables cette
  session (accès réseau disponible) : vérification empirique préalable
  des noms de champs EK réels contre un vrai tshark 4.2.2, à partir de
  pcaps scapy synthétiques couvrant Echo Request/Reply, *Packet Too Big*,
  *Destination Unreachable*, *Time Exceeded*, Neighbor Solicitation/
  Advertisement — pas une déduction par analogie avec ICMPv4. Rejeu du
  **vrai CLI** (`cross_capture_analyzer_cli.py --order A,B --pdf-report
  --json-report`) sur trois scénarios réels à 2 points, tous avec un vrai
  `tshark -T ek` : (1) noir PMTUD IPv6 (3 segments TCP retransmis en A,
  jamais vus en B, aucun ICMPv6) correctement détecté et remonté en
  console/JSON/PDF avec le libellé « IPv6, pas de bit DF » dans
  l'exemple ; (2) même scénario **avec** un *Packet Too Big* intercalé
  en A — détection correctement supprimée, occurrence bien comptée dans
  la section Fragmentation/MTU ; (3) non-régression du scénario PMTUD
  IPv4 historique (`DF` actif, sans ICMPv6 en jeu) — toujours détecté à
  l'identique, avec le libellé « DF actif » inchangé. `ruff check`, `ruff
  format --check` (46 fichiers déjà conformes, aucun reformatage
  nécessaire), `PYTHONPATH=src lint-imports` (aucun cycle introduit, 1
  contrat respecté) tous rejoués réellement, tout passe.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (Fragmentation IPv6 — Session 21)

- **Fragmentation IPv6** — voir section 2 `pcap_parser` pour le détail
  technique complet (`RawPacket.is_fragment`/`ip_id` côté IPv6). Dernier
  candidat 🟢 urgence faible listé en section 5.2 comme "trou identifié à
  l'origine, non confirmé comme corrigé" — confirmé et corrigé cette
  session : `is_fragment` valait toujours `False`/`ip_id` toujours `None`
  côté IPv6 depuis l'introduction du pipeline tshark, jamais traité
  depuis (la fragmentation IPv4, elle, avait été traitée dès la Session 9
  pour PMTUD).
- **Ce qui existait déjà et a été réutilisé sans modification** : tout le
  bloc "fragmentation / MTU" de `netcross_core.analysis` (`r.frag_count`,
  `r.frag_new`, `r.encap_frag_correlated`) était déjà générique sur
  `pk.ip_id`/`pk.is_fragment`, sans branche par famille d'adresse — seule
  `pcap_parser.packet.build_packet()` avait besoin d'être complété pour
  que ces compteurs profitent d'IPv6. Confirme le même schéma que
  d'autres pistes "câblage à coût faible" du projet (la donnée était déjà
  consommable, seule la production manquait) — même si celle-ci était
  classée dans un tableau de pistes distinct (section 5.2, pas section 4)
  faute d'avoir été identifiée comme un simple câblage au moment de sa
  première mention.
- **Décision de conception tranchée** (documentée dans
  `netcross_core.models`/`netcross_core.analysis`, voir section 2
  ci-dessus pour le détail complet) : accepter la limite protocolaire
  plutôt que de chercher à la contourner — un datagramme IPv6 jamais
  fragmenté n'a par construction aucun identifiant de datagramme à
  exposer (contrairement à `ip.id` en IPv4, champ ordinaire toujours
  présent), donc `frag_new`/`encap_frag_correlated` ne peuvent pas
  détecter une fragmentation qui *apparaît* en aval côté IPv6 — seul
  `frag_count` (comptage brut par point) bénéficie pleinement de cet
  ajout. Aucun contournement inventé (par exemple : traiter l'absence
  d'`ip_id` comme une clé de corrélation `None` distincte par paquet) —
  aurait produit un faux signal de "nouvelle fragmentation" à chaque
  paquet IPv6 non fragmenté suivi d'un paquet fragmenté sans lien réel
  entre les deux, pire que l'absence de détection actuelle.
- **ICMPv6 volontairement hors périmètre** : ce projet ne décode
  toujours pas ICMPv6 (pas de couche `icmpv6` dans
  `pcap_parser.tunnels.select_innermost_layers`, contrairement à `icmp`
  pour IPv4) — la détection PMTUD IPv6 (ICMPv6 *Packet Too Big*, type 2)
  reste donc hors d'atteinte, comme déjà documenté dans
  `_analyse_pmtud` avant cette session. Décodage ICMPv6 identifié comme
  une piste distincte pendant cette session (nouvelle couche EK, champs
  `RawPacket` dédiés ou réutilisés, décision de conception sur le
  chevauchement avec `icmp_type`/`icmp_code` existants) — pas ajoutée à
  cette passe pour rester dans le périmètre "fragmentation IPv6"
  initialement visé, mais notée en section 5.2 pour une session future.
- **Validé de bout en bout** : suite `pytest` complète rejouée avant
  toute modification (432/432 hérités de la Session 20, aucune
  régression préalable), 4 nouveaux tests dans `tests/test_packet.py`
  (premier fragment, dernier fragment, non-fragmenté sans `ip_id`,
  normalisation défensive liste/dict) et 3 dans `tests/test_analysis.py`
  (`frag_count` générique IPv6, `frag_new` qui fonctionne quand le
  datagramme est déjà fragmenté aux deux points, cas limite non détecté
  documenté explicitement par un test dédié plutôt que laissé implicite)
  — **439/439** au total, aucune régression. `tshark`/`pytest`/`ruff`/
  `import-linter`/`scapy` tous installables cette session (accès réseau
  disponible) : vérification empirique préalable des noms de champs EK
  réels (`ipv6_fraghdr_ipv6_fraghdr_ident`/`_offset`/`_more`, nichés sous
  `ip6["ipv6_fraghdr"]`) contre un vrai tshark 4.2.2, à partir d'un pcap
  scapy fragmenté via `fragment6()` — pas une déduction par analogie avec
  IPv4 comme cela avait dû être fait pour DNS en Session 13 faute
  d'accès à l'époque. Rejeu du **vrai CLI**
  (`cross_capture_analyzer_cli.py --order A,B --pdf-report --json-report
  --triage`) sur un scénario réel à 2 points (point A : un datagramme
  IPv6 UDP fragmenté en 3 par un vrai `tshark -T ek` ; point B : le même
  datagramme non fragmenté) : "3 paquets fragmentés vus" correctement
  affiché en console pour le point A, PDF (176 Ko) et JSON générés sans
  erreur, aucune "nouvelle fragmentation" signalée entre A et B (confirme
  empiriquement la limite documentée ci-dessus, pas seulement en théorie).
  `ruff check`, `ruff format --check` (49 fichiers déjà conformes,
  aucun reformatage nécessaire), `PYTHONPATH=src lint-imports` (aucun
  cycle introduit, 1 contrat respecté) et `pre-commit run --all-files`
  (les 3 hooks) rejoués réellement sur un dépôt git temporaire créé pour
  l'occasion (`pre-commit` a besoin d'un `.git/`, absent de l'archive
  livrée par construction) — tout passe.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (Graphiques temporels top-N — Session 20)

- **Graphiques temporels top-N (protocole/port/IP/DSCP)** — dernier
  candidat 🟢 urgence faible réalisable sans matériel/trafic vendeur réel
  (le seul point 🟠 restant, validation CAPWAP sur vraie capture
  Aruba/Cisco/Fortinet, en a besoin et reste hors d'atteinte). Retenu par
  élimination, même raisonnement que les Sessions 13/15/19 en leur temps.
- **Ce qui existait déjà et a été réutilisé sans modification** :
  `compute_throughput` (`netcross_core.correlate`) pour le découpage en
  buckets temporels, et le pattern `generate_all_charts`/`Image(...)` de
  `netcross_report.pdf` pour l'intégration au rapport — le débit
  déjà calculé par bucket, seule la ventilation par catégorie était
  manquante (confirme le "données déjà là" de `docs/features-backlog.md` section 5.2).
- **Décisions de conception tranchées** (aucune n'avait de précédent
  direct dans le code existant) :
  1. *Ventilation par destination uniquement* (pas source+destination)
     pour les dimensions `port`/`ip` — sinon la somme des catégories
     d'un point aurait dépassé son débit réel (chaque paquet compté deux
     fois). Conséquence acceptée et documentée : côté retour
     serveur->client, le "port" observé est un port éphémère qui se
     disperse dans la longue traîne plutôt que de faire ressortir le
     service — comportement recherché, pas un défaut.
  2. *DSCP 0 distingué de "non marqué"* — piège classique de tester
     `if pk.dscp` au lieu de `is not None` (0/best-effort est une valeur
     DSCP légitime, pas une absence de valeur). Repéré en écrivant le
     test dédié avant le code (`test_topn_series_dscp_distingue_zero_de_non_marque`),
     pas après coup.
  3. *Top-N calculé indépendamment par point* de capture, jamais par un
     classement global — deux points de capture n'ont pas forcément les
     mêmes catégories dominantes (ex: un point proche du serveur vs un
     point proche du poste client), un classement global aurait fait
     disparaître la catégorie dominante d'un point minoritaire en volume
     total. Vérifié par test
     (`test_topn_series_top_n_independant_par_point`).
  4. *Un seul point de capture tracé par graphique*, jamais plusieurs
     points superposés sur la même aire empilée — un paquet physique
     peut être vu à plusieurs points de capture ; l'additionner sur un
     même graphique gonflerait artificiellement le volume affiché (même
     raisonnement que `compute_throughput`, déjà par point). Le point
     tracé est configurable (`generate_topn_charts(r, tmpdir,
     point=...)`) mais vaut par défaut `r.points[0]` — choix pragmatique
     plutôt qu'une vraie sélection multi-points, qui aurait multiplié le
     nombre de pages du PDF par le nombre de points (potentiellement
     beaucoup, l'outil supportant un nombre arbitraire de points de
     capture) sans plus-value proportionnelle. `--topn-charts` (CLI)
     règle le nombre de catégories, pas le point choisi — changer de
     point se fait en appelant `generate_topn_charts()` directement
     (bibliothèque), pas encore exposé côté CLI/GUI (voir section 5.2
     pour cette limitation assumée).
  5. *Scope volontairement restreint* à `cross_capture_analyzer_cli.py` +
     `--pdf-report` — ni `cross_capture_diff_cli.py` (pas de direction
     évidente pour une comparaison avant/après, voir section "CLIs"),
     ni `--json-report` (les autres compteurs bruts de `Report`, comme
     `throughput` ou `latency`, ne sont eux non plus jamais exposés en
     JSON — seuls les `Finding`/triage/health_score le sont ; ajouter
     `topn_timeseries` au JSON aurait rompu cette cohérence sans
     demande explicite), ni la GUI (bénéficie du nouveau graphique
     automatiquement via `generate_pdf`, mais `--topn-charts` n'a pas
     d'équivalent réglable dans l'interface, voir section
     `netcross_gtk4.app` plus haut).
- **Bug réel trouvé et corrigé en testant** (pas en relisant) : le
  premier jet de `chart_topn_timeseries` traçait l'axe temporel en
  timestamp Unix absolu (`bucket * bucket_seconds`, où `bucket` vient de
  `int(pk.ts // bucket_seconds)` avec `pk.ts` en epoch Unix) tout en
  affichant la légende "secondes depuis le début de la capture" —
  contradiction repérée uniquement en inspectant visuellement le PDF
  généré (`pdf2image`), où matplotlib affichait un axe `0.0` à `3.0`
  avec une annotation d'offset `+1.788e9` illisible. Corrigé en
  normalisant par rapport au premier bucket de la série
  (`x = (bucket - bucket_min) * bucket_seconds`) — aucun test `pytest`
  n'aurait détecté ce bug (charts.py n'est pas couvert par la suite, la
  valeur numérique de l'axe n'étant pas assertée), confirmant l'utilité
  de la validation visuelle systématique déjà pratiquée dans les
  sessions précédentes pour ce module.
- **Validé de bout en bout** : suite `pytest` complète rejouée avant
  toute modification (419/419 hérités de la Session 19, aucune
  régression préalable), 19 nouveaux tests dans `tests/test_correlate.py`
  (dont la propriété de non-double-comptage et l'indépendance du top-N
  par point ci-dessus) et 3 dans `tests/test_analysis.py` (câblage du
  paramètre `topn` et présence des 4 dimensions dans
  `r.topn_timeseries`) — **432/432** au total, aucune régression. Un vrai
  serveur HTTP (`http.server`) capturé en direct par un vrai `tshark` sur
  `lo`, second point de capture fabriqué avec `editcap -r` (perte réelle
  de paquets, pas simulée), rejoué avec le vrai CLI
  (`cross_capture_analyzer_cli.py --pdf-report --topn-charts 4`) — PDF de
  8 pages généré, relu avec `pypdf` et **converti en image (`pdf2image`)
  pour inspection visuelle** des 4 nouveaux graphiques (protocole/port/
  IP/DSCP) et de la non-régression des graphiques existants
  (topologie/débit/latence/pertes, page juste avant). Cas limites
  vérifiés séparément : un seul point de capture (pas de risque de
  double comptage entre points), et `Report` totalement vide (0 paquet)
  — les deux génèrent un PDF sans erreur. `ruff check`, `ruff format
  --diff` (1 fichier reformaté après l'ajout du nouveau texte
  d'introduction de section dans `pdf.py`, guillemets simples autour
  d'un guillemet double littéral — appliqué sans discussion),
  `PYTHONPATH=src lint-imports` (aucun cycle, 1 contrat respecté) et
  `pre-commit run --all-files` (les 3 hooks) rejoués réellement — tout
  passe.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (Gestion mémoire des grosses captures — Session 19)

- **Gestion mémoire des grosses captures** — dernier point 🟠 urgence
  moyenne réalisable dans un environnement sans matériel/trafic vendeur
  réel (l'autre candidat restant, validation CAPWAP, en a besoin). Piste
  ouverte depuis la Session 1 (`idées.md` §3 actait déjà que scapy
  `rdpcap()`→streaming n'était plus le levier prévu une fois tshark
  adopté comme moteur unique, sans jamais confirmer ni infirmer l'état
  réel du nouveau pipeline) — jamais mesurée empiriquement jusqu'ici,
  faute d'un environnement combinant `tshark` réel et une capture assez
  grosse pour que le coût mémoire par paquet devienne visible.
- **Mesure préalable, avant tout code** (même discipline que PMTUD/
  retransmissions/options TCP en Sessions 9-11) : capture synthétique de
  200 000 paquets TCP générée avec `scapy`, décodée par le vrai
  `tshark -T ek`, profilée avec `tracemalloc`. Résultat initial :
  **~1971 octets par paquet** en régime établi (`RawPacket` et `Pkt`
  confondus), et un pic mémoire transitoire pendant la conversion
  `RawPacket → Pkt` **supérieur à la somme des deux listes** (722 Mo pour
  200 000 paquets, contre 394 Mo pour une seule des deux listes) — la
  compréhension de liste de `netcross_core.parsing.parse_capture()`
  gardait les deux entièrement matérialisées en RAM simultanément.
- **Cause identifiée par isolation** (dataclass `RawPacket` reconstruite
  à l'identique, avec puis sans `__slots__`, en dehors de tout code
  tshark) : chaque instance de dataclass **sans** `__slots__` porte un
  `__dict__` par instance — mesuré à lui seul responsable d'environ les
  deux tiers du coût par paquet (1696 → 528 octets/objet rien qu'en
  ajoutant `__slots__`, sur les mêmes ~55 champs). Le tiers restant :
  chaque ligne NDJSON `tshark -T ek` est décodée indépendamment par
  `json.loads()`, donc deux paquets qui portent la **même** valeur
  textuelle (la même IP source, le même User-Agent SIP, la même URI
  HTTP...) obtiennent chacun leur propre objet `str` distinct — vérifié
  empiriquement (~57 octets par chaîne dupliquée de ce type sur ce
  projet, `json.loads('{"v": "10.0.0.1"}')` appelé deux fois ne renvoie
  jamais le même objet, contrairement à une concaténation de littéraux
  que CPython replierait à la compilation).
- **Corrigé** :
  - `RawPacket` (`pcap_parser/packet.py`) et `Pkt`
    (`netcross_core/models.py`) déclarent maintenant `__slots__` (tuple
    exhaustif des champs, aucun champ n'a de valeur par défaut dans les
    deux dataclasses — condition nécessaire pour que `__slots__` cohabite
    sans conflit avec `@dataclass`, vérifiée avant d'appliquer le
    changement). Un test dédié sur chacune des deux classes vérifie
    l'absence de `__dict__` et qu'un attribut hors `__slots__` lève
    `AttributeError` plutôt que d'être silencieusement accepté — sans
    quoi une régression future (un champ ajouté à la dataclass mais
    oublié dans `__slots__`) planterait à l'instanciation, pas
    silencieusement : un troisième test compare explicitement l'ensemble
    des noms de champs de la dataclass à l'ensemble des noms dans
    `__slots__`.
  - Nouveau helper `packet._intern()` (tolérant à `None`, `sys.intern()`
    sinon) appliqué aux champs catégoriels à forte duplication attendue :
    `src`/`dst`, `flags` TCP, `dhcp_msg_type`/`server_id`/`vendor_class`,
    `sip_msg_type`/`user_agent`/`server`, `dns_qry_name`, `http_method`/
    `http_uri`. **Volontairement pas appliqué** à `sip_call_id`/
    `sip_cseq`/`payload_hash` (généralement uniques par appel/message/
    paquet — interner n'y apporterait rien, juste le coût d'une
    recherche dans la table globale d'interning) ni aux tags
    d'encapsulation (`encap_tags`, construits par `f"VLAN{vid}"` etc. —
    cas secondaire, rendement décroissant, laissé de côté pour rester
    dans le périmètre "rapide, isolé").
  - `netcross_core/parsing.py::parse_capture()` : la compréhension de
    liste `[_to_pkt(label, raw) for raw in raw_packets]` est remplacée
    par une boucle indexée qui remplace `raw_packets[i]` par `None` dès
    que ce `RawPacket` a été converti — élimine le double pic transitoire
    identifié ci-dessus (le coût résiduel, une liste de pointeurs `None`
    de même longueur, est négligeable face aux ~600 octets par
    `RawPacket` ainsi libérés immédiatement plutôt qu'en fin de fonction).
    `raw_packets.pop(0)` explicitement écarté (retrait en tête d'une
    liste Python : coût `O(n)` par appel, `O(n²)` au total sur une grosse
    capture).
- **Validation empirique de bout en bout, avant/après, avec du vrai
  `tshark`** (accès réseau disponible cette session, comme les Sessions
  9/10/11/14/17/18) :
  - Mémoire par paquet (`tracemalloc`, même capture synthétique 200 000
    paquets, pipeline réel `pcap_parser.parse_capture`/
    `netcross_core.parsing.parse_capture`) : **1971 → 636 octets/paquet
    (-68%)**, et le pic transitoire pendant la conversion `RawPacket →
    Pkt` : **722 → 129 Mo (-82%)**.
  - **Pic RSS réel du process CLI complet** (`/proc/<pid>/status`,
    `VmHWM`, mesuré depuis un thread de supervision pendant l'exécution —
    pas une estimation à partir des objets Python seuls) sur un scénario
    réaliste à 2 points de capture de 200 000 paquets chacun
    (`cross_capture_analyzer_cli.py --order A,B`, sans `--parallel`,
    donc les deux captures chargées séquentiellement dans le même
    process) : **1,3 Go avant cette session → ~500 Mo après**, soit une
    réduction d'environ **61%** du pic mémoire réel observé — mesuré en
    ré-exécutant le code de la session précédente (Session 18, code
    livré tel quel) sur exactement le même scénario, pas une
    extrapolation.
  - Rejeu du **vrai CLI** sur ce même scénario avec `--triage
    --parallel --pdf-report --json-report` : 400 paquets manquants
    détectés côté B (perte intentionnelle de 1 paquet sur 500 injectée
    dans la capture synthétique), score de santé 72/100 "À surveiller",
    PDF (122 Ko) et JSON générés sans erreur — confirme que les
    optimisations mémoire n'ont introduit aucune régression
    fonctionnelle sur un volume réaliste, pas seulement sur la suite
    `tests/` (paquets synthétiques, petits volumes par construction).
  - Suite `pytest` complète rejouée avant tout nouveau code (411/411
    hérités de la Session 18, aucune régression préalable), puis avec
    les 8 nouveaux tests (`test_packet.py` : slots, `_intern()`, partage
    d'objet `str` entre deux paquets de même IP, cohérence
    champs-dataclass/`__slots__` ; `test_parsing_adapter.py` : slots sur
    `Pkt`, cohérence champs/`__slots__`, libération incrémentale de
    `raw_packets` pendant `parse_capture()`) : **419/419**. `ruff check`,
    `ruff format --check`, `lint-imports` et `pre-commit run --all-files`
    rejoués réellement, tout passe (`ruff --fix` a trié `Pkt.__slots__`
    par ordre alphabétique — règle `RUF023`, déjà active dans
    `pyproject.toml`, non anticipée en écrivant le tuple dans son ordre
    naturel de déclaration des champs ; 2 occurrences `C416` corrigées
    à la main dans les nouveaux tests, compréhension d'ensemble
    superflue là où `set(...)` suffit).
- **Limite assumée, non traitée dans cette passe** : le pipeline reste
  entièrement en RAM — aucune des deux optimisations ci-dessus ne change
  cette architecture de fond (réduire le coût par paquet n'est pas la
  même chose qu'éliminer le besoin de garder tous les paquets en
  mémoire). Un vrai mode streaming multi-passes nécessiterait de repenser
  `correlate()`/`analyse()`, qui ont structurellement besoin d'une vue
  d'ensemble de tous les paquets pour la corrélation multi-points — un
  changement d'architecture, pas un câblage rapide, hors périmètre
  assumé de cette session (comme documenté depuis la Session 1 pour
  cette piste). Avec le gain mesuré ici, une capture de plusieurs
  millions de paquets par point se compte encore en Go de RAM, pas en
  dizaines de Mo — voir README.md "Limites connues" pour
  l'extrapolation et la recommandation de dimensionnement.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (Score de santé synthétique — Session 18)

- **Score de santé synthétique (0-100)** — `netcross_report/triage.py` :
  `health_score(ranked)`/`health_label(score)`/`format_health_line(score)`.
  Piste 🟢 urgence faible retenue pour cette session, explicitement
  qualifiée "coût faible, calculable à partir du triage déjà existant"
  dans ce document (section 5.2) — condense la même évidence pondérée que
  `rank_segments()`/`print_triage()` en un seul chiffre, ne prend QUE la
  sortie de `rank_segments()` en entrée (jamais les findings bruts) pour
  garantir que le score est toujours cohérent avec le triage affiché à
  côté, jamais un calcul parallèle qui pourrait diverger.
  - **Formule** : décroissance exponentielle de la somme des scores de
    segment (`100 * exp(-total/HEALTH_SCORE_SCALE)`) plutôt qu'une
    soustraction linéaire plafonnée à 0 — une dizaine de constats mineurs
    n'écrase pas mécaniquement le score à zéro comme le ferait une grosse
    anomalie unique, et le résultat reste toujours strictement borné dans
    [0, 100] sans seuil de coupure arbitraire à part. `HEALTH_SCORE_SCALE
    = 12.0` choisi empiriquement pour qu'une seule anomalie isolée (score
    de segment 3.0) fasse déjà sortir le score de la tranche "bon" (>= 85)
    sans l'écraser à elle seule. 4 tranches (`HEALTH_LABEL_THRESHOLDS`) :
    bon (>=85) / à surveiller (>=60) / dégradé (>=35) / critique (<35).
  - **Générique Finding/DiffFinding**, même duck-typing que
    `rank_segments` : sur un run simple, score de santé "instantané" ;
    sur un diff (`baseline_diff.DiffFinding`), reflète plutôt l'ampleur
    des régressions détectées entre baseline et courant (100 = aucune
    régression significative, pas "réseau parfait") — même réserve
    d'interprétation que tout ce que ce module produit déjà sur un diff.
  - **Câblage** : console (les deux CLI, sous `--triage`, juste après
    `print_triage`) et GUI GTK4 (les 2 points d'accroche, mode fichier et
    mode live) via `format_health_line()` — une seule source du texte
    exact pour éviter toute divergence entre les deux. `json_report.py` :
    clés `health_score`/`health_label` (code court, même vocabulaire que
    `severity`/`category`, pas le libellé affichable — laisse le
    consommateur externe choisir sa propre présentation/traduction) sur
    `generate_json_report` **et** `generate_json_diff`. `pdf.py` : badge
    coloré (`_health_badge`, 4 couleurs `HEALTH_BADGE_COLORS` alignées sur
    les 4 tranches) juste au-dessus de la table de triage, dans
    `generate_pdf` **et** `generate_diff_pdf`.
  - **Validation** : suite héritée rejouée avant tout nouveau code
    (399/399 verts, aucune régression préalable). 12 nouveaux tests
    (`tests/test_triage.py` : bornes [0,100], décroissance monotone,
    seuils des 4 tranches, ranked vide -> 100/bon, générisme sur le
    vocabulaire diff ; `tests/test_json_report.py` : cohérence
    `health_score`/`health_label` avec un recalcul indépendant côté test,
    cas 100/bon sans finding) — 411/411 au total. `ruff check`, `ruff
    format`, `lint-imports`, `pre-commit run --all-files` rejoués
    réellement, tout passe.
  - **`tshark` **et** `pytest` **et** `editcap` disponibles simultanément
    cette session** (rare — voir Sessions 9/10/11/14/17 pour les
    précédents) : validation bout-en-bout complète au-delà des tests
    unitaires, avec du **vrai trafic** plutôt que des paquets synthétiques
    monkeypatchés comme les sessions sans tshark. Serveur HTTP réel
    (`http.server`) capturé en direct sur `lo` via `tshark`, avec de
    vraies réponses 200/404/500 ; second point de capture fabriqué à
    partir du premier via `editcap` en retirant précisément une
    transaction `/error` (requête+réponse) — perte réelle, pas simulée.
    Les deux vraies CLI (`cross_capture_analyzer_cli.py` et
    `cross_capture_diff_cli.py`) rejouées de bout en bout avec
    `--triage --json-report --pdf-report` sur ces captures : score de
    santé cohérent entre console/JSON/PDF dans les deux scénarios (run
    simple : 31/100 "Critique" ; diff baseline sans perte vs courant avec
    la perte réelle : 69/100 "A surveiller"). Badge PDF inspecté
    visuellement via `pdf2image` dans les deux rapports (rouge/ambre selon
    la tranche, cohérent) ; non-régression du reste du PDF (page synthèse,
    tableau des constats) vérifiée sur la même génération.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (Codes de statut HTTP — Session 17)

- **Codes de statut HTTP/1.x** — voir section 2 `pcap_parser`/
  `netcross_core.analysis` pour le détail technique complet. Piste 🟢
  urgence faible retenue pour cette session : `tshark` **et** `pytest`
  étaient tous les deux disponibles en même temps dans cet environnement
  (comme les Sessions 9/10/11/14 — pas une première absolue, mais rare
  depuis : Sessions 12/13/15/16 n'avaient ni l'un ni l'autre, voir
  `docs/sessions/`) — occasion de vérifier empiriquement les noms de champs EK
  réels avant de coder (chose que DNS en Session 13 n'avait pas pu faire,
  faute d'accès à l'époque) et de rejouer la suite de tests réelle
  (`pytest`) plutôt que le harnais de secours utilisé quand ni l'un ni
  l'autre n'est disponible.
- **`pcap_parser.protocols.extract_http(layers)`** : lit la dissection
  HTTP/1.x native de tshark (`http.request`, `http.response`,
  `http.request.method`, `http.request.full_uri`/`http.request.uri`,
  `http.response.code`, `http.response_for.uri`, `http.time` — convention
  EK `http_http_<champ>` comme pour DNS/DHCP). Comme DNS, **pas de repli
  heuristique** : le port 80 (et quelques autres ports enregistrés) suffit
  à tshark. Reconnu sur TCP uniquement dans `packet.build_packet` — HTTP/2
  (dissecteur `http2` distinct) et HTTP/3 (QUIC/UDP, déjà couvert
  séparément par `quic_diagnostics`, SNI uniquement) sont hors périmètre.
- **Vérifié empiriquement contre un vrai tshark 4.2.2** (à la différence
  de DNS en Session 13, qui n'avait pas cet accès) : capture HTTP/1.1
  réelle générée sur loopback (`http.server` Python + `curl` + `tshark`)
  puis inspection de la sortie `-T ek` brute avant d'écrire `extract_http`.
  Deux découvertes qui ont directement influencé la conception :
  - `http.time` (écart requête→réponse) est **calculé nativement par
    tshark lui-même**, par transaction, présent uniquement sur le paquet
    de réponse quand tshark a pu apparier la transaction dans le fichier —
    contrairement à DNS/DHCP/SIP qui n'ont pas d'équivalent et doivent
    recomposer la durée à la main (`min(ts requête)`/`min(ts réponse)` sur
    toute la capture, moins précis). `_analyse_http` se contente de
    relever ce champ, sans le recalculer — nouveau helper
    `ek_fields.as_float()` (symétrique à `hex_or_dec_to_int`) pour le
    parser, rendu par tshark en chaîne flottante de secondes
    (`"0.000467410"`), jamais en flottant JSON natif.
  - La réponse ne porte pas la méthode HTTP (uniquement sur la requête),
    mais porte `http.response_for.uri` — l'URI complète déjà réappariée
    par tshark côté réponse. Utilisé directement plutôt que de refaire
    l'appariement requête/réponse nous-mêmes.
- **`_analyse_http`** (`netcross_core.analysis`) — même finalité que
  `_analyse_dhcp`/`_analyse_sip`/`_analyse_dns` (message manquant sur un
  segment, requêtes sans réponse observée nulle part dans la capture,
  erreurs 4xx/5xx par point avec quelques exemples concrets
  méthode+URI+code) mais **clé de transaction différente**, faute
  d'identifiant applicatif HTTP comparable à `dhcp.xid`/SIP Call-ID/
  `dns.id` : `(connexion TCP, URI, Nième occurrence de cette URI sur
  cette connexion à ce point)` plutôt qu'une simple position ordinale
  dans la connexion — une position ordinale pure se désynchroniserait dès
  qu'une requête entière est perdue sur un segment alors que les
  suivantes (sur une URI différente) survivent, provoquant un faux
  négatif sur la requête réellement perdue et un faux positif sur celle
  qui la suit. Voir la docstring de `_analyse_http` pour le raisonnement
  complet et son propre `sévérités` : 4xx = "info" (souvent légitime,
  côté client — même registre que NXDOMAIN), 5xx = "anomalie" (échec
  serveur/application, même registre que SERVFAIL), timeout = "anomalie",
  message manquant sur un segment = "a_surveiller" (mêmes choix que DNS),
  durée moyenne > 500ms = "a_surveiller" avec `sample_size`.
- **Limite assumée**, même famille que la réutilisation d'un id DNS 16
  bits (Session 13) : si la même URI est rejouée plusieurs fois sur la
  même connexion (ex: polling d'un endpoint de santé) ET qu'une occurrence
  précise est perdue entièrement à un point donné, le même glissement
  peut se reproduire entre les occurrences restantes de cette URI — non
  géré spécifiquement ici. Couverte par un test dédié qui documente le cas
  qui, lui, fonctionne correctement (deux URI différentes sur la même
  connexion, l'une perdue sur un segment).
- **Baseline diff** : mêmes seuils `_compare_count` que le reste du
  fichier pour 5xx/timeout (`min_delta=1, rel_threshold=0.0`, comme
  SERVFAIL — un événement qui doit normalement rester à zéro), mais
  **seuils par défaut, plus tolérants, pour le 4xx**
  (`min_delta=3, rel_threshold=0.5`) : contrairement au 5xx, un 404 isolé
  est trop souvent légitime (ressource réellement absente, bruit de
  robots) pour déclencher une régression dès la première occurrence —
  distinction volontaire, testée explicitement (une hausse de 2 est
  ignorée, une hausse de 3 déclenche). Pas de comparaison de
  `http_missing` (même choix que `dhcp_missing`/`dns_missing`/
  `sip_missing`, jamais comparés non plus dans ce fichier).
- **Automatique, sans nouveau flag CLI** (même choix que DNS/PMTUD/
  retrans/options TCP) : parité GUI/PDF/JSON gratuite via le mécanisme
  générique existant, confirmée par une génération PDF/JSON réelle (voir
  validation bout-en-bout ci-dessous), pas seulement supposée par analogie
  avec DNS. Section console dédiée ("HTTP (codes de statut, HTTP/1.x
  uniquement)") dans `report_text.print_report`.
- **Validation bout-en-bout avec deux vraies captures tshark** (au-delà
  des tests unitaires, et au-delà de ce que DNS avait pu faire en Session
  13 faute de `tshark`) : à partir de la capture loopback réelle,
  construction de deux fichiers "point A"/"point B" via `editcap` en
  retirant précisément une transaction entière (`/error`, requête+réponse)
  du second fichier, plus la réponse d'une autre transaction (`/slow`)
  des deux — simulant respectivement une perte sur le segment A→B et un
  timeout global. Rejeu du pipeline réel complet
  (`parse_captures_parallel` → `correlate` → `analyse` →
  `print_report`/`build_findings`/`generate_pdf`/export JSON) : les deux
  scénarios sont détectés exactement comme attendu, sans faux positif sur
  les 3 autres transactions présentes aux deux points — confirme en
  conditions quasi réelles la conception de la clé de transaction décrite
  plus haut.
- Validation : suite `pytest` réelle rejouée (comme les Sessions 9/10/11/14,
  qui avaient elles aussi `tshark` et `pytest` disponibles en même temps —
  voir la remarque en tête de section) — 399/399 au total (362
  préexistants + tests `extract_http`/`as_float` en isolation,
  `build_packet` sur TCP (requête/réponse) et confirmation qu'une couche
  `http` est ignorée sur UDP, `_analyse_http` via le pipeline complet
  (requête+réponse au même point, message manquant entre points, timeout,
  4xx/5xx comptés, exemple d'erreur avec méthode, glissement d'URI évité,
  polling sans perte), `build_findings`, `diff_reports`, `print_report`).
  `ruff check`/`ruff format`/`lint-imports`/`pre-commit run --all-files`
  également rejoués réellement (déjà fait en Session 7 à l'introduction de
  cet outillage, puis de nouveau chaque fois que l'accès réseau l'a permis
  depuis) : tout passe, y compris 3 fichiers préexistants
  (`cross_capture_diff_cli.py`, `netcross_report/triage.py`, un bloc de
  `tests/test_synthesis.py`) que `ruff format` n'avait pas encore eu
  l'occasion de reformater lors de leur session d'origine (accès réseau
  indisponible à l'époque) — reformatés au passage sans changement de
  comportement.

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (Comparaison client vs client — Session 14)

- **Comparaison client vs client** — voir section 2
  `netcross_core.client_diff` pour le détail technique complet. Piste 🟠
  urgence moyenne retenue en priorité pour cette session : design déjà
  détaillé dans `idées.md`/`netcross_pistes_evolution2.md` (Google
  Drive, dossier de suivi netcross), consultés en tout début de session
  — ce détail de conception n'était pas disponible lors de la Session 13
  (seule sa synthèse dans ce fichier l'était), ce qui l'avait fait
  écarter au profit de la résolution DNS à l'époque.
- **`netcross_core/client_diff.py`** (fichier neuf, même discipline que
  `baseline_diff.py`) : regroupe les paquets d'une même capture par
  poste (`group_packets_by_client`, groupement explicite `--client-group
  NOM=IP1[,IP2,...]`, pas d'auto-détection — voir discussion de
  conception en section 2), relance `analyse()` une fois par client
  (`build_client_report`), puis diffe chaque client contre un client de
  référence en réutilisant `diff_reports()` en mode N-way
  (`compare_clients`) — aucun nouveau moteur d'analyse ou de diff, un
  troisième axe de comparaison orthogonal aux deux déjà existants (point
  A vs point B, avant vs après).
- **Câblage** : `--client-group`/`--client-reference`/`--client-diff-csv`
  sur `cross_capture_analyzer_cli.py`, additif à l'analyse principale
  (le `Report` combiné habituel reste calculé et affiché en premier).
- **Non traité dans cette passe** (même raisonnement que la Session 12
  pour l'export JSON côté GUI, ou la Session 8 pour la parité TLS/QUIC
  en mode comparaison) : pas de wiring `--pdf-report`/`--json-report`
  (le mécanisme générique "stdout redirigé + `Finding` générique" qui a
  donné la parité gratuite à PMTUD/retrans/options TCP/DNS ne s'applique
  pas ici — `compare_clients` produit plusieurs `Report` et des
  `DiffFinding` par client, pas un seul `Report`, donc un vrai travail
  d'intégration serait nécessaire côté `netcross_report.pdf`/
  `json_report`) ; pas de câblage GUI (`netcross_gtk4/app.py`, vrai
  travail d'interface) ; pas de `--client-group` sur
  `cross_capture_diff_cli.py` (combiner client vs client ET avant/après
  dans une seule commande n'a pas de précédent ni de design tranché,
  question ouverte si le besoin se confirme).
- **Bonus d'environnement** : `tshark`/`pytest`/`ruff`/`import-linter`/
  `scapy` tous installables dans cette session (accès réseau disponible,
  comme les Sessions 9/10/11, contrairement aux Sessions 1-8/12/13) —
  premier rejeu de bout en bout contre un **vrai** `tshark 4.2.2` pour
  une fonctionnalité de ce projet depuis la Session 11 : deux pcap
  scapy réels (poste A vu aux 2 points, poste B vu seulement au premier)
  rejoués via le vrai CLI, régression détectée et isolée correctement.
- Validation : 14 nouveaux tests (`tests/test_client_diff.py`, 325/325
  au total), `pytest`/`ruff check`/`ruff format --check`/`lint-imports`/
  `pre-commit run --all-files` tous réellement exécutés et verts (pas de
  simulation manuelle cette fois) — voir `docs/sessions/session-14.md` pour le
  détail complet, y compris deux corrections de lint incidentes sans
  rapport avec ce module (`report_text.py`/`test_json_report.py`,
  dette résiduelle de Sessions 12/13 jamais passée dans un vrai `ruff`
  faute d'accès réseau à l'époque, corrigée au passage par
  `pre-commit run --all-files`).

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (Résolution DNS — Session 13)

- **Résolution DNS** — voir section 2 `pcap_parser`/`netcross_core.analysis`
  pour le détail technique complet. Piste 🟠 urgence moyenne retenue en
  priorité pour cette session, comme la sortie JSON en Session 12 : le
  seul module 🟠/⚠️ encore ouvert en section 5.2 explicitement signalé
  comme ne dépendant pas de tshark côté implémentation (le dissecteur
  DNS de tshark fait tout le travail de dissection, seule la corrélation
  entre points de capture est nouvelle ici) — un bon candidat pour une
  session sans accès à un vrai `tshark` (contrainte réseau de cet
  environnement, comme les Sessions 1-8 et 12, contrairement aux
  Sessions 9/10/11).
- **`pcap_parser.protocols.extract_dns(layers)`** : lit la dissection
  DNS native de tshark (`dns.id`, `dns.flags.response`, `dns.qry.name`,
  `dns.flags.rcode`, convention EK `dns_dns_<champ>` comme pour
  `extract_dhcp`) — reconnu sur UDP et TCP (transferts de zone,
  réponses tronquées). Contrairement à RTP/SIP, **pas de repli
  heuristique** : DNS n'a pas de forme "sans signalisation prealable" à
  détecter par lecture d'octets bruts, tshark le reconnaît nativement
  dès que le port est standard ou que la conversation est visible dans
  la capture — cas très majoritaire en pratique, donc pas de logique
  de repli à écrire ni à tester séparément (différence assumée avec
  RTP/SIP, pas un oubli).
- **`_analyse_dns`** (`netcross_core.analysis`) — même schéma de
  corrélation que `_analyse_dhcp`/`_analyse_sip` (dictionnaire
  identifiant de transaction → point → paquets) : message (requête ou
  réponse) manquant sur un segment entre deux points, requêtes sans
  aucune réponse observée nulle part dans la capture (timeout
  applicatif ou serveur/résolveur injoignable — `Report.dns_timeout`),
  réponses NXDOMAIN (`dns_nxdomain_count`, sévérité "info" — domaine
  inexistant, pas forcément un problème réseau) et SERVFAIL
  (`dns_servfail_count`, "anomalie" — échec de résolution côté serveur,
  **précisément l'angle mort visé par cette piste** : souvent pris à
  tort pour un problème réseau alors que le paquet a très bien
  transité), et durée moyenne query → réponse (`dns_duration_ms`,
  "a_surveiller" au-delà de 200ms).
- **Limite assumée** (même famille que `dhcp.xid`/SIP Call-ID, jamais
  mentionnée explicitement pour ceux-ci faute d'être pertinente à leur
  échelle) : l'identifiant de transaction DNS ne fait que 16 bits,
  contre 32 pour `dhcp.xid` — sur une capture très longue et très
  chargée en requêtes DNS concurrentes, une réutilisation d'id avant
  qu'une transaction précédente ne soit terminée est théoriquement
  possible et n'est pas gérée spécifiquement ici (les deux transactions
  seraient alors vues comme une seule, à tort).
- **Automatique, sans nouveau flag CLI** (même choix que PMTUD/retrans/
  options TCP) : parité GUI/PDF/JSON gratuite via le mécanisme générique
  existant (stdout redirigé + `Finding` générique + `Report` consommé
  tel quel par `json_report`). Section console dédiée ("DNS (résolution
  de noms)") dans `report_text.print_report`, comparaison avant/après
  dans `baseline_diff` (nouvelles régressions NXDOMAIN/SERVFAIL/timeout
  par point + comparaison de la durée moyenne globale, mêmes seuils
  `_compare_count`/logique `_compare_latency` que le reste du fichier).
- **Non vérifié empiriquement contre un vrai tshark** (comme la Session
  12 et contrairement aux Sessions 9/10/11) : noms de champs EK
  (`dns_dns_id`, `dns_dns_flags_response`, `dns_dns_qry_name`,
  `dns_dns_flags_rcode`) déduits par analogie avec la convention déjà
  vérifiée pour DHCP (`dhcp_dhcp_type`, `dhcp_dhcp_option_dhcp_server_id`)
  plutôt que confirmés sur une vraie sortie `tshark -T ek` — à vérifier
  dès qu'un environnement avec `tshark` est de nouveau disponible (même
  remarque que Sessions 1-8 pour RTP/DHCP/SIP à l'époque, confirmée
  exacte pour DHCP en Session 9/10/11 a posteriori).
- Validation : 21 nouveaux tests (`extract_dns` en isolation,
  `build_packet` sur UDP et TCP, `_analyse_dns` via le pipeline complet
  `correlate`/`analyse` — requête+réponse au même point, message
  manquant entre points, timeout, NXDOMAIN/SERVFAIL, paquet non-DNS
  ignoré —, `build_findings`, `diff_reports`, `print_report`),
  311/311 au total. `pytest` toujours indisponible dans cet
  environnement (pas d'accès réseau, comme toutes les sessions sauf
  9/10/11) : rejoué via le même harnais de secours que les Sessions 8/12
  (`capsys`/`monkeypatch`/`tmp_path`, `pytest.approx`/`pytest.raises`
  minimalement réimplémentés).

### Câblage à coût faible (le code existe, il manque juste le point d'entrée)

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (Sortie JSON structurée — Session 12)

- **Export JSON structuré** — voir section 2 `netcross_report.json_report`
  pour le détail technique complet. Piste 🟠 urgence moyenne retenue en
  priorité pour cette session car explicitement signalée en Session 11
  comme "ne dépendant pas de tshark" — un bon candidat pour une session
  sans accès à un vrai `tshark` (contrainte réseau de cet environnement,
  contrairement aux Sessions 9/10/11).
- **Câblage** : `--json-report CHEMIN` sur les deux CLI
  (`cross_capture_analyzer_cli.py` et `cross_capture_diff_cli.py`), même
  calcul de findings/triage que le PDF (aucune divergence possible entre
  les deux formats pour un même `Report`), aucune dépendance
  supplémentaire (contrairement à `--pdf-report`).
- **Non traité dans cette passe** : pas de bouton "Export JSON" côté GUI
  (`netcross_gtk4/app.py`) — vrai travail d'interface, hors périmètre
  d'une session dédiée au câblage CLI (même raisonnement que la Session 8
  pour la parité GUI TLS/QUIC en mode comparaison).
- Validation : 7 nouveaux tests (`tests/test_json_report.py`, 287/287 au total), les deux
  vrais CLI rejoués de bout en bout sur des paquets synthétiques
  (`Pkt` construits à la main + `parse_capture` monkeypatché, `tshark`
  toujours indisponible dans cet environnement comme lors des Sessions
  1-8), JSON produit relu et vérifié structurellement à chaque étage
  (voir `docs/sessions/session-12.md` pour le détail complet).

### Câblage à coût faible (le code existe, il manque juste le point d'entrée)

### ✅ Nouvelle fonctionnalité ajoutée dans cette passe (PMTUD — Session 9)

- **Détection de noir PMTUD** (RFC 1191) — voir section 2
  `netcross_core.analysis` pour le détail technique complet. Ancienne
  piste d'évolution priorité #1 (section 5.2), la plus ancienne encore
  ouverte, désormais faite.
- **Bug réel trouvé et corrigé au passage** (comme en Session 5 pour la
  compatibilité 3.9, même esprit) : `is_fragment` (bit MF) utilisait
  `bool(g(...))` nu sur un champ EK — `bool("0")` vaut `True` en Python,
  ce qui aurait été incorrect si ce champ était un jour rendu en chaîne
  plutôt qu'en booléen JSON natif. Trouvé en écrivant le test du nouveau
  champ `df` (même construction), jamais couvert par un test avant.
  Corrigé pour les deux champs (`df` et `is_fragment`/MF) via un nouveau
  helper tolérant `ek_fields.as_bool()`.
- **Premier accès à un vrai `tshark` dans l'historique de ce projet** :
  `tshark`/`wireshark-common` 4.2.2 installables dans cet environnement
  (`archive.ubuntu.com` accessible, contrairement à toutes les sessions
  précédentes). A permis de vérifier **empiriquement** — plutôt que par
  hypothèse comme jusqu'ici — que `ip.flags.df`/`.mf` sont bien rendus en
  booléen JSON natif par cette version (pcap de test généré via `scapy`,
  décodé par le vrai `tshark -T ek`, voir `docs/sessions/session-09.md` pour le
  détail complet de la démarche). `as_bool()` reste tolérant à une
  représentation en chaîne par prudence pour d'autres versions.
- Validation : 21 nouveaux tests (242/242 au total, voir Outillage
  qualité ci-dessus), `ruff`/`lint-imports`/`pre-commit run --all-files`
  propres, et — nouveau pour ce projet — un scénario PMTUD synthétique
  complet (pcap scapy → vrai `tshark` → `parse_capture` → `correlate` →
  `analyse`) rejoué de bout en bout via les deux vrais CLIs
  (`cross_capture_analyzer_cli.py --triage`, `cross_capture_diff_cli.py`)
  ET un PDF réellement généré (`reportlab`, relu avec `pypdf`) : cas
  positif (noir détecté) et cas négatif (ICMP présent → rien signalé)
  tous deux confirmés à chaque étage.

### ✅ Corrigé dans cette passe (nettoyage warnings + compatibilité — Session 5)

- **Tous les warnings `ruff`/`flake8` corrigés** : les 3 `F541` connus
  dans `report_text.py` depuis la Session 3 (signalés hors périmètre à
  l'époque), une variable ambiguë `l` (`E741`, `pcap_parser/tunnels.py`),
  et ~24 warnings supplémentaires (imports/annotations modernisés via
  `ruff --fix`, mise en forme via `ruff format`, exceptions trop larges
  documentées avec justification plutôt que silencieusement supprimées —
  voir `docs/sessions/session-05.md` pour le détail).
- **Bug de compatibilité trouvé et corrigé en cours de nettoyage** : la
  modernisation automatique `Optional[X]` → `X | None` (PEP 604,
  syntaxe Python 3.10+) cassait l'import à l'exécution sur le `python3`
  3.9 par défaut de Rocky/RHEL 9 — la cible réelle de ce projet — dans 5
  fichiers dépourvus de `from __future__ import annotations`
  (`models.py`, `baseline_diff.py`, `tls_diagnostics.py`,
  `quic_diagnostics.py`, `triage.py`). Corrigé en ajoutant cet import
  future aux 5 fichiers concernés. Vérifié exhaustivement qu'aucun autre
  fichier n'était dans ce cas, et qu'aucune autre construction récente
  (`itertools.pairwise`, `isinstance(x, A | B)`, etc.) n'avait été
  introduite par erreur : `itertools.pairwise` (aussi suggéré par
  `ruff`, aussi 3.10+ uniquement) a été explicitement refusé et documenté
  (`# noqa: RUF007`) aux deux endroits où `ruff --fix` voulait
  l'introduire (`analysis.py`, `tls_diagnostics.py`).
- Validation : `python -m compileall`, `ruff check` (toutes règles) et
  `flake8` (profil documenté) propres sur tout `src/` ; import réel de
  tous les modules non-GTK4 sans erreur ; pipeline complet
  (`correlate`/`analyse`/`print_report`/`build_findings`/`rank_segments`
  /`diff_reports`) rejoué sur des paquets synthétiques après coup pour
  confirmer l'absence de régression comportementale.

### ✅ Corrigé dans cette passe (câblage à coût faible)

1. ~~Exposer `triage.rank_segments`/`print_triage`~~ — fait :
   `netcross_report/__init__.py` les exporte, `--triage`/`--triage-top-n`
   sur `cross_capture_analyzer_cli.py`, section "Par où commencer" en tête
   de `generate_pdf` ET `generate_diff_pdf`.
2. ~~Câbler `tls_diagnostics` et `quic_diagnostics`~~ — fait :
   `--tls`/`--quic` sur `cross_capture_analyzer_cli.py`. Le double
   pipeline de lecture (tshark pour l'analyse principale, scapy/`rdpcap()`
   pour TLS/QUIC) qui existait à l'issue de cette passe a depuis été
   éliminé (voir section "✅ Corrigé dans cette passe (dette
   structurelle)" plus bas, point 7) : les deux modules passent
   maintenant par `pcap_parser` comme le reste de l'outil. À corriger a
   minima à l'époque : `tls_diagnostics.py` levait `sys.exit(1)` à
   l'import si scapy manquant, ce qui aurait tué tout process qui
   importe `netcross_core` sans scapy même sans --tls ; corrigé pour
   lever `ImportError` (capturable) — devenu sans objet depuis que
   scapy a disparu du projet.
3. ~~`--pdf-report` sur `cross_capture_diff_cli.py`~~ — fait :
   `netcross_report.generate_diff_pdf`, `chart_severity_summary` généralisé
   pour le vocabulaire diff. Testé avec un vrai scénario de régression
   (fenêtres TCP=0 baseline vs courant) : PDF 3 pages valide, code de
   sortie non nul preserve.
6. ~~`parse_dhcp`/`innermost_layer` cassées~~ — fait : supprimées de
   `netcross_core/parsing.py` et de `__init__.py` plutôt que laissées à
   lever `NotImplementedError` a l'usage.
9. ~~Cohérence README~~ — fait : nouveaux flags documentés dans la
   section Utilisation, sous-section dédiée à `cross_capture_diff_cli.py`
   (absente jusqu'ici), note de parité GUI/CLI incomplète explicite.

### ✅ Corrigé dans cette passe (dette structurelle)

7. ~~Doublon de lecture de capture pour TLS/QUIC~~ — **fait** :
   `tls_diagnostics.py` et `quic_diagnostics.py` n'ont plus leur propre
   pipeline `scapy.rdpcap()`. Un champ `payload: bytes` a été ajouté à
   `pcap_parser.RawPacket` (la charge utile TCP/UDP était déjà calculée
   en interne pour RTP/SIP/le hash, mais jetée ensuite — elle est
   maintenant exposée). `parse_tls_capture`/`parse_quic_capture` lisent
   désormais via `pcap_parser.parse_capture()`, exactement comme le
   reste de l'outil (donc via tshark, un seul type de pipeline de
   décodage dans tout le projet). **`scapy` a disparu du projet** :
   plus aucun `import scapy`, plus de fallback, `requirements.txt` /
   `install.sh` / `build-rpm/netcross.spec` / `build-deb/debian/control`
   mis à jour en conséquence (remplacé par `cryptography`, seule
   dépendance réelle restante propre à `--quic`). Revalidé avec des
   paquets TLS/QUIC synthétiques injectés directement en `RawPacket`
   (montage/démontage du pipeline confirmé sans dépendre de la
   disponibilité de tshark dans l'environnement de test) : `--tls`
   retrouve bien un ClientHello, `--quic` retrouve bien un paquet
   Initial et échoue proprement son déchiffrement sur un ciphertext
   invalide (comportement attendu, pas un crash).
   Corrigé au passage : l'import de `cryptography` dans
   `quic_diagnostics.py` n'était protégé par aucun `try/except`
   (défaut préexistant, indépendant de scapy) — protégé maintenant par
   le même style de garde `ImportError` explicite que scapy avait.

### ✅ Corrigé (câblage GUI, effort moyen)

4. ~~**Parité GUI/CLI** dans `netcross_gtk4/app.py`~~ — **découvert déjà
   fait en relisant le code réel en tout début de cette passe**, alors
   que ce document (jusqu'à la version précédente de ce fichier)
   affichait encore ce point comme non traité. Le code avait déjà tout :
   mode `--parallel`, export CSV, `--triage`/`--tls`/`--quic`, déduction
   automatique de topologie (`points_order=None`), ET le mode
   comparaison baseline/courant complet (case dédiée, deux panneaux,
   seuils, export PDF/CSV) — voir section 2 pour le détail module par
   module. Reconstruit et vérifié plutôt que supposé : lecture complète
   du fichier (996 lignes avant cette passe), `python -m compileall`
   propre, et confirmation programmatique que chaque fonction que
   `app.py` importe existe réellement avec la signature attendue
   (`inspect.signature` comparé à chaque site d'appel) — GTK4 n'étant
   pas installé dans l'environnement de cette passe, l'interface
   elle-même n'a pas pu être ouverte pour un test visuel direct. Seule
   lacune trouvée à l'époque : le "top N" du triage n'était pas réglable
   côté GUI (toujours 5 par défaut, contrairement à `--triage-top-n`
   côté CLI) — corrigé depuis, voir point 11 ci-dessous.
5. ~~**`pcap_parser.iter_live` / `netcross_core.parsing.parse_live`**~~
   — **fait côté GUI dans cette passe** (seule vraie brique manquante
   trouvée après vérification du point 4) : nouveau mode "Capture en
   direct" — case à cocher, panneau dédié (nom/interface/filtre BPF
   par point, réordonnable comme les captures fichier), démarrage/arrêt
   manuel ou durée max optionnelle, affichage incrémental (compteur de
   paquets par point toutes les ~1s dans le journal). Arrêt propre
   implémenté en profondeur plutôt qu'en façade : nouveau paramètre
   `stop_event` (`threading.Event`) sur `iter_ek_records`/`iter_live`/
   `parse_live` (couches `pcap_parser.ek_source` → `pcap_parser.capture`
   → `netcross_core.parsing`) — un thread dédié termine le sous-processus
   tshark dès que l'événement est positionné, ce qui débloque la lecture
   même sur une interface totalement silencieuse (un simple
   `if stop_event.is_set(): break` vérifié entre deux paquets ne
   l'aurait pas permis, puisqu'aucun paquet ne déclenche jamais ce test
   sur une interface sans trafic). Validé isolément avant intégration
   avec un sous-processus factice sans aucune sortie : arrêt confirmé en
   ~1s au lieu de rester bloqué indéfiniment (`test_stop_mechanism.py`,
   non inclus dans la livraison — script de validation ponctuel).
   TLS/QUIC volontairement indisponibles dans ce mode (nécessitent un
   fichier à relire, absent en capture live) ; mode comparaison
   baseline/courant non combiné avec la capture live (cases à cocher
   mutuellement exclusives) — limitation assumée, pas une omission.

### Reste à faire — câblage à coût faible

*(les points 10 à 12 de la version précédente de ce document ont été
traités en Session 5, voir "Corrigé" ci-dessus — nouveau point restant :)*

10. ~~Capture en direct absente des deux CLIs~~ — **fait pour
    `cross_capture_analyzer_cli.py`** (`--live LABEL:INTERFACE[:FILTRE_BPF]`,
    répétable, `--live-duration` optionnel) : un thread par point comme
    la GUI, arrêt sur `SIGINT` (Ctrl+C, gestionnaire installé le temps de
    la capture) ou durée max, `--capture`/`--parallel`/`--tls`/`--quic`
    explicitement refusés en combinaison (mêmes limitations assumées que
    la GUI). Testé avec un `parse_live` simulé (tshark non disponible
    dans l'environnement de cette passe, comme les sessions précédentes) :
    arrêt correct via timeout ET via signal, sur un seul point et sur
    plusieurs points simultanés, un point en échec ne bloque pas les
    autres. **Non fait pour `cross_capture_diff_cli.py`** — la session a
    été interrompue par l'utilisateur avant cette partie ; ajouter
    `--live`/`--live-current` à cette CLI n'a pas de précédent côté GUI
    (mode comparaison et capture live y sont mutuellement exclusifs) et
    resterait à concevoir spécifiquement si demandé.
11. ~~Top N du triage non réglable côté GUI~~ — **fait** : `Gtk.SpinButton`
    (1-50, défaut 5) à côté de la case "Triage", câblé mode fichier et
    mode live.
12. ~~TLS/QUIC absents du rapport PDF~~ — **fait** : nouvelle section
    dédiée dans `generate_pdf` (GUI et CLI), en plus d'être mêlés au
    triage global en tête de rapport. `generate_diff_pdf` n'avait pas
    cet ajout à l'époque — **fait depuis, en Session 8, voir point 13
    ci-dessous** (section séparée dédiée, pas mêlée au triage — raison
    détaillée au point 13).
13. ~~`cross_capture_diff_cli.py` n'avait pas de `--triage` (sortie
    console), `--tls` ni `--quic` dédiés~~ — **fait en Session 8** :
    - `--triage`/`--triage-top-n` : simple, les `DiffFinding` sont déjà
      calculés inconditionnellement par ce CLI (contrairement à
      l'analyzer CLI où `build_findings(r)` est lazy) — juste
      `rank_segments`/`print_triage` appelés en plus si le flag est
      présent, même triage que celui déjà inclus automatiquement dans
      `--pdf-report` depuis la Session 2, maintenant aussi sur la
      console.
    - `--tls`/`--quic` : décision de conception tranchée comme
      pressenti ci-dessous — chaque diagnostic est exécuté **séparément**
      sur le baseline et sur le run courant (pas de vraie diff
      sémantique disponible, ces deux modules ne connaissent qu'un état
      à un instant donné), affichés l'un après l'autre sur la console
      (bannières `-- TLS : BASELINE --`/`-- TLS : COURANT --`, idem
      QUIC) et dans une section dédiée du PDF (`generate_diff_pdf`,
      nouveaux paramètres `tls_findings_baseline`/`tls_findings_current`/
      `quic_findings_baseline`/`quic_findings_current`) — **volontairement
      pas fondus** dans le triage/la table de constats principale (voir
      section 2 "netcross_report.pdf" pour la justification complète).
    - Validé de bout en bout sans tshark (comme toutes les sessions
      précédentes) : paquets TLS/QUIC synthétiques construits en
      réutilisant les fabriques déjà testées de `test_tls_diagnostics.py`/
      `test_quic_diagnostics.py`, injectés via `pcap_parser.parse_capture`
      monkeypatché, scénario "LAN OK partout, WAN casse en courant"
      (alert TLS fatal + ClientHello QUIC qui disparaît) — les deux
      correctement détectés et affichés dans la bonne section (baseline
      vs courant). PDF généré relu avec `pypdf` **et converti en image
      (`pdf2image`) pour inspection visuelle** de la nouvelle section et
      des 3 autres pages (non-régression). Suite `pytest` rejouée via un
      petit harnais de secours reproduisant les fixtures réellement
      utilisées (`capsys`/`monkeypatch`/`tmp_path`, `pytest.approx`/
      `pytest.raises`) — `pytest` lui-même n'a pas pu être installé dans
      cet environnement (pas d'accès réseau) : 221/221 toujours verts,
      aucune régression (les deux fichiers modifiés, `cross_capture_diff_cli.py`
      et `netcross_report/pdf.py`, n'ont pas de test dédié — cohérent
      avec la couverture existante, voir section 5.2).
14. ~~**`cross_capture_diff_cli.py` n'a toujours pas de `--live` dédié**~~
    **✅ Fait en Session 16** — `--live-current LABEL:INTERFACE[:FILTRE_BPF]`
    (répétable) + `--live-duration`. Décision de conception tranchée entre
    les deux lectures possibles identifiées ici depuis la Session 5
    (capturer les DEUX scénarios en direct simultanément, ou capturer
    seulement le run courant en direct face à un baseline déjà enregistré
    sur fichier) : la seconde a été retenue. Raisonnement : un baseline
    est par construction une référence **déjà établie** (un état de
    fonctionnement connu, enregistré à l'avance, souvent avant un
    changement) — le capturer en direct en parallèle du run courant
    n'aurait de sens que si les deux réseaux à comparer coexistaient au
    même instant, ce qui n'est pas le scénario que ce CLI sert (comparer
    un AVANT et un APRÈS, pas deux sites simultanés — ce dernier cas est
    déjà couvert par la comparaison client vs client de la Session 14 sur
    une même capture). `--baseline` reste donc toujours un ou plusieurs
    fichiers ; seul `--current` a un équivalent live (`--live-current`,
    mutuellement exclusif avec `--current`, l'un des deux étant requis).
    Cette dissymétrie règle aussi la question du format `NOM=chemin`
    laissée ouverte ici : `--live-current` a son propre format
    `LABEL:INTERFACE[:FILTRE_BPF]` (identique à `--live` sur l'autre CLI),
    `--baseline`/`--current` gardent inchangé leur format `NOM=chemin`.
    `--tls`/`--quic`/`--parallel` refusés en combinaison avec
    `--live-current`, mêmes limitations assumées que `--live` sur
    `cross_capture_analyzer_cli.py` (voir point 10 plus haut) : `--tls`/
    `--quic` doivent relire un fichier pour le run courant, qui n'existe
    pas en mode live ; `--parallel` n'a pas de sens pour un run déjà
    capturé en un thread par point, et s'appliquerait par ailleurs aussi
    au chargement du baseline, ce qui mélangerait les deux mécaniques
    pour un gain marginal. Testé comme les Sessions 5/9 précédentes sans
    tshark ni réseau : `parse_capture`/`parse_live` monkeypatchés, run
    bout-en-bout avec baseline fichier + courant live simulé (un point et
    plusieurs points simultanés), toutes les validations d'arguments
    (ni l'un ni l'autre, les deux à la fois, combinaisons refusées)
    couvertes par 12 nouveaux tests dans `tests/test_diff_cli_live.py` —
    premier fichier de tests à couvrir directement une des deux CLI (voir
    section 5.2, ce n'était pas le cas jusqu'ici).

### Dette structurelle restante (nécessite une vraie décision de conception, non traitée)

8. ~~**Pas de test automatisé** dans le dépôt~~ **✅ Corrigé en Session 6** :
   voir `tests/` (`pytest`, 221 tests) — détail dans `docs/sessions/session-06.md`. Ce point
   restait ouvert depuis la Session 1 ; c'est le premier des 5 items de
   dette structurelle jamais traités à l'être. La validation manuelle par
   scripts ponctuels décrite dans les sessions précédentes n'est donc plus
   la seule protection contre les régressions sur `pcap_parser`/
   `netcross_core`/`netcross_report`.

---

## 5. Suivi des pistes d'évolution (`idées.md` vs état actuel)

Croisement entre `idées.md` (synthèse des pistes proposées, elle-même consolidée à
partir de `netcross_pistes_evolution2.md`, `RAPPORT_PROJET.md`, `CLAUDEanalyse.md` et
du mail "Netcross1") et l'état réel du code décrit dans les sections 1 à 4 ci-dessus.

**Changement d'architecture à noter** : `idées.md` §3 actait la décision de rester sur
scapy et d'étendre son écosystème (`scapy.layers.dns`/`.tls`/`.http`). Le code réel
(section 1) montre l'inverse : scapy a été totalement éliminé, remplacé par tshark
comme moteur unique — y compris pour TLS et QUIC, qui avaient chacun leur propre
pipeline `scapy.rdpcap()`. Les pistes ci-dessous formulées à l'origine "via
`scapy.layers.X`" sont donc requalifiées en équivalent tshark.

**Source croisée** : `netcross_pistes_evolution2.md` (un des documents sources de
`idées.md`) a été comparé point par point à `idées.md` — il ne contient aucune piste
d'évolution qui ne soit déjà reprise ci-dessous ; la synthèse de `idées.md` est fidèle
et complète vis-à-vis de cette source.

### 5.1 Idées déjà passées en fonctionnalités

| Idée | Devenu dans le code actuel |
|---|---|
| Module TLS | ✅ Fait, relit maintenant via tshark, intégré au PDF |
| Baseline diff (avant/après) | ✅ Fait + export PDF dédié + intégré à la GUI |
| Triage inter-catégories | ✅ Fait, intégré aux deux rapports PDF |
| Module QUIC | ✅ Fait, idem TLS (tshark, scapy éliminé) |
| tshark en sous-processus | ✅ Fait, bien plus large que prévu : moteur unique, pas un simple pont ciblé |
| CAPWAP via tshark | ✅ Fait + détection DTLS (nouveau, absent des pistes d'origine) |
| Capture en direct | ✅ Fait (GUI + `--live` CLI) — pas demandé tel quel dans les pistes d'origine |
| Comparaison client vs client | ✅ Fait en Session 14 — `netcross_core/client_diff.py`, `--client-group`/`--client-reference` sur `cross_capture_analyzer_cli.py` |

### 5.2 Évolutions pas encore portées

Légende urgence : ⚠️ Haute · 🟠 Moyenne · 🟢 Faible
*(⚠️ a ici le sens "urgence haute" — différent de son usage en section 2, "non câblé
dans aucune interface".)*

**⚠️ Urgence haute**

| Évolution | Pourquoi |
|---|---|
| ~~Suite de tests automatisés~~ | **✅ Fait en Session 6** — `tests/` (`pytest`, 221 tests) : `pcap_parser` (toutes couches), `correlate`/`analysis`/`baseline_diff`/`synthesis`/`triage`/`report_text`, `tls_diagnostics`/`quic_diagnostics` (dont vecteurs officiels RFC 9001 Annexe A). Non couverts : `netcross_report/charts.py` et `pdf.py` (rendu visuel), la GUI GTK4, et tout chemin qui appellerait réellement le binaire `tshark` (toujours absent de l'environnement de développement, voir `docs/sessions/`) |
| ~~Parité `cross_capture_diff_cli.py` (triage/TLS/QUIC)~~ | **✅ Fait en Session 8** — voir section 4 point 13 pour le détail. `--live` sur ce même CLI reste ouvert, requalifié en urgence moyenne ci-dessous (ce n'est pas un simple câblage, voir section 4 point 14) |
| ~~PMTUD black hole~~ | **✅ Fait en Session 9** — priorité #1 des pistes d'évolution, voir section 2 `netcross_core.analysis` pour le détail (`_analyse_pmtud`). Requalifiée ici depuis 🟠 urgence moyenne : c'était la piste la plus ancienne et la plus prioritaire encore ouverte |
| ~~Classification retransmissions (Fast Retransmit vs RTO)~~ | **✅ Fait en Session 10** — voir section 2 `netcross_core.analysis` pour le détail (`_analyse_retransmission_types`). Bonus par rapport à la piste d'origine : une 3ᵉ catégorie ajoutée au passage (`spurious_retransmission`, quasi gratuite une fois les deux autres câblées) |
| ~~Négociation options TCP (MSS/Window Scale/SACK)~~ | **✅ Fait en Session 11** — voir section 2 `netcross_core.analysis` pour le détail (`_analyse_tcp_options`) |

**🟠 Urgence moyenne**

| Évolution | Pourquoi |
|---|---|
| ~~`--live` sur `cross_capture_diff_cli.py`~~ | **✅ Fait en Session 16** — `--live-current`/`--live-duration`, voir section 4 point 14 pour le détail et la décision de conception (seul le run courant peut être live, le baseline reste toujours fichier) |
| ~~Résolution DNS~~ | **✅ Fait en Session 13** — voir section 2 `pcap_parser`/`netcross_core.analysis` (`extract_dns`/`_analyse_dns`). Retenue en priorité comme la sortie JSON en Session 12 : explicitement signalée comme réalisable sans accès à `tshark` (le dissecteur DNS de tshark fait tout le travail de dissection, seule la corrélation entre points est nouvelle) |
| ~~Score de confiance / `sample_size`~~ | **✅ Fait en Session 15** — voir section 2 `netcross_report.synthesis`/`netcross_core.baseline_diff`/`netcross_report.triage` pour le détail. Portée volontairement restreinte aux valeurs ESTIMÉES (taux/moyenne/MOS) — pas aux compteurs bruts d'événements, voir `docs/sessions/session-15.md` pour la justification |
| ~~Sortie JSON structurée~~ | **✅ Fait en Session 12** — voir section 2 `netcross_report.json_report` (`--json-report` sur les deux CLI). Retenue en priorité car explicitement identifiée comme réalisable sans accès à `tshark` (voir `docs/sessions/session-11.md`) |
| Validation CAPWAP sur vraie capture (Aruba/Cisco/Fortinet) | Détection DTLS annoncée mais jamais testée contre du vrai trafic ; piège connu des trames Cisco "Malformed" en pur clean-room RFC |
| ~~Gestion mémoire des grosses captures~~ | **✅ Fait en Session 19** — voir section 2 `pcap_parser`/`netcross_core.models`/`netcross_core.parsing` pour le détail (`__slots__`, interning sélectif, conversion incrémentale). Le pipeline reste entièrement en RAM (pas de streaming multi-passes, la corrélation multi-points en a besoin), mais la mémoire par paquet a été mesurée et réduite empiriquement de ~68% (1971 → 636 octets/paquet), et le pic RSS réel du process principal de ~61% sur un scénario réaliste à 2 points × 200k paquets (1,3 Go → ~500 Mo) |

**🟢 Urgence faible**

| Évolution | Pourquoi |
|---|---|
| ~~Graphiques temporels top-N~~ | **✅ Fait en Session 20** — voir section 2 `netcross_core.correlate`/`netcross_report.charts`/`netcross_report.pdf` pour le détail (`compute_topn_series`, `chart_topn_timeseries`, section "Évolution temporelle (top-N)" du PDF). Scope volontairement restreint à `cross_capture_analyzer_cli.py --pdf-report`, un seul point de capture tracé par graphique (voir section 4 pour la justification complète des décisions de conception) |
| ~~TLS approfondi (chaîne de certs, réassemblage)~~ | **✅ Fait en Session 26** (pour le certificat feuille) — voir section 4 pour le détail complet. `_analyse_tls_certificate` : dates de validité hors fenêtre (par point) et substitution de certificat entre deux points pour une même connexion (par paire). Réassemblage : gratuit via le dissecteur natif tshark (qui réassemble les segments TCP avant dissection). **Reste hors de portée, limite architecturale documentée** : Subject/Issuer (Distinguished Name complet) — positionnellement ambigu en EK (`-T ek`), demanderait `-T json`/`-T pdml` pour reconstruire l'arbre ASN.1 de façon fiable ; certificats intermédiaires/racine de la chaîne (seul le certificat feuille, le premier, est analysé — garanti par RFC 5246 §7.4.2) ; vérification de la chaîne de confiance PKI (hors de portée d'une capture passive) |
| ~~Codes de statut HTTP~~ | **✅ Fait en Session 17** — voir section 2 `pcap_parser`/`netcross_core.analysis` (`extract_http`/`_analyse_http`). Comme pour DNS (Session 13), aucun changement PDF/JSON/GUI/triage nécessaire (génériques sur `Finding`/`Report`). `tshark` **et** `pytest` étaient tous les deux disponibles cette session (comme les Sessions 9/10/11/14) — vérification empirique des champs EK réels puis validation bout-en-bout complète (2 vraies captures tshark, scénario de perte construit via `editcap`) avant livraison, voir `docs/sessions/session-17.md` pour le détail |
| ~~Analyse L2 (ARP + STP)~~ | **✅ Fait en Session 24 (ARP) puis Session 25 (STP)** — voir section 4 pour le détail complet. ARP : `_analyse_arp_ip_conflict`, deux MAC différentes revendiquant la même IP au même point. STP : `_analyse_stp_instability`, tempête de changements de topologie (TCN/bit TC) et réélections de pont racine, par point. **Correction Session 25** : la limitation `scapy.contrib.stp` documentée en Session 24 était une fausse piste — `scapy.layers.l2.STP` existe nativement, jamais cherché au bon endroit. "Flapping de port" au sens strict (état d'un port de commutateur) reste hors de portée par construction : non observable depuis une capture de trafic, cette information vit dans la table d'état du commutateur (SNMP/syslog), pas sur le fil — limite architecturale honnête, pas un chantier reporté |
| ~~Fragmentation IPv6~~ | **✅ Fait en Session 21** — voir section 2 `pcap_parser` et section 4 pour le détail complet (`is_fragment`/`ip_id` peuplés via l'en-tête d'extension Fragment RFC 8200). `r.frag_count` en profite pleinement (générique IPv4/IPv6) ; `r.frag_new`/`r.encap_frag_correlated` limités par construction à un datagramme déjà fragmenté aux deux points côté IPv6 (pas d'équivalent à `ip.id` sur un datagramme jamais fragmenté) — limite protocolaire assumée, pas un oubli. Décodage ICMPv6 (donc PMTUD IPv6) toujours hors périmètre, identifié comme piste distincte |
| ~~Décodage ICMPv6 (PMTUD IPv6 inclus)~~ | **✅ Fait en Session 22** — voir section 2 `pcap_parser`/`netcross_core.models` et section 4 pour le détail complet. Nouvelle couche `icmpv6` sélectionnée (miroir de `icmp`), `icmpv6_type`/`icmpv6_code` sur `RawPacket`/`Pkt` (champs séparés de `icmp_type`/`icmp_code`, espaces de valeurs non comparables). `_analyse_pmtud` étend la détection de noir PMTUD à IPv6 (sans bit DF, via ICMPv6 *Packet Too Big* type 2 — nouveau compteur `Report.icmpv6_too_big`) ; `r.pmtud_blackhole` reste un compteur unique générique IPv4/IPv6, messages généralisés dans `synthesis.py`/`report_text.py`/`baseline_diff.py`. Aucun changement nécessaire côté `charts.py`/`json_report.py`/GUI (déjà génériques sur `pk.proto`) |
| ~~Timeout inactivité / coupure NAT-FW silencieuse~~ | **✅ Fait en Session 23** — voir section 4 pour le détail complet (`_analyse_idle_timeout`, `Report.idle_timeout_dropped`/`idle_timeout_examples`). Détecte une connexion TCP établie des deux côtés, silence prolongé (60s) en amont, trafic repris jamais revu en aval. Regroupe par connexion (5-tuple) sur `all_packets`, pas par segment via `flows` — piège identifié et corrigé en session (voir section 4) |
| ~~Score de santé synthétique (0-100)~~ | **✅ Fait en Session 18** — voir section 4 pour le détail complet (`netcross_report.triage.health_score`/`health_label`). Câblé sur les deux CLI (console), la GUI GTK4, le JSON (`generate_json_report`/`generate_json_diff`) et le PDF (badge coloré, `generate_pdf`/`generate_diff_pdf`). Validé de bout en bout avec du vrai trafic (`tshark`/`editcap` disponibles cette session) |
| ~~Historique inter-sessions (SQLite)~~ | **✅ Fait en Session 29** — voir section 4 et `netcross_report.history`/CLIs pour le détail. `--history-db`/`--history-label`/`--history-show` sur les deux CLI, résumé compact par run (score, constats par sévérité), pas le détail (déjà couvert par `--json-report`/`--pdf-report`/`--detail-csv`) |
| ~~Anonymisation (`--redact`)~~ | **✅ Fait en Session 28** — voir section 4 et `netcross_core.redact`/CLIs pour le détail. Adresses IP (RFC 5737/3849)/MAC (OUI localement administré) uniquement, mapping partagé baseline/courant, refusé avec `--tls`/`--quic`/`--client-group` (pipelines indépendants, fuite sinon). Non câblé côté GUI GTK4 dans cette passe |
| ~~Fusion de captures segmentées~~ | **✅ Fait en Session 27** — voir section 4 et `netcross_core.parsing`/CLIs pour le détail. `--capture`/`--baseline`/`--current` acceptent désormais `NOM=chemin1,chemin2,...` (rotation tcpdump/tshark) |
| CAPWAP Fortinet | Peu couvert même par Wireshark en natif ; passerait par un post-dissecteur Lua côté tshark (le clean-room scapy-natif prévu à l'origine n'a plus lieu d'être) |
| Ingestion NetFlow/sFlow | Chantier plus large, architecture à part |
| Capture en continu + diff en direct | Le plus gros chantier des pistes d'origine, explicitement "à cadrer avant de coder" |
| Pistes GitHub (Zeek/Suricata/Spicy...) | Exploratoire, aucun engagement concret pris ; PcapPlusPlus/Spicy explicitement classés "à surveiller, pas à adopter" dès l'origine |
| ~~Validations admin — gain `--parallel`~~ | **✅ Mesuré en Session 31** — voir section 4 pour le détail complet. Sur cet environnement (1 seul cœur CPU) : aucun gain, léger surcoût (+4 à +10%), aggravé en cas de sur-souscription explicite. Diagnostic ajouté sur les deux CLI (workers effectifs/cœurs détectés, avertissement adapté). Gain réel sur un hôte multi-cœurs non vérifiable ici (architecture jugée saine mais non confirmée empiriquement) |
| Validations admin restantes (.rpm Rocky, FIXME/licence) | .rpm Rocky : nécessite une vraie Rocky Linux, indisponible ici (`rpmbuild` lui-même absent depuis la Session 30). FIXME/licence : placeholders nécessitant les vraies coordonnées du mainteneur, non renseignables sans inventer une fausse information — `LICENSE` elle-même est déjà complète, seuls `debian/control`/`changelog` et `netcross.spec` portent encore un FIXME |
| ~~CLI d'interrogation de l'historique sans capture~~ | **✅ Fait en Session 30** — voir section 4 et `cross_history_cli.py`/`netcross_report.history` pour le détail. `--db`/`--label`/`--run-type`/`--limit`, jamais de `--capture`/`--baseline`/`--current`. Packaging complet (wrapper `netcross-history`, `.deb` construit et vérifié réellement, `.spec` RPM à jour mais non rejoué — `rpmbuild` indisponible) |

---

## 6. Évolutions issues de la comparaison OmniPeek / Netcross / Wireshark

> **Note de fusion** : les sections 6 à 14 ci-dessous proviennent d'un document
> distinct, élaboré à partir de l'état des fonctionnalités de la session
> précédente (avant les sessions 12 à 20 décrites en section 2 ci-dessus,
> déjà intégrées et à jour dans ce document fusionné). Elles constituent une
> feuille de route prospective (comparaison avec OmniPeek/Wireshark, pistes
> non codées) et non un compte-rendu de code déjà livré. En particulier, la
> numérotation « Session 0 » à « Session 11 » utilisée en section 13.3
> ci-dessous désigne un **nouveau cycle de sessions proposé** pour ce chantier
> spécifique — à ne pas confondre avec les Sessions 1 à 20 déjà réalisées et
> décrites en section 2.

Cette section complète l'état du projet à partir de la comparaison fonctionnelle avec
OmniPeek et avec les capacités d'expertise et de statistiques exposées par Wireshark.
Elle ne propose pas de recopier l'interface ou les noms de fonctions de ces produits :
les fonctions ci-dessous sont décrites comme des capacités Netcross à construire.

Les éléments marqués **🟡 Partiel** existent déjà sous une autre forme dans Netcross
et doivent être étendus plutôt que recréés. Les éléments **🔴 Manquant** nécessitent
un nouveau composant. Les éléments **🟢 À forte valeur** sont à prioriser lorsqu'ils
peuvent réutiliser le moteur actuel.

### 6.1 Moteur d'événements d'expertise corrélés

**Statut : 🟡 Partiel — priorité très haute**

Netcross possède déjà des constats issus de règles sur pertes, saturation,
routage, QoS, fragmentation, VLAN, TCP, RTP/MOS, réseau/serveur, DHCP et SIP,
puis un triage par segment. Il manque une couche événementielle générique qui
transforme ces observations en objets d'expertise indépendants et corrélables.

#### Chemin pour y parvenir

```text
Report / métriques existantes
        ↓
Moteur de règles d'expertise
        ↓
ExpertEvent
        ├── catégorie
        ├── couche réseau
        ├── protocole
        ├── sévérité
        ├── confiance
        ├── première / dernière occurrence
        ├── points de capture concernés
        ├── flux concernés
        ├── paquets concernés
        ├── cause probable
        ├── impact
        └── action de vérification / remédiation
        ↓
Corrélation entre événements
        ↓
Triage global
```

Le modèle doit être distinct de `Finding` : un finding peut rester une formulation
finale de rapport alors que l'événement constitue une donnée analytique réutilisable
par le triage, la GUI, le JSON, le PDF, la comparaison baseline/courant et les
notifications futures.

#### Ce que cela apporte

- plusieurs symptômes peuvent être regroupés autour d'une même cause probable ;
- un même problème peut être visible sur plusieurs points sans créer quatre alarmes ;
- chaque constat peut remonter jusqu'aux paquets responsables ;
- les événements deviennent réutilisables dans les rapports et les dashboards ;
- possibilité d'afficher « pourquoi Netcross pense que c'est un problème » plutôt
  qu'un simple seuil dépassé ;
- base pour un futur score de confiance et un moteur de recommandation.

### 6.2 Bibliothèque de règles d'expertise réseau

**Statut : 🟡 Partiel — priorité très haute**

Le moteur actuel possède déjà de nombreuses règles spécialisées. La prochaine étape
est de les normaliser dans une bibliothèque déclarative et extensible.

#### Chemin pour y parvenir

```text
Rule
 ├── id stable
 ├── domaine
 ├── préconditions
 ├── métriques requises
 ├── fenêtre temporelle
 ├── seuils / percentiles
 ├── contexte requis
 ├── règle de corrélation
 ├── sévérité
 ├── confiance
 ├── explication
 └── pistes de vérification
```

Les premières règles à formaliser peuvent être celles déjà présentes : pertes par
segment, retransmissions TCP, fenêtres à zéro, RST, SYN sans réponse, variation de
TTL, remarking QoS, fragmentation, saturation, bufferbloat, RTP, DHCP et SIP.

Ensuite seulement viennent les règles nouvelles : DNS lent, PMTUD black hole,
NAT/FW silencieux, anomalies L2, options TCP incompatibles, négociations TLS
incomplètes, etc.

#### Ce que cela apporte

- couverture d'expertise extensible sans modifier le pipeline de corrélation ;
- tests unitaires indépendants par règle ;
- possibilité d'indiquer précisément la donnée qui a déclenché une conclusion ;
- possibilité de comparer deux versions du référentiel de règles ;
- préparation à une future distribution de règles internes par domaine métier.

### 6.3 Corrélation événement → flux → paquet

**Statut : 🔴 Manquant — priorité très haute**

Le moteur actuel produit des constats, mais il ne possède pas encore un mécanisme
universel permettant de partir d'un constat et de retrouver directement les flux
puis les paquets qui le justifient.

#### Chemin pour y parvenir

Ajouter dans le modèle d'événement des identifiants stables :

```text
ExpertEvent
  ↓
flow_ids[]
  ↓
packet_refs[]
  ↓
point / segment
  ↓
time_range
```

Puis construire une API de sélection liée utilisable depuis CLI, GUI, PDF et JSON.

#### Ce que cela apporte

Un analyste pourra passer de :

```text
« perte anormale sur le segment B-C »
```

à :

```text
segment B-C
  ↓
flux 10.10.10.20:443 → 10.20.20.30:53124
  ↓
paquets perdus / retransmis
  ↓
premier événement observé
```

C'est une capacité centrale pour transformer Netcross en outil d'investigation,
plutôt qu'en générateur de rapports.

### 6.4 Vue temporelle d'un flux

**Statut : 🔴 Manquant — priorité haute**

Netcross calcule déjà les données de débit, latence, retransmissions, réponse
serveur et RTP, mais il manque une vue unifiée d'un flux individuel.

#### Chemin pour y parvenir

Construire un objet `FlowView` alimenté par le modèle de corrélation existant :

```text
FlowView
 ├── identité client / serveur
 ├── durée
 ├── direction
 ├── paquets
 ├── payload disponible
 ├── timeline
 ├── latence
 ├── débit
 ├── TCP
 ├── événements
 ├── transactions
 └── liens vers les points de capture
```

La présentation doit permettre de passer du flux à ses paquets, puis d'un paquet
à son événement ou à la transaction correspondante.

#### Ce que cela apporte

- compréhension immédiate d'un échange particulier ;
- analyse des bursts, trous, retransmissions et temps morts ;
- lecture beaucoup plus rapide d'un problème TCP ;
- support naturel d'un futur diagramme de séquence ;
- point d'entrée commun aux analyses Web, VoIP et applicatives.

### 6.5 Diagramme de séquence multi-hôtes

**Statut : 🔴 Manquant — priorité haute**

Wireshark possède déjà une représentation des échanges entre hôtes, et tshark peut
également produire des statistiques de flux. Netcross peut aller plus loin grâce
à sa connaissance des points de capture.

#### Chemin pour y parvenir

```text
Flow / transaction
      ↓
ordre temporel
      ↓
regroupement par endpoint
      ↓
événements et paquets
      ↓
diagramme vertical / horizontal
```

Chaque ligne doit pouvoir être reliée à un paquet et à un point de capture.

#### Ce que cela apporte

Une lecture immédiate des séquences :

```text
Client       FW        Serveur
  |          |           |
  | SYN      |           |
  |---------->---------->|
  |          |           |
  |          |<----------|
  |<---------|           |
```

avec en plus les délais mesurés entre étapes et l'endroit où une anomalie apparaît.

### 6.6 Cartographie interactive des communications

**Statut : 🟡 Partiel — priorité haute**

Netcross déduit déjà une topologie multi-points. Il manque une vue exploratoire
centrée sur les relations entre nœuds et volumes de trafic.

#### Chemin pour y parvenir

Réutiliser `topology_edges`, les flows et les statistiques de volume pour construire
un graphe :

```text
Node
 ├── type
 ├── adresse(s)
 ├── volume
 ├── nombre de conversations
 └── événements

Edge
 ├── protocole
 ├── paquets
 ├── octets
 ├── direction
 ├── latence
 └── anomalies
```

Ajouter filtrage par protocole, direction, Top-N, fenêtre temporelle et gravité.

#### Ce que cela apporte

- identification immédiate des gros producteurs/consommateurs ;
- visualisation des chemins et branches ;
- localisation visuelle d'un segment dégradé ;
- exploration d'une capture sans connaître à l'avance les adresses à rechercher.

### 6.7 Visualisation du chemin multi-points

**Statut : 🟡 Partiel — priorité haute**

La déduction de topologie et les métriques par segment existent déjà. Il manque une
présentation dédiée du chemin observé avec les métriques attachées à chaque segment.

#### Chemin pour y parvenir

```text
points de capture
    ↓
topology_edges
    ↓
chemin(s) candidats
    ↓
agrégation par segment
    ↓
vue chemin + métriques
```

Pour chaque segment :

- délai min/moyenne/P95/P99 ;
- perte ;
- jitter ;
- débit ;
- DSCP/PCP ;
- fragmentation ;
- nombre de hops estimés ;
- événements associés.

#### Ce que cela apporte

Le rapport répond directement à :

> « Où exactement la qualité se dégrade-t-elle ? »

et pas seulement :

> « Quelle est la perte globale ? »

### 6.8 Exploration statistique interactive

**Statut : 🟡 Partiel — module core créé (Session 72), câblage GUI à faire**

Netcross possède déjà les données de flows, endpoints, topologie, débit, pertes,
latence et événements, ainsi que des graphiques PDF. Une couche générique
d'exploration statistique a été ajoutée (Session 72, Job 27).

**Implémenté (Session 72) :**
- Module `netcross_core/stats.py` : `compute_stats()` avec Top-N, tri multi-critères,
  regroupement par endpoint/protocole/segment/flux, filtres temporels et par segment
- Export CSV/JSON pour drill-down
- 20 tests unitaires

**Reste à faire :**
- Câblage GUI GTK4 (vue interactive, drill-down, sélection de critères)
- Intégration avec les vues existantes (conversations, flows, endpoints)

#### Chemin pour y parvenir

Construire une vue paramétrable avec :

- Top-N ;
- tri par paquets, octets, durée, débit, latence ou événements ;
- regroupement par endpoint, protocole, application ou segment ;
- filtres temporels ;
- drill-down vers les flows ;
- export CSV/JSON.

#### Ce que cela apporte

L'analyste peut partir d'une capture inconnue et découvrir rapidement :

```text
protocoles dominants
→ endpoints dominants
→ conversations dominantes
→ flux anormaux
→ événements associés
```

### 6.9 Analyse applicative et transactionnelle

**Statut : 🔴 Manquant — priorité haute**

Netcross possède déjà la séparation temps réseau / temps serveur. Cette brique peut
être transformée en modèle applicatif plus général.

#### Chemin pour y parvenir

```text
Flow
 ↓
protocole applicatif
 ↓
requête / réponse
 ↓
transaction
 ↓
temps réseau
 + temps serveur
 + temps total
 ↓
statistiques par application
```

Commencer par HTTP, DNS, SMB et éventuellement RPC, puis généraliser le modèle.

#### Ce que cela apporte

Distinction automatique entre :

- réseau lent ;
- serveur lent ;
- application lente ;
- absence de réponse ;
- pertes/retransmissions responsables de la dégradation.

Cette séparation est beaucoup plus utile opérationnellement qu'une simple moyenne
de latence TCP.

### 6.10 Analyse HTTP/HTTPS observable

**Statut : 🟡 Partiel pour HTTP / 🔴 pour HTTPS approfondi — priorité moyenne/haute**

Tshark fournit déjà une dissection HTTP riche, mais Netcross ne l'exploite pas encore
comme une couche d'analyse métier.

#### Chemin pour y parvenir

Exploiter les champs du dissecteur HTTP via `tshark` et compléter le modèle :

```text
request
 ├── méthode
 ├── URI
 ├── hôte
 └── timestamp
        ↓
response
 ├── code
 ├── longueur
 └── timestamp
        ↓
transaction
        ↓
serveur / client / page / objet
```

Ajouter les statistiques HTTP : codes, méthodes, temps de réponse, requêtes sans
réponse, erreurs, volume et séquences.

#### Ce que cela apporte

Une expertise orientée utilisateur :

```text
HTTP 500
→ serveur

HTTP 200 + temps serveur élevé
→ application

HTTP lent avant réception du premier octet
→ réseau ou serveur à corréler

requête sans réponse
→ perte / serveur / proxy à investiguer
```

Pour TLS, poursuivre le travail déjà prévu : réassemblage, handshake complet,
certificats et corrélation avec TCP. Ne pas réimplémenter un dissecteur TLS si
Wireshark/tshark fournit déjà les champs nécessaires.

### 6.11 Extraction et corrélation de contenus applicatifs

**Statut : 🔴 Manquant — priorité moyenne**

Une capture HTTP réassemblable peut contenir des fichiers ou objets transférés.
Netcross ne propose pas actuellement une couche permettant de les inventorier et
de les relier aux flux.

#### Chemin pour y parvenir

```text
HTTP reassembly
 ↓
objet
 ↓
Content-Type / taille / URI
 ↓
flow_id
 ↓
paquets
```

Ajouter un mécanisme de sauvegarde optionnelle du payload et un mode strictement
forensic avec contrôle de confidentialité.

#### Ce que cela apporte

- savoir quel objet est responsable d'un volume ou d'un délai ;
- relier un fichier à son serveur et à son flux ;
- faciliter les investigations applicatives ;
- permettre une analyse de contenu sans parcourir manuellement les paquets.

### 6.12 Analyse VoIP/vidéo orientée appel

**Statut : 🟡 Partiel — priorité moyenne**

Le moteur Netcross calcule déjà RTP, jitter, pertes, délai, MOS/R-factor et possède
une analyse SIP par Call-ID.

#### Chemin pour y parvenir

Fusionner SIP et RTP autour d'une entité `Call` :

```text
Call
 ├── signalisation
 ├── participants
 ├── établissement
 ├── durée
 ├── flux RTP
 ├── pertes
 ├── jitter
 ├── délai
 ├── MOS / R-factor
 └── événements
```

Puis créer une timeline signalisation + média et une vue de distribution de qualité.

#### Ce que cela apporte

Passage d'un diagnostic « RTP mauvais » à :

> « cet appel s'établit en 1,8 s, la qualité média se dégrade sur le segment X,
> avec 2,3 % de perte et un jitter P95 de 18 ms pendant 4,2 s ».

### 6.13 Recherche forensic post-capture

**Statut : 🔴 Manquant — priorité haute**

Les filtres BPF et la recherche tshark existent, mais Netcross ne possède pas encore
un moteur de recherche analytique post-capture transversal.

#### Chemin pour y parvenir

Construire une recherche basée sur les champs déjà décodés :

```text
Recherche
 ├── temps
 ├── point
 ├── endpoint
 ├── flow
 ├── protocole
 ├── champ tshark
 ├── événement
 └── texte/payload si disponible
```

La recherche doit retourner des paquets, flows et événements et permettre leur
sélection croisée.

#### Ce que cela apporte

- investigation rapide d'une capture inconnue ;
- recherche d'un SNI, URI, code HTTP, adresse, port, Call-ID, DNS name, etc. ;
- point d'entrée naturel vers les vues de flux et de séquence.

### 6.14 Sélection liée universelle

**Statut : 🔴 Manquant — priorité haute**

À partir de n'importe quel objet affiché, Netcross doit pouvoir retrouver les objets
liés :

```text
événement → flows → paquets
flow      → événements → paquets
endpoint  → flows → paquets
transaction → flow → paquets
segment   → flows → événements → paquets
```

#### Chemin pour y parvenir

Créer une couche d'index/corrélation indépendante de l'interface. La GUI, le CLI,
le PDF et le JSON ne doivent pas implémenter chacun leur propre logique de recherche.

#### Ce que cela apporte

C'est le mécanisme qui transforme les différents écrans en une seule expérience
d'analyse continue.

### 6.15 Table des noms et contexte réseau persistant

**Statut : 🔴 Manquant — priorité moyenne**

Ajouter une table locale de correspondance :

```text
adresse / MAC / endpoint
        ↓
nom logique
        ↓
type : client / serveur / routeur / firewall / AP
        ↓
commentaire / site / rôle
```

#### Chemin pour y parvenir

SQLite ou fichier YAML/JSON versionnable, avec résolution DNS optionnelle mais sans
dépendance obligatoire à la résolution inverse.

#### Ce que cela apporte

Les rapports passent de :

```text
10.24.12.31 → 10.24.80.10
```

à :

```text
PC-COMPTA-31 → APP-SQL-01
```

Ce contexte doit également être réutilisé par le triage et les graphiques.

### 6.16 Alarmes et surveillance de seuils

**Statut : 🟡 Partiel — priorité moyenne**

Le moteur de règles prévu en 6.2 doit pouvoir être utilisé en analyse live.

#### Chemin pour y parvenir

```text
capture live
 ↓
fenêtre glissante
 ↓
métriques
 ↓
règles
 ↓
événements
 ↓
seuil / hystérésis / durée minimale
 ↓
notification
```

Ne pas déclencher une alarme sur une valeur ponctuelle isolée : chaque règle doit
pouvoir définir une fenêtre, un échantillon minimal et éventuellement une durée de
persistance.

#### Avancement (Session 70)

Le module `src/netcross_core/alarms.py` implémente les briques « fenêtre
glissante → hystérésis → durée minimale de persistance → notification » :
`AlarmEngine` consomme des `AlarmSignal` (convertibles depuis les `Finding` du
moteur de règles), applique hystérésis `trigger`/`clear`, ratio minimal
d'échantillons positifs et durée minimale de persistance avant de lever un
`AlarmEvent`. 12 tests couvrent le critère d'acceptation (signal isolé ne
déclenche pas). Le cablage au moteur de règles (`rule_engine.evaluate()` →
`AlarmSignal`) et à la capture live reste à faire — c'est le périmètre de
l'issue #33 (diff en direct).

#### Ce que cela apporte

Netcross peut évoluer du forensic post-capture vers la supervision légère d'un
chemin réseau ou d'un service.

### 6.17 Dashboards analytiques interactifs

**Statut : 🟡 Partiel — priorité haute**

Le PDF possède déjà synthèse, triage et graphiques. La GUI possède trois pages,
mais pas encore de tableau de bord d'exploration comparable à un cockpit d'analyse.

#### Chemin pour y parvenir

Construire des widgets alimentés par les mêmes objets que le rapport :

```text
Timeline
 ├── débit
 ├── latence
 ├── perte
 ├── événements
 └── sélection temporelle

Widgets
 ├── segments
 ├── flows
 ├── endpoints
 ├── protocoles
 ├── applications
 └── événements
```

Toutes les sélections doivent modifier le même contexte d'analyse et déclencher les
sélections liées décrites en 6.14.

#### Ce que cela apporte

- analyse interactive sans régénérer un PDF ;
- passage immédiat d'une anomalie globale à sa période ;
- filtrage par gravité ;
- exploration d'une capture inconnue ;
- future base pour un mode NOC/SOC.

### 6.18 Générateur de graphes générique

**Statut : 🟡 Partiel — priorité moyenne**

Netcross dispose actuellement de graphiques spécialisés. Il manque un moteur capable
de représenter n'importe quelle série issue du modèle analytique.

#### Chemin pour y parvenir

Créer une API commune :

```text
MetricSeries
 ├── nom
 ├── unité
 ├── timestamp
 ├── valeurs
 ├── source
 └── contexte
```

Puis une couche de rendu capable de produire ligne, aire, barres, distribution,
histogramme et scatter, avec seuils de référence et zones de conformité.

#### Ce que cela apporte

Les nouveaux modules d'analyse n'auront plus besoin de créer leur propre système
de graphique.

### 6.19 Analyse des statistiques Wireshark/tshark réutilisables

**Statut : 🟡 Partiel — priorité haute car coût relativement faible**

Wireshark dispose déjà d'un ensemble important de statistiques : hiérarchie des
protocoles, conversations, endpoints, longueurs de paquets, graphes I/O, temps de
réponse, DNS, HTTP, flux et statistiques spécifiques à de nombreux protocoles.

Le CLI tshark expose également des statistiques par protocole et des statistiques
I/O temporelles avec filtres et agrégations.

#### Chemin pour y parvenir

Ne pas réimplémenter ces calculs lorsqu'ils sont déjà fiables dans tshark :

```text
Netcross
   ↓
wrapper statistiques tshark
   ↓
normalisation
   ↓
MetricSeries / ExpertEvent / Transaction
   ↓
triage + GUI + PDF + JSON
```

Exemples de statistiques immédiatement exploitables :

- conversations ;
- endpoints ;
- hiérarchie protocolaire ;
- I/O par intervalle ;
- HTTP ;
- DNS ;
- temps de réponse applicatif ;
- graphes de flux ;
- statistiques TCP/UDP ;
- statistiques spécifiques aux protocoles déjà supportés par tshark.

#### Ce que cela apporte

Une couverture analytique très supérieure sans multiplier le code de décodage
Netcross.

---

## 7. Potentiel spécifique de l'expertise Wireshark à exploiter

Wireshark possède un mécanisme d'informations d'expertise produit directement par
les dissecteurs. Chaque information possède notamment une sévérité, un résumé,
un groupe et un protocole ; les groupes couvrent entre autres checksum, déchiffrement,
paquet malformé, violation de protocole et réassemblage. Wireshark précise toutefois
que la présence d'une information d'expertise ne signifie pas nécessairement qu'il
y a un problème, et que son absence ne prouve pas que tout va bien.

Cette nuance doit être conservée dans Netcross : les informations de tshark/Wireshark
sont des **signaux**, pas des diagnostics définitifs.

### 7.1 Importer les signaux d'expertise de tshark

**Statut : 🔴 Manquant — priorité très haute**

Tshark permet déjà d'extraire les informations d'expertise par sévérité et protocole.
Il expose également de nombreuses statistiques indépendantes du flux de sortie
normal.

#### Chemin pour y parvenir

Créer un adaptateur dédié :

```text
pcap
 ↓
tshark
 ├── décodage EK actuel
 └── statistiques / expert information
        ↓
WiresharkSignal
        ↓
normalisation Netcross
        ↓
ExpertEvent
```

Le signal doit conserver :

- numéro de paquet / identifiant ;
- protocole ;
- sévérité ;
- groupe ;
- résumé ;
- champs utiles ;
- filtre ou expression permettant de retrouver le paquet.

#### Ce que cela apporte

Netcross récupère immédiatement une partie importante du travail d'expertise déjà
présent dans les dissectors Wireshark : erreurs de réassemblage, anomalies de
protocole, checksums, problèmes de séquence, paquets malformés, alertes applicatives,
et autres signaux propres aux protocoles.

### 7.2 Fusionner expertise Wireshark et expertise Netcross

**Statut : 🔴 Manquant — priorité très haute**

Il ne faut surtout pas additionner naïvement les deux listes.

Exemple :

```text
Wireshark : TCP out-of-order
Wireshark : TCP retransmission
Netcross  : perte segment B-C
Netcross  : RTT P99 élevé
Netcross  : bufferbloat probable
```

Ces cinq observations peuvent correspondre à **un seul incident**.

#### Chemin pour y parvenir

```text
Signaux tshark
       +
Règles Netcross
       +
Référentiel de conformité
       ↓
Corrélateur causal
       ↓
Incident / ExpertEvent racine
       ├── preuves
       ├── symptômes
       ├── impact
       ├── confiance
       └── recommandations
```

#### Ce que cela apporte

C'est probablement la meilleure utilisation combinée de Wireshark et Netcross :
Wireshark fournit la profondeur protocolaire, Netcross apporte la corrélation
multi-points et la localisation du problème sur le chemin.

### 7.3 Exploiter les statistiques tshark sans dépendre de l'interface Wireshark

**Statut : 🟡 Partiel — priorité haute**

Le CLI tshark permet déjà de calculer notamment conversations, endpoints, hiérarchie
protocolaire, I/O temporel, HTTP, DNS, temps de réponse, flux et statistiques
spécifiques aux protocoles.

#### Chemin pour y parvenir

Créer des adaptateurs ciblés plutôt qu'un wrapper universel opaque :

```text
netcross_core/tshark_stats/
 ├── conversations
 ├── endpoints
 ├── io
 ├── response_time
 ├── http
 ├── dns
 └── protocol_specific
```

Chaque adaptateur convertit le résultat vers un modèle Netcross commun.

#### Ce que cela apporte

- forte extension fonctionnelle avec peu de code ;
- cohérence avec les dissectors déjà utilisés ;
- réduction du code spécifique protocole ;
- possibilité d'exposer les mêmes données en GUI, PDF, JSON et CLI.

### 7.4 Exploiter les indicateurs TCP déjà calculés par Wireshark

**Statut : 🟡 Partiel — priorité haute**

Netcross détecte déjà plusieurs anomalies TCP. Il peut compléter cette analyse en
s'appuyant sur les indicateurs de séquence, retransmission, ordre, ACK et autres
champs d'analyse exposés par tshark.

#### Chemin pour y parvenir

```text
champs tcp.analysis.*
        ↓
classification
 ├── retransmission
 ├── fast retransmission
 ├── out-of-order
 ├── duplicate ACK
 ├── lost segment
 ├── zero window
 ├── window update
 └── autres signaux disponibles
        ↓
corrélation multi-points Netcross
```

#### Ce que cela apporte

Meilleure distinction entre :

- perte réelle sur le réseau ;
- réordonnancement ;
- retransmission rapide ;
- expiration de temporisation ;
- comportement du récepteur ;
- problème localisé à un seul segment.

### 7.5 Exploiter les graphes de flux et statistiques de réponse

**Statut : 🟡 Partiel — priorité moyenne**

Wireshark possède déjà des graphes de flux et des statistiques de temps de réponse.
Netcross doit les utiliser comme source de données, puis ajouter son contexte
multi-points.

#### Ce que cela apporte

Une combinaison :

```text
statistique protocolaire Wireshark
             +
position dans le chemin Netcross
             +
latence/perte par segment
             ↓
diagnostic localisé
```

---

## 8. Comparaison à des valeurs théoriques, recommandées et observées

**Statut : 🔴 Manquant — priorité très haute**

L'étape suivante de l'expertise Netcross ne doit pas consister uniquement à ajouter
des seuils fixes. Il faut distinguer plusieurs sources de référence.

### 8.1 Les quatre niveaux de référence

```text
                    Référence
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
     normative      recommandée     observée
        │              │              │
        │              │          baseline
        │              │          historique
        └──────────────┴──────────────┘
                       │
                       ▼
                  SLO / SLA
                       │
                       ▼
                moteur conformité
```

#### Référence normative

Valeur ou comportement imposé/recommandé par un protocole ou une méthode
standardisée. Exemple : paramètres et comportement TCP définis dans les RFC.

#### Référence recommandée

Valeur de bonne pratique issue d'un guide technique, d'un standard de déploiement
ou d'une méthodologie reconnue.

#### Référence observée

Valeur mesurée sur une période saine ou sur une capture de référence du même
service, chemin ou environnement.

#### SLO / SLA

Objectif explicitement défini pour le service ou le réseau. C'est la référence la
plus importante lorsqu'elle existe.

### 8.2 Référentiels déjà exploitables

#### TCP et performance réseau

Le RFC 6349 fournit une méthodologie de mesure du débit TCP basée notamment sur la
bande passante du goulot, RTT, buffers, fenêtre TCP, MTU et pertes. Il définit aussi
des métriques comme le ratio de temps de transfert, l'efficacité TCP et le délai de
bufferisation.

Cela peut donner à Netcross un calcul de :

```text
Débit théorique / attendu
        ↓
Débit réellement observé
        ↓
écart
        ↓
recherche de cause
```

Le RFC 6349 fournit également des indications de contexte : une perte ou un jitter
trop élevés peuvent rendre une mesure de débit TCP non représentative ; ces valeurs
ne doivent donc pas être transformées en seuils universels pour tous les réseaux.
citeturn0search2

### 8.3 SLO et métriques de performance

Le RFC 9544 fournit un cadre IETF pour exprimer des objectifs de niveau de service et
les comparer à des mesures observées. Il constitue une bonne base conceptuelle pour
le moteur de conformité Netcross plutôt qu'une table arbitraire de seuils.

#### Chemin pour y parvenir

Créer un modèle :

```text
ReferenceProfile
 ├── id
 ├── source
 ├── version
 ├── contexte
 ├── métrique
 ├── unité
 ├── statistique (mean/p95/p99/max...)
 ├── opérateur
 ├── valeur
 ├── tolérance
 └── justification
```

Puis :

```text
trace
 ↓
métriques Netcross
 ↓
référence applicable
 ↓
conformité
 ↓
écart
 ↓
ExpertEvent
```

### 8.4 Ne pas confondre norme et seuil de performance

**Règle de conception importante :** un RFC qui définit un protocole ne fournit pas
nécessairement un seuil de performance.

Par exemple, un protocole peut imposer une séquence ou une temporisation sans dire
qu'une latence réseau de 30 ms est « bonne » ou « mauvaise ».

Netcross doit donc conserver la provenance :

```text
observed value
reference value
reference type
reference source
reference version
confidence
```

et afficher :

```text
Conforme
Déviation
Non conforme
Non évaluable
```

plutôt qu'un simple « OK / KO ».

### 8.5 Baseline comme référence dynamique

**Statut : 🟡 Partiel — priorité très haute**

Netcross possède déjà une comparaison baseline/courant et une comparaison client vs
client dans l'évolution récente du projet. Ces mécanismes doivent devenir une source
de référence générale plutôt qu'un simple diff de rapports. 

#### Chemin pour y parvenir

```text
captures saines
       ↓
agrégation historique
       ↓
distribution de référence
 ├── médiane
 ├── P50
 ├── P95
 ├── P99
 ├── variance
 └── saisonnalité éventuelle
       ↓
BaselineProfile
       ↓
comparaison nouvelle trace
```

#### Ce que cela apporte

Une valeur de 25 ms peut être normale sur un WAN et anormale sur un chemin qui
présente historiquement 4 ms. La baseline locale permet donc de détecter des
régressions que des seuils universels ne verront jamais.

### 8.6 Comparaison théorique + baseline + SLO

La meilleure sortie finale n'est pas une valeur unique :

```text
                         OBSERVÉ
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
          théorie       baseline        SLO/SLA
              │             │             │
              └─────────────┼─────────────┘
                            ▼
                     moteur de décision
                            │
                ┌───────────┼───────────┐
                ▼           ▼           ▼
             conforme    déviation    non conforme
                            │
                            ▼
                       expertise
```

#### Ce que cela apporte

Netcross peut expliquer simultanément :

> « La latence respecte le SLO client, mais elle est 3,2 fois supérieure à la
> baseline historique et dégrade l'efficacité TCP. La cause probable est localisée
> au segment B-C. »

C'est beaucoup plus pertinent qu'un seuil générique.

---

## 9. Priorisation consolidée des évolutions

| Priorité | Évolution | État actuel | Gain attendu | Chemin principal |
|---|---|---|---|---|
| ⚠️ Très haute | Modèle d'événement d'expertise | 🟡 Partiel | Très fort | `Report` → `ExpertEvent` → corrélation |
| ⚠️ Très haute | Bibliothèque de règles | 🟡 Partiel | Très fort | règles actuelles → moteur déclaratif |
| ⚠️ Très haute | Corrélation événement/flow/paquet | 🔴 Manquant | Très fort | index analytique |
| ⚠️ Très haute | Signaux d'expertise tshark | 🔴 Manquant | Très fort | adaptateur `-z expert` / champs expert |
| ⚠️ Très haute | Fusion Wireshark + Netcross | 🔴 Manquant | Très fort | corrélateur causal |
| ⚠️ Très haute | Référentiels + SLO + baseline | 🔴/🟡 | Très fort | `ReferenceProfile` + moteur conformité |
| 🟠 Haute | Vue temporelle d'un flux | 🔴 Manquant | Très fort | `FlowView` |
| 🟠 Haute | Sélection liée universelle | 🔴 Manquant | Très fort | index flow/event/packet |
| 🟠 Haute | Dashboard interactif | 🟡 Partiel | Fort | widgets + contexte partagé |
| 🟠 Haute | Analyse applicative | 🔴 Manquant | Fort | transactions |
| 🟠 Haute | Vue chemin multi-points | 🟡 Partiel | Fort | topologie + métriques segment |
| 🟠 Haute | Cartographie des communications | 🟡 Partiel | Fort | flows + topology |
| 🟠 Haute | Statistiques tshark | 🟡 Partiel | Fort | wrappers `tshark -z` |
| 🟠 Haute | TCP enrichi | 🟡 Partiel | Fort | `tcp.analysis.*` + corrélation |
| 🟡 Moyenne | HTTP transactionnel | 🟡 Partiel | Fort | champs HTTP tshark |
| 🟡 Moyenne | VoIP orientée appel | 🟡 Partiel | Fort | SIP + RTP → Call |
| 🟡 Moyenne | Forensic search | 🔴 Manquant | Fort | index champs/flows/events |
| 🟡 Moyenne | Table des noms | 🔴 Manquant | Moyen | SQLite/YAML |
| 🟡 Moyenne | Alarmes live | 🔴 Manquant | Fort | règles + fenêtres glissantes |
| 🟡 Moyenne | Générateur de graphes générique | 🟡 Partiel | Moyen | `MetricSeries` |
| 🟢 Faible | Extraction de contenus | 🔴 Manquant | Spécialisé | réassemblage HTTP |

---

## 10. Principes d'architecture à conserver

1. **tshark reste le moteur de dissection**, afin d'éviter de réimplémenter les
   protocoles déjà correctement couverts par Wireshark.
2. **Netcross reste le moteur de corrélation multi-points** : c'est sa valeur
   différentiante et ne doit pas être remplacée par une simple agrégation tshark.
3. Les signaux Wireshark sont des **preuves**, pas des verdicts.
4. Les règles Netcross doivent produire des événements structurés, testables et
   traçables.
5. Toute expertise doit pouvoir répondre à : **quelle donnée, quel paquet, quel
   segment, quelle règle et quelle référence ont conduit à cette conclusion ?**
6. Les seuils doivent conserver leur **provenance** et leur contexte.
7. Une valeur hors plage ne doit pas automatiquement devenir une anomalie : tenir
   compte du volume d'échantillons, de la qualité de la capture, de la couverture,
   du protocole et du contexte.
8. La présentation doit toujours permettre de redescendre du verdict vers la preuve.
9. Les mêmes objets analytiques doivent alimenter CLI, GUI, PDF, JSON et, à terme,
   les notifications.
10. Le moteur de conformité doit distinguer **norme**, **bonne pratique**, **baseline
    historique** et **SLO/SLA**.

---

## 11. Sources techniques de référence utilisées pour cette comparaison

- Documentation officielle OmniPeek / LiveAction : expertise par flux, événements,
  analyse applicative, vues statistiques, analyse multi-segments, visualisation des
  communications, tableaux de bord et modules d'analyse.
- Documentation officielle Wireshark : informations d'expertise, sévérité et groupes,
  statistiques, conversations, endpoints, graphes I/O, temps de réponse et graphe de
  flux.
- Documentation officielle TShark : statistiques `-z`, informations d'expertise,
  conversations, endpoints, I/O temporel, HTTP, DNS, temps de réponse et flux.
 
- RFC 6349 : méthodologie de mesure du débit TCP, BDP, RTT, efficacité TCP, délai de
  bufferisation, MTU et interprétation des performances.
- RFC 9544 : cadre de référence IETF pour les objectifs et mesures de niveau de
  service (à exploiter comme modèle de conformité, pas comme catalogue universel de
  seuils).

---

## 12. Note de méthode sur les référentiels

Aucune base unique ne doit être considérée comme « la vérité » pour tous les réseaux.
Les seuils de latence, jitter, perte ou débit dépendent du type de réseau, de la
distance, du service, du protocole, du contrat et de l'architecture.

La base Netcross doit donc être **versionnée, sourcée et contextualisée**.

Une règle de référence devrait toujours pouvoir répondre à :

```text
Qui a défini cette valeur ?
Quelle version du document ?
Pour quel environnement ?
Pour quelle métrique ?
Quelle méthode de mesure ?
Quelle population d'échantillons ?
Quelle confiance ?
```

La cible est ainsi un moteur capable de produire non seulement :

```text
Latence P95 = 18,4 ms
```

mais :

```text
Latence P95 = 18,4 ms
SLO          = 20 ms        → conforme
Baseline P95 = 7,2 ms       → déviation importante
Référence    = RFC / profil → contexte applicable
Confiance    = élevée
Cause        = segment B-C
Preuves      = flows + paquets + événements tshark
```

C'est cette dernière forme qui doit devenir la référence de l'expertise Netcross.

---

## 13. Estimation de couverture et trajectoire de réalisation

Cette section ne constitue pas une promesse de planning. Elle sert à mesurer la
masse de travail restante et à organiser le développement sans confondre les
fonctionnalités déjà présentes avec les fonctionnalités d'exploitation avancée.

### 13.1 Estimation de couverture fonctionnelle

L'estimation ne doit pas être faite en comptant les lignes du document : certaines
entrées décrivent une capacité déjà opérationnelle, d'autres une architecture cible
ou une capacité composite.

Au regard des briques déjà présentes dans Netcross, une estimation raisonnable est :

```text
Socle fonctionnel actuel                         ≈ 45–55 %
Projet cible complet raisonnable                  100 %
```

Cette proportion doit être interprétée avec prudence : les fonctionnalités déjà
réalisées comprennent plusieurs briques techniquement difficiles (décodage,
corrélation multi-points, topologie, analyse par segment, TCP, QoS, RTP/SIP,
TLS/QUIC, baseline/diff et triage). Le travail restant porte donc largement sur
l'industrialisation de l'expertise, la corrélation causale, les référentiels et
l'exploitation interactive des résultats.

L'objectif n'est pas de reproduire OmniPeek fonctionnalité par fonctionnalité.
L'objectif est de reprendre les concepts utiles et de les intégrer au modèle
multi-points de Netcross, tout en exploitant Wireshark/TShark pour éviter de
réimplémenter inutilement les dissections et analyses protocolaires existantes.

### 13.2 Chantiers et difficulté

| Chantier | Couverture initiale indicative | Difficulté | Ordre de grandeur |
|---|---:|---:|---:|
| Contrats analytiques communs | à créer | 3/5 | 1 session |
| Ingestion expertise Wireshark/TShark | partielle | 3/5 | 1 session |
| Moteur Expert Event | faible | 5/5 | 1–2 sessions |
| Corrélation causale | faible | 5/5 | 1–2 sessions |
| Modèle Flow enrichi | partiel | 4/5 | 1 session |
| Timeline / visualisation de flow | faible | 4/5 | 1 session |
| Flow Map / Ladder / chemin multi-points | faible | 4/5 | 1 session |
| Référentiels techniques | faible | 3/5 | 1 session |
| SLO / baseline / conformité | faible | 3/5 | 1 session |
| Forensic Search | faible | 3/5 | 1 session |
| Sélection liée preuve → flow → paquet | faible | 2/5 | 1 session |
| Dashboard interactif | faible | 4/5 | 1–2 sessions |
| Statistiques interactives | faible | 2/5 | 1 session |
| Analyse transactionnelle | faible | 5/5 | 1–2 sessions |
| Analyse Web / applicative | faible | 5/5 | 1–2 sessions |
| Analyse expérience utilisateur | faible | 4/5 | 1 session |
| Alarmes / triggers / notifications | absente | 2/5 | 1 session |

En pratique, le chantier complet représente environ **15–22 sessions de travail
bien cadrées** si les interfaces sont stabilisées avant la parallélisation. Une
réalisation strictement séquentielle pourrait dépasser cette estimation.

### 13.3 Découpage recommandé des sessions

#### Session 0 — contrats et architecture d'intégration

**Difficulté : 3/5 — priorité maximale**

Avant de lancer plusieurs branches, stabiliser les objets communs :

```text
PacketEvidence
Flow
Conversation
ExpertEvent
Finding
Diagnosis
Reference
ComplianceResult
EvidenceLink
```

Ces objets doivent être indépendants de la GUI et suffisamment génériques pour
alimenter le CLI, JSON, PDF et les futures vues interactives.

La règle essentielle est que les branches spécialisées ne redéfinissent pas leur
propre représentation des mêmes concepts.

**État (Session 32, étendu Sessions 33, 35, 36 et 37)** : les NEUF objets de
contrat existent désormais tous dans `netcross_core/expert_model.py` (+
`netcross_core/correlate.py`/`compliance.py` pour leurs constructeurs) :
`EvidenceLink` posé et câblé de bout en bout sur `Finding` (Session 32)
puis étendu à `DiffFinding` (Session 33) ; `PacketEvidence` (Session 35),
débloqué par `frame.number`, câblé en pilote sur la seule catégorie
PMTUD puis **étendu aux 8 autres catégories déjà porteuses d'un
`EvidenceLink` textuel, sur `Finding` ET `DiffFinding` (Session 37)** —
les 9 catégories (PMTUD, NAT/Pare-feu, ARP, STP, TLS x2, MSS, DNS, HTTP)
portent désormais un numéro de trame quand disponible ; `Flow`/
`Conversation` (Session 36), restructuration pure du dict
`flows` déjà produit par `correlate()` ; `ExpertEvent`/`Diagnosis`
(Session 36), vue générique d'un `Finding`/`DiffFinding` déjà construit
(`cause`/`impact` toujours `None`, moteur de causalité — Session 3 —
absent) ; `ReferenceProfile`/`ComplianceResult` (Session 36), évaluateur
minimal (2 métriques, statuts CONFORME/VIOLATION/INDETERMINE — la nuance
DEVIATION reste la matière de la Session 7 dédiée) ; `Finding` gagne un
champ `event` ("Finding enrichi"). Câblés dans `--json-report` des
**deux** CLI (Session 36 pour l'analyzer, Session 37 pour le diff CLI —
nouvelles clés JSON `flows`/`conversations`/`expert_events`/`diagnoses`/
`compliance`, toujours côté rapport courant pour le diff) — voir
section 4 pour le détail complet. Important : "stabiliser les objets
communs" (ce que vise la Session 0) n'est PAS "construire le moteur
d'expertise complet" — les Sessions 1 à 11 ci-dessous restent
entièrement à faire ; plusieurs champs des objets Session 36 restent
volontairement vides (`cause`/`impact`/nuance `DEVIATION`) tant que ces
sessions n'existent pas, documenté explicitement objet par objet dans
`expert_model.py`.

#### Session 1 — exploitation de l'expertise Wireshark/TShark

**Difficulté : 3/5**

Extraire les informations d'expertise et d'analyse déjà disponibles dans Wireshark
et TShark, notamment les événements protocolaires, sévérités, groupes, références de
paquets, analyses TCP et statistiques pertinentes.

Le résultat attendu est une conversion vers les objets Netcross, par exemple :

```text
Wireshark/TShark
       ↓
ExpertEvent brut
       ↓
normalisation Netcross
       ↓
preuve + paquet + protocole + contexte
```

Il ne faut pas considérer les signaux Wireshark comme des diagnostics définitifs.
Ils constituent des preuves supplémentaires pour le moteur Netcross.

**État (Session 39, clôture)** : les deux points laissés ouverts par le
premier lot (Session 38) sont traités — voir section 4 pour le détail
complet (bug trouvé/corrigé, décisions de conception, validation).
`expert_flag_names()`/nouvelle `expert_flag_details()` (`pcap_parser.
ek_fields`) couvrent désormais toutes les couches d'un paquet (L3
`ip4`/`ip6`/`arp`/`stp` + L4 `tcp`/`udp`/`icmp`/`icmpv6`, plus
seulement TCP) et exposent la sévérité/le groupe/le message NATIFS
tshark (`RawPacket.expert_details`/`Pkt.expert_details`), vérifiés
empiriquement avec un vrai tshark 4.2.2 (tables `_SEVERITY_LABELS`/
`_GROUP_LABELS` générées depuis `tshark -G values`, pas devinées).
`build_wireshark_expert_events()` utilise cette sévérité native en
priorité sur la table `_KNOWN_FLAGS` (repli si absente) et enrichit
`evidence`/`message` avec message/groupe natifs. La Session 1 du
découpage recommandé est désormais complète, modulo Console/PDF/GUI
(voir ci-dessous, question architecturale distincte).

**Volontairement non traité** (question architecturale distincte des
deux points ci-dessus, partagée avec la Session 0 — voir section 4 de
la Session 39 pour le détail) :
- Console/PDF : même convention que les cinq objets de la Session 0
  (`flows`/`conversations`/`expert_events`/`diagnoses`/`compliance`),
  qui n'ont jamais été câblés ailleurs que `--json-report` non plus —
  cohérent, pas une régression de périmètre propre à cette session.
- Export JSON de la GUI (`netcross_gtk4/app.py`,
  `_generate_json_thread`) : n'expose déjà aucun des cinq objets de la
  Session 0, et n'expose pas non plus `wireshark_expert_events` —
  lacune préexistante, pas introduite ici.

#### Session 2 — moteur d'événements d'expertise

**Difficulté : 5/5**

Construire le moteur qui transforme les observations élémentaires en événements
structurés : catégorie, sévérité, confiance, contexte, preuve, flow, segment et
paquets concernés.

**État (Session 40, premier lot)** : `ExpertEvent` (`netcross_core.
expert_model`) gagne `confidence`/`first_seen`/`last_seen` — deux des
onze champs du schéma cible de la section 6.1 (confiance,
première/dernière occurrence). Calculés uniquement pour les événements
de source `"tshark"` (`netcross_core.wireshark_expert.
build_wireshark_expert_events`, sur des données déjà disponibles :
sévérité native/table `_KNOWN_FLAGS` pour la confiance, `Pkt.ts` pour
les occurrences) ; toujours `None` pour les événements de source
`"netcross"` (`Finding` ne porte aujourd'hui aucune de ces deux
données — voir section 4 pour le détail complet). Reste entièrement à
faire : couche réseau/protocole explicites, flux/paquets concernés
comme listes structurées (pas seulement `evidence`), cause probable/
impact (Session 3), action de vérification/remédiation, et la
bibliothèque de règles déclarative au sens strict décrite en 6.2
(préconditions, fenêtre temporelle, corrélation).

**État (Session 41, deuxième lot)** : `ExpertEvent` gagne `layer`/
`protocol` — deux champs de plus du schéma cible (couche réseau,
protocole). Calculés uniquement pour les événements de source
`"tshark"`, lus directement (pas déduits) depuis le préfixe du nom de
flag EK brut (`netcross_core.wireshark_expert._layer_and_protocol_for`,
voir section 4 pour le détail complet) ; toujours `None` côté
`"netcross"` — `Finding.category` étant un regroupement métier sans
correspondance protocole/couche unique fiable pour plusieurs catégories
(`"Pertes"`, `"Saturation"`...), documenté explicitement comme une
limite assumée plutôt qu'une lacune à combler par une supposition.
Reste entièrement à faire : flux concernés, points/paquets concernés
comme listes structurées (pas seulement `evidence`), cause probable/
impact (Session 3), action de vérification/remédiation, et la
bibliothèque de règles déclarative au sens strict décrite en 6.2.

**État (Session 43, troisième lot)** : `ExpertEvent` gagne `flow_keys`
— premier des deux points restants listés en tête de `CLAUDE.md`
(« flux concernés »). Liste de clés au sens exact de
`netcross_core.correlate.flow_key()` (`(proto, src, sport, dst, dport,
key_id)` en mode strict), pas une nouvelle notion d'identité de flux :
un consommateur retrouve directement le `Flow` correspondant en
comparant `Flow.key` à un élément de cette liste. Calculée uniquement
pour les événements de source `"tshark"`
(`netcross_core.wireshark_expert.build_wireshark_expert_events`), sur
la totalité des occurrences d'un (point, flag) — pas seulement les
exemples plafonnés conservés dans `evidence`, même discipline que
`first_seen`/`last_seen` (Session 40) — dédoublonnée dans l'ordre de
première rencontre (jamais triée : `key_id`/`sport`/`dport` mélangent
`int` et `None` selon le protocole, un tri naïf lèverait `TypeError`).
Toujours `[]` côté `"netcross"` : `Finding`/`EvidenceLink` ne portent
qu'un numéro de trame optionnel, sans les autres champs du 5-tuple
nécessaires pour reconstruire un `flow_key()` exact — même discipline
que `confidence`/`layer`/`protocol` ci-dessus. Câblé dans
`_expert_event_dict` (`netcross_report.json_report`, tuples convertis
en listes pour rester sérialisables JSON, même convention que
`Conversation.flow_keys`) — donc exposé dans `--json-report` des deux
CLI comme les autres champs de cette série. Reste entièrement à faire :
points/paquets concernés comme listes structurées (au-delà des exemples
plafonnés), cause probable/impact (Session 3), action de vérification/
remédiation, et la bibliothèque de règles déclarative au sens strict
décrite en 6.2.

**État (Session 44, quatrième lot)** : `ExpertEvent` gagne
`packet_evidence: list[PacketEvidence]` — second des deux points
restants listés en tête de `CLAUDE.md` (« points/paquets concernés »).
Réutilise l'objet `PacketEvidence` déjà introduit en Session 35 (via
`EvidenceLink.packet`), mais couvrant ici la TOTALITÉ des occurrences
d'un (point, flag) — pas seulement les `_MAX_EXAMPLES` (5) exemples
plafonnés déjà portés par `evidence`. Calculé uniquement côté
`"tshark"`, toujours `[]` côté `"netcross"` (même discipline que
`flow_keys` : `Finding`/`EvidenceLink` ne portent un `PacketEvidence`
que pour la seule catégorie PMTUD, et seulement pour les exemples
plafonnés — voir section 4 pour le détail complet). Reste entièrement à
faire : action de vérification/remédiation, cause probable/impact
(Session 3), et la bibliothèque de règles déclarative au sens strict
décrite en 6.2.

**État (Session 45, cinquième et dernier lot)** : `ExpertEvent` gagne
`remediation: str | None` — dernier des onze champs du schéma cible de
la section 6.1 accessible sans le moteur de corrélation causale de la
Session 3 (« action de vérification/remédiation »). Contrairement à
tous les champs des lots précédents (tous LUS depuis une donnée déjà
disponible), `remediation` est un texte RÉDIGÉ par ce projet — voir
`netcross_core.wireshark_expert._REMEDIATION` — volontairement
restreint aux onze flags déjà répertoriés dans `_KNOWN_FLAGS` : `None`
pour tout flag absent de cette table plutôt qu'un conseil générique
inventé, et toujours `None` côté `"netcross"` (généraliser
supposerait une bibliothèque par catégorie de `Finding`, un chantier
distinct non cadré ici — voir section 4 pour le détail complet). Avec
ce lot, la Session 2 ne laisse plus que la bibliothèque de règles
déclarative au sens strict décrite en 6.2 (préconditions, fenêtre
temporelle, corrélation — un moteur à part entière, pas un champ) avant
de basculer sur la Session 3 (cause probable/impact).

**État (Session 46, premier jalon de la bibliothèque de règles
déclarative, §6.2)** : nouveau module `netcross_core/expert_rules.py`
avec le contrat `Rule` (douze champs calqués exactement sur le schéma
de §6.2) et un catalogue de quinze règles formalisant les treize règles
« déjà présentes » nommées par §6.2 (pertes par segment,
retransmissions TCP en trois sous-types, fenêtres à zéro, RST, SYN sans
réponse, variation de TTL, remarquage QoS, fragmentation, saturation,
bufferbloat, RTP, DHCP, SIP) — voir section 4 pour le détail complet
(justification du nombre d'entrées, échelle de confiance, règles
corrélées, validation). Catalogue purement DESCRIPTIF : ne réimplémente
aucune détection (`analysis.py`/`synthesis.py` restent la seule source
de vérité), n'est câblé nulle part dans `ExpertEvent`/le pipeline JSON/
GUI. `domain` reprend exactement le vocabulaire de `Finding.category`,
vérifié par un test de traçabilité contre une vraie sortie de
`build_findings()`. Il ne reste donc dans la Session 2, au sens strict
de §6.2, que les règles « nouvelles » (DNS lent, PMTUD noir, NAT/FW
silencieux, anomalies L2, options TCP incompatibles, négociations TLS
incomplètes) et un éventuel câblage du catalogue à un consommateur réel
(`rule_id` sur `ExpertEvent`, ou un moteur d'exécution qui évaluerait
une `Rule` contre un `Report`) — cause probable/impact restant, comme
avant ce lot, de la matière de la Session 3.

**État (Session 47, second lot de la bibliothèque de règles
déclarative, §6.2)** : huit règles supplémentaires (23 au total)
couvrant cinq des six règles « nouvelles » de §6.2 — vérifiées déjà
implémentées avant rédaction, malgré le qualificatif « nouvelles »
(DNS lent, PMTUD black hole, NAT/FW silencieux, anomalies L2 en trois
entrées ARP/STP/VLAN, options TCP incompatibles en deux entrées dont une
non nommée par §6.2) — voir section 4 pour le détail complet. Seule
« négociations TLS incomplètes » reste sans détecteur réel et donc sans
entrée de catalogue ; le signal TLS certificat déjà existant par
ailleurs (Session 26) reste également hors catalogue, non nommé par
§6.2. Il ne reste donc dans la Session 2, au sens strict de §6.2, que
« négociations TLS incomplètes » — qui suppose d'écrire un vrai
détecteur avant de pouvoir le cataloguer, chantier de nature différente
des deux lots précédents — et le câblage du catalogue à un consommateur
réel. Cause probable/impact reste, comme avant ce lot, de la matière de
la Session 3.

**État (Session 48, câblage du catalogue à un consommateur réel)** :
champ `rule_id` (`str | None`) ajouté à `Finding`/`ExpertEvent`, recopié
de l'un à l'autre, exposé en JSON — voir section 4 pour le détail
complet (audit des ~44 sites de `build_findings()`, 23/23 règles
utilisées, ~18 sites volontairement orphelins). Ce câblage reste dans le
sens ANNOTATION (un `rule_id` documente un Finding déjà produit par le
code procédural existant) et non EXÉCUTION (aucune `Rule` n'évalue elle-
même un `Report` pour produire un Finding) : le second reste à faire, de
même que « négociations TLS incomplètes » (toujours sans détecteur réel)
et l'extension de couverture du catalogue aux trois catégories encore
sans aucune règle et aux quelques signaux isolés identifiés cette
session. Cause probable/impact reste, comme avant ce lot, de la matière
de la Session 3.

**État (Session 49, extension de couverture du catalogue)** : huit
règles supplémentaires (23 → 31) formalisant les cinq paires
« signal isolé à côté d'une règle déjà existante » identifiées à la
Session 48, et câblage `rule_id` sur les neuf sites de `Finding`
correspondants — voir section 4 pour le détail complet (règles, sévérités,
justification de la fusion ICMP/ICMPv6 et du maintien de quatre règles
DNS distinctes). Toujours dans le sens ANNOTATION, inchangé depuis la
Session 48 : `analysis.py`/`synthesis.py` non modifiés dans leur logique.
Restent volontairement sans règle : les trois catégories entières
(`"Reseau/Serveur"`/`"TLS"`/`"HTTP"`, aucune nommée par §6.2). Découverte
de cette session, sans incidence sur le périmètre traité mais qui
reformule la décision restante pour « négociations TLS incomplètes » :
`netcross_core/tls_diagnostics.py` (module indépendant, section 2 —
« Fonctionnalités par module ») suit déjà un état de handshake par flux
et par point très proche en esprit de ce concept, mais via son propre
type `TlsFinding` jamais relié à `synthesis.Finding` — le combler pour de
bon suppose de décider explicitement dans quel pipeline ce signal doit
vivre (voir `CLAUDE.md`), pas seulement d'écrire une détection qui
n'existait pas avant. Cause probable/impact et le moteur d'EXÉCUTION
restent, comme avant ce lot, de la matière des Sessions 2 (suite) et 3.

**État (Session 51, extension à "Reseau/Serveur")** : une règle
supplémentaire (31 → 32), `server_processing_dominant`, câblée sur
l'unique site de `Finding` de cette catégorie — retenue avant `"TLS"`/
`"HTTP"` car sans concept architectural non tranché et sans coût
d'extension multi-sites. Restent volontairement sans règle : `"TLS"`
et `"HTTP"` (voir section 4 pour le détail complet).

**État (Session 52, extension à "HTTP")** : cinq règles supplémentaires
(32 → 37) pour la catégorie `"HTTP"` (codes de statut, Session 17),
câblées sur les cinq sites de `Finding` correspondants — retenue avant
`"TLS"` pour la même raison qu'en Session 51 (le coût plus élevé de
cinq sites plutôt qu'un n'est pas une difficulté de fond). Seule
`"TLS"` reste désormais entièrement sans règle, décision toujours liée
à celle sur « négociations TLS incomplètes » ci-dessus (voir section 4
pour le détail complet des cinq règles). Cause probable/impact et le
moteur d'EXÉCUTION restent, comme avant ce lot, de la matière des
Sessions 2 (suite) et 3.

**État (Session 53, extension à "TLS" — certificat)** : deux règles
supplémentaires (37 → 39) pour la DERNIÈRE catégorie laissée ouverte
par la Session 49 — `"TLS"` (certificat hors validité/pas encore
valide, certificat substitué, Session 26, DEUX sites de `Finding`),
câblées sur ces deux sites. **Correction apportée cette session** au
lien établi depuis la Session 49 et repris tel quel par les Sessions
51/52 (voir leurs paragraphes ci-dessus) : cataloguer ce signal
certificat ne « recoupe » PAS la décision architecturale sur
« négociations TLS incomplètes » — vérifié dans le code avant
rédaction, ce second signal ne produit aucun `synthesis.Finding` (il
vit exclusivement dans `TlsFinding`, `netcross_core.tls_diagnostics`,
type jamais relié à `Finding.category`), donc il n'a jamais été,
et ne devient pas maintenant, un candidat à une entrée de ce catalogue
(voir section 4 pour le détail complet de cette correction et des deux
règles). À l'issue de cette session, **plus aucune catégorie de
`Finding` n'est entièrement sans règle** — mais « négociations TLS
incomplètes » reste, comme documenté depuis la Session 49, un signal
entièrement hors du système Finding/rule_id : la décision
architecturale ((a) le faire vivre dans `Report`/`analysis.py`, ou (b)
l'enrichir dans `tls_diagnostics.py` en acceptant qu'il ne sera jamais
catalogable ici) reste ouverte, non traitée par cette session. Cause
probable/impact et le moteur d'EXÉCUTION restent, comme avant ce lot,
de la matière des Sessions 2 (suite) et 3.

**État (Session 54, décision architecturale tranchée sur "négociations
TLS incomplètes")** : option (a) retenue -- le signal rejoint
`Report`/`analysis.py` (détecteur entièrement nouveau,
`_analyse_tls_handshake`/`extract_tls_handshake`, PAS une réutilisation
de `tls_diagnostics.py` qui reste inchangé et indépendant). Le coût
redouté de (a) depuis la Session 49 (dupliquer le parsing manuel de
`tls_diagnostics.py`, ou casser son indépendance) s'est révélé, une
fois vérifié dans le code, ne pas exister : le pipeline principal lit
déjà nativement les champs tshark nécessaires (voir section 4 pour le
détail complet, notamment la validation empirique par capture réelle).
Deux nouvelles règles (39 → **41**) : `tls_handshake_no_reply`
(ClientHello sans ServerHello) et `tls_handshake_incomplete`
(ServerHello sans données applicatives), toutes deux domaine `"TLS"`,
PAR POINT, câblées (`rule_id`) dès leur création. À l'issue de cette
session, **tous les signaux nommés par la section 6.2 sont couverts**
par le catalogue -- plus aucune décision architecturale en suspens sur
ce périmètre précis. Cause probable/impact et le moteur d'EXÉCUTION
restent, comme avant ce lot, de la matière des Sessions 2 (suite) et 3
-- désormais les DEUX seuls chantiers ouverts sur cette feuille de
route à court terme (voir CLAUDE.md, section « Prochaine feature »).

#### Session 3 — corrélation et causalité

**Difficulté : 5/5**

Fusionner les événements élémentaires :

```text
perte
 + retransmissions
 + dup ACK
 + hausse RTT
 + anomalie sur un segment
             ↓
      événement corrélé
             ↓
      cause probable
             ↓
          impact
```

Le moteur doit conserver toutes les preuves ayant conduit au diagnostic.

#### Session 4 — Flow enrichi

**Difficulté : 4/5**

Faire du Flow un objet central reliant endpoints, paquets, timing, protocoles,
segments, événements, findings, QoS et diagnostics.

#### Session 5 — timeline et chemin

**Difficulté : 4/5**

Ajouter une représentation temporelle d'un flow et sa projection sur le chemin
multi-points : client, captures, segments, serveur, événements et temps associés.

#### Session 6 — référentiels

**Difficulté : 3/5**

Créer le modèle `ReferenceProfile`, avec provenance, version, contexte, métrique,
unité, opérateur, seuil, percentile et niveau de confiance.

#### Session 7 — conformité

**Difficulté : 3/5**

Comparer simultanément :

```text
observé
   vs
référence normative
   vs
bonne pratique
   vs
baseline historique
   vs
SLO/SLA
```

Le résultat doit distinguer au minimum :

```text
CONFORME
DÉVIATION
VIOLATION
INDETERMINÉ
```

#### Session 8 — forensic et navigation vers la preuve

**Difficulté : 2–3/5**

Permettre de naviguer dans les deux sens :

```text
Diagnostic → Finding → Event → Flow → Paquets
Paquet    → Flow → Event → Finding → Diagnostic
Segment   → Flows → Events → Paquets
```

#### Session 9 — présentation interactive

**Difficulté : 4/5**

Construire dashboards, graphes, statistiques, cartographies et vues temporelles
à partir des objets analytiques déjà stabilisés.

#### Session 10 — applicatif et expérience utilisateur

**Difficulté : 4–5/5**

Ajouter progressivement transactions, temps de réponse applicatif, HTTP/Web,
indicateurs d'expérience et, lorsque les données sont disponibles, des scores de
type Apdex.

#### Session 11 — automatisation

**Difficulté : 2/5**

Ajouter les déclencheurs, seuils, alarmes, notifications et exécution périodique
une fois le moteur d'événements et de conformité stabilisé.

### 13.4 Stratégie de parallélisation Git

Le développement doit être organisé avec des **Git worktrees**, et non avec un
seul répertoire où plusieurs sessions changent de branche successivement.

Exemple :

```text
netcross-main/
netcross-expert/
netcross-flow/
netcross-reference/
netcross-forensic/
netcross-dashboard/
netcross-application/
```

Chaque worktree pointe vers une branche indépendante :

```bash
git worktree add ../netcross-expert feature/expert-engine
git worktree add ../netcross-flow feature/flow-engine
git worktree add ../netcross-reference feature/reference-engine
git worktree add ../netcross-forensic feature/forensic
```

La parallélisation n'est sûre qu'après stabilisation des contrats communs.

### 13.5 Propriété des fichiers

Chaque branche doit avoir un périmètre de fichiers clairement défini :

```text
expert/
    expert_events.py
    expert_rules.py
    expert_engine.py

flow/
    flow_model.py
    flow_timeline.py
    flow_graph.py

reference/
    reference_model.py
    reference_engine.py
    profiles/

forensic/
    search.py
    related.py

dashboard/
    dashboard.py
    widgets/

application/
    transactions.py
    http.py
```

Une branche ne doit pas modifier le cœur partagé si cette modification n'est pas
nécessaire. Si une évolution du contrat commun est indispensable, elle doit être
traitée comme une évolution d'architecture explicitement intégrée avant de
continuer le développement parallèle.

### 13.6 Règle de livraison d'une session

Une session ne doit pas seulement produire du code partiel. Elle doit viser :

```text
fonctionnalité
     ↓
implémentation
     ↓
tests
     ↓
CLI / JSON si applicable
     ↓
documentation
```

La GUI et le PDF ne doivent pas être des prérequis du moteur analytique.

Chaque branche doit pouvoir être testée indépendamment sur un corpus PCAP minimal.

### 13.7 Corpus de tests par domaine

```text
tests/pcaps/
├── tcp/
├── qos/
├── mtu/
├── rtp/
├── sip/
├── tls/
├── quic/
├── expert/
├── application/
├── references/
└── multi_segment/
```

Chaque nouvelle capacité doit ajouter au moins un scénario représentatif et un
cas négatif ou ambigu lorsque cela est pertinent.

### 13.8 Architecture cible de l'expertise

```text
                     PCAP / PCAPNG / LIVE
                              │
                              ▼
                        tshark / Wireshark
                              │
                 ┌────────────┴────────────┐
                 ▼                         ▼
          dissection / stats         expertise native
                 │                         │
                 └────────────┬────────────┘
                              ▼
                       Netcross Evidence
                              │
                              ▼
                    corrélation multi-points
                              │
                              ▼
                       Expert Event Engine
                              │
                  ┌───────────┴───────────┐
                  ▼                       ▼
             causalité                référentiel
                  │                       │
                  └───────────┬───────────┘
                              ▼
                         diagnostic
                    cause + impact + preuve
                              │
             ┌────────────────┼────────────────┐
             ▼                ▼                ▼
            CLI              GUI              PDF
             │                │                │
             └────────────────┼────────────────┘
                              ▼
                         JSON / API
```

Cette architecture permet de faire évoluer Netcross sans recopier dans chaque
interface la logique d'expertise.

### 13.9 Principe directeur

Netcross ne doit pas devenir un clone d'OmniPeek ou de Wireshark.

La répartition cible est :

```text
Wireshark/TShark
    = profondeur protocolaire + dissections + signaux d'expertise

Netcross
    = corrélation multi-points + localisation + causalité + conformité

Référentiels
    = contexte permettant de qualifier l'écart

Présentation
    = navigation de la conclusion vers la preuve
```

La valeur ajoutée principale est donc la chaîne :

```text
signal protocolaire
       ↓
preuve
       ↓
localisation multi-point
       ↓
corrélation
       ↓
cause probable
       ↓
impact
       ↓
référence applicable
       ↓
conformité / déviation / violation
       ↓
preuve navigable
```

---

## 14. Priorisation recommandée

### P0 — fondations

1. Contrats analytiques communs.
2. `ExpertEvent` / `EvidenceLink`.
3. Ingestion des informations d'expertise Wireshark/TShark.
4. Corrélation événement → flow → paquet → segment.

### P1 — différenciation Netcross

5. Diagnostic causal.
6. Flow enrichi.
7. Timeline de flow.
8. Path / Flow Map / Ladder multi-points.
9. Référentiels et conformité.
10. Baseline enrichie par profil.

### P2 — exploitation

11. Forensic Search.
12. Navigation vers les preuves.
13. Dashboard interactif.
14. Statistiques interactives.
15. Rapport d'expertise enrichi.

### P3 — expertise applicative

16. Transactions.
17. HTTP/Web.
18. Expérience utilisateur.
19. Voice/Video avancé.
20. Alarmes et notifications.

Cette priorisation maximise la valeur obtenue rapidement et évite de commencer par
les composants visuels alors que le modèle d'expertise n'est pas encore stabilisé.

---

## 15. Décisions d'architecture

### 15.1 Bascule build_findings() → moteur d'exécution (issue #27)

**Statut : décision documentée, pas de code — Session 70**

**Constat** : `build_findings()` (`synthesis.py`) trie sa liste complète
en sortie par `(SEVERITY_ORDER, category, segment)` — une étape de
PRÉSENTATION appliquée à l'ensemble des 41 règles à la fois.
`evaluate()` (`rule_engine.py`) renvoie ses `Finding` dans l'ordre de
CONSTRUCTION et ne reproduit délibérément PAS ce tri. Divergence mise au
jour par la Session 63 (`sip_issues`).

**Décision** :

1. `evaluate()` ne triera jamais ses propres `Finding` — le tri est une
   étape de présentation globale, pas une propriété d'une règle isolée.
2. La bascule de `build_findings()` vers le moteur d'exécution est
   RETENUE comme objectif à long terme, mais pas exécutée maintenant.
   Les deux chemins coexistent.

**Plan de migration** (à exécuter quand les 41 règles auront un
évaluateur — 2 restantes : `rtp_quality_mos`,
`server_processing_dominant`) :

1. Créer `evaluate_all(report) -> list[Finding]` dans `rule_engine.py`
   qui itère sur `available_rule_ids()`, appelle `evaluate()` pour
   chaque règle, concatène les résultats.
2. Appliquer le tri `(SEVERITY_ORDER, category, segment)` à la liste
   concaténée — point UNIQUE d'ordonnancement.
3. Remplacer l'appel à `build_findings()` dans le CLI/GUI par
   `evaluate_all()`.
4. Vérifier l'équivalence sur les jeux de tests existants.
5. Supprimer `build_findings()` une fois la parité vérifiée.

**Risque** : basculer sans les 2 règles restantes créerait une
régression silencieuse (perte de 2 détections). D'où le prérequis.
