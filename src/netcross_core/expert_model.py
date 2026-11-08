# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.expert_model -- objets de contrat partages entre
netcross_core et netcross_report ("Session 0" de FEATURES.md section 13.3 :
stabiliser les objets communs avant de batir le moteur d'expertise vise par
la comparaison OmniPeek/Wireshark, section 6).

STATUT (Session 36) : les NEUF objets vises par la Session 0 existent
desormais ici : `EvidenceLink` (Session 32, etendu a `DiffFinding` en
Session 33), `PacketEvidence` (Session 35, pilote sur PMTUD), `Flow`,
`Conversation`, `ExpertEvent`, `Diagnosis`, `ReferenceProfile` et
`ComplianceResult` (Session 36). Important : "stabiliser les objets
communs" (Session 0, difficulte 3/5) ne veut PAS dire "construire le
moteur d'expertise complet" -- ce dernier est explicitement la matiere
des Sessions 1 a 11 de la section 13.3 (moteur de regles, correlation
causale, referentiels de conformite avec DEVIATION nuancee, dashboards
interactifs...). Chaque objet ci-dessous est donc un contrat REEL et
teste, cable sur des donnees qui existent deja aujourd'hui (jamais une
coquille vide), mais dont plusieurs champs restent volontairement `None`
ou absents quand la donnee/le moteur qui les alimenterait n'existe pas
encore -- toujours documente explicitement objet par objet ci-dessous,
jamais silencieux.

`EvidenceLink` relie un constat (`Finding`, netcross_report.synthesis) a une
preuve textuelle qui existe deja ailleurs dans Report (les differents
champs `*_examples`, ou les listes `*_missing`/`*_timeout` elles-memes) --
sans dupliquer cette donnee ni la recalculer, seulement en la rendant
accessible depuis le meme objet que le constat qu'elle justifie, pour
CLI/JSON/PDF/GUI (voir netcross_report.synthesis.build_findings et
netcross_report.json_report._finding_dict).

`PacketEvidence` etait bloque depuis la Session 32 par l'absence d'un index
paquet reel : les `*_examples` de Report sont deja des chaines mises en
forme au moment de la collecte, pas des references vers un paquet precis.
La Session 35 leve ce blocage en exposant `frame.number` (le numero de
trame attribue par tshark au sein d'un fichier de capture) sur
`RawPacket`/`Pkt` (voir pcap_parser.packet), puis construit ce second objet
minimal : `point` (memes valeurs que Finding.segment/EvidenceLink.point) +
`frame_number`. Volontairement SANS chemin de fichier pcap : Report ne
garde nulle part la trace du fichier source associe a un `point` (seul le
label existe, deja suffisant pour qu'un analyste retrouve le bon fichier
parmi ceux qu'il a lui-meme passes en argument de CLI/GUI) -- ajouter ce
chemin serait une extension separee, plus invasive (il faudrait le faire
transiter depuis parse_capture() jusqu'a Report, qui ne le fait pour aucun
autre besoin aujourd'hui), hors perimetre de cette passe.

Cable en pilote sur UNE SEULE categorie (PMTUD noir, `analysis.
_analyse_pmtud`) plutot que sur les huit autres deja porteuses d'un
`EvidenceLink` textuel (meme discipline que Session 32 : un cablage reel et
teste de bout en bout sur un perimetre serre, plutot qu'une esquisse
partout sans consommateur verifie). Les sept autres categories restent
avec un `EvidenceLink.packet` a `None` -- comportement par defaut, pas une
regression (`EvidenceLink` reste utilisable exactement comme avant pour
elles). Voir netcross_core.analysis (collecte de `Report.
pmtud_blackhole_frames`) et netcross_report.synthesis (construction de
l'EvidenceLink avec `packet` renseigne) pour le detail du cablage.

`Flow`/`Conversation` (Session 36) restructurent des donnees DEJA calculees
par `netcross_core.correlate.correlate()` (le dict `flows`) -- aucun
nouveau calcul, seulement une vue agregee/typee de ce qui existe deja
(nombre de paquets/octets par point, premiere/derniere observation).
Construits par `netcross_core.correlate.build_flows()`/
`build_conversations()` (colocalises avec `correlate()`, qui produit deja
le dict `flows` source).

`ExpertEvent`/`Diagnosis` (Session 36) sont des vues generiques d'un
`Finding`/`DiffFinding` deja construit (category/severity/segment/message/
evidence recopies tels quels), PAS un nouveau moteur de detection --
`cause`/`impact` restent TOUJOURS `None` ici : les deviner necessiterait le
moteur de corrélation causale explicitement prevu en Session 3 de la
section 13.3 ("fusionner les evenements elementaires... cause probable...
impact"), absent aujourd'hui. Construits par
`netcross_report.build_expert_events()`/`build_diagnoses()` (vivent cote
netcross_report, qui heberge deja `Finding` -- l'inverse casserait la
couche imposee par import-linter). `Finding` (netcross_report.synthesis)
gagne en Session 36 un champ `event: ExpertEvent | None` -- "Finding
enrichi" au sens de la Session 0 : depuis un Finding, on peut desormais
naviguer vers l'ExpertEvent qui le represente (meme s'il ne porte pas
encore de cause/impact), premiere brique de la navigation "Diagnostic ->
Finding -> Event -> Flow -> Paquets" visee en section 6.14/Session 8.

`ReferenceProfile`/`ComplianceResult` (Session 36) : seuil normatif applique
a une metrique DEJA calculee de `Report`, statut CONFORME/VIOLATION/
INDETERMINE. `DEVIATION` (distinguer un ecart mineur d'une vraie violation)
est un statut valide du contrat mais N'EST JAMAIS PRODUIT par l'evaluateur
minimal de cette session -- cette nuance suppose une marge de tolerance et
une comparaison a une baseline/SLO, explicitement la matiere de la Session
7 dediee ("conformite", section 13.3), pas une valeur inventee ici sans
cadrage ni test. Construits par `netcross_core.compliance.
evaluate_compliance()` (vit cote netcross_core, n'a besoin que de `Report`).

Vivent dans netcross_core (et non netcross_report, qui heberge Finding) pour
rester disponibles a netcross_core.baseline_diff (DiffFinding) le jour ou
ses propres constats gagneront la meme preuve -- l'inverse casserait la
couche imposee par import-linter (netcross_report -> netcross_core, jamais
l'inverse, voir pyproject.toml [tool.importlinter]).

STATUT (Session 40) : premier lot de la Session 2 de la section 13.3
("moteur d'evenements d'expertise", difficulte 5/5). `ExpertEvent` gagne
trois nouveaux champs optionnels tires du schema cible de la section 6.1
(catégorie / couche reseau / protocole / severite / CONFIANCE / PREMIERE
ET DERNIERE OCCURRENCE / points concernes / flux concernes / paquets
concernes / cause / impact / action de remediation) : `confidence`,
`first_seen`, `last_seen` -- voir la docstring d'`ExpertEvent` ci-dessous
pour le detail complet (calcul, limites, pourquoi `None` cote source
"netcross"). Les autres champs du schema cible restent hors perimetre de
cette passe (voir claude.md Session 40, "Non traite dans cette passe") :
couche reseau/protocole explicites (`ExpertEvent` ne porte aujourd'hui
que `category`/`segment`, pas de champ dedie), flux concernes (pas de
lien vers `Flow`/`flow_key`), action de verification/remediation, et la
generalisation de `confidence`/`first_seen`/`last_seen` aux evenements de
source "netcross" (qui suppose que `Finding` gagne lui-meme cette donnee,
hors perimetre ici -- voir docstring d'`ExpertEvent`).

STATUT (Session 41) : deuxieme lot de la Session 2 de la section 13.3.
`ExpertEvent` gagne deux nouveaux champs optionnels du meme schema cible :
`layer` (couche reseau : "liaison"/"reseau"/"transport") et `protocol`
(nom de protocole : "ARP"/"STP"/"IPv4"/"IPv6"/"ICMP"/"ICMPv6"/"TCP"/
"UDP"). Comme pour `confidence`/`first_seen`/`last_seen` en Session 40,
seule `netcross_core.wireshark_expert` les renseigne a ce jour : le nom du
flag EK brut (ex: "tcp_tcp_analysis_retransmission") porte deja, sans
ambiguite, le prefixe de la couche EK qui l'a produit ("tcp", "ip",
"ipv6", "arp", "stp", "udp", "icmp" ou "icmpv6" -- voir
`_layer_and_protocol_for` dans wireshark_expert.py), une donnee
STRUCTURELLE deja disponible, pas une deduction. Cote source "netcross"
(`netcross_report.build_expert_events`, a partir d'un `Finding` deja
construit) : `layer`/`protocol` restent `None`, et PAS par simple manque
de temps -- `Finding.category` est un regroupement METIER ("Pertes",
"Saturation", "Routage", "Reseau/Serveur"...) qui ne correspond pas a un
protocole ni une couche unique pour plusieurs de ces categories ("Pertes"
et "Saturation" s'appliquent a n'importe quel protocole transporte,
"Reseau/Serveur" melange deliberement plusieurs indicateurs de couches
differentes -- voir netcross_core.models/netcross_core.analysis).
Inventer une couche/un protocole pour ces categories serait une
association fabriquee, pas une donnee lue -- meme discipline que
`cause`/`impact` (Session 3, absente) et `confidence`/`first_seen`/
`last_seen` cote "netcross" (Session 40) : `None` explicite plutot qu'une
supposition. Reste hors perimetre (voir claude.md Session 41, "Non traite
dans cette passe") : flux concernes (pas de lien vers `Flow`/`flow_key`),
paquets/points concernes comme listes structurees (au-dela de ce que
porte deja `evidence`), cause probable/impact (Session 3), action de
verification/remediation.

STATUT (Session 43) : troisieme lot de la Session 2 de la section 13.3.
`ExpertEvent` gagne `flow_keys: list[tuple]` -- voir docstring
d'`ExpertEvent` ci-dessous pour le detail complet.

STATUT (Session 44) : quatrieme lot de la Session 2 de la section 13.3.
`ExpertEvent` gagne `packet_evidence: list[PacketEvidence]` -- liste
COMPLETE des paquets porteurs du signal (tous les numeros de trame, pas
seulement les `_MAX_EXAMPLES` exemples conserves dans `evidence`), meme
objet `PacketEvidence` que celui deja utilise par `EvidenceLink.packet`
(Session 35), voir docstring d'`ExpertEvent` ci-dessous pour le detail
complet. Reste hors perimetre dans la Session 2 : action de verification/
remediation, bibliotheque de regles declarative (section 6.2), cause
probable/impact (bascule vers la Session 3).

STATUT (Session 45) : cinquieme et dernier lot cote `ExpertEvent` de la
Session 2 de la section 13.3. `ExpertEvent` gagne `remediation: str |
None` -- dernier des onze champs du schema cible de la section 6.1
("action de verification / remediation"), voir docstring d'`ExpertEvent`
ci-dessous pour le detail complet (contenu, limites, pourquoi `None` cote
source "netcross"). Avec ce lot, les DIX champs du schema cible
accessibles sans le moteur de correlation causale de la Session 3 sont
desormais tous portes par `ExpertEvent` (seuls `cause`/`impact` restent
`None`, Session 3 non commencee) ; il ne reste dans la Session 2 que la
bibliotheque de regles declarative au sens strict decrite en section 6.2
(un moteur a part entiere -- preconditions, fenetre temporelle,
correlation --, pas un champ a ajouter ici).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class PacketEvidence:
    """Reference minimale vers UN paquet precis au sein de la capture d'un
    point donne -- deuxieme des neuf objets de contrat vises par la
    Session 0 (voir docstring de module ci-dessus pour ce qui la debloque
    et ses limites assumees, notamment l'absence volontaire de chemin de
    fichier pcap).

    `point` reprend exactement la meme valeur que `EvidenceLink.point` (le
    point de capture ou le segment "A -> B" auquel appartient le paquet).

    `frame_number` est `frame.number` tel que rendu par tshark : un entier
    1-indexe, UNIQUE au sein d'un seul fichier/flux de capture (PAS un
    identifiant global comparable entre plusieurs points -- deux points
    de capture distincts ont chacun leur propre numerotation qui recommence
    a 1, exactement comme `tcp.seq`/`tcp.ack` avant `seq_raw`/`ack_raw`,
    voir pcap_parser.packet). Suffisant ici car chaque `PacketEvidence`
    est deja rattache a un `point` precis : pas d'ambiguite tant qu'on ne
    compare pas des numeros de trame entre deux points differents.
    """

    point: str
    frame_number: int


@dataclass
class EvidenceLink:
    """Une ligne de preuve brute deja produite par l'analyse, rattachee a un
    point de capture ou un segment "A -> B".

    `point` reprend exactement la meme valeur que `Finding.segment` pour le
    constat qu'elle illustre -- ce n'est pas une nouvelle notion de
    localisation, seulement un moyen de retrouver le contexte d'une preuve
    isolee de son constat.

    `text` est deja formate pour la lecture humaine (c'est la meme chaine
    que celle imprimee par netcross_core.report_text dans le detail par
    categorie) : EvidenceLink ne fait qu'exposer cette meme chaine a cote
    du constat qui s'appuie dessus, pas une nouvelle mise en forme.

    `packet` (Session 35, optionnel, `None` par defaut) : `PacketEvidence`
    designant le paquet precis illustre par `text`, quand cette donnee est
    disponible et cablee pour la categorie concernee (voir docstring de
    module). Rester `None` ne degrade rien : c'etait deja le comportement
    de toute categorie avant cette session.
    """

    point: str
    text: str
    packet: PacketEvidence | None = None


@dataclass
class Flow:
    """Un flux (meme cle que `netcross_core.correlate.flow_key`), agrege a
    travers TOUS les points de capture ou il a ete vu -- troisieme objet de
    la Session 0. Ne recalcule rien : pure restructuration typee du dict
    `flows` deja produit par `correlate()` (point -> liste de `Pkt`), voir
    `netcross_core.correlate.build_flows()`.

    `key` reprend exactement la cle de `flow_key()` : `(proto, src, sport,
    dst, dport, key_id)` en mode strict, ou `("NAT", proto, payload_hash,
    bucket)` en mode --nat-tolerant -- pas de nouvelle notion d'identite de
    flux.

    `points`, `packet_count`, `byte_count`, `first_ts`, `last_ts` : un point
    n'apparait dans ces dicts que s'il a reellement vu ce flux (meme
    convention que le dict `flows` source -- absence, pas zero, si un point
    n'a jamais vu ce flux).

    `endpoints` : paire d'adresses (`src`, `dst`) du premier paquet
    rencontre pour ce flux, toujours ordonnee (`min`, `max`) -- meme
    convention que `Conversation.endpoints` ci-dessous, pour que
    `build_conversations()` puisse regrouper les `Flow` sans relire les
    paquets bruts. `None` uniquement si le flux n'a reellement aucun
    paquet (garde defensive, ne devrait jamais arriver en pratique).
    """

    key: tuple
    points: list[str] = field(default_factory=list)
    packet_count: dict[str, int] = field(default_factory=dict)
    byte_count: dict[str, int] = field(default_factory=dict)
    first_ts: dict[str, float] = field(default_factory=dict)
    last_ts: dict[str, float] = field(default_factory=dict)
    endpoints: tuple[str, str] | None = None


@dataclass
class Conversation:
    """Paire d'adresses IP (protocole/port ignores), agregeant tous les
    `Flow` qui partagent cette paire -- quatrieme objet de la Session 0.
    Vue "qui parle a qui" complementaire du `Flow` "quel echange precis" :
    plusieurs flux (ports differents, ou meme protocoles differents)
    entre les deux memes hotes se regroupent sous une seule Conversation.

    `endpoints` est toujours ordonne (`min`, `max`) sur les deux adresses,
    pour qu'un flux src->dst et un flux dst->src entre les 2 memes hotes
    rejoignent la MEME Conversation plutot que d'en creer deux distinctes.
    """

    endpoints: tuple[str, str]
    flow_keys: list[tuple] = field(default_factory=list)
    packet_count: int = 0
    byte_count: int = 0


@dataclass
class ExpertEvent:
    """Vue evenementielle generique d'un constat deja produit (`Finding`/
    `DiffFinding`) -- cinquieme objet de la Session 0, premiere brique du
    "moteur d'evenements d'expertise" vise section 6.1 de FEATURES.md.

    Distinct de `Finding` par construction (voir section 6.1) : `Finding`
    reste une formulation finale de rapport, `ExpertEvent` est cense
    devenir la donnee analytique reutilisable (triage, GUI, JSON, PDF,
    notifications futures) -- mais dans cette premiere passe (Session 36),
    `ExpertEvent` ne fait que RECOPIER category/severity/segment/message/
    evidence d'un `Finding`/`DiffFinding` deja construit (voir
    `netcross_report.build_expert_events()`), rien de plus : `cause`/
    `impact` restent TOUJOURS `None` ici, le moteur de correlation causale
    qui les alimenterait (fusionner pertes + retransmissions + hausse RTT
    en UNE cause probable) est explicitement la Session 3 de la section
    13.3, non traitee ici.

    `source` (ajoute dans une passe posterieure a la Session 36) distingue
    la provenance de l'evenement : `"netcross"` (valeur par defaut,
    retrocompatible avec tout `ExpertEvent` construit avant cette passe)
    pour un evenement issu d'un `Finding`/`DiffFinding` deja calcule par un
    detecteur Netcross (voir `netcross_report.build_expert_events`) ;
    `"tshark"` pour un signal d'expertise BRUT du moteur de dissection
    tshark lui-meme, jamais interprete par Netcross (voir
    `netcross_core.wireshark_expert.build_wireshark_expert_events`,
    Session 1 de la section 13.3 -- "il ne faut pas considerer les signaux
    Wireshark comme des diagnostics definitifs, ils constituent des
    preuves supplementaires"). Les deux categories restent toujours
    exposees separement (cles JSON distinctes cote `generate_json_report`/
    `generate_json_diff`), jamais fondues dans la meme liste.

    `confidence`/`first_seen`/`last_seen` (Session 2 de la section 13.3,
    "moteur d'evenements d'expertise" -- premier lot) : trois des champs
    listes par le schema cible de la section 6.1 (`confiance`, `premiere
    / derniere occurrence`), volontairement ajoutes ENSEMBLE car les deux
    dependent de la meme donnee source (les paquets qui composent un
    evenement) et se calculent au meme endroit. Comme pour tout champ
    ajoute progressivement a ce contrat (`source` ci-dessus, `packet` sur
    `EvidenceLink`...), `None` par defaut -- retrocompatible avec tout
    `ExpertEvent` construit avant cette passe, jamais suppose renseigne.

    `confidence` : score de confiance entre 0.0 et 1.0 dans la fiabilite
    du signal, PAS une probabilite statistique calibree -- un niveau
    discret refletant la nature de la donnee source (voir
    `netcross_core.wireshark_expert` pour la seule implementation
    concrete a ce jour : 1.0 si la severite est NATIVE tshark
    -- classification faite par le dissecteur lui-meme, la plus fiable
    disponible --, 0.7 si le flag est seulement connu de la table
    `_KNOWN_FLAGS` maintenue a la main par ce projet, 0.4 si ni l'un ni
    l'autre -- nom de champ EK brut jamais vu, severite de repli
    `_DEFAULT_SEVERITY`). `None` pour un `ExpertEvent` de source
    `"netcross"` (voir `netcross_report.build_expert_events`) : un
    `Finding` deja produit par un detecteur Netcross n'a aujourd'hui
    aucune notion de confiance calculee -- lui en inventer une ici serait
    une valeur devinee, pas mesuree (meme discipline que `cause`/`impact`
    ci-dessus, qui restent `None` en l'absence du moteur qui les
    calculerait reellement).

    `first_seen`/`last_seen` : timestamps `Pkt.ts` (memes unites,
    secondes epoch tel que rendu par tshark) du premier et du dernier
    paquet ayant produit ce signal -- PAS seulement parmi les exemples
    plafonnes conserves dans `evidence` (voir `_MAX_EXAMPLES` cote
    `wireshark_expert.py`), calcules sur la totalite des occurrences pour
    rester exacts meme quand `evidence` est tronque. `None` pour un
    `ExpertEvent` de source `"netcross"` : `Finding` ne porte aujourd'hui
    aucun timestamp (ni directement, ni via `EvidenceLink`/`PacketEvidence`,
    qui n'exposent qu'un numero de trame -- voir `expert_model.
    PacketEvidence` -- pas un instant), rien a lire pour les calculer sans
    deviner.

    `layer`/`protocol` (Session 2 de la section 13.3, deuxieme lot) : deux
    autres champs du schema cible de la section 6.1 ("couche reseau",
    "protocole"). Comme `confidence`/`first_seen`/`last_seen` ci-dessus,
    `None` par defaut -- retrocompatible avec tout `ExpertEvent` construit
    avant cette passe.

    `layer` : une des trois couches OSI que ce projet observe deja
    ailleurs ("liaison" pour ARP/STP, "reseau" pour IPv4/IPv6/ICMP/ICMPv6,
    "transport" pour TCP/UDP) -- pas les sept couches completes du modele
    OSI, seulement celles que `netcross_core.wireshark_expert` peut
    aujourd'hui distinguer sans ambiguite (voir `_layer_and_protocol_for`
    la-bas).

    `protocol` : nom de protocole court ("ARP", "STP", "IPv4", "IPv6",
    "ICMP", "ICMPv6", "TCP", "UDP") -- PAS une deduction statistique, lu
    directement depuis le prefixe du nom de flag EK brut qui a produit ce
    signal (structurellement fiable, voir docstring de module).

    `None` pour un `ExpertEvent` de source `"netcross"` : voir la
    docstring de module ci-dessus pour le detail complet (`Finding.
    category` est un regroupement metier, pas un protocole ni une couche
    unique pour plusieurs categories -- inventer l'association serait une
    supposition, pas une lecture).

    `flow_keys` (Session 2 de la section 13.3, troisieme lot) : premier des
    deux points restants du schema cible listes en tete de CLAUDE.md
    ("flux concernes -- lien structure vers Flow/flow_key, pas seulement
    evidence"). Liste de cles au sens EXACT de `netcross_core.correlate.
    flow_key()` -- `(proto, src, sport, dst, dport, key_id)` en mode
    strict -- PAS une nouvelle notion d'identite de flux : un consommateur
    peut directement retrouver le `Flow` correspondant dans la liste
    produite par `build_flows()` en comparant `Flow.key` a un element de
    cette liste. Vide par defaut (`list`, pas `None`, meme convention que
    `evidence` juste au-dessus) -- retrocompatible avec tout `ExpertEvent`
    construit avant cette passe.

    Renseigne uniquement par `netcross_core.wireshark_expert.
    build_wireshark_expert_events()` (source `"tshark"`), calcule sur la
    TOTALITE des occurrences d'un (point, flag) -- pas seulement les
    exemples plafonnes conserves dans `evidence`, meme discipline que
    `first_seen`/`last_seen` (Session 40) -- dedoublonne, dans l'ordre de
    premiere rencontre (PAS trie : `key_id`/`sport`/`dport` melangent
    `int` et `None` selon le protocole, un tri naif leverait `TypeError`
    en comparant les deux ; l'ordre d'insertion est deterministe des lors
    que l'iteration sur `all_packets` l'est, ce qui est deja le cas
    ailleurs dans ce module -- voir `evidence`).

    Toujours vide (`[]`) pour un `ExpertEvent` de source `"netcross"` :
    `Finding`/`EvidenceLink` ne portent aujourd'hui qu'un numero de trame
    optionnel (`PacketEvidence.frame_number`) sans les autres champs du
    5-tuple (`sport`/`dport`/`key_id`...) necessaires pour reconstruire un
    `flow_key()` exact -- le deduire depuis le seul point/texte
    d'`evidence` serait une supposition, pas une lecture, meme discipline
    que `confidence`/`layer`/`protocol` ci-dessus.

    `packet_evidence` (Session 2 de la section 13.3, quatrieme lot) :
    second des deux points restants du schema cible listes en tete de
    CLAUDE.md ("points/paquets concernes -- lien direct vers les numeros
    de trame de TOUTES les occurrences, au-dela des exemples plafonnes").
    Liste de `PacketEvidence` -- PAS une nouvelle notion, le meme objet de
    contrat que celui deja porte par `EvidenceLink.packet` (Session 35) --
    mais couvrant ICI la totalite des occurrences d'un (point, flag),
    contrairement a `evidence` ci-dessus qui reste plafonnee a
    `_MAX_EXAMPLES` (5) : un flux avec des centaines de retransmissions
    n'expose aujourd'hui que 5 numeros de trame via `evidence`, ce champ
    expose les centaines de numeros reels. Vide par defaut (`list`, pas
    `None`), meme convention que `evidence`/`flow_keys` -- retrocompatible
    avec tout `ExpertEvent` construit avant cette passe.

    Renseigne uniquement par `netcross_core.wireshark_expert.
    build_wireshark_expert_events()` (source `"tshark"`), un
    `PacketEvidence` par occurrence dont `frame_number` est disponible --
    `None` reste tolere plutot que suppose (meme garde defensive que pour
    `evidence` ci-dessus, systematique avec un vrai tshark). Pas de
    deduplication necessaire : au sein d'un (point, flag) donne, chaque
    paquet n'est parcouru qu'une seule fois (`pk.expert_flags` ne repete
    jamais le meme nom de flag pour un meme paquet), donc chaque numero de
    trame n'apparait naturellement qu'une fois.

    Toujours vide (`[]`) pour un `ExpertEvent` de source `"netcross"` :
    `Finding`/`EvidenceLink` ne portent un `PacketEvidence` que pour la
    seule categorie PMTUD deja cablee (Session 35), et seulement pour les
    exemples plafonnes conserves dans `evidence` -- aucune liste de LA
    TOTALITE des numeros de trame n'existe cote `Finding` aujourd'hui,
    quelle que soit la categorie. L'inventer serait relire `evidence` en
    pretendant qu'elle est complete alors qu'elle ne l'est pas -- meme
    discipline que `flow_keys` ci-dessus.

    `remediation` (Session 2 de la section 13.3, cinquieme et dernier lot
    cote `ExpertEvent`) : dernier des onze champs du schema cible de la
    section 6.1 ("action de verification / remediation"). Contrairement
    a `layer`/`protocol`/`flow_keys`/`packet_evidence` ci-dessus (tous
    LUS depuis une donnee deja disponible, jamais devines), `remediation`
    est un texte REDIGE -- une piste de verification technique COURTE
    associee au nom de flag EK connu qui a produit ce signal (voir
    `netcross_core.wireshark_expert._REMEDIATION`), pas une donnee
    calculee. Volontairement restreint aux onze flags deja repertories
    dans `_KNOWN_FLAGS` (les seuls dont ce projet connaisse deja le sens
    exact et la severite -- voir docstring de module de
    `wireshark_expert.py`) : `None` pour tout flag ABSENT de cette table,
    plutot qu'un conseil generique invente sans connaitre la nature reelle
    du signal (meme discipline defensive que `_flag_label`/`_flag_severity`
    pour un flag inconnu). Un texte de remediation n'est PAS une cause ni
    un impact (`cause`/`impact` ci-dessus, qui restent `None` en l'absence
    du moteur de la Session 3) : c'est une piste de verification pour un
    analyste humain, formulee au conditionnel/a l'imperatif de suggestion,
    jamais une affirmation de diagnostic definitif -- coherent avec le
    principe directeur de la Session 1 ("il ne faut pas considerer les
    signaux Wireshark comme des diagnostics definitifs").

    Toujours `None` pour un `ExpertEvent` de source `"netcross"` :
    generaliser `remediation` aux Finding Netcross supposerait une
    bibliotheque de textes par CATEGORIE (pas par flag EK -- `Finding`
    n'expose aucun flag EK), un chantier de redaction bien plus large
    portant sur les ~20 categories de `Finding.category` (Pertes,
    Saturation, Routage, QoS, Fragmentation, VLAN, TCP, RTP/MOS,
    Reseau/Serveur, DHCP, SIP, PMTUD, NAT/FW, ARP, STP, TLS x2, MSS, DNS,
    HTTP -- voir netcross_core.analysis/netcross_report.synthesis), non
    cadre ni redige dans cette passe -- hors perimetre explicite, pas un
    oubli silencieux, meme discipline que `confidence`/`layer`/`protocol`/
    `flow_keys`/`packet_evidence` cote source "netcross" ci-dessus.

    `rule_id` (Session 48) : premier cablage reel du catalogue DESCRIPTIF
    de `netcross_core.expert_rules` (vingt-trois regles, Sessions 46-47) --
    exact MIROIR de `remediation` ci-dessus mais dans l'autre sens.
    `remediation` est un texte redige, disponible UNIQUEMENT cote
    `"tshark"` (onze flags connus) et toujours `None` cote `"netcross"` ;
    `rule_id` est un identifiant LU (recopie depuis `Finding.rule_id` --
    voir `netcross_report.synthesis.build_findings()` -- jamais devine ni
    recalcule ici), disponible UNIQUEMENT cote `"netcross"` (quand le
    `Finding`/`DiffFinding` source correspond exactement a une regle du
    catalogue) et toujours `None` cote `"tshark"` : le catalogue de
    `expert_rules.py` decrit des detecteurs Netcross (`analysis.py`/
    `synthesis.py`), pas les signaux d'expertise bruts du dissecteur
    tshark lui-meme (source distincte, voir docstring de module
    ci-dessus). Recopie duck-type via `getattr(f, "rule_id", None)` dans
    `netcross_report.expert_events.build_expert_events()` -- `None` par
    defaut pour tout `ExpertEvent` construit avant cette passe, ou depuis
    un `DiffFinding` (qui ne declare pas ce champ).
    """

    category: str
    severity: str
    segment: str
    message: str
    evidence: list[EvidenceLink] = field(default_factory=list)
    # Cause probable / impact -- TOUJOURS None dans cette passe, voir
    # docstring ci-dessus (moteur de causalite, Session 3 de FEATURES.md).
    cause: str | None = None
    impact: str | None = None
    source: str = "netcross"
    # Confiance/premiere-derniere occurrence -- voir docstring ci-dessus
    # (Session 2 de la section 13.3, premier lot) : None par defaut,
    # renseignes uniquement par build_wireshark_expert_events() a ce jour.
    confidence: float | None = None
    first_seen: float | None = None
    last_seen: float | None = None
    # Couche reseau / protocole -- voir docstring ci-dessus (Session 2 de
    # la section 13.3, deuxieme lot) : None par defaut, renseignes
    # uniquement par build_wireshark_expert_events() a ce jour, jamais
    # cote source "netcross" (voir docstring de module).
    layer: str | None = None
    protocol: str | None = None
    # Flux concernes -- voir docstring ci-dessus (Session 2 de la section
    # 13.3, troisieme lot) : liste vide par defaut, renseignee uniquement
    # par build_wireshark_expert_events() a ce jour, jamais cote source
    # "netcross".
    flow_keys: list[tuple] = field(default_factory=list)
    # Points/paquets concernes -- voir docstring ci-dessus (Session 2 de
    # la section 13.3, quatrieme lot) : liste vide par defaut, renseignee
    # uniquement par build_wireshark_expert_events() a ce jour (TOUTES les
    # occurrences, au-dela des exemples plafonnes d'evidence), jamais cote
    # source "netcross".
    packet_evidence: list[PacketEvidence] = field(default_factory=list)
    # Action de verification/remediation -- voir docstring ci-dessus
    # (Session 2 de la section 13.3, cinquieme et dernier lot) : None par
    # defaut, texte REDIGE (pas calcule) uniquement pour les onze flags
    # deja connus de _KNOWN_FLAGS, renseigne uniquement par
    # build_wireshark_expert_events() a ce jour, jamais cote source
    # "netcross".
    remediation: str | None = None
    # Lien vers netcross_core.expert_rules (Session 48) -- voir docstring
    # ci-dessus : miroir de remediation, mais peuple cote "netcross"
    # (recopie depuis Finding.rule_id) et toujours None cote "tshark".
    rule_id: str | None = None


@dataclass
class Diagnosis:
    """Regroupe les `ExpertEvent` d'un meme segment -- sixieme objet de la
    Session 0. Comme pour `ExpertEvent` ci-dessus, `cause`/`impact` restent
    TOUJOURS `None` dans cette passe : un vrai diagnostic (au sens de la
    section 13.8 -- "corrélation entre evenements -> cause probable ->
    impact") suppose le meme moteur de causalite (Session 3), absent
    aujourd'hui. Ce regroupement par segment est en revanche deja reel et
    utile en soi (voir `netcross_report.build_diagnoses()`) : il repond
    directement a "quels constats analytiques concernent ce segment ?",
    meme s'il ne sait pas encore les fusionner en UNE explication.
    """

    segment: str
    events: list[ExpertEvent] = field(default_factory=list)
    cause: str | None = None
    impact: str | None = None


@dataclass
class ReferenceProfile:
    """Seuil normatif ou de bonne pratique applique a UNE metrique nommee,
    deja calculee par `Report` (netcross_core.models) -- septieme objet de
    la Session 0 (`Reference` dans la liste de section 13.3).

    `metric` est une cle du registre `netcross_core.compliance._METRIC_FUNCS`
    (PAS un nom d'attribut `Report` lu par `getattr` -- la plupart des
    champs `Report` sont des dict par point/segment, pas des scalaires
    directement comparables a un seuil ; le registre fournit la fonction
    d'agregation explicite pour chaque metrique nommee, voir
    `netcross_core.compliance` pour le detail et la liste des metriques
    actuellement definies).

    `operator` : `"<="`, `"<"`, `">="`, `">"` ou `"=="` -- comparaison de
    `observed` a `threshold` pour decider de la conformite (voir
    `ComplianceResult`).

    `source` : provenance textuelle libre (RFC, bonne pratique
    operationnelle, SLO...) -- affichee telle quelle, jamais interpretee.

    `provenance` (Session 6/Job 10) : type de reference -- "normative"
    (RFC/standard), "recommandee" (bonne pratique), "baseline" (historique),
    "slo" (SLA/SLO operationnel). Defaut "recommandee".

    `version` : version du document source (ex: "RFC 6349" -> "6349"),
    libre, principalement informatif.

    `context` : contexte d'application (ex: "fiber", "mobile", "wan",
    "datacenter") -- filtre optionnel, None = applicable partout.

    `percentile` : percentile de la distribution observee a comparer au
    seuil (ex: 95 pour P95). None = valeur brute (moyenne/total).

    `confidence` : niveau de confiance du seuil -- "high" (RFC/standard),
    "medium" (bonne pratique), "low" (estime). Principalement informatif.

    `deviation_margin` (Session 7/Job 11) : marge de tolerance relative
    (ex: 0.1 = 10%). Si la valeur observee depasse le seuil de moins de
    cette marge, le statut est "DEVIATION" au lieu de "VIOLATION".
    None = pas de nuance DEVIATION (comportement d'origine).
    """

    id: str
    metric: str
    operator: str
    threshold: float
    unit: str
    source: str
    provenance: str = "recommandee"
    version: str | None = None
    context: str | None = None
    percentile: float | None = None
    confidence: str = "medium"
    deviation_margin: float | None = None


@dataclass
class ComplianceResult:
    """Resultat de la comparaison d'une valeur observee a un
    `ReferenceProfile` -- huitieme objet de la Session 0 (`ComplianceResult`
    dans la liste de section 13.3), calcule par
    `netcross_core.compliance.evaluate_compliance()`.

    `status` : `"CONFORME"`, `"VIOLATION"` ou `"INDETERMINE"` (metrique du
    referentiel absente du registre, ou valeur non calculable) dans cette
    passe. `"DEVIATION"` (distinguer un ecart mineur d'une vraie violation)
    est un statut VALIDE du contrat -- mais jamais produit par l'evaluateur
    actuel : cette nuance suppose une marge de tolerance et une comparaison
    a une baseline/SLO historique, explicitement la matiere de la Session 7
    dediee ("conformite", section 13.3) plutot qu'une marge arbitraire
    choisie sans cadrage ici.
    """

    reference: ReferenceProfile
    observed: float | None
    status: str
