# Session 78 : échantillons UDP d'horloge non ambigus

Date : 9 novembre 2026. Périmètre : issue #1029, dépendance #1027 déjà
livrée. La session 77 est réservée à la campagne de performances #1018,
qui reste exécutée sur sa révision applicative initiale.

## Collecte et garde-fous

Le nouveau module `clock_samples.py` collecte les échantillons UDP avant
la correction des latences. Les handshakes TCP et l'estimateur robuste
existants restent en place.

- **DNS** : regroupement local par point, client/serveur, ports et
  identifiant ; noms normalisés, complément d'un nom manquant seulement
  si unique. Il faut exactement une requête et une réponse par identité
  aux deux points, dans l'ordre local. Réutilisations ambiguës,
  retransmissions et échanges incomplets sont refusés. En mode NAT,
  la relaxation des extrémités exige nom et empreintes concordantes
  des deux messages, toujours uniques à chaque point.
- **RTP** : identité SSRC, séquence, horodatage, longueur et empreinte
  de charge utile lorsqu'elle est disponible. Il faut des copies uniques
  aux deux points et deux sens cohérents de la même connexion.
- **RTCP** : couche native TShark et charge utile requises ; empreinte
  SHA-256 transmise de `RawPacket` à `Pkt`. Une dissection RTCP native
  empêche le repli RTP heuristique.
- **Média** : association temporelle monotone, sans réutilisation des
  datagrammes et sans abandonner les couples suivants après un paquet
  isolé. Écart maximal d'une seconde selon chaque horloge. Une seule
  direction ne fournit aucun offset ; l'horodatage RTP n'est jamais
  pris pour une heure murale. Le couple est ancré au milieu des
  observations du point de référence.
- **Provenance** : source sur chaque échantillon, liste structurée
  `clock_offsets[].sources` dans le JSON et sources dans la méthode
  reprise par les rapports. Cette liste décrit la collecte avant le
  filtre, pas une garantie que chaque source est retenue. Un décalage
  imposé n'a aucune source automatique.

## Vérifications

La sélection finale du collecteur et de l'horloge existante, incluant
l'intégration analyse/texte/JSON, réussit : **42 tests, 0,90 s**.
`clock_samples.py` est couvert à **100 % des lignes et branches**
(123 instructions, 50 branches, aucune ligne ou branche manquante).
Ruff est vert. Ce périmètre ciblé n'est pas la suite complète du dépôt ;
la suite complète, GTK4 et la couverture combinée restent exigées en CI
avant fusion.

La sélection complémentaire parseur/adaptateur/JSON réussit également :
**141 tests, 0,88 s**. Le contrat d'import-linter est conservé, le typage
du nouveau module est vert, les contrôles de fraîcheur diagramme/OpenAPI
réussissent et MkDocs strict construit la documentation en 3,17 s.

La fixture DNS du test NAT historique inversait les ports mais pas les
adresses dans les réponses. Elle est corrigée sans retirer les assertions
de décalage. La campagne #1018 tourne dans un autre worktree ; aucune
suite locale lourde n'est lancée pendant ses mesures. Les petits tests
ciblés sont exécutés à faible priorité et leur coexistence est déclarée
dans la méthodologie de la campagne.

## Limites

La formule conserve l'hypothèse de délais de transit symétriques ; la
proximité temporelle ne la prouve pas et les empreintes n'authentifient
pas les captures. Les horloges doivent rester stables sur un couple.
Les doublons, pertes, transformations de SSRC/séquence/contenu/longueur
ou ambiguïtés peuvent supprimer des échantillons plutôt que fabriquer
un offset. Le lot ne fournit pas une synchronisation matérielle, ni
une reconstruction complète des Sender Reports RTCP ou des réécritures
de contenu par un SBC.
