# Détecteurs — comportement, limites et inventaire

## Plages TEST-NET (RFC 5737)

Les plages d'adresses de documentation (TEST-NET) sont utilisées en
démonstration et dans les exemples :

| Plage | Nom |
|-------|-----|
| 192.0.2.0/24 | TEST-NET-1 |
| 198.51.100.0/24 | TEST-NET-2 |
| 203.0.113.0/24 | TEST-NET-3 |

La bibliothèque standard Python (`ipaddress`) considère ces plages comme
**privées** (`is_private = True`, `is_global = False`). En conséquence :

- **Beaconing** (`security.beaconing`) : avec `external_only=True` (défaut),
  les destinations TEST-NET sont filtrées — le détecteur reste muet.
- **Exfiltration** (`security.exfiltration`) : les destinations TEST-NET
  ne sont pas considérées comme externes.
- **Mouvements latéraux** (`security.lateral_movement`) : les adresses
  TEST-NET sont considérées comme internes (RFC1918 / link-local).

### Option `treat_test_net_as_external` / `--test-net-external`

Pour les démonstrations utilisant des adresses TEST-NET, le beaconing **et**
l'exfiltration peuvent les traiter comme externes (issue #365) :

```bash
python3 src/cross_capture_analyzer_cli.py --capture A=demo.pcap \
    --security-report --test-net-external
```

En Python, l'option existe sur les deux jeux de seuils, et
`apply_security_findings(..., treat_test_net_as_external=True)` la transmet
aux deux détecteurs :

```python
from netcross_core.security.beaconing import BeaconingThresholds, detect_beaconing
from netcross_core.security.exfiltration import ExfiltrationThresholds, detect_exfiltration

detect_beaconing(packets, BeaconingThresholds(treat_test_net_as_external=True))
detect_exfiltration(packets, ExfiltrationThresholds(treat_test_net_as_external=True))
```

Seules les trois plages TEST-NET changent de statut : les autres adresses
privées (RFC 1918, link-local…) restent internes. Les mouvements latéraux
ne sont pas concernés : l'option ne s'y applique pas. La logique commune se
trouve dans `netcross_core.security.address_scope`.

Le comportement par défaut est figé par `tests/test_test_net_scope.py`.

## Inventaire pour le pipeline en flux

Issue #1020 (chantier #995). Avant de passer l'analyse en flux, chaque
détecteur est classé selon l'état qu'il doit garder pour décider :

- **incremental** : une seule passe, état indépendant du nombre de paquets
  (compteurs, agrégats par point, clé ou tranche, finalisés en fin de
  capture) ; compatible tel quel avec un pipeline en flux ;
- **fenetre_bornee** : rapproche des paquets (copies d'un même paquet à
  plusieurs points, requête et réponse, messages d'une transaction) ;
  l'état par clé peut être expiré après la fenêtre indiquée. Relève de la
  fenêtre glissante (#1022) et de l'expiration par flux (#1023) ;
- **seconde_passe** : la décision dépend de la capture entière ou relit les
  fichiers avec tshark ; relève de la seconde passe ciblée (#1025).

Provenance : `phase` = `with _phase(...)` de `analyse()` ; `en_ligne` = bloc
de `analyse()` hors phase nommée ; `signature` = registre de
`netcross_core.exploit_signatures` ; `securite` = détecteurs appelés par
`security.findings.apply_security_findings` (`--security-report`) ;
`diagnostic` = diagnostics TLS/QUIC de la CLI ; `greffon` = contrat des
greffons.

La source de vérité est `netcross_core.detector_inventory.DETECTEURS`.
`tests/test_detector_inventory.py` échoue si une phase de `analyse()`, une
signature enregistrée ou un détecteur de sécurité n'y est pas classé, si un
champ du rapport cité n'existe pas, ou si le tableau ci-dessous n'est plus
celui que produit `tableau_markdown()`.

<!-- inventaire-detecteurs:debut (généré par netcross_core.detector_inventory) -->

| Détecteur | Provenance | Classe | État conservé | Fenêtre | Champs du rapport | Note |
|---|---|---|---|---|---|---|
| `infer_topology` | phase | seconde_passe | écarts de TTL et ensembles de flux vus par paire de points | capture entière | `topology_edges` | recouvrement de Jaccard entre ensembles complets ; sans objet avec --order |
| `compute_throughput` | phase | incremental | octets par (point, tranche) | aucune | `throughput` |  |
| `detect_extracted_files` | phase | fenetre_bornee | charges utiles en cours de réassemblage par flux | durée du transfert de l'objet | `extracted_files` |  |
| `application_transactions` | phase | fenetre_bornee | requêtes HTTP/DNS en attente de réponse | seuil de réponse du protocole ; « réponse manquante » décidée à l'expiration | `application_transactions` |  |
| `pmtud` | phase | fenetre_bornee | segments retransmis en amont, par flux ; drapeau « ICMP trop grand vu » par point | durée des retransmissions d'un segment | `pmtud_blackhole` | l'absence d'ICMP « sur toute la capture » est un drapeau par point, finalisé en fin de capture |
| `idle_timeout` | phase | fenetre_bornee | plus long silence et reprise par connexion TCP (5-tuple orienté) | vie de la connexion, potentiellement toute la capture | `idle_timeout_dropped` | connexions longues : candidat au débordement sur disque (#1024) |
| `arp_ip_conflict` | phase | incremental | adresses MAC revendiquées par IP, par point | aucune | `arp_ip_conflict` |  |
| `stp_instability` | phase | incremental | compteurs TCN/TC et ponts racines vus, par point | aucune | `stp_topology_change`, `stp_root_change` |  |
| `tls_certificate` | phase | fenetre_bornee | numéro de série du certificat par connexion et par point | latence entre points adjacents | `tls_cert_invalid_dates`, `tls_cert_mismatch` | dates invalides : par paquet ; substitution : comparaison entre points |
| `tls_handshake` | phase | fenetre_bornee | ClientHello en attente de ServerHello par (IP, port) | délai de poignée de main | `tls_handshake_incomplete`, `tls_handshake_no_reply` |  |
| `retransmission_types` | phase | incremental | compteurs par point (drapeaux tcp.analysis de tshark) | aucune | `retrans_fast`, `retrans_rto`, `retrans_spurious` |  |
| `tcp_expert_signals` | phase | incremental | compteurs par point (drapeaux tcp.analysis de tshark) | aucune | `out_of_order`, `lost_segment`, `window_update` |  |
| `detect_sequence_gaps` | phase | fenetre_bornee | trous de séquence ouverts par flux orienté et par point | réordonnancement ; trou « jamais comblé » décidé en fin de flux | `sequence_gaps` | aujourd'hui tri des paquets de chaque flux : à remplacer par un suivi des trous ouverts |
| `validate_checksums` | phase | incremental | aucun (vérification paquet par paquet) | aucune | `checksum_errors` |  |
| `apply_expert_correlation` | phase | fenetre_bornee | alertes Expert Info horodatées par flux et par hôte | fenêtres des seuils de fuzzing / débordement / DoS | `expert_malformed`, `exploit_suspicion` | seuls les paquets en anomalie sont retenus |
| `saturation` | phase | incremental | aucun paquet : débit par tranche et pertes déjà agrégés | aucune | `saturation_verdict` | aval du rapport agrégé |
| `bufferbloat` | phase | incremental | aucun paquet : latence par tranche et débit déjà agrégés | aucune | `bufferbloat_hint` | aval du rapport agrégé |
| `handshake` | phase | fenetre_bornee | SYN en attente de SYN-ACK, par point | délai de connexion TCP (retransmissions du SYN comprises) | `syn_no_synack`, `syn_reply_missing`, `clock_offset_estimate` | fournit aussi l'estimation de décalage d'horloge utilisée par rtp |
| `tcp_options` | phase | fenetre_bornee | options du SYN / SYN-ACK par point | latence entre points adjacents | `mss_clamped`, `wscale_stripped`, `sack_stripped` |  |
| `rtp` | phase | incremental | par flux RTP (5-tuple + SSRC) et par point : dernière séquence, gigue, compteurs | aucune | `rtp_streams` | le délai bout en bout dépend du décalage d'horloge estimé par handshake |
| `response_time` | phase | fenetre_bornee | client de chaque connexion (SYN) et dernière requête en attente de réponse | temps de réponse serveur ; client connu pendant la vie de la connexion | `server_think_time` |  |
| `dhcp` | phase | fenetre_bornee | messages par xid et par point | durée d'une transaction DHCP | `dhcp_missing`, `dhcp_duration_ms` |  |
| `sip` | phase | fenetre_bornee | messages par Call-ID et par point | durée de l'appel | `sip_missing`, `sip_setup_duration_ms`, `sip_failed_calls` |  |
| `build_calls` | phase | fenetre_bornee | signalisation par Call-ID et résumés des flux RTP | appel + 300 s après le dernier message SIP sans BYE | `voip_calls` |  |
| `dns` | phase | fenetre_bornee | requêtes par dns.id et par point | délai de réponse DNS ; « sans réponse » décidé à l'expiration | `dns_missing`, `dns_timeout`, `dns_duration_ms` |  |
| `http` | phase | fenetre_bornee | requêtes HTTP/1.x en attente de réponse, par point | délai de réponse HTTP ; « sans réponse » décidé à l'expiration | `http_missing`, `http_timeout`, `http_response_time_ms` |  |
| `detect_exfiltration` | phase | incremental | octets, protocoles et bornes temporelles par (point, source, destination) | aucune | `exfiltration_alerts` | garde aussi la liste des numéros de trame par couple : à borner pour un état constant |
| `topn_timeseries` | en_ligne | incremental | octets par (point, catégorie, tranche) | aucune | `topn_timeseries` | classement top-N en fin de capture ; état proportionnel au nombre de catégories |
| `http_objects` | en_ligne | fenetre_bornee | requêtes HTTP en attente par flux | durée de la transaction | `http_objects` |  |
| `order_consistency` | en_ligne | seconde_passe | arêtes de topologie inférées | capture entière (dépend de infer_topology) | `topology_order_conflicts` |  |
| `vlan_encap_vus` | en_ligne | incremental | ensembles de VLAN et d'encapsulations par point | aucune | `vlan_seen`, `encap_seen` |  |
| `compteurs_flux_par_point` | en_ligne | fenetre_bornee | copies de chaque segment (clé de flux) par point | délai maximal entre deux copies d'un même segment (retransmission) | `retrans`, `dup_ack`, `zero_window`, `rst_count`, `ttl_unstable`, `rst_localized` | rst_localized exige de savoir que le segment n'est vu qu'à un point |
| `pertes` | en_ligne | fenetre_bornee | clés vues en amont et pas encore en aval ; conversations vues par point | latence maximale entre points + marge | `loss_count`, `off_path_count`, `loss_event_buckets` | la règle « hors chemin » (#352) demande l'état de conversation par point avec expiration (#1023) |
| `comparaison_paires` | en_ligne | fenetre_bornee | première copie de chaque clé à chaque point | latence maximale entre points + marge | `latency`, `latency_by_bucket`, `qos_change`, `hop_delta`, `qos_l2_remark`, `qos_l3_remark`, `vlan_change`, `pcp_change`, `vlan_tag_flip`, `encap_change` |  |
| `hop_delta_outliers` | en_ligne | incremental | histogramme des écarts de TTL par paire | aucune | `hop_delta_outliers` | mode calculé en fin de capture sur l'histogramme (petit) |
| `fragmentation` | en_ligne | fenetre_bornee | état fragmenté / encapsulation par datagramme (src, dst, ip.id) et par point | délai de réassemblage IP | `icmpv6_too_big`, `icmp_frag_needed`, `frag_count`, `frag_new`, `encap_frag_correlated` | compteurs ICMP : incrémentaux |
| `http2_rapid_reset` | signature | incremental | état de flux des signatures (_FlowState) | aucune |  | lecture dédiée des charges utiles de chaque fichier (security.findings.scan_capture_exploits) |
| `rdp_bluekeep` | signature | incremental | état de flux des signatures (_FlowState) | aucune |  | lecture dédiée des charges utiles de chaque fichier (security.findings.scan_capture_exploits) |
| `smb1_eternalblue` | signature | incremental | état de flux des signatures (_FlowState) | aucune |  | lecture dédiée des charges utiles de chaque fichier (security.findings.scan_capture_exploits) |
| `tls_compression` | signature | incremental | état de flux des signatures (_FlowState) | aucune |  | lecture dédiée des charges utiles de chaque fichier (security.findings.scan_capture_exploits) |
| `tls_heartbleed` | signature | incremental | état de flux des signatures (_FlowState) | aucune |  | lecture dédiée des charges utiles de chaque fichier (security.findings.scan_capture_exploits) |
| `build_service_fingerprints` | securite | incremental | logiciels identifiés, dédupliqués par (point, hôte, port, logiciel, version) | aucune | `service_fingerprints` |  |
| `build_fingerprint_records` | securite | incremental | empreintes JA4/HASSH dédupliquées par (point, hôte, type, valeur) | aucune | `service_fingerprints` |  |
| `detect_protocol_mismatches` | securite | incremental | aucun (décision paquet par paquet) | aucune |  | la liste des cas croît avec le nombre d'occurrences |
| `count_protocol_mismatches` | securite | incremental | compteurs par protocole et description | aucune | `protocol_mismatches` |  |
| `detect_dga` | securite | incremental | score et compteurs de réponses NXDOMAIN par domaine | aucune |  |  |
| `detect_fast_flux` | securite | fenetre_bornee | adresses A/AAAA horodatées par (point, nom) | window_seconds des seuils fast flux |  |  |
| `detect_lateral_movement` | securite | fenetre_bornee | cibles et tentatives par source (scans de ports et d'hôtes, force brute, protocoles, connexions) | fenêtres des seuils LateralMovementThresholds |  | nouvelles connexions : comparaison à une base, incrémentale |
| `analyze_flow_stats` | securite | incremental | par couple (source, destination) : premières tailles (SPLT), distributions, entropie, régularité | aucune |  | garde aujourd'hui les paquets de chaque couple : à remplacer par des agrégats |
| `build_asset_inventory` | securite | incremental | fiche par hôte (adresses, ports, services, points) | aucune |  |  |
| `detect_dns_tunneling` | securite | incremental | statistiques des requêtes par domaine parent | aucune |  |  |
| `detect_beaconing` | securite | fenetre_bornee | série d'horodatages par couple (source, destination) | durée d'observation d'une balise (plusieurs périodes) |  | séries longues : candidat au débordement sur disque (#1024) |
| `audit_tls_certificates` | securite | incremental | certificats vus, dédupliqués | aucune |  |  |
| `dns_tunnel_sources` | securite | incremental | (point, IP source) des requêtes vers les domaines suspects | aucune |  |  |
| `tls_diagnostics` | diagnostic | seconde_passe | événements TLS de chaque point | capture entière |  | --tls : relit les fichiers avec tshark (pipeline indépendant) |
| `quic_diagnostics` | diagnostic | seconde_passe | paquets QUIC Initial de chaque point | capture entière |  | --quic : relit les fichiers avec tshark |
| `greffons` | greffon | seconde_passe | DetectorContext : tous les paquets et le rapport, en lecture seule | capture entière |  | contrat de netcross_core.plugins.api ; un mode en flux devra proposer un contrat incrémental |

Total : 57 détecteurs -- incremental : 28, fenetre_bornee : 24, seconde_passe : 5.

<!-- inventaire-detecteurs:fin -->

Constats utiles pour la suite du chantier :

- seuls `infer_topology` / `order_consistency` (sans `--order`), les
  diagnostics `--tls` / `--quic` et les greffons demandent une vraie vue
  globale ;
- les rapprochements entre points (`pertes`, `comparaison_paires`,
  `compteurs_flux_par_point`) sont bornés par la latence maximale entre
  points : c'est la fenêtre glissante de #1022 ;
- quelques détecteurs classés incrémentaux gardent aujourd'hui des listes
  qui croissent avec le trafic (`detect_exfiltration`, `analyze_flow_stats`,
  `detect_protocol_mismatches`) ; ils sont signalés dans la colonne « Note ».

## Voir aussi

- [README.md](https://github.com/MathildeDec/Netcross/blob/dev/README.md) — vue d'ensemble du projet
- [CONTRIBUTING.md](https://github.com/MathildeDec/Netcross/blob/dev/CONTRIBUTING.md) — guide de contribution
