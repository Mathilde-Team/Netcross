# Catalogue des métriques Prometheus

Catalogue figé par #1110 (chantier #1003), **avant** toute exposition. Le
texte OpenMetrics et le fichier `.prom` (#1112), la route `/metrics` (#1113)
et le tableau de bord Grafana (#1118) reprennent ces noms sans les modifier.
La définition fait foi dans `src/netcross_report/metrics_export.py`
(`METRICS`) ; `tests/test_metrics_export.py` vérifie que cette page la suit.

## Conventions

- Préfixe `netcross_`, puis domaine (`point`, `segment`, `health`,
  `findings`), en snake_case.
- Unités SI en suffixe : `_seconds` (jamais de millisecondes), `_ratio` pour
  une proportion comprise entre 0 et 1.
- `_total` pour les compteurs, et seulement pour eux.
- Un résumé (`summary`) porte l'étiquette `quantile` et expose aussi
  `<nom>_count` et `<nom>_sum`. Sans échantillon, les quantiles valent `NaN`.

## Métriques

| Nom | Type | Étiquettes | Signification |
|---|---|---|---|
| `netcross_health_score` | gauge | `run` | Score de santé global (0 à 100), comme dans les rapports |
| `netcross_findings_total` | counter | `run`, `severity` | Nombre de constats par sévérité (`anomalie`, `a_surveiller`, `info`) |
| `netcross_point_packets_total` | counter | `run`, `point` | Paquets vus au point de capture |
| `netcross_point_flows_total` | counter | `run`, `point` | Flux vus au point |
| `netcross_point_lost_flows_total` | counter | `run`, `point` | Flux vus au point précédent et absents de celui-ci |
| `netcross_point_retransmissions_total` | counter | `run`, `point` | Retransmissions TCP observées au point |
| `netcross_segment_loss_ratio` | gauge | `run`, `segment` | Flux perdus en aval / flux vus en amont du segment |
| `netcross_segment_delay_seconds` | summary | `run`, `segment`, `quantile` | Délai de transit entre les deux points (quantiles 0.5, 0.95, 0.99) |
| `netcross_segment_triage_score` | gauge | `run`, `segment` | Score de priorité du segment dans le triage |

Exemple de séries (format OpenMetrics à venir avec #1112) :

```text
netcross_segment_loss_ratio{run="inc-42",segment="ROUTEUR -> SERVEUR"} 0.0909
netcross_segment_delay_seconds{run="inc-42",segment="CLIENT -> ROUTEUR",quantile="0.95"} 0.0385
netcross_findings_total{run="inc-42",severity="anomalie"} 1
```

## Étiquettes et cardinalité

Seules cinq étiquettes existent :

- `run` : identifiant de l'analyse ;
- `point` : nom du point de capture ;
- `segment` : paire de points consécutifs, `"A -> B"` ;
- `severity` : sévérité du constat ;
- `quantile` : quantile d'un résumé.

**Aucune adresse IP, aucun port, aucun nom d'hôte ni aucun identifiant de
flux** n'est jamais une valeur d'étiquette. Le nombre de séries ne dépend donc
que du nombre de points `P` et de segments `S`, jamais du volume de trafic :

```text
séries <= 1 + 3 + 4 × P + 7 × S
```

Par analyse, ce qui donne 30 séries pour 3 points et 2 segments, que la
capture compte 50 ou 5 000 flux. Au-delà de 32 points ou de 64 segments
(paramètres `max_points` et `max_segments`), le surplus est regroupé sous
l'étiquette `"_autres"`, ce qui garde la borne.

## Limites

- Le catalogue ne couvre que les grandeurs disponibles dans le rapport. Les
  métriques par flux ou par hôte sont volontairement exclues : elles
  passeront par l'export Zeek `conn.log` (#1115).
- `netcross_segment_triage_score` ne compte que les constats dont le segment
  est exactement `"A -> B"`. Les constats rattachés à un seul point restent
  visibles dans `netcross_point_*`.
