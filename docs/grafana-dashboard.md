# Tableau de bord Grafana d'exemple

Issue #1118 (sous-issue 5/5 du chantier [export observabilité
#1003](https://github.com/Mathilde-Team/Netcross/issues/1003)). Objectif :
brancher Netcross dans Grafana en cinq minutes, sur le
[catalogue de métriques figé](metriques-prometheus.md) (`netcross_*`).

## 1. Exposer les métriques

Deux chemins, sans nouveau composant côté Netcross :

- **analyse ponctuelle** : `--prom-file` écrit le texte Prometheus 0.0.4
  pour le *textfile collector* de node_exporter
  (`--collector.textfile.directory=/var/lib/node_exporter/textfile`) —
  voir la [page du catalogue](metriques-prometheus.md#fichier-prom-et-openmetrics) ;
- **capture en direct** : la [route `/metrics`](metriques-prometheus.md#route-api-en-direct)
  de l'API sert le dernier relevé (authentification habituelle, aucune
  mesure inventée).

Configuration Prometheus pour la route directe :

```yaml
scrape_configs:
  - job_name: netcross
    metrics_path: /metrics
    scheme: http          # ou https selon votre déploiement de l'API
    static_configs:
      - targets: ["netcross-api:8000"]
    # si NETCROSS_API_TOKEN est configuré :
    # authorization:
    #   credentials_file: /etc/prometheus/netcross-token
```

## 2. Importer le tableau de bord

Le tableau de bord d'exemple est [`docs/grafana/netcross-segments.json`](https://github.com/Mathilde-Team/Netcross/blob/dev/docs/grafana/netcross-segments.json) :

1. Grafana → *Dashboards* → *New* → *Import* ;
2. coller le JSON (ou le charger depuis le dépôt) ;
3. choisir la source Prometheus qui scrape Netcross (`DS_PROMETHEUS`).

Deux variables en haut de page : `$run` (analyse affichée) et `$segment`
(sélection multiple, « All » par défaut). Rafraîchissement : 30 s — la
route ne sert que le dernier relevé, les courbes avancent par paliers à
chaque analyse ou tick de capture.

## 3. Ce que montrent les panneaux

| Panneau | Métrique | Lecture |
|---|---|---|
| Score de santé | `netcross_health_score` | 0 à 100, seuils couleur 60/80 |
| Pertes par segment | `netcross_segment_loss_ratio` | flux perdus en aval / vus en amont |
| Délai de transit par segment | `netcross_segment_delay_seconds` | quantiles 0.5 / 0.95 / 0.99 |
| Score de triage par segment | `netcross_segment_triage_score` | priorité du segment (constats exactement `A -> B`) |
| Constats par sévérité | `netcross_findings_total` | anomalie / à surveiller / info |
| Paquets, flux perdus, retransmissions par point | `netcross_point_*` | vue par point de capture |

Les panneaux « Par segment » se limitent à `$segment` ; les panneaux
« Par point de capture » montrent tous les points du dernier relevé.
Au-delà des bornes (`max_points`, `max_segments`), le surplus est
regroupé sous l'étiquette `_autres` : le tableau de bord n'a rien à
faire de plus, la cardinalité reste bornée.

## 4. Exemples d'alertes Prometheus

Règles prêtes à coller dans Prometheus (adapter les seuils à votre
réseau) :

```yaml
groups:
  - name: netcross
    rules:
      - alert: NetcrossPerteSegmentElevee
        expr: netcross_segment_loss_ratio > 0.10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Perte de flux > 10 % sur {{ $labels.segment }}"
          description: "run {{ $labels.run }} : {{ $value | humanizePercentage }} des flux vus en amont sont absents en aval."

      - alert: NetcrossDelaiP95Eleve
        expr: netcross_segment_delay_seconds{quantile="0.95"} > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Délai p95 > 100 ms sur {{ $labels.segment }}"

      - alert: NetcrossSanteBasse
        expr: netcross_health_score < 80
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "Score de santé Netcross {{ $value }} sur {{ $labels.run }}"

      - alert: NetcrossFluxPerdusEnPoint
        expr: increase(netcross_point_lost_flows_total[10m]) > 0
        labels:
          severity: info
        annotations:
          summary: "Flux perdus au point {{ $labels.point }} (capture ou amont)"
```

Les deux premières alertent sur le réseau (`segment`), la dernière
distingue « la sonde a perdu » de « le réseau a perdu » : à croiser
avec l'état de santé de la capture elle-même.

## Limites

- Le tableau de bord n'affiche que les métriques du catalogue
  (`metriques-prometheus.md`) : les grandeurs par flux ou par hôte
  passent par l'export Zeek `conn.log`, pas par Grafana.
- La route `/metrics` ne garde que le **dernier** relevé par processus :
  l'historique vient de Prometheus, pas de Netcross.
- Ce tableau de bord est un exemple : les requêtes et seuils sont à
  adapter au site (nombre de points, tolérance de perte, budget de
  délai).
