# Seconde passe en flux (topologie)

**Issue [#1025](https://github.com/Mathilde-Team/Netcross/issues/1025)**
(chantier [#995](https://github.com/Mathilde-Team/Netcross/issues/995),
sous-issue 6/6) · exemple : `--capture LAN=… --capture WAN=… --streaming --json-report rapport.json`

L'inventaire des détecteurs (issue [#1020](https://github.com/Mathilde-Team/Netcross/issues/1020))
classe `infer_topology` en détecteur **seconde passe** : sa décision dépend d'agrégats
couvrant la capture entière (flux vus par paire de points, votes de TTL entre
premiers paquets). Le mode en flux l'exécute désormais de façon bornée :
**`streaming.seconde_passe`** dans le rapport JSON (`--streaming`).

## Comment ça marche

Deux passes distinctes, comme en batch :

1. **Au fil de l'eau (`feed`)** — un enregistrement compact par (flux, point) :
   l'horodatage et le TTL du *premier* paquet du flux au point (exactement ce
   que compare la déduction batch, `_stats_topologie`). ARP et STP sont exclus
   (mêmes exclusions que `correlate`), les doublons sont exclus avec
   `--exclude-duplicates`. Un seul enregistrement par (flux, point) : la mémoire
   est proportionnelle au nombre de flux, pas au nombre de paquets.
2. **À la fermeture (`finish`)** — reconstruction des agrégats de la passe
   déportée (flux vus par point, votes de TTL par paire), puis la même déduction
   que le mode batch (`_deduire_topologie`) : mêmes seuils, mêmes arêtes, mêmes
   ambiguïtés, mêmes branchements/fusions/isolés.

Les flux sont identifiés par `flow_key` (nat-tolerant avec
`--nat-tolerant` / `--nat-window-ms`, `--exclude-duplicates` avec la même
option). Au-delà du seuil de débordement `--spill-seuil` (issue [#1024](https://github.com/Mathilde-Team/Netcross/issues/1024)),
les agrégats sont déportés sur disque (SQLite temporaire) puis relus en un
seul parcours à la fermeture — la topologie ne change pas.

## Rapport JSON

```json
{
  "streaming": {
    "seconde_passe": {
      "topology_edges": [["LAN", "WAN", {"confiance": "forte", "flows": 118, "jaccard": 0.94}]],
      "topology_ambiguous": [],
      "topology_isolated": [],
      "topology_branch_points": [],
      "topology_merge_points": []
    }
  }
}
```

## Équivalence avec le mode actuel

La seconde passe reproduit exactement `_infer_topology(correlate(paquets), points)` :
les tests croisent les deux modes sur du trafic synthétique (TTL décroissant
le long du chemin, pertes, flux locaux isolés), avec débordement sur disque
(`--spill-seuil` petit) et sans `--order`, et sur les exemples du guide
(`docs/guide/exemples/lan.pcap` + `wan.pcap`).

## Restent hors de cette passe ciblée

Voir l'issue [#1025](https://github.com/Mathilde-Team/Netcross/issues/1025) :
les deux autres détecteurs classés seconde passe (`clock_sync`,
`detect_microbursts`), l'équivalence complète du rapport, et le basculement du
défaut vers `--streaming` (décision humaine explicitement demandée par
l'issue).
