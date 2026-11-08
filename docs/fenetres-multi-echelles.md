# Débit crête multi-échelle

Brique de calcul du chantier microrafales (#1005, issue #1133). Une microrafale de quelques centaines de
microsecondes au débit de ligne disparaît dans une moyenne à la seconde. Le module `netcross_core.multiscale`
mesure donc le débit crête de chaque point à plusieurs échelles de temps à la fois : 100 µs, 1 ms et 10 ms par
défaut.

## Ce qui est calculé

Pour chaque échelle, le module cherche la fenêtre de cette durée qui contient le plus d'octets, quelle que soit sa
position dans le temps. Il ne découpe pas la capture en tranches fixes, qui couperaient une rafale en deux. Chaque
fiche donne :

| Champ | Contenu |
|---|---|
| `scale_s`, `scale` | échelle en secondes et en texte (`100 µs`) |
| `peak_bytes`, `peak_packets` | octets et paquets de la fenêtre la plus chargée |
| `peak_bps` | débit crête : `peak_bytes × 8 / échelle` |
| `peak_start`, `peak_end` | horodatages du premier et du dernier paquet de cette fenêtre |
| `utilisation_pct` | débit crête en % de la vitesse de l'interface, si elle est connue (`if_speed` ou `--link-speed`, voir #1132) |
| `max_window_packets` | plus grand nombre de paquets gardés en mémoire pour cette échelle |

## Exactitude et mémoire

- La fenêtre est semi-ouverte : `]t − échelle, t]`. Deux paquets séparés d'exactement 1 ms ne sont jamais comptés
  dans la même fenêtre de 1 ms.
- La crête maximale est toujours atteinte par une fenêtre qui se termine sur un paquet. Il suffit donc d'évaluer la
  fenêtre à chaque arrivée de paquet pour obtenir la valeur exacte.
- Seuls les paquets de la fenêtre courante restent en mémoire, une file par échelle. La mémoire dépend de la densité
  du trafic dans la plus grande échelle, pas de la taille de la capture. Le calcul accepte les paquets un par un
  (`MultiScaleRates.update`) : il fonctionne avec la corrélation en flux (`--streaming`).
- Un paquet légèrement en retard (réordonnancement à la capture) est compté au dernier instant vu. Le nombre de ces
  paquets est donné dans `reordered`.

## Refus des échelles trop fines

Si l'horodatage d'un point n'a qu'une précision de 1 ms (`if_tsresol`), une fenêtre de 100 µs ne veut rien dire :
deux paquets distincts peuvent porter la même date. Une telle échelle est donc refusée explicitement :

- `MultiScaleRates(..., ts_resolution=...)` et `check_scale` lèvent `ScaleTooFineError` ;
- `multiscale_peaks` ne calcule pas cette échelle pour ce point et la liste dans `refused` avec la raison, par
  exemple « échelle 100 µs refusée : plus fine que la résolution d'horodatage du point R (1 ms, if_tsresol) ».

Les horodatages sont manipulés en secondes `float`. Près de l'époque actuelle, ce type n'a qu'une granularité
d'environ 0,24 µs. Les dates sont donc arrondies au quantum d'horodatage du point (1 µs au minimum), et toute échelle
inférieure à 1 µs est refusée.

## Utilisation

```python
from netcross_core.link_speed import resolve_link_speeds
from netcross_core.multiscale import multiscale_peaks

speeds = resolve_link_speeds(captures, overrides)  # if_speed, if_tsresol
peaks = multiscale_peaks(packets_by_point, speeds)  # {point: {"scales": [...], "refused": [...]}}
```

## Limites

- Le module calcule seulement les crêtes. Il ne décide pas de ce qui constitue une microrafale (#1135). Il ne fait
  pas non plus le lien avec les pertes du segment aval (#1137), et ses résultats n'apparaissent pas encore dans le
  rapport (#1139).
- La taille comptée est celle de la trame capturée (`length`). Le préambule et l'espace inter-trames Ethernet ne
  sont pas comptés : le taux d'occupation est donc légèrement sous-estimé pour les petites trames.
