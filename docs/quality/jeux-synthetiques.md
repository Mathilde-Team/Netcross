# Jeux synthétiques multi-points

Issue #1015 (sous-issue 1/5 du banc de performance #994).

`netcross_core.testing.synth` produit, pour un chemin linéaire
`P1 → … → PN`, un fichier pcapng par point et un fichier `verite.json` qui
décrit exactement ce qui a été injecté. Ces jeux servent de référence au
banc de performance et, plus tard, aux tests d'équivalence du pipeline en
flux.

## Utilisation

```bash
# un jeu : 3 points, 10⁵ paquets, 1 % de pertes sur le segment P2 → P3
python3 scripts/bench_datasets.py --sortie /tmp/jeu --points 3 --paquets 100000 \
    --segment-perte 2 --taux-perte 0.01 --graine 7

# retard de 20 ms sur le segment 1 pendant le tiers central, horloges décalées
python3 scripts/bench_datasets.py --sortie /tmp/jeu --points 3 \
    --segment-retard 1 --retard-ms 20 --decalages-ms 0,3.5,-1

# matrice standard : points 2, 3, 5, 10 x paquets 10⁴, 10⁵, 10⁶
python3 scripts/bench_datasets.py --sortie /tmp/banc --matrice
```

Chaque jeu de la matrice est rangé dans `p<points>-n<paquets>-g<graine>/`.
Depuis Python : `generer(Configuration(...), dossier)` renvoie la vérité
terrain.

## Garanties

- **Déterminisme** : même graine et mêmes paramètres ⇒ mêmes octets
  (horodatages entiers en nanosecondes, aucun nom d'hôte, OS ni date
  machine dans les blocs). Les empreintes SHA-256 sont dans `verite.json`.
- **Sans tshark** : trames Ethernet/IPv4/TCP/UDP construites octet par
  octet, sommes de contrôle IP/TCP/UDP valides, pcapng à résolution
  nanoseconde (`if_tsresol = 9`), interface nommée d'après le point.
- **Mémoire bornée** : 5 points × 10⁶ paquets en environ 40 s pour
  ~45 Mo de RSS (mesure locale) ; 10 points × 10⁶ paquets ≈ 4 Go sur disque.

## Contenu

| Type | Échange |
|------|---------|
| `tcp` | poignée de main, 2 à 12 segments de données (ports 80, 8080, 22, 3306), fermeture FIN |
| `tls` | idem sur 443 avec ClientHello (SNI `synth-<n>.example.test`), ServerHello et enregistrements applicatifs |
| `dns` | requête A et sa réponse |
| `udp` | 5 à 25 datagrammes à 20 ms (type média), sens aller |

Le mélange est réglable (`Configuration.melange`, défaut 40/30/20/10 %).

## Modèle de chemin

Client en amont de `P1`, serveur en aval de `PN`. Le segment `k` relie
`Pk` à `Pk+1`. Chaque traversée ajoute `delai_segment_ms ± gigue_ms` et
décrémente le TTL (somme IP recalculée). `--paquets` compte les paquets
émis (client et serveur) : c'est ce que voit un point placé avant toute
perte.

- **Pertes** : sur le segment `segment_perte`, chaque paquet *perdable*
  du sens visé (`aller`, `retour`, `les_deux`) est perdu avec la
  probabilité `taux_perte`. Seuls les segments de données TCP/TLS et les
  datagrammes UDP hors DNS sont perdables : perdre un SYN, un FIN ou une
  requête DNS sans retransmission rendrait la suite du flux incohérente.
  Un paquet perdu dans le sens aller est vu jusqu'à `Pk` ; dans le sens
  retour, de `PN` jusqu'à `Pk+1`.
- **Retard** : `retard_ms` s'ajoute sur le segment `segment_retard` pour
  les paquets qui y entrent pendant le tiers central de la durée estimée
  (fenêtre en ns dans `verite.json`).
- **Horloges** : `decalages_ms` (une valeur par point) décale les
  horodatages écrits, sans changer l'ordre des paquets.

## Vérité terrain

`verite.json` contient : la configuration, les points et segments,
`paquets_emis`, `paquets_par_point`, `flux_par_type`, la perte (segment,
sens, taux, `paquets_perdus` et ventilation par type), le retard (segment,
valeur, fenêtre, paquets concernés), les décalages d'horloge et l'empreinte
SHA-256 de chaque fichier.

Les compteurs Netcross peuvent différer légèrement de la vérité : la
corrélation TCP utilise (5-tuple, numéro de séquence), et le premier
segment de données partage son numéro de séquence avec l'ACK de la
poignée de main ; sa perte n'est alors pas vue comme telle. Le test
`test_netcross_localise_la_perte_sur_le_bon_segment` vérifie que la perte
est localisée au bon point et que le compte ne dépasse jamais la vérité.
