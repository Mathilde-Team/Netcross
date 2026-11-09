# Transport RTP par segment

L'issue #1123 complète l'[appariement RTP entre points](appariement-rtp.md).
Le rapport JSON expose `rtp_segments` pour les flux appariés sur un chemin
explicitement ordonné. La synthèse réutilisée par les rapports et les interfaces
localise une dégradation observée sur le segment concerné.

## Mesures

- **Pertes supplémentaires** : couples (séquence, horodatage RTP) normalisés
  selon les décalages NAT/SBC déjà reconnus. Les doublons sont dédupliqués.
  Le dénominateur est le nombre de paquets amont entre le premier et le dernier
  paquet commun. Les bords tronqués d'une capture et les pertes déjà présentes
  aux deux points ne sont donc pas imputés une nouvelle fois au segment.
- **Gigue** : interarrival jitter RFC 3550 aux deux points, calculé sur les
  mêmes paquets communs, avec passage à zéro des horodatages RTP 32 bits.
  `added_jitter_ms` retient uniquement la différence positive aval moins amont.
- **Délai** : médiane des deltas de capture des paquets communs, corrigés par
  l'estimation d'horloge au temps de chaque paquet, dérive comprise.
  `clock_uncertainty_ms` est la borne conservatrice maximale
  `ic_decalage_ms + abs(t - t0) * ic_derive_ppm / 1000`.
  `delay_ms` reste `null` sans estimation ou si l'incertitude atteint ou dépasse le delta.
  `signed_delta_ms` conserve alors une observation, pas un délai physique.

Le nom canonique `segment` suit l'ordre du chemin. Si la correction d'horloge
permet de déterminer un sens retour, `upstream` et `downstream` sont inversés
pour compter les pertes dans le sens média. Sans cette preuve, les comptes
suivent l'ordre fourni et `direction_confirmed` reste faux. Sans ordre explicite
ou avec moins de deux paquets communs, aucune mesure par segment n'est publiée.

## Note et constat

`transport_quality` va de 100 (transport de référence) à 0 ; `degradation`
est son complément. Cette estimation réutilise le R-factor de l'E-model
simplifié déjà employé par Netcross, avec l'hypothèse G.711 explicitement
annoncée, une base de paquetisation de 20 ms, un tampon estimé à deux fois la
gigue ajoutée, le délai mesurable éventuel et le taux de pertes supplémentaires.
La référence est le même modèle à 20 ms sans perte. Ce n'est ni une écoute,
ni une identification du codec, ni une mesure de qualité audio perçue.

Le constat « Dégradation de transport RTP/SRTP » apparaît si au moins un paquet
est perdu dans la fenêtre commune, si la gigue ajoutée atteint 5 ms, ou si le
délai corrigé mesurable atteint 150 ms. Sa taille d'échantillon est conservée
pour ne pas présenter un taux sur quelques paquets comme une certitude.
La sévérité reste « à surveiller » : des pertes de capture doivent être exclues
avant d'attribuer la disparition au réseau.

## SRTP et limites

Le calcul n'accède à aucune charge utile : il ne déchiffre ni ne décode le son.
Il s'applique aux en-têtes RTP/SRTP lisibles et indique toujours `scope=transport`
avec une note explicite sur cette limite. Il ne déduit pas qu'un flux est
chiffré à partir de sa seule forme et ne prétend pas détecter SRTP sans métadonnée.
Un flux que le parseur ne reconnaît pas comme RTP reste hors de cette analyse.

L'horloge RTP reprend le paramètre d'analyse existant (8 000 Hz par défaut),
pas une horloge de codec devinée. La gigue et la note exigent une valeur adaptée
au média étudié. Cette passe utilise les paquets de l'analyse en mémoire ; elle
ne démontre pas une nouvelle borne mémoire du pipeline en flux.

Les tests sont synthétiques : pertes uniquement sur le dernier segment,
pertes communes, bords tronqués, doublons, NAT/SBC, passages à zéro, dérive,
incertitude et sens retour. Quatre essais supplémentaires écrivent trois PCAP
Ethernet/IPv4/UDP/RTP puis les décodent réellement avec TShark, avec/sans perte
sur le dernier segment et avec/sans anonymisation avant analyse. Ils vérifient
les délais, la localisation du constat et l'absence d'adresses originales
dans le JSON anonymisé. Aucune validation sur appel client ou équipement
physique, ni de déchiffrement SRTP, n'est revendiquée.
