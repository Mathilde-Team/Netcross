# Session 87 : transport RTP par segment (#1123)

L'appariement multi-points de #1121 est réutilisé sans modifier ses critères.
Une passe indépendante normalise les couples séquence/horodatage, déduplique
les paquets et compare seulement la fenêtre commune, afin de ne pas attribuer
à un segment une perte déjà présente en amont ou un bord de capture absent.

Les deltas corrigés conservent l'incertitude d'horloge et sa propagation dans
le temps. Le sens retour n'est retenu que si l'horloge permet de le distinguer.
La note de transport expose ses hypothèses G.711 et son périmètre RTP/SRTP :
aucun contenu ni qualité perçue n'est mesuré.

Les 69 tests ciblés couvrent le rapport JSON et la synthèse, les pertes aval,
les décalages NAT/SBC, les passages à zéro, les doublons, la dérive et
l'incertitude, avec 100 % des lignes et branches du nouveau module.
La première suite complète sous Xvfb confirme un code de sortie nul,
7 341 réussites, un saut préexistant et 111 avertissements, à 98,08 %
de couverture combinée. Hooks, mypy et MkDocs strict passent également.

Quatre tests ajoutés ensuite écrivent trois vrais fichiers PCAP synthétiques
et les décodent avec TShark : pertes uniquement sur le dernier segment,
absence de perte, puis les deux cas après anonymisation. Ils passent et
vérifient la restitution JSON et la localisation du constat, sans substituer
ces quatre essais à une nouvelle suite complète sur l'arbre final intégré.
La synchronisation de dev, la CI et la livraison jusqu'à main restent
nécessaires avant toute clôture.
