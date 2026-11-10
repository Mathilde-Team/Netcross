# Session 91 : WAV multi-points alignés (#1127)

L'extraction audio réutilise le même appariement RTP que les rapports via
`RtpLeg` et `match_rtp_legs`, sans reconstruire de paquets du moteur d'analyse.
Les décalages de timestamp reconnus sont retirés modulo 32 bits, puis chaque
point est placé sur l'origine média commune et la durée de l'union des
échantillons. Les pertes, même initiales ou finales, restent des silences.
Le WAV stéréo entrelace par blocs le premier et le dernier point du chemin.

La CLI transmet son ordre physique explicite à l'extracteur ; par défaut,
l'ordre des captures est retenu. Les mono alignés remplacent les exports
mono redondants dans les entrées du manifeste. Les flux non appariés gardent
le comportement historique. Une association RTP n'identifie pas une voix ;
l'origine média commune ne mesure pas le délai du réseau.

Les fichiers sont créés exclusivement, privés avant l'écriture du contenu,
et empreintés en SHA-256. Une erreur nettoie seulement les fichiers créés par
le groupe courant, pas un fichier préexistant ou créé concurremment.
La durée est bornée à une heure par groupe ; les durées invalides,
chevauchements et changements de payload type sont signalés sans troncature.
Le périmètre reste G.711 clair à 8000 Hz, sans déchiffrement SRTP.

Les essais ciblés relisent chaque échantillon mono et les quatre octets de
chaque trame stéréo, y compris sur plusieurs blocs. Ils couvrent les pertes
aux bords et internes, wraps, NAT/SBC, A-law/µ-law, doublons, désordre,
budgets, collisions, erreurs IO/WAV, nettoyage et permissions.
Un essai CLI écrit trois vrais PCAP et les décode avec TShark, avec captures
C/B/A mais chemin demandé A/B/C, puis vérifie les canaux A/C, le manifeste,
les empreintes et les quatre seuls fichiers WAV attendus.

Les 98 tests ciblés passent, à 99,70 % de couverture combinée du module média.
Le premier parcours complet a relevé deux doublures CLI d'ancienne signature :
elles sont adaptées et vérifient maintenant l'ordre transmis, sans retirer
leurs contrôles d'usage raisonné ou de qualité seule.

Après intégration normale de dev `030e72e` et régénération du diagramme,
la suite complète sous Xvfb passe : 7 502 réussites, un saut ERF préexistant,
111 avertissements, 236,44 secondes, couverture combinée 98,10 %, code zéro.
Hooks complets, mypy sur 244 fichiers et MkDocs strict sont verts.
La CI du dernier head et les fusions restent obligatoires avant de déclarer
la livraison terminée.
