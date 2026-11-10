# Session 90 : corrélation des microrafales et impacts aval

Date : 10/11/2026 (Paris). Issue #1137, dépendance #1135 terminée.
Le travail porte sur la branche `feat/1137-correlation-rafales-pertes`,
initialisée depuis dev puis actualisée avec les contributions suivantes.

## Réalisation

Le corrélateur de `netcross_core.causality` reçoit les épisodes déjà détectés,
les pertes réellement localisées par la boucle d'analyse après sa garde
hors chemin, et les copies TCP supplémentaires observées au point aval.
Les retransmissions déjà vues en amont, les ACK purs et les doublons marqués
ne deviennent pas de nouveaux impacts du segment.

Les paquets communs doivent encadrer strictement l'instant de l'impact :
les trames manquantes en début ou fin de capture ne prouvent pas une perte.
Le chemin doit être ordonné explicitement. Une perte utilise l'horloge de son
observation amont ; une copie TCP aval est ramenée à cette horloge par inversion
du modèle affine de décalage et dérive, en tenant compte de son incertitude.

La fenêtre de 50 ms par défaut commence à la fin de l'épisode. La variable
`NETCROSS_MICROBURST_WINDOW_MS` configure tous les processus CLI/API/GTK4 ;
`analyse(..., microburst_window_ms=...)` est prioritaire en Python. Les valeurs
invalides échouent explicitement. Les deux bornes sont inclusives, sans
soustraction flottante susceptible de rejeter la borne finale exacte.

Les compteurs sont exacts ; chaque couple épisode/segment conserve au plus
dix preuves, avec le vrai point, la trame observée si disponible, les deux
horodatages et l'incertitude. Les résultats sont partagés dans les constats,
la console et `microburst_correlations` du document JSON ; la règle stable
`microburst_downstream_impact` rejoint le catalogue et ses tests exhaustifs.
L'inventaire et le diagramme de classes sont actualisés.

## Vérifications

La campagne ciblée initiale confirme 148 réussites, dont deux parcours CLI
sur de vrais PCAP synthétiques à trois points décodés par TShark. Avec une
perte aval, seule B -> C reçoit un constat ; sans perte, aucun constat n'est
produit. Le module causalité atteint 100 % des lignes et des branches.
La suite complète et les contrôles finaux sont consignés après leur exécution,
pas déduits de cette campagne ciblée.

Après intégration de dev `1f2ee59`, la suite complète sous Xvfb confirme
7 410 réussites, un saut ERF préexistant, 111 avertissements, 282,46 secondes,
98,09 % de couverture combinée et code de sortie zéro. Les hooks complets,
mypy sur les 244 fichiers sources et MkDocs strict passent également.
Ces résultats précèdent le premier push ; ils ne remplacent pas la CI du
dernier head ni une vérification après livraison sur main.

Les premiers tests ont détecté puis corrigé une exclusion de la borne finale
par arrondi flottant. Le test de l'incertitude a également été précisé pour
comparer la demi-largeur après inversion de la dérive, pas avant.

## Limites

Le résultat établit une association temporelle et spatiale, pas une preuve
de congestion physique. La collecte peut perdre ou dupliquer des paquets ;
un rejeu ou un incident indépendant reste possible. Les rapports exposent
`physical_cause_proven=false` et demandent de vérifier les files et la qualité
des captures. Aucun trafic externe, test matériel ou réseau client n'est utilisé.
La configuration d'environnement ne constitue pas un nouveau champ HTTP
ni un contrôle graphique ; le service API la reçoit au démarrage.
