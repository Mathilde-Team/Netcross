# Session 82 : confirmation active explicite (#1068)

Le raccordement CLI/API n'émet rien par défaut. La simulation affiche des
commandes validées sans lancer de processus, socket ni résolution DNS,
et reste prioritaire sur l'activation. L'API exige aussi l'autorisation de
l'opérateur du serveur avant une émission.

Les preuves paquet univoques et les clés réellement en perte collectées
par le détecteur sont reliées à leurs flux. La collecte de ces clés est
désactivée en analyse passive. Les constats agrégés sans ces preuves et
les références ambiguës sont explicitement non sondables.
Les mesures sont bornées à huit et réutilisent les backends Paris/TWAMP
existants, sans élévation de privilège. Les résultats et leurs limites
sont publiés dans les sorties texte, JSON, PDF, Markdown et HTML.

Les tests vérifient la non-émission, les priorités des options, le refus
des adresses anonymisées, les budgets, les erreurs partielles et les
parcours CLI/API alimentés par des paquets typés PMTUD. Les restitutions
PDF et HTML sont contrôlées séparément. Les parcours HTML de filtres,
preuves, zoom et carte ont été rejoués, ainsi que la lecture sans
JavaScript et à 375 px.

Un contrôle complémentaire de la CLI, alimenté par des paquets typés et
non par des fichiers de capture réels, utilise un véritable réflecteur
TWAMP sur 127.0.0.1 : zéro sonde en mode passif, dix envoyées et reçues
après activation. Le port de test est libre, substitué au port standard
862, privilégié dans cet environnement ; aucun droit n'est élevé. Paris
y reste indisponible faute de Scamper. Ces contrôles ne certifient ni un
réseau de production ni l'accessibilité du port 862.

La validation complète et le suivi CI doivent être terminés avant fusion.
