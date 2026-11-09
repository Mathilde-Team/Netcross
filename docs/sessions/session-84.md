# Session 84 : délais corrigés bidirectionnels (#996)

L'audit indépendant du parent a exercé le parsing de PCAP synthétiques
sur une heure, les sources DNS sans handshake TCP, la dérive et les
aberrants, puis les sorties JSON/PDF et le décalage manuel.

Le jeu révèle une annulation des délais aller et retour dans la moyenne
du segment. Un test à décalage connu isole le défaut : les six variantes
avec décalage de -37, 0 ou +37 ms, avec ou sans RTP, échouent avant
correction. Le cas sans estimation conserve déjà correctement le delta
signé nécessaire au diagnostic.

Après correction d'horloge, la durée de transit est désormais la valeur
absolue du delta corrigé. Le changement concerne la latence par segment,
ses fenêtres temporelles et le délai RTP ; sans estimation, le delta
signé reste inchangé. Les règles d'incertitude ne sont pas désactivées.

Les sept nouveaux cas réussissent après correction, ainsi que 284 tests
ciblés et la suite complète : 7 217 réussites, un saut ERF préexistant.
La couverture distingue 98,3503 % des lignes et 97,1674 % des branches,
sans exclusion ajoutée. Ruff, le format des 572 fichiers, import-linter,
les hooks, mypy et la construction MkDocs stricte réussissent.

Les huit audits externes réussissent également, dont les PCAP synthétiques
réellement parsés avec +37 ms, +15 ppm sur une heure et, selon le cas,
10 % d'aberrants de +500 ms. La moyenne et la gigue bidirectionnelles
sont maintenant contrôlées, et pas seulement les paquets sondes.
Le parcours CLI JSON/PDF retrouve environ 5,00008 ms et une gigue
négligeable sans aberrants ; il conserve « non mesurable » puisque
l'intervalle d'incertitude de 13,87 ms dépasse le délai.

Les CI du dernier head, le relais et les vérifications sur main doivent
encore réussir avant de déclarer le parent terminé. Ces jeux synthétiques
ne constituent pas une validation sur équipement ou réseau client.
