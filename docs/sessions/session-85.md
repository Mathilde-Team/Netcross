# Session 85 : expiration et mémoire de l'état par flux (#1023)

La réalisation initiale des PR #1252/#1258 reste créditée à deusyv.
L'audit indépendant après livraison a reproduit 101 états ouverts au
lieu de deux lorsqu'un TCP à délai long bloquait des UDP expirés, puis
1 000 historiques TCP en RAM alors qu'aucun flux n'était actif.

Huit des neuf premières régressions échouaient : délais hétérogènes,
NaN/infinis ou délais directs invalides, et croissance de l'historique.
Le correctif indexe les échéances dans un tas compacté, valide les délais
et déplace les résumés/coupures dans un historique SQLite temporaire privé.
Le cache natif est borné et les fichiers sont nettoyés à la fin ou à la
finalisation, sans oubli silencieux des preuves NAT tardives.

Une extension de l'audit d'équivalence a ensuite reproduit neuf échecs
sur quinze cas : un flux revu tardivement en aval ou plusieurs silences
pouvaient laisser un faux positif. Des statistiques globales compactes
par point sont maintenant conservées avec l'historique sur disque ;
la réconciliation finale retient le premier plus grand silence, comme
le batch, à seuil TCP identique.

Les 65 tests ciblés réussissent ; les deux modules ont 100 % de lignes
couvertes et plus de 98 % de branches couvertes. La première suite globale
a trouvé deux écarts de livraison, pas un résultat entièrement vert :
le diagramme généré était obsolète et deux propagations d'erreur manquaient
de trace de sortie debug. Les traces ont été ajoutées et le diagramme
régénéré, sans modifier la référence d'audit ni aucun seuil.

Les validations complètes finales, hooks, CI, relais vers main et
vérifications finales restent nécessaires avant clôture. Le reste du
pipeline #995 n'est pas déclaré borné : sa lecture entière et les autres
composants conservent leurs limites propres.
