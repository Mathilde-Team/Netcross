# Confirmation active

Les options de confirmation active complètent un constat passif par une
mesure postérieure. Elles sont désactivées par défaut ; ni l'analyse ni
l'ouverture d'un rapport n'émettent de sondes sans activation explicite.

## Préparer sans émettre

```bash
netcross --capture A=a.pcap --capture B=b.pcap --order A,B \
  --active-dry-run --json-report simulation.json
```

`--active-dry-run` affiche les commandes et les rattache au constat dans
la section « Confirmation active ». Il reste prioritaire même avec
`--confirm-active`. Il ne recherche pas Scamper, ne lance aucun processus,
n'ouvre aucun socket et ne résout aucun nom DNS.

## Autoriser une mesure

`--confirm-active` est une autorisation d'émettre vers les flux précisément
liés aux constats. L'opérateur doit avoir le droit de sonder ces cibles.
Au maximum huit mesures séquentielles sont exécutées : Paris conserve le
5-uplet, avec 30 TTL, une tentative par TTL, dix sondes/s au plus et arrêt
après trois sauts silencieux ; TWAMP utilise dix sondes à 100 ms d'intervalle.
Les propositions dépassant ce budget sont comptées comme non exécutées.

La source Paris doit être locale à la machine d'exécution, et Scamper doit
être installé avec les droits nécessaires. Aucun `sudo`, changement de
capability ni remplacement de source n'est tenté. TWAMP vise la destination
du flux, port 862 ; en l'absence de réflecteur, le rapport le dit. Les
horodatages, cibles et nombres de sondes sont journalisés par les backends.

## API

Les formulaires `POST /captures` et `POST /captures/multi` acceptent
`confirm_active` et `active_dry_run`, faux par défaut. La simulation n'émet
rien. Une demande d'émission renvoie 403 à moins que l'opérateur n'ait aussi
démarré le serveur avec `NETCROSS_API_ACTIVE=1` ; `confirm_active=true` dans
la requête reste nécessaire. Conserver l'authentification de l'API en
production et limiter l'accès réseau au serveur.

Le JSON de `GET /analyses/{id}/report`, les exports PDF, Markdown et HTML
contiennent la même confirmation. Les exports ne rejouent jamais une
mesure. L'anonymisation `redact` est incompatible avec la confirmation,
même simulée : les adresses pseudonymisées ne sont pas des cibles.

## Preuves et limites

Les preuves paquet univoques et les clés de flux réellement en perte,
collectées par le détecteur, permettent de retrouver un flux. Une mesure
au plus est proposée par type et par constat, sur son premier flux prouvé.
Les constats agrégés sans preuve de paquet ni clé fournie par le détecteur, les clés NAT sans 5-uplet, et
les numéros de trame ambigus entre fichiers d'un même point sont déclarés
non sondables. Aucun premier flux arbitraire n'est choisi dans un segment.
Actuellement, les constats PMTUD exposent des preuves paquet et les pertes
exposent leurs clés exactes ; les autres catégories peuvent donc rester
inéligibles même si le planificateur connaît leur règle.

Les sauts et RTT proviennent de la sortie native Paris. Une absence de
réponse ICMP est indiquée comme non-réponse, pas comme perte réseau
prouvée : un routeur peut limiter ou déprioriser ses réponses. En cas
d'interruption, le nombre de sondes réellement émises peut rester inconnu,
jamais ramené artificiellement à zéro.

TWAMP rapporte des délais et pertes aller-retour, pas une latence aller
simple ni des pertes par saut. Une absence de perte pendant une mesure
active courte est une divergence possible, pas une réfutation du constat
historique ; le chemin vers un réflecteur et les conditions ont pu changer.
