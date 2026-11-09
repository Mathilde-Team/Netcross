# Gel rétroactif et incidents archivés

Chantier #1001 (issues #1087, #1090, #1093, #1091, #1095). Quand une
alarme se lève en analyse live, les paquets qui l'ont provoquée sont
souvent déjà partis du tampon circulaire. Le **gel** protège à chaud, sur
tous les points en direct, les fichiers qui couvrent la fenêtre
`[t - secondes avant, t + secondes après]` ; l'incident est ensuite
**archivé** (découpe précise + manifeste signé SHA-256), **analysé**
(rapport multi-points rangé avec les preuves) et **notifié** (résumé +
chemin de l'archive).

Code : `netcross_core.retro_capture` (gel, archivage, quota),
`netcross_core.incident_analysis` (analyse), `netcross_core.gel_settings`
(réglages et inventaire, partagés par l'API et la GUI).

## Les réglages

Un seul fichier de réglages, partagé par la GUI et l'API :
`~/.netcross/gel_config.json` (l'administrateur du serveur peut imposer
un autre chemin via `NETCROSS_API_GEL_CONFIG`). Fichier absent = valeurs
par défaut ; chaque clé absente garde sa valeur par défaut.

| Réglage | Défaut | Rôle |
|---|---|---|
| `seconds_before` | `60` | Secondes conservées **avant** l'alarme |
| `seconds_after` | `30` | Secondes conservées **après** l'alarme |
| `min_severity` | `anomalie` | Sévérité minimale qui déclenche le gel (`anomalie`, `a_surveiller`, `info`) |
| `min_delay_between_gels` | `30` | Délai minimal (s) entre deux gels |
| `max_octets_archives` | `null` | Quota d'archives (octets) : les gels les plus anciens sont supprimés, le gel courant jamais ; `null` = illimité |
| `archives_dir` | `~/.netcross/incidents` | Répertoire où les gels écrivent, et où la liste des incidents cherche |

Un réglage inconnu, mal typé ou hors bornes est **refusé** à la
sauvegarde (GUI comme API) : mieux vaut un message immédiat qu'un gel qui
ne se déclenchera pas à la prochaine alarme.

## Le déroulé d'un incident

1. **Alarme** → gel des fichiers du tampon (liens durs : la rotation du
   tampon ne détruit pas les données protégées) ;
2. **Archivage** : découpe `editcap` de la fenêtre précise (horloge du
   point, décalage pris en compte) dans
   `<archives_dir>/<gel>/incident/<point>/`, puis
   `manifeste.json` avec les empreintes SHA-256 de chaque segment — la
   chaîne de preuve ;
3. **Analyse** (`POST .../analyse` ou bouton « Analyser ») : analyse
   multi-points des segments (label du point attaché à chaque paquet,
   même socle que la CLI), vérification préalable des empreintes — une
   archive altérée n'est PAS analysée. Le rapport
   `rapport.json` (schéma `netcross.incident/1`) est rangé **avec** les
   segments, plus `rapport.html` si le rendu est disponible ;
4. **Notification** : résumé (sévérités, constats principaux, score du
   tableau de bord de sécurité) et **chemin de l'archive**, via les
   canaux configurés (même configuration que les notifications
   d'analyse).

## Dans la GUI

Onglet « **Incidents** » :

- **Réglages du gel** : les six réglages ci-dessus, « Enregistrer »
  valide et écrit le fichier partagé avec l'API ;
- **Incidents archivés** : la liste (horodatage, règle, points,
  segments, état des rapports) avec un bouton **Analyser** par incident.
  L'analyse tourne en arrière-plan, le résultat est journalisé dans la
  page « Travail » et la liste se rafraîchit.

## Par l'API

Issue #1095. Mêmes données que la GUI, authentification par clé API :

```bash
# réglages effectifs (défauts fusionnés avec le fichier)
curl -H "X-API-Key: $NETCROSS_API_TOKEN" http://localhost:8000/gel/config

# modifier des réglages (les absents gardent leur valeur courante)
curl -X PUT -H "X-API-Key: $NETCROSS_API_TOKEN" -H "Content-Type: application/json" \
  -d '{"seconds_before": 120, "max_octets_archives": 5000000000}' \
  http://localhost:8000/gel/config

# inventaire des incidents archivés (depuis archives_dir des réglages)
curl -H "X-API-Key: $NETCROSS_API_TOKEN" http://localhost:8000/incidents

# détail : manifeste complet + rapport d'analyse s'il existe
curl -H "X-API-Key: $NETCROSS_API_TOKEN" http://localhost:8000/incidents/gel-1

# lancer l'analyse de la fenêtre gelée (rapports rangés dans l'archive)
curl -X POST -H "X-API-Key: $NETCROSS_API_TOKEN" \
  http://localhost:8000/incidents/gel-1/analyse
```

L'analyse est synchrone (la fenêtre d'un incident est courte). Un
incident inconnu renvoie 404, une archive altérée ou indécodable 409,
un échec d'analyse 500.
