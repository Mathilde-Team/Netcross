# Session 76 : détecteur automatique de microrafales

Date : 09/11/2026. Issue #1135, branche `feat/1135-detecteur-microrafales`,
depuis `dev`, actualisée sur `fddd1e3` après livraison du guide #1049.

## Périmètre et intégration

`netcross_core.microburst.detect_microbursts` analyse chaque point aux
échelles de #1133, sans échelle plus fine que la résolution. La crête
réutilise la fenêtre glissante exacte `SlidingWindowPeak`, dont deux
accesseurs tracés exposent l'état courant sans le confondre avec le
maximum historique.

`analyse` appelle le détecteur et conserve les événements et refus dans
`Report.microbursts`. Les vitesses sont désormais résolues avant l'analyse
CLI, API, pipelines fichier GTK4, batch et archives d'incident. Les
analyses sur paquets en mémoire sans métadonnées restent au seuil relatif.
Le texte, le document JSON et les constats alimentant
les rapports reçoivent les résultats. La règle `microburst` rejoint le
catalogue exhaustif, désormais 42 règles, avec ses seuils testés.

## Seuils et limites

- Au moins deux paquets dans la fenêtre.
- Pic au moins quatre fois la médiane des débits des tranches non vides
  de cette échelle et de ce point.
- Avec une vitesse connue, au moins 80 % d'occupation supplémentairement.
- Sans vitesse connue, aucun pourcentage inventé : le rapport mentionne
  explicitement le seuil relatif et donne son ratio et sa référence.
- Les fenêtres chevauchantes deviennent un épisode conservateur, avec
  sa durée, sa crête et ses principaux émetteurs par octets.

Les bornes couvrent des fenêtres de détection, pas l'instant physique
exact de congestion. Les constats restent à surveiller, sans affirmer
de perte. La référence médiane nécessite la capture du point : classement
`seconde_passe`, sans promesse de fonctionnement en flux ni de mémoire
indépendante du nombre de paquets. Les tranches sont creuses, sans
allocation proportionnelle à une longue durée de silence.

La corrélation aux pertes et la localisation par segment (#1137), les
grandes captures et les sondes physiques ne sont pas déclarées validées.
Les émetteurs proviennent des paquets déjà pseudonymisés par l'appelant.

## Vérifications locales

Sous Python 3.14.8 avec les dépendances verrouillées et le venv transmis
dans `PATH` aux sous-processus :

- 18 tests dédiés réussis ; module `microburst.py` à 100 % des lignes
  et des branches, sans exclusion.
- Rafales de 2 ms à 1 Gbit/s sur fond 100 Mbit/s détectées, trafic lissé
  de même volume sans constat ; seuil relatif, vitesse trop élevée,
  résolution insuffisante, points distincts et désordre testés.
- Analyse réelle, constats, JSON, texte et passage préalable des métadonnées
  dans la CLI, l'API et GTK4 testés ; aucune adresse réelle dans le JSON après
  redaction. La comparaison live ignore les fichiers non utilisés, y compris
  leurs métadonnées.
- 69 tests complémentaires batch, incidents et pipelines GTK4 réussis.
- Suite complète après tous les raccordements : 6 478 réussis, 93 sautés
  et deux avertissements FastAPI/Starlette, en 144,15 secondes.
- `mypy src/` : aucune erreur sur 229 fichiers.
- L'audit de sorties a détecté les deux accesseurs initialement non
  tracés ; leurs traces ont été ajoutées, et les contrôles loguru repassent
  sans changement de référence ni d'exclusion.

Les vérifications finales après actualisation et les contrôles du dernier
head sont détaillés dans la PR. Aucun seuil de couverture, workflow,
protection ou test n'est assoupli.

## Mesure par le banc existant

Commande exécutée avant les modifications applicatives, puis après :

```sh
PYTHONPATH=src python scripts/bench.py --mini --repetitions 3 --parallel 1 \
  --json /tmp/mesure.json
```

Mini-jeu déterministe : deux points, 4 000 paquets vus, graine 1. Même
sandbox, Python 3.14.8 et TShark 4.6.4, deux cœurs utilisables. Les
deux séries sont successives, non entrelacées, sans autre suite de tests
locale simultanée pendant la mesure.

| Mesure du passage médian | Avant | Après | Écart |
|---|---:|---:|---:|
| Durée totale | 1,119711 s | 1,188002 s | +6,10 % |
| Étape détecteurs | 0,233987 s | 0,229492 s | −1,92 % |
| Étape lecture | 0,876616 s | 0,945790 s | +0,069174 s |
| Pic RSS principal | 111,0 Mio | 111,4 Mio | +0,4 Mio |
| Pic RSS enfants | 179,6 Mio | 179,6 Mio | inchangé |

Les trois durées avant sont 1,128122 / 1,119711 / 1,107641 s ;
après, 1,244533 / 1,188002 / 1,084657 s. L'écart de lecture domine
l'écart total de ces passages. La baisse mesurée de l'étape détecteurs
ne démontre pas une accélération : trois répétitions et ce petit jeu ne
séparent pas le coût propre du détecteur du bruit de mesure.

Le coût observé est donc communiqué, sans garantie de débit ni
extrapolation aux grandes captures ou à un déclenchement massif.
Résultats bruts, environnement et durées individuelles dans les fichiers
versionnés à la racine du dépôt :
`benchmarks/microrafales-1135-avant.json` et
`benchmarks/microrafales-1135-apres.json`.
