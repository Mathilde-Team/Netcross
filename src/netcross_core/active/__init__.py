"""
netcross_core.active -- confirmation active du diagnostic passif (chantier
#999, parent #993).

Ce paquet est OPTIONNEL et DESACTIVE PAR DEFAUT : rien ici n'est appele par
le pipeline d'analyse passif. Premier sous-module (issue #1063) :

- `planner` : a partir des constats localises (`ExpertEvent`), propose la
  mesure active ciblee sur le MEME 5-uplet (traceroute a la Paris,
  TWAMP-Light). Fonction pure : AUCUNE emission reseau, aucun socket,
  aucun sous-processus -- l'execution relevera des sous-issues #1065
  (traceroute), #1066 (TWAMP-Light) et #1068 (CLI/API, accord explicite).
"""
