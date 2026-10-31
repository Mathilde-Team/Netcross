# Tests réels sur la banque de pcap

Issue [#1008](https://github.com/Mathilde-Team/Netcross/issues/1008). La suite de tests habituelle tourne sur des
captures synthétiques. Le workflow **Tests réels (banque de pcap)** (`.github/workflows/pcap-reels.yml`) analyse
en plus une banque de **vraies captures**, rangée sur la VM `ubuntu` qui porte le runner `docker`, dans
`/app/pcaps`.

## Confidentialité : ce qui ne sort jamais de la VM

Les captures de la banque sont sensibles. Le dépôt étant public, le dispositif est conçu pour qu'aucune donnée
ne quitte la VM :

| Risque | Parade |
|---|---|
| Code d'une PR (fork) exécuté sur la VM | aucun déclencheur `pull_request` : planification nocturne et lancement manuel uniquement (droits d'écriture requis), sur du code déjà relu (`dev` par défaut) |
| Modification de la banque | montage `/app/pcaps:/app/pcaps:ro`, vérifié par le workflow (échec si inscriptible) ; conteneur sans `--privileged` |
| Fuite par artefact ou cache | aucun `upload-artifact`, aucun cache des sorties ; rapports dans un répertoire temporaire `0700` supprimé à la fin de chaque cas |
| Fuite par les journaux | chaque cas est désigné par un identifiant opaque (`f-…` fumée, `s-…` scénario : empreinte SHA-256 du chemin relatif) ; la sortie de Netcross n'est jamais recopiée ; une exception est résumée par son **type** et son emplacement dans le **code** de Netcross, sans son message |
| Fuite par les manifestes | les manifestes vivent **dans la banque**, jamais dans le dépôt |
| Options dangereuses dans un manifeste | liste blanche d'options d'analyse pure : tout ce qui écrit un fichier, émet sur le réseau (`--notify-*`, `--ai-endpoint`, `--replay`), capture en direct ou charge du code est refusé |

!!! warning "Autres jobs sur la même VM"
    Les jobs `Qualité`, `GTK4`, `Paquets` et `i18n` de `ci.yml` tournent sur ce même runner dans un conteneur
    `--privileged` et se déclenchent sur les PR. Un conteneur privilégié peut lire tout le disque de l'hôte,
    `/app/pcaps` compris. Pour une PR de fork, le réglage du dépôt *Settings → Actions → Approval for running
    fork pull request workflows* doit être sur **« Require approval for all external contributors »**, et le
    code de la PR relu avant d'approuver son exécution.

## Ce qui est vérifié

1. **Fumée** : chaque capture (`.pcap`, `.pcapng`, `.cap`, et leurs versions `.gz`) qui n'est pas citée par un
   manifeste est analysée seule (un point). L'analyse doit se terminer avec le code 0, produire un rapport JSON
   valide, sans exception Python, en moins de 30 minutes (`--delai`).
2. **Scénarios** : chaque fichier `netcross-cas.yaml` de la banque décrit un ou plusieurs cas multi-points et ce
   que Netcross doit y trouver.

Le harnais échoue (code 2) si la banque est absente ou vide, si un manifeste est invalide (clé inconnue, capture
citée absente ou hors de la banque, option non permise) : une faute de frappe ne doit pas passer pour un test
réussi.

## Format d'un manifeste

Les chemins sont relatifs au dossier du manifeste.

```yaml
# /app/pcaps/incident-vpn-2026-03/netcross-cas.yaml
ignorer:                      # captures de ce dossier exclues de la fumée (motifs fnmatch)
  - "brut-*.pcapng"
cas:
  - nom: perte-sur-le-wan
    captures:
      CLIENT: client.pcapng
      ROUTEUR: [routeur-1.pcap, routeur-2.pcap]   # capture segmentée, ordre chronologique
      SERVEUR: serveur.pcapng
    ordre: [CLIENT, ROUTEUR, SERVEUR]
    options: [--bucket-ms, "100", --nat-tolerant]
    attendu:
      code_retour: 0           # défaut 0
      duree_max_s: 900         # défaut : --delai (1800)
      score_sante: {min: 20, max: 60}
      label_sante: [degrade, critique]
      constats:                # chaque motif doit être satisfait par au moins nombre_min constats
        - {rule_id: loss_per_segment, segment: ROUTEUR, severite: anomalie}
        - {rule_id: saturation, message_contient: "policing", nombre_min: 1}
      constats_absents:        # aucun constat ne doit satisfaire ces motifs
        - {rule_id: syn_flood}
```

Champs d'un motif de constat (tous facultatifs, combinés en ET) : `rule_id`, `severite`, `categorie`, `segment`
(égalité exacte avec le rapport JSON), `message_contient` (sous-chaîne), `nombre_min` (défaut 1). Pour connaître
les valeurs exactes, lancer Netcross une fois avec `--json-report` sur la VM et lire la liste `findings`.

En cas d'écart, le journal ne cite que le numéro du motif et son `rule_id` (un identifiant du code), jamais le
segment, le message ou les noms de points.

## Utilisation

Le workflow tourne chaque nuit sur `dev`. Lancement manuel : *Actions → Tests réels (banque de pcap) → Run
workflow*, avec une branche ou un commit déjà poussé et éventuellement un filtre.

Sur la VM, pour mettre au point un manifeste avec les vrais noms (sortie à garder sur la VM) :

```bash
uv sync --extra dev
uv run python scripts/pcap_reels.py --banque /app/pcaps --lister --noms
uv run python scripts/pcap_reels.py --banque /app/pcaps --filtre 'incident-vpn-2026-03/*' --noms
```

`--noms` ne doit jamais être utilisé dans le workflow. Un identifiant opaque vu dans un journal se retrouve avec
`--lister --noms` sur la VM.

## Mise en place sur la VM

- la banque est dans `/app/pcaps` sur l'hôte Docker du runner `docker` (le conteneur du job la monte au même
  chemin) ; elle doit être lisible par root dans le conteneur ;
- si un autre runner doit porter la banque, définir la variable de dépôt `NETCROSS_RUNS_ON_PCAP` (même format
  JSON que `NETCROSS_RUNS_ON`) ;
- un runner lui-même conteneurisé ne convient pas : le chemin du volume est résolu sur l'hôte Docker (même
  limite que #848/#936).
