# Session 92 : paquets de déploiement de la sonde

Date : 19/11/2026 (Paris). Issue #1107 (P1, sous-issue 6/6 du chantier
[sondes distribuées #1002](https://github.com/Mathilde-Team/Netcross/issues/1002)).
Le travail porte sur la branche `feature/issue-1107-deploiement-sonde`,
initialisée depuis dev (e9ef78d, merge de la PR #1290 du collecteur
#1105). Les paquets deb/rpm embarquent `netcross_probe` et le lanceur
`netcross-probe` depuis la PR #1290 — cette session ajoute l'unité
systemd durcie, l'image conteneur minimale et le guide de déploiement.

## Réalisation

### Unité systemd durcie

`deploy/systemd/netcross-probe.service` : `servir` sous utilisateur
dynamique (`DynamicUser=yes`, `StateDirectory=netcross-probe` —
`/var/lib/netcross-probe` créé et possédé par lui), capacités limitées à
`CAP_NET_RAW` + `CAP_NET_ADMIN` (`CapabilityBoundingSet` fermé,
`AmbientCapabilities`, `NoNewPrivileges=yes` — le binaire ne tourne pas
en root), racine système en lecture seule (`ProtectSystem=strict`),
`/home` protégé, `/tmp` privé, `/dev` restreint, noyau/cgroups/horloge/
nom d'hôte protégés, familles d'adresses réduites à IPv4/IPv6/AF_PACKET
(capture) + AF_UNIX (mTLS local), syscalls filtrés à `@system-service`,
mémoire non exécutable, `RestrictSUIDSGID`/`RestrictRealtime`. La
configuration (interface, nom, jeton d'enrôlement) vit dans
`/etc/netcross-probe/netcross-probe.conf` lu comme `EnvironmentFile` :
rien de sensible dans l'unité. Le jeton vide fait `--enrolement ""`
(faux pour `_commande_servir`) : l'inscription est sautée, l'identité
relue suffit.

Syntaxe validée par `systemd-analyze verify` (seule plainte tolérée en
test : `/usr/bin/netcross-probe` absent de la machine de test).

### Image conteneur minimale

`deploy/conteneur/Dockerfile` : contrairement au `Dockerfile` racine
(image d'analyse complète, #170), celle-ci ne porte que l'agent — tshark
et libpcap côté système (compilation BPF via ctypes),
`cryptography`/`loguru` côté Python, code réduit à `netcross_probe` +
`pcap_parser`. Utilisateur non privilégié `sonde` (uid 10001),
`ENTRYPOINT python3 -m netcross_probe`, `HEALTHCHECK` sur le port 9443.
Les capacités réseau passent par `docker run --cap-add`, pas par root.

### Construction en CI

`.github/workflows/ci-image-sonde.yml` (motif de `ci-image.yml`, issue
#968) : construction + contrôle de l'image sur PR touchant `deploy/`,
`src/netcross_probe/` ou `src/pcap_parser/` (le contrôle y vérifie
tshark/editcap/mergecap/capinfos et les imports `netcross_probe`,
`pcap_parser`) ; publication vers `ghcr.io/mathilde-team/netcross-probe`
depuis dev seulement.

### Guide de déploiement

`docs/deploiement-sonde.md` (nav `Utilisation`) : installation par paquet
deb/rpm, enrôlement par jeton à usage unique, installation de l'unité
systemd (avec tableau explicatif du durcissement), exécution conteneur
(volume d'identité, `--network host` + `--cap-add`), vérification côté
collecteur (`GET /probes`, `GET /probes/{probe_id}/health`).

## Tests

`tests/test_issue_1107_deploiement.py` (9 tests) : durcissement de
l'unité (chaque directive attendue, bounding set exactement
`CAP_NET_RAW`+`CAP_NET_ADMIN`), `ExecStart` (`netcross-probe servir`,
chemins d'état), variables `${NETCROSS_PROBE_*}` toutes définies par le
`.conf`, syntaxe `systemd-analyze verify` quand l'outil existe, contenu
du Dockerfile (tshark + libpcap, absence de GTK/API/rapport, `USER` non
root, `ENTRYPOINT`), workflow (chemins déclencheurs, construction +
contrôle, publication hors PR), guide complet et référencé dans la nav,
shell du contrôle bien formé.

## Vérifications

`PYTHONPATH=src python -m pytest tests/test_issue_1107_deploiement.py -q` :
9 réussis. Suite complète (Python 3.14, `PYTHONPATH=src python -m pytest
tests/ -q`) : 7361 réussis, 107 ignorés, 0 échec ; ruff check et format
propres ; import-linter : 1 contrat respecté ; `mkdocs build --strict` :
succès ; `docs/openapi.yaml` à jour. Consigné avant le push ; la CI du
dernier head reste la référence.

## Limites

L'unité systemd n'est pas installée par le paquet deb/rpm (elle vit dans
`deploy/systemd/`, installée par le guide) : l'empaquetage d'une unité
dans le .deb (postinst d'activation) reste un travail à part. L'image
conteneur n'embarque pas chrony : `clock` vaut `unknown` pour une sonde
conteneurisée sans démon NTP sur l'hôte — l'hôte reste la référence.
