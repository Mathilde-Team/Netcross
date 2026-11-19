# Déployer une sonde

Issue #1107 (sous-issue 6/6 du chantier [sondes distribuées #1002](https://github.com/Mathilde-Team/Netcross/issues/1002)).
Trois chemins officiels pour une sonde complète (`servir` : tampon
circulaire + service mTLS du [contrat v1](probe-api.md), inventoriée
par le collecteur [#1105](capture-distante.md)) : paquet Debian/RPM,
unité systemd durcie, image conteneur minimale. Comptez quelques minutes
sur n'importe quel Linux.

## 1. Paquet Debian ou RPM

Le paquet installe le code sous `/usr/share/netcross`, le lanceur
`/usr/bin/netcross-probe` (`python3 -m netcross_probe`) et ses
dépendances (tshark, python3-cryptography, python3-loguru) :

```bash
# Debian/Ubuntu (construction : ./build-deb/build.sh)
sudo apt install ./build-deb/dist/netcross_*.deb

# Fedora/RHEL/Rocky (construction : ./build-rpm/build.sh)
sudo dnf install ./build-rpm/dist/netcross-*.rpm

netcross-probe --help    # doit répondre
```

## 2. Enrôlement

La sonde s'inscrit une seule fois auprès du collecteur, par jeton à
usage unique (détails dans [Sonde `netcross-probe`](probe-agent.md)) :

```bash
# côté collecteur : imprime le jeton (administrateur)
PYTHONPATH=src python3 -c "from netcross_api.probe_routes import registre_sondes; \
    print(registre_sondes.creer_jeton())"
```

La clé privée est générée sur la sonde et ne la quitte jamais : seule la
CSR part sur le réseau. Conservez le jeton pour l'étape suivante — il
n'est utile qu'au premier lancement.

## 3. Unité systemd durcie

`deploy/systemd/netcross-probe.service` fait tourner `servir` sous un
utilisateur dynamique sans privilèges, avec les seules capacités
réseau nécessaires à la capture (`CAP_NET_RAW`, `CAP_NET_ADMIN`), la
racine système en lecture seule et le seul `/var/lib/netcross-probe`
inscriptible :

```bash
sudo mkdir -p /etc/netcross-probe
sudo cp deploy/systemd/netcross-probe.conf /etc/netcross-probe/netcross-probe.conf
sudo chmod 600 /etc/netcross-probe/netcross-probe.conf
sudo nano /etc/netcross-probe/netcross-probe.conf   # interface, nom, jeton

sudo cp deploy/systemd/netcross-probe.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now netcross-probe
journalctl -u netcross-probe -f
```

Résumé du durcissement (aucune option n'est décorative) :

| Option | Effet |
|---|---|
| `DynamicUser=yes` + `StateDirectory=netcross-probe` | utilisateur jetable, `/var/lib/netcross-probe` créé et possédé par lui |
| `CapabilityBoundingSet=` / `AmbientCapabilities=` | exactement `CAP_NET_RAW` + `CAP_NET_ADMIN`, rien d'autre |
| `ProtectSystem=strict` | toute l'arborescence système en lecture seule |
| `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes` | pas de `/home`, `/tmp` privé, `/dev` restreint |
| `ProtectKernel*`, `ProtectClock`, `ProtectHostname` | noyau, cgroups, horloge et nom d'hôte protégés |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_PACKET AF_UNIX` | seules les familles utiles à la capture et au mTLS |
| `SystemCallFilter=@system-service`, `MemoryDenyWriteExecute`, `LockPersonality` | surface d'appels système minimale, pas de mémoire exécutable |
| `NoNewPrivileges=yes`, `RestrictSUIDSGID=yes` | aucune élévation possible, y compris par les enfants (tshark, dumpcap) |

Après l'inscription (visible dans le journal), retirez le jeton du
fichier de configuration — l'identité relue suffit aux lancements
suivants :

```bash
sudo systemctl edit netcross-probe   # ou : retirer NETCROSS_PROBE_JETON du .conf
sudo systemctl restart netcross-probe
```

La sonde apparaît alors côté collecteur dans `GET /probes`, et sa santé
dans `GET /probes/{probe_id}/health` ([#1105](probe-agent.md)).

## 4. Image conteneur

`deploy/conteneur/Dockerfile` est l'image minimale de la sonde : tshark
et libpcap côté système, `cryptography` et `loguru` côté Python, le code
réduit à `netcross_probe` + `pcap_parser`. Publiée depuis dev vers
`ghcr.io/mathilde-team/netcross-probe:latest` (workflow
`Image de sonde`, construite et contrôlée en CI).

```bash
docker build -t netcross-probe deploy/conteneur

# les capacités réseau sont nécessaires à la capture ; --network host
# pour joindre le collecteur et écouter sur l'interface de la sonde
docker run -d --name netcross-probe --restart unless-stopped \
  --network host --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -v netcross-probe-identite:/var/lib/netcross-probe/identite \
  ghcr.io/mathilde-team/netcross-probe:latest \
  servir --interface eth0 \
    --dossier /var/lib/netcross-probe/tampon \
    --identite /var/lib/netcross-probe/identite \
    --nom ROUTEUR \
    --ecoute 0.0.0.0:9443 \
    --enrolement https://collecteur.lan:8443/probe/v1/enrollments \
    --jeton <jeton-à-usage-unique> \
    --listen-url https://sonde.lan:9443

docker logs -f netcross-probe
```

Premier lancement : l'enrôlement crée l'identité dans le volume. Lancers
suivants : relancez sans `--enrolement`/`--jeton`. La conteneur
s'exécute sous l'utilisateur non privilégié `sonde` (uid 10001) ; les
capacités passent par `--cap-add`, pas par un utilisateur root.

## 5. Vérifier le déploiement

```bash
# sur la sonde : le service écoute (9443)
ss -tlnp | grep 9443

# côté collecteur : la sonde est inventoriée (clé API du collecteur)
curl -s -H "X-API-Key: $NETCROSS_API_TOKEN" \
  https://collecteur.lan:8443/probes | python3 -m json.tool

curl -s -H "X-API-Key: $NETCROSS_API_TOKEN" \
  https://collecteur.lan:8443/probes/<probe_id>/health
```

## Fichiers du dépôt

| Fichier | Rôle |
|---|---|
| `deploy/systemd/netcross-probe.service` | unité systemd durcie |
| `deploy/systemd/netcross-probe.conf` | configuration lue par l'unité |
| `deploy/conteneur/Dockerfile` | image conteneur minimale de la sonde |
| `.github/workflows/ci-image-sonde.yml` | construction + contrôle en CI, publication depuis dev |
