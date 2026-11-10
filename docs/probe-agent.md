# Sonde `netcross-probe`

Issue #1099 (sous-issue 2/6 du chantier [sondes distribuées #1002](https://github.com/Mathilde-Team/Netcross/issues/1002)).
L'agent léger qui capture en local dans un tampon circulaire et extrait à
la demande une fenêtre [t1, t2] filtrée BPF, livrée en pcapng. Le contrat
avec le collecteur est figé dans [l'API des sondes distribuées](probe-api.md)
(v1) ; cette page décrit l'agent livré ici, sans la couche réseau.

## Principe

La capture en direct multi-points repose aujourd'hui sur un flux tiré à
travers le réseau (`rpcap://`, `sshdump://`) : une coupure du lien
d'administration fait perdre des paquets au point de mesure. La sonde
inverse la charge : elle écrit **localement** dans un tampon circulaire
(tshark/dumpcap, `ring_recorder_args`), et le collecteur ne tire que les
fenêtres utiles à une analyse.

Sans GTK ni dépendance lourde : tshark (et ses outils mergecap/editcap)
seuls côté capture, plus libpcap pour compiler les filtres BPF.

## Lancer la capture

```bash
PYTHONPATH=src python3 -m netcross_probe capture \
    --interface eth0 \
    --dossier /var/lib/netcross-probe/tampon \
    --nb-fichiers 10 --duree-par-fichier 60 \
    --filtre-bpf "not port 22"
```

Le tampon fait `--nb-fichiers × --duree-par-fichier` secondes de profondeur
; au-delà, tshark supprime le plus ancien fichier. Ctrl-C (ou SIGTERM)
arrête l'enregistreur proprement : le fichier en cours reste lisible.

## Extraire une fenêtre

```bash
PYTHONPATH=src python3 -m netcross_probe fenetre \
    --dossier /var/lib/netcross-probe/tampon \
    --debut 1791000003 --fin 1791000006 \
    --filtre-bpf "udp" \
    --sortie /var/lib/netcross-probe/fenetres
```

Étapes exécutées par la sonde (contrat v1, `request_window`) :

1. sélection des fichiers du tampon qui chevauchent [t1, t2] (bornes
   incluses ; `select_ring_files`, inventaire horodaté #1086) ;
2. découpe de l'intervalle (editcap `-A/-B`) et fusion des morceaux
   (mergecap) ;
3. application du **vrai filtre BPF** : tshark interdit `-f` en relecture
   de fichier et dumpcap ne l'applique pas sur un tube, la sonde passe
   donc par libpcap elle-même (`netcross_probe.bpf`, chargée via ctypes,
   aucune dépendance Python ajoutée) puis convertit le résultat en pcapng
   (editcap) ;
4. calcul du SHA-256, de la taille et de l'intervalle réellement couvert
   (premier/dernier paquet, via capinfos).

La sortie standard décrit la fenêtre en JSON (miroir de l'objet `Window`
du contrat v1) : `window_id`, `requested`, `covered` (plus court que la
demande si le tampon a déjà tourné -- ce n'est pas une absence de trafic),
`packet_count`, `bytes`, `sha256`, `chemin` du pcapng.

Codes de retour de `fenetre` : 0 nominal, 2 rien dans le tampon pour
cette fenêtre, 3 fenêtre refusée (bornes inversées, BPF invalide), 4
fenêtre au-delà de `--max-octets` (le pcapng est alors supprimé).

## Sécurité : mTLS, enrôlement, révocation (#1101)

Aucune écoute ni transfert sans authentification mutuelle. La sonde
s'inscrit auprès du collecteur une seule fois, par jeton à usage unique
remis par l'administrateur :

```bash
PYTHONPATH=src python3 -c "
from netcross_api.probe_routes import registre_sondes
print(registre_sondes.creer_jeton())"   # côté collecteur : imprime le jeton

PYTHONPATH=src python3 -c "
from netcross_probe.enrolement import demander_enrolement
demander_enrolement('https://collecteur:8443/probe/v1/enrollments',
                     JETON, 'ROUTEUR', '/var/lib/netcross-probe/identite')"
```

La clé privée est générée sur la sonde et ne la quitte jamais : seule la
CSR PKCS#10 part sur le réseau. Le collecteur signe un certificat client
dont le SAN URI vaut `urn:netcross:probe:<probe_id>` et répond la chaîne
de son autorité (`netcross_probe.securite.AutoriteConfiance`).

Ensuite, tout échange passe en TLS mutuel (TLS 1.3, certificat exigé
pendant la poignée de main, épinglage sur l'autorité du collecteur) :
`netcross_probe.securite.contexte_mtls_serveur` / `contexte_mtls_client`
construisent les contextes, `verifier_certificat_sonde` refuse un
certificat non signé, expiré ou révoqué. Une sonde est révoquée côté
collecteur (`RegistreSondes.revoquer(probe_id)`) : son certificat est
refusé partout, refus explicite jamais silencieux.

## Programmation

L'agent est aussi une bibliothèque (`AgentProbe`) : capture
(`AgentCapture`, réglages `ReglagesCapture`) et registre de fenêtres avec
expiration (`extraire`/`fenetre`/`liberer`). La couche réseau (mTLS,
#1101), la remontée pertes/horloge (#1103), le collecteur et le schéma
`probe://` (#1105) et les paquets de déploiement (#1107) s'y brancheront
sans réécrire cette mécanique.
