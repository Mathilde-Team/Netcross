# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.fingerprint -- empreintes JA4 (TLS) et HASSH (SSH), issue
#143 (FLOW-2, parent #141).

Objectif : identifier l'OUTIL/CLIENT (curl, un navigateur, OpenSSH...) a
partir de la maniere dont il negocie un handshake TLS ou SSH, meme quand
le protocole applicatif au-dessus est masque ou chiffre -- complementaire
de `netcross_core.application.banners` (CVE-1, #135) qui lit lui des
bannieres EXPLICITES annoncees par le service.

Deux sous-modules, un par empreinte :
- `tls_ja4` : construit le ClientHello TLS depuis la charge utile brute
  (record layer + handshake) et calcule JA4 (spec FoxIO/John Althouse).
- `ssh_hassh` : construit le message SSH_MSG_KEXINIT depuis la charge
  utile brute et calcule HASSH/HASSHServer (spec Salesforce).

Meme discipline que `application.banners` : lecture directe du payload
TCP (pas des champs EK tshark, non disponibles pour ecrire ni valider ce
module -- voir la docstring de `application.banners` pour la
justification complete), aucune exception ne sort des fonctions
d'extraction, un payload tronque ou malforme donne simplement `None`.

`known` fournit une petite base d'empreintes connues (curl, Chrome,
OpenSSH...) chargeable, utilisee pour transformer un hash opaque en nom
d'outil lisible. `report` consolide les empreintes vues par paquet en
entrees pretes pour `Report.service_fingerprints`.

Avertissement (a lever avant de comparer ces empreintes a une base
publique type ja4db.com) : les constantes JA4_b/JA4_c (tronque SHA256,
tri des listes) sont ecrites depuis la specification publique, sans
capture reelle ni tshark disponibles ici pour les valider paquet par
paquet -- voir la docstring de `tls_ja4.compute_ja4` pour le detail des
hypotheses. HASSH est une specification plus simple (un seul md5, champs
non tries) et n'appelle pas la meme reserve.
"""

from __future__ import annotations

from netcross_core.logging_config import get_logger

logger = get_logger(__name__)
