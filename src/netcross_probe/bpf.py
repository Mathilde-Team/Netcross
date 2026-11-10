# SPDX-License-Identifier: GPL-3.0-or-later
"""Filtrage BPF (syntaxe pcap-filter) en relecture d'un fichier de capture.

Issue #1099 (agent ``netcross-probe``) : le contrat v1 de l'agent
(``docs/probe-api-v1.yaml``, ``WindowRequest.bpf``) exige un filtre BPF
« compilé par la sonde » à l'extraction d'une fenêtre. Or les outils en
ligne de commande Wireshark ne peuvent pas le faire sur un fichier déjà
écrit :

- ``tshark -r`` refuse catégoriquement ``-f`` : « Only read filters, not
  capture filters, can be specified when reading a capture file » (voir
  ``export_filtered``, issue #261) ;
- ``dumpcap -f`` sur un tube n'applique PAS le filtre (vérifié : un
  fichier 100 % TCP renvoyé intégralement avec ``-f "not tcp"``).

La seule façon d'appliquer un vrai filtre BPF en relecture est donc
libpcap elle-même -- la même bibliothèque que dumpcap utilise en capture.
Ce module la charge via :mod:`ctypes` (aucune dépendance Python ajoutée :
libpcap est déjà requise par tshark, présent partout où le dépôt tourne),
compile l'expression avec :c:func:`pcap_compile` et écrit les paquets
retenus au format pcap classique, converti en pcapng par ``editcap``
ensuite. Les erreurs de compilation remontent le message exact de libpcap.
"""

from __future__ import annotations

import contextlib
import ctypes
import ctypes.util
import os
import struct
import tempfile
from typing import BinaryIO

from loguru import logger

__all__ = [
    "FiltreBpfInvalideError",
    "LibpcapIndisponibleError",
    "filtrer_capture",
    "valider_filtre",
]

# En-tête de fichier pcap classique : magic, version 2.4, zones horaires
# nulles (inconnues), snaplen et type de liaison -- ce dernier vient de
# pcap_datalink() sur le fichier lu, pour que la conversion editcap
# conserve le bon décodage.
_MAGIE_PCAP = 0xA1B2C3D4


class LibpcapIndisponibleError(RuntimeError):
    """libpcap est introuvable : la sonde ne peut pas compiler de filtre BPF."""


class FiltreBpfInvalideError(ValueError):
    """L'expression BPF est refusée par libpcap (syntaxe pcap-filter invalide).

    Porte le message exact de ``pcap_geterr`` pour que l'appelant puisse le
    renvoyer tel quel (code d'erreur ``invalid_bpf`` du contrat v1).
    """


class _BpfProgramme(ctypes.Structure):
    """``struct bpf_program`` : une longueur et un pointeur d'instructions."""

    _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]


class _EnTetePaquet(ctypes.Structure):
    """``struct pcap_pkthdr`` : timeval natif (deux long) puis caplen/len.

    Vérifié empiriquement sur libpcap 1.10 (Debian, 64 bits) : l'en-tête
    fait 24 octets -- ``struct timeval`` natif, pas les champs 32 bits
    fixes de ``pcap_timeval`` réservés au format des fichiers. Une
    disposition 16 octets lit caplen à 0.
    """

    _fields_ = [
        ("ts_sec", ctypes.c_long),
        ("ts_usec", ctypes.c_long),
        ("caplen", ctypes.c_uint),
        ("len", ctypes.c_uint),
    ]


def _charger_libpcap() -> ctypes.CDLL:
    """Charge libpcap par son nom canonique ; lève si elle est absente."""
    logger.debug("_charger_libpcap: entrée")
    nom = ctypes.util.find_library("pcap")
    if nom is None:
        logger.warning("_charger_libpcap: libpcap introuvable sur ce système")
        raise LibpcapIndisponibleError(
            "libpcap introuvable -- installer le paquet 'libpcap' (apt install libpcap0.8 / dnf install libpcap), "
            "requis pour compiler les filtres BPF de la sonde."
        )
    lib = ctypes.CDLL(nom)
    logger.debug("_charger_libpcap: retour {}", nom)
    return lib


def _configurer_signatures(lib: ctypes.CDLL) -> None:
    """Signatures des points d'entrée libpcap utilisés par la sonde."""
    logger.debug("_configurer_signatures: entrée")
    lib.pcap_open_offline.restype = ctypes.c_void_p
    lib.pcap_open_offline.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    lib.pcap_compile.restype = ctypes.c_int
    lib.pcap_compile.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_BpfProgramme),
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    lib.pcap_setfilter.restype = ctypes.c_int
    lib.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(_BpfProgramme)]
    lib.pcap_freecode.argtypes = [ctypes.POINTER(_BpfProgramme)]
    lib.pcap_geterr.restype = ctypes.c_char_p
    lib.pcap_geterr.argtypes = [ctypes.c_void_p]
    lib.pcap_datalink.restype = ctypes.c_int
    lib.pcap_datalink.argtypes = [ctypes.c_void_p]
    lib.pcap_snapshot.restype = ctypes.c_int
    lib.pcap_snapshot.argtypes = [ctypes.c_void_p]
    lib.pcap_next_ex.restype = ctypes.c_int
    lib.pcap_next_ex.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(_EnTetePaquet)),
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
    ]
    lib.pcap_close.argtypes = [ctypes.c_void_p]
    logger.debug("_configurer_signatures: fin")


def _compiler_filtre(lib: ctypes.CDLL, handle: int, filtre: str) -> _BpfProgramme:
    """Compile ``filtre`` contre le fichier ouvert ; lève avec le message libpcap."""
    logger.debug("_compiler_filtre: entrée ({})", filtre)
    programme = _BpfProgramme()
    # Optimisation (1) et masque 0.0.0.0 (réseau inconnu) : mêmes choix que
    # dumpcap pour un filtre de capture sans contexte réseau.
    code = lib.pcap_compile(handle, ctypes.byref(programme), filtre.encode("utf-8"), 1, 0)
    if code != 0:
        message = (lib.pcap_geterr(handle) or b"?").decode("utf-8", "replace")
        logger.warning("_compiler_filtre: filtre refusé par libpcap : {}", message)
        raise FiltreBpfInvalideError(f"filtre BPF {filtre!r} refusé par libpcap : {message}")
    logger.debug("_compiler_filtre: retour programme de {} instruction(s)", programme.bf_len)
    return programme


def valider_filtre(filtre: str) -> None:
    """Compile l'expression et la jette : valide la syntaxe BPF sans rien écrire.

    La compilation se fait sur un pcap vide minimal (en-tête seul, liaison
    Ethernet) : libpcap exige un contexte de type de liaison, et un fichier
    temporaire évite de dépendre d'une capture réelle.

    Lève :class:`FiltreBpfInvalideError` (syntaxe refusée) ou
    :class:`LibpcapIndisponibleError` (bibliothèque absente).
    """
    logger.debug("valider_filtre: entrée ({})", filtre)
    lib = _charger_libpcap()
    _configurer_signatures(lib)
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as vide:
        vide.write(struct.pack("<IHHIIII", _MAGIE_PCAP, 2, 4, 0, 0, 65535, 1))  # DLT_EN10MB
        chemin_vide = vide.name
    try:
        errbuf = ctypes.create_string_buffer(256)
        handle = lib.pcap_open_offline(os.fsencode(chemin_vide), errbuf)
        if not handle:
            logger.debug("valider_filtre: pcap_open_offline a échoué -> levée LibpcapIndisponibleError")
            raise LibpcapIndisponibleError("libpcap n'ouvre même pas un pcap vide")
        try:
            programme = _compiler_filtre(lib, handle, filtre)
            lib.pcap_freecode(ctypes.byref(programme))
        finally:
            lib.pcap_close(handle)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(chemin_vide)
    logger.debug("valider_filtre: fin")


def _ecrire_en_tete_pcap(sortie: BinaryIO, snaplen: int, type_liaison: int) -> None:
    """Écrit l'en-tête pcap classique (24 octets) du fichier filtré."""
    logger.debug("_ecrire_en_tete_pcap: entrée (snaplen={}, DLT={})", snaplen, type_liaison)
    sortie.write(struct.pack("<IHHIIII", _MAGIE_PCAP, 2, 4, 0, 0, snaplen, type_liaison))
    logger.debug("_ecrire_en_tete_pcap: fin")


def filtrer_capture(chemin_in: str, chemin_out: str, filtre_bpf: str) -> int:
    """Applique un VRAI filtre BPF à un fichier de capture et écrit le résultat.

    Lit ``chemin_in`` (pcap ou pcapng) via ``pcap_open_offline``, compile
    ``filtre_bpf`` (syntaxe pcap-filter, mêmes règles que tcpdump/dumpcap)
    et recopie dans ``chemin_out`` (format pcap classique) uniquement les
    paquets qui passent le filtre. Renvoie le nombre de paquets retenus.

    Le format intermédiaire pcap est assumé : l'écriture pcapng à la main
    (blocs SHB/IDB/EPB) serait une réimplémentation de wiretap ; la
    conversion pcap -> pcapng est ensuite un simple ``editcap`` sans
    ambiguïté. Les horodatages sont recopiés tels quels (µs), le type de
    liaison et le snaplen proviennent du fichier source.

    Lève :class:`LibpcapIndisponibleError`, :class:`FiltreBpfInvalideError`
    ou :class:`OSError` (fichier illisible/absent).
    """
    logger.debug("filtrer_capture: entrée ({} -> {}, filtre {!r})", chemin_in, chemin_out, filtre_bpf)
    lib = _charger_libpcap()
    _configurer_signatures(lib)
    errbuf = ctypes.create_string_buffer(256)
    handle = lib.pcap_open_offline(os.fsencode(chemin_in), errbuf)
    if not handle:
        detail = errbuf.value.decode("utf-8", "replace")
        logger.warning("filtrer_capture: pcap_open_offline a échoué pour {} : {}", chemin_in, detail)
        raise OSError(f"capture illisible par libpcap : {chemin_in} ({detail})")
    try:
        programme = _compiler_filtre(lib, handle, filtre_bpf)
        if lib.pcap_setfilter(handle, ctypes.byref(programme)) != 0:
            message = (lib.pcap_geterr(handle) or b"?").decode("utf-8", "replace")
            logger.debug("filtrer_capture: setfilter a échoué -> levée FiltreBpfInvalideError")
            raise FiltreBpfInvalideError(f"filtre BPF {filtre_bpf!r} inapplicable : {message}")
        type_liaison = int(lib.pcap_datalink(handle))
        snaplen = int(lib.pcap_snapshot(handle))
        # pcap_next_ex remplit lui-même un pointeur d'en-tête (alloué par
        # libpcap) : on lui passe l'adresse d'un pointeur, pas une structure.
        pointeur_entete = ctypes.POINTER(_EnTetePaquet)()
        pointeur_donnees = ctypes.POINTER(ctypes.c_ubyte)()
        retenus = 0
        dossier = os.path.dirname(chemin_out)
        if dossier:
            os.makedirs(dossier, exist_ok=True)
        with open(chemin_out, "wb") as sortie:
            _ecrire_en_tete_pcap(sortie, snaplen, type_liaison)
            while lib.pcap_next_ex(handle, ctypes.byref(pointeur_entete), ctypes.byref(pointeur_donnees)) == 1:
                entete = pointeur_entete.contents
                sortie.write(
                    struct.pack(
                        "<IIII",
                        int(entete.ts_sec),
                        int(entete.ts_usec),
                        int(entete.caplen),
                        int(entete.len),
                    )
                )
                sortie.write(ctypes.string_at(pointeur_donnees, int(entete.caplen)))
                retenus += 1
        lib.pcap_freecode(ctypes.byref(programme))
    finally:
        lib.pcap_close(handle)
    logger.debug("filtrer_capture: retour {} paquet(s) retenu(s)", retenus)
    return retenus
