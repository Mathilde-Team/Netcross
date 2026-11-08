"""
pcap_parser.capfile -- cadrage binaire pcap/pcapng et decoupage par
taille (Job 35, issue #155). Aucun outil externe : les fichiers sont
fabriques et relus par tests/pcap_builders.py, comme le reste de la suite
(voir conftest.py -- pas de dependance a tshark/editcap).
"""

import os
import struct

import pytest
from pcap_builders import (
    DSB,
    IDB,
    SHB,
    dsb,
    epb,
    frame,
    frame_index,
    idb,
    pcap_bytes,
    pcapng_packets,
    read_pcap,
    read_pcapng,
    shb,
    synthetic_packets,
    write_bytes,
    write_pcap,
)

from pcap_parser.capfile import (
    _BLOCK_EPB,
    _BLOCK_IDB,
    _BLOCK_ISB,
    _BOM_BE,
    _BOM_LE,
    _MAX_UNIT_LEN,
    _PCAP_HEADER_LEN,
    _PCAPNG_MAGIC,
    FORMAT_NSECPCAP,
    FORMAT_PCAP,
    FORMAT_PCAPNG,
    _iter_options,
    _iter_pcap_records,
    _iter_pcapng_blocks,
    _read_exact_or_none,
    _SegmentSink,
    detect_format,
    first_timestamp,
    format_extension,
    has_packets,
    read_structure,
    split_by_size,
)

# Un enregistrement pcap de 100 octets de donnees occupe 116 octets fichier.
RECORD = 116
PCAP_HEADER = 24


# -- detect_format / format_extension / has_packets ---------------------------


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({}, FORMAT_PCAP),
        ({"endian": ">"}, FORMAT_PCAP),
        ({"nsec": True}, FORMAT_NSECPCAP),
        ({"nsec": True, "endian": ">"}, FORMAT_NSECPCAP),
    ],
)
def test_detect_format_pcap(tmp_path, kwargs, expected):
    path = tmp_path / "x.bin"  # l'extension ne compte pas, seulement les octets magiques
    path.write_bytes(pcap_bytes([], **kwargs))
    assert detect_format(str(path)) == expected


def test_detect_format_pcapng(tmp_path):
    path = tmp_path / "x.pcap"  # extension trompeuse volontaire
    write_bytes(path, shb(), idb())
    assert detect_format(str(path)) == FORMAT_PCAPNG


def test_detect_format_inconnu_ou_vide(tmp_path):
    (tmp_path / "gz").write_bytes(b"\x1f\x8b\x08\x00 fichier compresse")
    (tmp_path / "vide").write_bytes(b"")
    assert detect_format(str(tmp_path / "gz")) is None
    assert detect_format(str(tmp_path / "vide")) is None


def test_format_extension():
    assert format_extension(FORMAT_PCAP) == ".pcap"
    assert format_extension(FORMAT_NSECPCAP) == ".pcap"
    assert format_extension(FORMAT_PCAPNG) == ".pcapng"
    assert format_extension(None) == ".pcapng"  # comme editcap sans -F


def test_has_packets_pcap(tmp_path):
    vide, plein, tronque = tmp_path / "v.pcap", tmp_path / "p.pcap", tmp_path / "t.pcap"
    vide.write_bytes(pcap_bytes([]))
    plein.write_bytes(pcap_bytes(synthetic_packets(1)))
    tronque.write_bytes(pcap_bytes([])[:10])  # en-tete global incomplet
    assert has_packets(str(vide)) is False
    assert has_packets(str(plein)) is True
    assert has_packets(str(tronque)) is False


def test_has_packets_pcapng(tmp_path):
    vide, plein = tmp_path / "v.pcapng", tmp_path / "p.pcapng"
    write_bytes(vide, shb(), idb())
    write_bytes(plein, shb(), idb(), epb(frame(0)))
    assert has_packets(str(vide)) is False
    assert has_packets(str(plein)) is True


def test_has_packets_format_inconnu_ne_jette_pas_le_fichier(tmp_path):
    (tmp_path / "gz").write_bytes(b"\x1f\x8b\x08\x00 compresse")
    assert has_packets(str(tmp_path / "gz")) is True


# -- split_by_size : pcap classique -------------------------------------------


def test_split_by_size_pcap_taille_exacte(tmp_path):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(100))
    limite = PCAP_HEADER + 10 * RECORD  # exactement 10 paquets par segment

    segments = split_by_size(str(src), str(tmp_path / "cap"), limite)

    assert [os.path.basename(s) for s in segments] == [f"cap_{i:05d}.pcap" for i in range(10)]
    for seg in segments:
        assert os.path.getsize(seg) == limite
        assert len(read_pcap(seg)[1]) == 10


def test_split_by_size_pcap_respecte_la_limite_et_conserve_tout_dans_l_ordre(tmp_path):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(1000))
    limite = 15_000  # ne tombe pas juste : le dernier segment est plus petit

    segments = split_by_size(str(src), str(tmp_path / "cap"), limite)

    assert len(segments) > 1
    assert all(os.path.getsize(s) <= limite for s in segments)
    # aucun paquet perdu ni duplique, ordre d'origine conserve
    indices = [frame_index(data) for seg in segments for _s, _f, data in read_pcap(seg)[1]]
    assert indices == list(range(1000))
    # timestamps conserves tels quels
    _hdr, first = read_pcap(segments[0])
    assert first[0][:2] == (1_700_000_000, 0)


def test_split_by_size_pcap_recopie_l_en_tete_global_dans_chaque_segment(tmp_path):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(30), endian=">", nsec=True)  # endianness + ns conservees
    original_header = read_pcap(src)[0]

    segments = split_by_size(str(src), str(tmp_path / "cap"), PCAP_HEADER + 10 * RECORD)

    assert len(segments) == 3
    assert all(read_pcap(seg)[0] == original_header for seg in segments)
    assert all(detect_format(seg) == FORMAT_NSECPCAP for seg in segments)


def test_split_by_size_un_paquet_plus_gros_que_la_limite_a_son_propre_segment(tmp_path):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(5))

    segments = split_by_size(str(src), str(tmp_path / "cap"), 10)  # < un seul paquet

    # jamais de segment vide : un paquet par segment, meme s'il depasse la limite
    assert len(segments) == 5
    assert all(len(read_pcap(seg)[1]) == 1 for seg in segments)


def test_split_by_size_capture_sans_paquet_ne_cree_aucun_fichier(tmp_path):
    src = tmp_path / "cap.pcap"
    write_pcap(src, [])
    assert split_by_size(str(src), str(tmp_path / "cap"), 1000) == []
    assert list(tmp_path.glob("cap_*")) == []


def test_split_by_size_ignore_le_dernier_enregistrement_tronque(tmp_path):
    src = tmp_path / "cap.pcap"
    src.write_bytes(pcap_bytes(synthetic_packets(10))[:-30])  # capture interrompue en cours d'ecriture

    segments = split_by_size(str(src), str(tmp_path / "cap"), PCAP_HEADER + 4 * RECORD)

    indices = [frame_index(data) for seg in segments for _s, _f, data in read_pcap(seg)[1]]
    assert indices == list(range(9))  # le 10e (incomplet) est ignore, pas d'erreur


def test_split_by_size_pcap_corrompu_leve_et_ne_laisse_aucun_segment(tmp_path):
    src = tmp_path / "cap.pcap"
    bon = pcap_bytes(synthetic_packets(5))
    # 6e enregistrement : longueur capturee aberrante (~4 Gio)
    mauvais = struct.pack("<IIII", 1, 0, 0xFFFFFFF0, 0xFFFFFFF0)
    src.write_bytes(bon + mauvais)

    with pytest.raises(ValueError, match="corrompu"):
        split_by_size(str(src), str(tmp_path / "cap"), PCAP_HEADER + 2 * RECORD)

    assert list(tmp_path.glob("cap_*")) == []  # les segments deja ecrits sont nettoyes


# -- split_by_size : pcapng ---------------------------------------------------


def _pcapng_capture(count, endian="<", interfaces=1):
    blocks = [shb(endian)] + [idb(endian=endian)] * interfaces
    for i in range(count):
        blocks.append(epb(frame(i), ts_us=i, interface=i % interfaces, endian=endian))
    return blocks


@pytest.mark.parametrize("endian", ["<", ">"])
def test_split_by_size_pcapng_conserve_tout_et_chaque_segment_est_autonome(tmp_path, endian):
    src = tmp_path / "cap.pcapng"
    write_bytes(src, *_pcapng_capture(200, endian=endian, interfaces=2))
    limite = 3000

    segments = split_by_size(str(src), str(tmp_path / "cap"), limite)

    assert len(segments) > 1
    assert all(seg.endswith(".pcapng") and os.path.getsize(seg) <= limite for seg in segments)
    for seg in segments:
        types = [b[0] for b in read_pcapng(seg)]
        # SHB puis les DEUX IDB en tete de chaque segment : sans eux, les
        # paquets qui referencent l'interface 1 seraient illisibles
        assert types[:3] == [SHB, IDB, IDB]
    packets = [p for seg in segments for p in pcapng_packets(seg)]
    assert [frame_index(d) for _i, d in packets] == list(range(200))
    assert [i for i, _d in packets] == [n % 2 for n in range(200)]  # numeros d'interface conserves


def test_split_by_size_pcapng_duplique_les_secrets_de_dechiffrement(tmp_path):
    src = tmp_path / "cap.pcapng"
    write_bytes(src, shb(), idb(), dsb(), *[epb(frame(i)) for i in range(60)])

    segments = split_by_size(str(src), str(tmp_path / "cap"), 1500)

    assert len(segments) > 1
    assert all(DSB in [b[0] for b in read_pcapng(seg)] for seg in segments)


def test_split_by_size_pcapng_plusieurs_sections(tmp_path):
    src = tmp_path / "cap.pcapng"
    # deux sections concatenees, d'endianness DIFFERENTES, chacune avec ses interfaces
    section_a = [shb("<"), idb(endian="<")] + [epb(frame(i), endian="<") for i in range(20)]
    section_b = [shb(">"), idb(endian=">")] + [epb(frame(100 + i), endian=">") for i in range(20)]
    write_bytes(src, *section_a, *section_b)

    segments = split_by_size(str(src), str(tmp_path / "cap"), 1500)

    indices = [frame_index(d) for seg in segments for _i, d in pcapng_packets(seg)]
    assert indices == list(range(20)) + list(range(100, 120))
    # un segment qui demarre dans la 2e section doit porter le SHB/IDB de CETTE section
    dernier = read_pcapng(segments[-1])
    assert [b[0] for b in dernier[:2]] == [SHB, IDB]
    assert dernier[0][1][:4] == b"\x1a\x2b\x3c\x4d"  # byte-order magic big-endian


def test_split_by_size_pcapng_sans_paquet_ne_cree_aucun_fichier(tmp_path):
    src = tmp_path / "cap.pcapng"
    write_bytes(src, shb(), idb())
    assert split_by_size(str(src), str(tmp_path / "cap"), 1000) == []
    assert list(tmp_path.glob("cap_*")) == []


def test_split_by_size_pcapng_corrompu_leve_et_ne_laisse_aucun_segment(tmp_path):
    src = tmp_path / "cap.pcapng"
    mauvais_bloc = struct.pack("<II", 6, 0xFFFFFFF0)  # longueur aberrante
    write_bytes(src, *_pcapng_capture(20), mauvais_bloc)

    with pytest.raises(ValueError, match="corrompu"):
        split_by_size(str(src), str(tmp_path / "cap"), 800)

    assert list(tmp_path.glob("cap_*")) == []


# -- split_by_size : garde-fous -------------------------------------------------


def test_split_by_size_refuse_un_format_non_reconnu(tmp_path):
    src = tmp_path / "cap.pcap.gz"
    src.write_bytes(b"\x1f\x8b\x08\x00 compresse")
    with pytest.raises(ValueError, match="format non reconnu"):
        split_by_size(str(src), str(tmp_path / "cap"), 1000)


@pytest.mark.parametrize("max_bytes", [0, -5])
def test_split_by_size_refuse_une_limite_invalide(tmp_path, max_bytes):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(3))
    with pytest.raises(ValueError, match=">= 1"):
        split_by_size(str(src), str(tmp_path / "cap"), max_bytes)


def test_split_by_size_n_ecrase_jamais_un_fichier_existant(tmp_path):
    src = tmp_path / "cap.pcap"
    write_pcap(src, synthetic_packets(50))
    existant = tmp_path / "cap_00001.pcap"
    existant.write_bytes(b"a ne pas toucher")

    with pytest.raises(FileExistsError):
        split_by_size(str(src), str(tmp_path / "cap"), PCAP_HEADER + 10 * RECORD)

    assert existant.read_bytes() == b"a ne pas toucher"
    assert not (tmp_path / "cap_00000.pcap").exists()  # le segment deja ecrit est nettoye


# -- Tests de couverture des branches partielles (issue #288) ------------------

# -- _read_exact_or_none -------------------------------------------------------


def test_read_exact_or_none_complet(tmp_path):
    """Lecture complete d'un fichier."""
    p = tmp_path / "test.bin"
    p.write_bytes(b"\x01\x02\x03\x04")
    with open(p, "rb") as f:
        assert _read_exact_or_none(f, 4) == b"\x01\x02\x03\x04"


def test_read_exact_or_none_tronque(tmp_path):
    """Fichier tronque : retourne None."""
    p = tmp_path / "test.bin"
    p.write_bytes(b"\x01\x02")
    with open(p, "rb") as f:
        assert _read_exact_or_none(f, 4) is None


# -- _iter_pcap_records : corruption -------------------------------------------


def test_iter_pcap_records_longueur_aberrante():
    """Une longueur de record aberrante leve ValueError."""
    # En-tete global pcap (24 octets) - little endian
    header = (
        b"\xd4\xc3\xb2\xa1"
        + b"\x00\x02\x00\x04"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\xff\xff\x00\x00"
        + b"\x01\x00\x00\x00"
    )
    # Record header avec incl_len aberrant (offset 8 = 3e uint32)
    record_header = struct.pack("<IIII", 1, 0, _MAX_UNIT_LEN + 1, 0)
    import io

    f = io.BytesIO(header + record_header)
    f.seek(_PCAP_HEADER_LEN)  # skip global header
    endian = "<"
    with pytest.raises(ValueError, match="corrompu"):
        list(_iter_pcap_records(f, endian))


def test_iter_pcap_records_tronque():
    """Un record tronque (header incomplet) arrete silencieusement."""
    header = (
        b"\xd4\xc3\xb2\xa1"
        + b"\x00\x02\x00\x04"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\xff\xff\x00\x00"
        + b"\x01\x00\x00\x00"
    )
    import io

    f = io.BytesIO(header + b"\x00" * 10)  # header de record incomplet
    f.seek(_PCAP_HEADER_LEN)  # skip global header
    endian = "<"
    records = list(_iter_pcap_records(f, endian))
    assert records == []


# -- _iter_pcapng_blocks : BOM et corruption -----------------------------------


def test_iter_pcapng_blocks_bom_tronque():
    """SHB avec BOM tronque : arret silencieux (ligne 142)."""
    import io

    # SHB header (8 octets) + BOM incomplet (2 octets au lieu de 4)
    data = _PCAPNG_MAGIC + struct.pack("<I", 12) + _BOM_LE[:2]
    f = io.BytesIO(data)
    blocks = list(_iter_pcapng_blocks(f))
    assert blocks == []


def test_iter_pcapng_blocks_bom_invalide():
    """BOM invalide dans un SHB : ValueError (ligne 148)."""
    import io

    # SHB header + BOM invalide
    data = _PCAPNG_MAGIC + struct.pack("<I", 12) + b"\x00\x00\x00\x00"
    f = io.BytesIO(data)
    with pytest.raises(ValueError, match="byte-order magic"):
        list(_iter_pcapng_blocks(f))


def test_iter_pcapng_blocks_bom_big_endian():
    """BOM big-endian dans un SHB."""
    import io

    # SHB avec BOM big-endian : total_len doit etre packe en big-endian
    shb = _PCAPNG_MAGIC + struct.pack(">I", 16) + _BOM_BE
    # Ajouter un IDB simple en big-endian
    idb = struct.pack(">I", _BLOCK_IDB) + struct.pack(">I", 20) + struct.pack(">HHI", 1, 0, 65535) + b"\x00\x00\x00\x00"
    f = io.BytesIO(shb + idb)
    blocks = list(_iter_pcapng_blocks(f))
    # Au moins le SHB doit etre lu
    assert len(blocks) >= 1


def test_iter_pcapng_blocks_bloc_corrompu():
    """Bloc avec longueur invalide : ValueError."""
    import io

    # SHB valide (total_len=16, avec 4 octets de padding apres BOM)
    shb = _PCAPNG_MAGIC + struct.pack("<I", 16) + _BOM_LE + b"\x00" * 4
    # Bloc corrompu : total_len < 12
    bad_block = struct.pack("<I", _BLOCK_IDB) + struct.pack("<I", 4)
    f = io.BytesIO(shb + bad_block)
    with pytest.raises(ValueError, match="corrompu"):
        list(_iter_pcapng_blocks(f))


# -- _iter_options -------------------------------------------------------------


def test_iter_options_endofopt():
    """opt_endofopt arrete l'iteration."""
    data = struct.pack("<HH", 0, 0)  # opt_endofopt
    assert list(_iter_options(data, "<")) == []


def test_iter_options_normales():
    """Options normales sont yielded."""
    # Option code=2, length=5, value="eth0\0" padded to 8
    value = b"eth0\0"
    padded_len = (len(value) + 3) & ~3  # 8
    opt = struct.pack("<HH", 2, len(value)) + value + b"\x00" * (padded_len - len(value))
    opt += struct.pack("<HH", 0, 0)  # endofopt
    options = list(_iter_options(opt, "<"))
    assert len(options) == 1
    code, val = options[0]
    assert code == 2
    assert val == b"eth0\0"


def test_iter_options_tronquee():
    """Option tronquee : arret."""
    data = struct.pack("<HH", 2, 100) + b"\x00"  # length=100 mais 1 octet present
    options = list(_iter_options(data, "<"))
    assert options == []


def test_iter_options_trop_court():
    """Donnees trop courtes pour un en-tete d'option."""
    assert list(_iter_options(b"\x00\x00", "<")) == []


# -- _read_pcapng_structure : ISB et interfaces --------------------------------


def test_read_structure_pcapng_avec_isb(tmp_path):
    """read_structure lit les compteurs ISB d'un pcapng."""
    p = tmp_path / "test.pcapng"
    # SHB
    shb_body = _BOM_LE + struct.pack("<HH", 1, 0) + b"\x00" * 4
    shb_total_len = 8 + len(shb_body) + 4
    shb = _PCAPNG_MAGIC + struct.pack("<I", shb_total_len) + shb_body + b"\x00" * 4
    # IDB avec nom d'interface
    if_name = b"eth0"
    if_name_padded = if_name + b"\x00" * ((4 - len(if_name) % 4) % 4)
    idb_options = struct.pack("<HH", 2, len(if_name)) + if_name_padded + struct.pack("<HH", 0, 0)
    idb_body = struct.pack("<HHI", 1, 0, 65535) + idb_options
    idb_total_len = 8 + len(idb_body) + 4
    idb = struct.pack("<I", _BLOCK_IDB) + struct.pack("<I", idb_total_len) + idb_body + b"\x00" * 4
    # ISB avec ifrecv=100, ifdrop=5
    # ISB body: interface_id(4) + timestamp(8) = 12 bytes avant options
    isb_body = struct.pack("<I", 0) + struct.pack("<II", 0, 0)  # interface_id=0 + timestamp
    isb_options = (
        struct.pack("<HH", 4, 8)
        + struct.pack("<Q", 100)  # ifrecv
        + struct.pack("<HH", 5, 8)
        + struct.pack("<Q", 5)  # ifdrop
        + struct.pack("<HH", 0, 0)  # endofopt
    )
    isb_total_len = 8 + len(isb_body) + len(isb_options) + 4
    isb = struct.pack("<I", _BLOCK_ISB) + struct.pack("<I", isb_total_len) + isb_body + isb_options + b"\x00" * 4
    p.write_bytes(shb + idb + isb)

    struct_info = read_structure(str(p))
    assert struct_info is not None
    assert struct_info.fmt == FORMAT_PCAPNG
    assert len(struct_info.interfaces) == 1
    assert struct_info.interfaces[0].name == "eth0"
    assert struct_info.interfaces[0].received == 100
    assert struct_info.interfaces[0].dropped_by_interface == 5


def test_read_structure_pcapng_isb_interface_inconnue(tmp_path):
    """ISB pour une interface inconnue : ignore (ligne 244)."""
    p = tmp_path / "test.pcapng"
    shb_body = _BOM_LE + struct.pack("<HH", 1, 0) + b"\x00" * 4
    shb_total_len = 8 + len(shb_body) + 4
    shb = _PCAPNG_MAGIC + struct.pack("<I", shb_total_len) + shb_body + b"\x00" * 4
    # ISB pour interface_id=99 (inexistante)
    isb_body = struct.pack("<I", 99) + struct.pack("<HH", 0, 0)
    isb_total_len = 8 + len(isb_body) + 4
    isb = struct.pack("<I", _BLOCK_ISB) + struct.pack("<I", isb_total_len) + isb_body + b"\x00" * 4
    p.write_bytes(shb + isb)

    struct_info = read_structure(str(p))
    assert struct_info is not None
    assert len(struct_info.interfaces) == 0  # pas d'IDB


def test_read_structure_pcapng_isb_valeur_non_8_octets(tmp_path):
    """ISB avec une option dont la valeur n'a pas 8 octets : ignore (ligne 249)."""
    p = tmp_path / "test.pcapng"
    shb_body = _BOM_LE + struct.pack("<HH", 1, 0) + b"\x00" * 4
    shb_total_len = 8 + len(shb_body) + 4
    shb = _PCAPNG_MAGIC + struct.pack("<I", shb_total_len) + shb_body + b"\x00" * 4
    # IDB simple
    idb_body = struct.pack("<HHI", 1, 0, 65535)
    idb_total_len = 8 + len(idb_body) + 4
    idb = struct.pack("<I", _BLOCK_IDB) + struct.pack("<I", idb_total_len) + idb_body + b"\x00" * 4
    # ISB avec option ifrecv de longueur 4 (pas 8)
    isb_body = struct.pack("<I", 0)
    isb_options = struct.pack("<HH", 4, 4) + struct.pack("<I", 100) + struct.pack("<HH", 0, 0)
    isb_total_len = 8 + len(isb_body) + len(isb_options) + 4
    isb = struct.pack("<I", _BLOCK_ISB) + struct.pack("<I", isb_total_len) + isb_body + isb_options + b"\x00" * 4
    p.write_bytes(shb + idb + isb)

    struct_info = read_structure(str(p))
    assert struct_info is not None
    assert struct_info.interfaces[0].received is None  # valeur ignoree


def test_read_structure_format_inconnu(tmp_path):
    """read_structure avec un format non reconnu retourne None."""
    p = tmp_path / "test.bin"
    p.write_bytes(b"\x00\x00\x00\x00")
    assert read_structure(str(p)) is None


def test_read_structure_pcap_tronque(tmp_path):
    """read_structure avec un pcap tronque avant l'en-tete global."""
    p = tmp_path / "test.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1\x00\x02")  # magic + version incomplete
    assert read_structure(str(p)) is None


def test_read_structure_pcapng_sans_shb(tmp_path):
    """read_structure pcapng sans SHB : version None, retourne None (ligne 263)."""
    p = tmp_path / "test.pcapng"
    # Pas de SHB, juste un IDB
    idb = struct.pack("<I", _BLOCK_IDB) + struct.pack("<I", 20) + struct.pack("<HHI", 1, 0, 65535) + b"\x00\x00\x00\x00"
    p.write_bytes(idb)
    assert read_structure(str(p)) is None


# -- has_packets ---------------------------------------------------------------


def test_has_packets_pcap_vide(tmp_path):
    """has_packets sur un pcap sans paquet."""
    p = tmp_path / "empty.pcap"
    header = (
        b"\xd4\xc3\xb2\xa1"
        + b"\x00\x02\x00\x04"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\xff\xff\x00\x00"
        + b"\x01\x00\x00\x00"
    )
    p.write_bytes(header)
    assert has_packets(str(p)) is False


def test_has_packets_format_inconnu(tmp_path):
    """has_packets sur un format inconnu retourne True."""
    p = tmp_path / "unknown.bin"
    p.write_bytes(b"\x00" * 4)
    assert has_packets(str(p)) is True


# -- _SegmentSink --------------------------------------------------------------


def test_segment_sink_is_open():
    """_SegmentSink.is_open avant et apres ouverture."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        sink = _SegmentSink(f"{tmpdir}/seg", ".pcap", 1024)
        assert sink.is_open is False
        sink.preamble = [b"header"]
        sink.write(b"packet", is_packet=True)
        assert sink.is_open is True


def test_segment_sink_close_segment_sans_paquet(tmp_path):
    """close() supprime un segment sans paquet."""
    sink = _SegmentSink(str(tmp_path / "seg"), ".pcap", 1024)
    sink.preamble = [b"header"]
    sink.write(b"preamble_only", is_packet=False)
    sink.close()
    assert len(sink.paths) == 0  # segment supprime car sans paquet


def test_segment_sink_abort(tmp_path):
    """abort() supprime tous les segments."""
    sink = _SegmentSink(str(tmp_path / "seg"), ".pcap", 1024)
    sink.preamble = [b"header"]
    sink.write(b"packet1", is_packet=True)
    sink.write(b"packet2", is_packet=True)
    assert len(sink.paths) >= 1
    sink.abort()
    assert len(sink.paths) == 0
    import os

    for path in sink.paths:
        assert not os.path.exists(path)


# -- split_by_size : cas limites ------------------------------------------------


def test_split_by_size_max_bytes_invalide(tmp_path):
    """split_by_size avec max_bytes < 1 : ValueError."""
    p = tmp_path / "test.pcap"
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    with pytest.raises(ValueError, match="max_bytes"):
        split_by_size(str(p), str(tmp_path / "out"), 0)


def test_split_by_size_format_inconnu(tmp_path):
    """split_by_size avec un format non reconnu : ValueError."""
    p = tmp_path / "test.bin"
    p.write_bytes(b"\x00" * 4)
    with pytest.raises(ValueError, match="format non reconnu"):
        split_by_size(str(p), str(tmp_path / "out"), 1024)


def test_split_by_size_pcap_vide(tmp_path):
    """split_by_size sur un pcap sans paquet : aucun segment."""
    p = tmp_path / "empty.pcap"
    header = (
        b"\xd4\xc3\xb2\xa1"
        + b"\x00\x02\x00\x04"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\xff\xff\x00\x00"
        + b"\x01\x00\x00\x00"
    )
    p.write_bytes(header)
    segments = split_by_size(str(p), str(tmp_path / "seg"), 1024)
    assert segments == []


# -- first_timestamp : cas limites ---------------------------------------------


def test_first_timestamp_pcapng_sans_paquet(tmp_path):
    """first_timestamp sur un pcapng sans EPB : ValueError."""
    p = tmp_path / "test.pcapng"
    shb_body = _BOM_LE + struct.pack("<HH", 1, 0) + b"\x00" * 4
    shb_total_len = 8 + len(shb_body) + 4
    shb = _PCAPNG_MAGIC + struct.pack("<I", shb_total_len) + shb_body + b"\x00" * 4
    p.write_bytes(shb)
    with pytest.raises(ValueError, match="sans paquet"):
        first_timestamp(str(p))


def test_first_timestamp_pcap_sans_paquet(tmp_path):
    """first_timestamp sur un pcap sans paquet : ValueError."""
    p = tmp_path / "empty.pcap"
    header = (
        b"\xd4\xc3\xb2\xa1"
        + b"\x00\x02\x00\x04"
        + b"\x00\x00\x00\x00"
        + b"\x00\x00\x00\x00"
        + b"\xff\xff\x00\x00"
        + b"\x01\x00\x00\x00"
    )
    p.write_bytes(header)
    with pytest.raises(ValueError, match="sans paquet"):
        first_timestamp(str(p))


def test_first_timestamp_fichier_inexistant():
    """first_timestamp sur un fichier inexistant : FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        first_timestamp("/nonexistent/path/file.pcap")


def test_first_timestamp_format_inconnu(tmp_path):
    """first_timestamp sur un format inconnu : ValueError."""
    p = tmp_path / "test.bin"
    p.write_bytes(b"\x00" * 4)
    with pytest.raises(ValueError, match="format non reconnu"):
        first_timestamp(str(p))


# -- format_extension ----------------------------------------------------------


def test_format_extension_pcap():
    assert format_extension(FORMAT_PCAP) == ".pcap"


def test_format_extension_nsecpcap():
    assert format_extension(FORMAT_NSECPCAP) == ".pcap"


def test_format_extension_pcapng():
    assert format_extension(FORMAT_PCAPNG) == ".pcapng"


def test_format_extension_none():
    assert format_extension(None) == ".pcapng"


def test_format_extension_unknown():
    assert format_extension("unknown") == ".pcapng"


# -- first_timestamp avec paquets reels ----------------------------------------


def test_first_timestamp_pcap_avec_paquet(tmp_path):
    """first_timestamp sur un pcap avec un paquet (lignes 465-467)."""
    p = tmp_path / "test.pcap"
    # En-tete global pcap little-endian
    header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    # Record: ts_sec=1000, ts_usec=500000, incl_len=4, orig_len=4, data=4 octets
    record = struct.pack("<IIII", 1000, 500000, 4, 4) + b"\x00" * 4
    p.write_bytes(header + record)
    ts = first_timestamp(str(p))
    assert ts == 1000.5  # 1000 + 500000/1e6


def test_first_timestamp_nsecpcap(tmp_path):
    """first_timestamp sur un nsecpcap (diviseur 1e9)."""
    p = tmp_path / "test.pcap"
    # Magic nsecpcap little-endian
    header = b"\x4d\x3c\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    # Record: ts_sec=1000, ts_nsec=500000000, incl_len=4, orig_len=4
    record = struct.pack("<IIII", 1000, 500000000, 4, 4) + b"\x00" * 4
    p.write_bytes(header + record)
    ts = first_timestamp(str(p))
    assert abs(ts - 1000.5) < 0.001


def test_first_timestamp_pcapng_avec_epb(tmp_path):
    """first_timestamp sur un pcapng avec un EPB (lignes 498-510)."""
    p = tmp_path / "test.pcapng"
    # SHB
    shb_body = _BOM_LE + struct.pack("<HH", 1, 0) + struct.pack("<q", -1)
    shb_total_len = 8 + len(shb_body) + 4
    shb = _PCAPNG_MAGIC + struct.pack("<I", shb_total_len) + shb_body + b"\x00" * 4
    # IDB
    idb_body = struct.pack("<HHI", 1, 0, 65535)
    idb_total_len = 8 + len(idb_body) + 4
    idb = struct.pack("<I", _BLOCK_IDB) + struct.pack("<I", idb_total_len) + idb_body + b"\x00" * 4
    # EPB: interface_id(4) + ts_high(4) + ts_low(4) + captured_len(4) + packet_len(4) + data
    epb_ts_high = 0
    epb_ts_low = 1000  # timestamp = 1000 (en unite de tsresol, defaut us)
    epb_data = b"\x00" * 4
    epb_body = struct.pack("<IIIII", 0, epb_ts_high, epb_ts_low, len(epb_data), len(epb_data)) + epb_data
    # Pad to 4 bytes
    padded_len = (len(epb_body) + 3) & ~3
    epb_body += b"\x00" * (padded_len - len(epb_body))
    epb_total_len = 8 + len(epb_body) + 4
    epb = struct.pack("<I", _BLOCK_EPB) + struct.pack("<I", epb_total_len) + epb_body + b"\x00" * 4
    p.write_bytes(shb + idb + epb)

    ts = first_timestamp(str(p))
    # Issue #1132 : if_tsresol absent -> 10^-6 s par tick (pcapng, 4.2) ;
    # l'ancienne valeur 1000 / 2^6 lisait a tort le defaut comme une
    # puissance de 2.
    assert ts == pytest.approx(1000 * 1e-6)


def test_first_timestamp_pcapng_avec_tsresol(tmp_path):
    """first_timestamp sur un pcapng avec if_tsresol (option 9 dans IDB)."""
    p = tmp_path / "test.pcapng"
    # SHB
    shb_body = _BOM_LE + struct.pack("<HH", 1, 0) + struct.pack("<q", -1)
    shb_total_len = 8 + len(shb_body) + 4
    shb = _PCAPNG_MAGIC + struct.pack("<I", shb_total_len) + shb_body + b"\x00" * 4
    # IDB avec option if_tsresol (code 9, value=0 = 2^0 = 1 = secondes)
    tsresol_val = bytes([0])  # shift=0, divisor=2^0=1 (secondes)
    tsresol_opt = struct.pack("<HH", 9, 1) + tsresol_val + b"\x00\x00\x00"  # padded to 4
    idb_body = struct.pack("<HHI", 1, 0, 65535) + tsresol_opt + struct.pack("<HH", 0, 0)
    idb_total_len = 8 + len(idb_body) + 4
    idb = struct.pack("<I", _BLOCK_IDB) + struct.pack("<I", idb_total_len) + idb_body + b"\x00" * 4
    # EPB avec timestamp = 5 (en secondes)
    epb_body = struct.pack("<IIIII", 0, 0, 5, 4, 4) + b"\x00" * 4
    padded_len = (len(epb_body) + 3) & ~3
    epb_body += b"\x00" * (padded_len - len(epb_body))
    epb_total_len = 8 + len(epb_body) + 4
    epb = struct.pack("<I", _BLOCK_EPB) + struct.pack("<I", epb_total_len) + epb_body + b"\x00" * 4
    p.write_bytes(shb + idb + epb)

    ts = first_timestamp(str(p))
    assert ts == 5.0  # 5 secondes


def test_first_timestamp_pcap_big_endian(tmp_path):
    """first_timestamp sur un pcap big-endian."""
    p = tmp_path / "test.pcap"
    # Magic pcap big-endian
    header = b"\xa1\xb2\xc3\xd4" + struct.pack(">HHiIII", 2, 4, 0, 0, 65535, 1)
    # Record: ts_sec=2000, ts_usec=250000, incl_len=4, orig_len=4
    record = struct.pack(">IIII", 2000, 250000, 4, 4) + b"\x00" * 4
    p.write_bytes(header + record)
    ts = first_timestamp(str(p))
    assert ts == 2000.25


# -- split_by_size avec donnees reelles ----------------------------------------


def test_split_by_size_pcap_avec_paquet(tmp_path):
    """split_by_size sur un pcap avec un paquet (ligne 410)."""
    p = tmp_path / "test.pcap"
    header = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1000, 0, 4, 4) + b"\x00" * 4
    p.write_bytes(header + record)
    segments = split_by_size(str(p), str(tmp_path / "seg"), 1024)
    assert len(segments) == 1
    import os

    assert os.path.exists(segments[0])


def test_split_by_size_pcapng_avec_paquet(tmp_path):
    """split_by_size sur un pcapng avec un EPB (ligne 452)."""
    p = tmp_path / "test.pcapng"
    # SHB
    shb_body = _BOM_LE + struct.pack("<HH", 1, 0) + struct.pack("<q", -1)
    shb_total_len = 8 + len(shb_body) + 4
    shb = _PCAPNG_MAGIC + struct.pack("<I", shb_total_len) + shb_body + b"\x00" * 4
    # IDB
    idb_body = struct.pack("<HHI", 1, 0, 65535)
    idb_total_len = 8 + len(idb_body) + 4
    idb = struct.pack("<I", _BLOCK_IDB) + struct.pack("<I", idb_total_len) + idb_body + b"\x00" * 4
    # EPB
    epb_data = b"\x00" * 4
    epb_body = struct.pack("<IIIII", 0, 0, 1000, len(epb_data), len(epb_data)) + epb_data
    padded_len = (len(epb_body) + 3) & ~3
    epb_body += b"\x00" * (padded_len - len(epb_body))
    epb_total_len = 8 + len(epb_body) + 4
    epb = struct.pack("<I", _BLOCK_EPB) + struct.pack("<I", epb_total_len) + epb_body + b"\x00" * 4
    p.write_bytes(shb + idb + epb)

    segments = split_by_size(str(p), str(tmp_path / "seg"), 1024)
    assert len(segments) >= 1
    import os

    for s in segments:
        assert os.path.exists(s)


def test_split_by_size_pcapng_multi_sections(tmp_path):
    """split_by_size sur un pcapng avec deux sections (SHB multiple)."""
    p = tmp_path / "test.pcapng"
    # Premiere section
    shb1_body = _BOM_LE + struct.pack("<HH", 1, 0) + struct.pack("<q", -1)
    shb1_total_len = 8 + len(shb1_body) + 4
    shb1 = _PCAPNG_MAGIC + struct.pack("<I", shb1_total_len) + shb1_body + b"\x00" * 4
    idb_body = struct.pack("<HHI", 1, 0, 65535)
    idb_total_len = 8 + len(idb_body) + 4
    idb = struct.pack("<I", _BLOCK_IDB) + struct.pack("<I", idb_total_len) + idb_body + b"\x00" * 4
    epb_data = b"\x00" * 4
    epb_body = struct.pack("<IIIII", 0, 0, 1000, len(epb_data), len(epb_data)) + epb_data
    padded_len = (len(epb_body) + 3) & ~3
    epb_body += b"\x00" * (padded_len - len(epb_body))
    epb_total_len = 8 + len(epb_body) + 4
    epb = struct.pack("<I", _BLOCK_EPB) + struct.pack("<I", epb_total_len) + epb_body + b"\x00" * 4
    # Deuxieme section
    shb2 = shb1  # meme structure
    p.write_bytes(shb1 + idb + epb + shb2 + idb + epb)
    segments = split_by_size(str(p), str(tmp_path / "seg"), 4096)
    assert len(segments) >= 1


# -- has_packets pcapng --------------------------------------------------------


def test_has_packets_pcapng_avec_epb(tmp_path):
    """has_packets sur un pcapng avec un EPB."""
    p = tmp_path / "test.pcapng"
    shb_body = _BOM_LE + struct.pack("<HH", 1, 0) + struct.pack("<q", -1)
    shb_total_len = 8 + len(shb_body) + 4
    shb = _PCAPNG_MAGIC + struct.pack("<I", shb_total_len) + shb_body + b"\x00" * 4
    idb_body = struct.pack("<HHI", 1, 0, 65535)
    idb_total_len = 8 + len(idb_body) + 4
    idb = struct.pack("<I", _BLOCK_IDB) + struct.pack("<I", idb_total_len) + idb_body + b"\x00" * 4
    epb_data = b"\x00" * 4
    epb_body = struct.pack("<IIIII", 0, 0, 1000, len(epb_data), len(epb_data)) + epb_data
    padded_len = (len(epb_body) + 3) & ~3
    epb_body += b"\x00" * (padded_len - len(epb_body))
    epb_total_len = 8 + len(epb_body) + 4
    epb = struct.pack("<I", _BLOCK_EPB) + struct.pack("<I", epb_total_len) + epb_body + b"\x00" * 4
    p.write_bytes(shb + idb + epb)
    assert has_packets(str(p)) is True


def test_has_packets_pcapng_sans_paquet(tmp_path):
    """has_packets sur un pcapng sans bloc de paquet."""
    p = tmp_path / "test.pcapng"
    shb_body = _BOM_LE + struct.pack("<HH", 1, 0) + struct.pack("<q", -1)
    shb_total_len = 8 + len(shb_body) + 4
    shb = _PCAPNG_MAGIC + struct.pack("<I", shb_total_len) + shb_body + b"\x00" * 4
    p.write_bytes(shb)
    assert has_packets(str(p)) is False


# -- _SegmentSink.write_if_open ------------------------------------------------


def test_segment_sink_write_if_open(tmp_path):
    """write_if_open ecrit dans le segment courant s'il est ouvert."""
    sink = _SegmentSink(str(tmp_path / "seg"), ".pcap", 1024)
    sink.preamble = [b"header"]
    sink.write(b"packet", is_packet=True)  # ouvre un segment
    assert sink.is_open
    sink.write_if_open(b"preamble_block")  # ecrit dans le segment ouvert
    sink.close()
    # Le segment doit exister et contenir le preamble_block
    assert len(sink.paths) == 1
    with open(sink.paths[0], "rb") as f:
        content = f.read()
    assert b"preamble_block" in content


def test_segment_sink_write_if_open_sans_segment(tmp_path):
    """write_if_open sans segment ouvert n'ecrit rien."""
    sink = _SegmentSink(str(tmp_path / "seg"), ".pcap", 1024)
    sink.preamble = [b"header"]
    # Pas de segment ouvert : write_if_open ne fait rien
    sink.write_if_open(b"preamble_block")
    assert not sink.is_open
    sink.close()
    assert len(sink.paths) == 0  # aucun segment cree


# -- detect_format : nsecpcap --------------------------------------------------


def test_detect_format_nsecpcap_le(tmp_path):
    """detect_format reconnait un nsecpcap little-endian."""
    p = tmp_path / "test.pcap"
    p.write_bytes(b"\x4d\x3c\xb2\xa1")
    assert detect_format(str(p)) == FORMAT_NSECPCAP


def test_detect_format_nsecpcap_be(tmp_path):
    """detect_format reconnait un nsecpcap big-endian."""
    p = tmp_path / "test.pcap"
    p.write_bytes(b"\xa1\xb2\x3c\x4d")
    assert detect_format(str(p)) == FORMAT_NSECPCAP


def test_detect_format_pcap_be(tmp_path):
    """detect_format reconnait un pcap big-endian."""
    p = tmp_path / "test.pcap"
    p.write_bytes(b"\xa1\xb2\xc3\xd4")
    assert detect_format(str(p)) == FORMAT_PCAP


def test_detect_format_inconnu(tmp_path):
    """detect_format retourne None pour un format inconnu."""
    p = tmp_path / "test.bin"
    p.write_bytes(b"\x00\x00\x00\x00")
    assert detect_format(str(p)) is None


def test_detect_format_vide(tmp_path):
    """detect_format retourne None pour un fichier vide."""
    p = tmp_path / "empty.pcap"
    p.write_bytes(b"")
    assert detect_format(str(p)) is None


# -- ISB (Interface Statistics Block) : issue #288 ---------------------------


def _isb(interface_id: int = 0, *, ifrecv=None, ifdrop=None, osdrop=None, endian="<"):
    """Construit un bloc ISB pcapng avec les options donnees.
    Le corps d'un ISB contient interface_id (4) + timestamp (8) + options."""
    from pcap_builders import _pad4, block

    body = struct.pack(endian + "I", interface_id)
    body += struct.pack(endian + "Q", 0)  # timestamp (8 octets)
    for code, val in [
        (4, ifrecv),  # _OPT_ISB_IFRECV
        (5, ifdrop),  # _OPT_ISB_IFDROP
        (7, osdrop),  # _OPT_ISB_OSDROP
    ]:
        if val is not None:
            opt_val = struct.pack(endian + "Q", val)
            body += struct.pack(endian + "HH", code, len(opt_val)) + _pad4(opt_val)
    body += struct.pack(endian + "HH", 0, 0)  # opt_endofopt
    return block(0x00000005, body, endian)


def test_read_structure_pcapng_avec_isb_remplit_les_compteurs(tmp_path):
    """Un ISB avec ifrecv/ifdrop/osdrop renseigne les compteurs de
    l'InterfaceRecord correspondant (lignes 255-260)."""
    from pcap_builders import epb, frame, idb, shb, write_bytes

    from pcap_parser.capfile import read_structure

    pkt = frame(0, 60)
    write_bytes(
        tmp_path / "isb.pcapng",
        shb(),
        idb(),
        epb(pkt, ts_us=1_700_000_000_000_000),
        _isb(ifrecv=1000, ifdrop=5, osdrop=2),
    )
    struct = read_structure(str(tmp_path / "isb.pcapng"))
    assert struct is not None
    assert struct.interfaces[0].received == 1000
    assert struct.interfaces[0].dropped_by_interface == 5
    assert struct.interfaces[0].dropped_by_os == 2


def test_read_structure_pcapng_isb_interface_inconnu_ignore(tmp_path):
    """Un ISB pour une interface inexistante est ignore sans erreur
    (ligne 253)."""
    from pcap_builders import idb, shb, write_bytes

    from pcap_parser.capfile import read_structure

    write_bytes(
        tmp_path / "isb_unknown.pcapng",
        shb(),
        idb(),
        _isb(interface_id=99, ifrecv=42),
    )
    struct = read_structure(str(tmp_path / "isb_unknown.pcapng"))
    assert struct is not None
    assert len(struct.interfaces) == 1
    # L'ISB pour l'interface 99 n'a pas modifie l'interface 0
    assert struct.interfaces[0].received is None


def test_read_structure_pcapng_isb_option_non_8_octets_ignoree(tmp_path):
    """Une option ISB dont la valeur ne fait pas 8 octets est ignoree
    (ligne 259-260 : if len(value) != 8: continue)."""
    from pcap_builders import _pad4, block, idb, shb, write_bytes

    from pcap_parser.capfile import read_structure

    # ISB avec une option IFRECV dont la valeur fait 4 octets (pas 8)
    isb_body = struct.pack("<I", 0)  # interface_id
    isb_body += struct.pack("<Q", 0)  # timestamp
    isb_body += struct.pack("<HH", 4, 4) + _pad4(b"\x01\x00\x00\x00")  # IFRECV, 4 octets
    isb_body += struct.pack("<HH", 0, 0)  # opt_endofopt
    bad_isb = block(0x00000005, isb_body)

    write_bytes(
        tmp_path / "isb_bad.pcapng",
        shb(),
        idb(),
        bad_isb,
    )
    cap = read_structure(str(tmp_path / "isb_bad.pcapng"))
    assert cap is not None
    assert cap.interfaces[0].received is None


def test_read_structure_pcapng_avec_isb_retourne_capture_structure(tmp_path):
    """Un pcapng valide avec ISB retourne bien un CaptureStructure (ligne 267)."""
    from pcap_builders import epb, frame, idb, shb, write_bytes

    from pcap_parser.capfile import FORMAT_PCAPNG, read_structure

    pkt = frame(0, 60)
    write_bytes(
        tmp_path / "ok.pcapng",
        shb(),
        idb(),
        epb(pkt, ts_us=1_700_000_000_000_000),
        _isb(ifrecv=10),
    )
    struct = read_structure(str(tmp_path / "ok.pcapng"))
    assert struct is not None
    assert struct.fmt == FORMAT_PCAPNG
    assert struct.version is not None


# -- _first_timestamp_pcap : issue #288 (ligne 456) -------------------------


def test_first_timestamp_pcap_retourne_le_timestamp_du_premier_paquet(tmp_path):
    """first_timestamp sur un pcap classique lit le timestamp du premier
    paquet (couvre _first_timestamp_pcap, ligne 456)."""
    from pcap_builders import synthetic_packets, write_pcap

    from pcap_parser.capfile import first_timestamp

    pkts = synthetic_packets(3, start_us=1_700_000_000_000_000)
    path = tmp_path / "ts.pcap"
    write_pcap(path, pkts)
    ts = first_timestamp(str(path))
    assert ts == 1700000000.0  # premier paquet a t=1700000000.0


def test_first_timestamp_nsecpcap_retourne_en_nanosecondes(tmp_path):
    """first_timestamp sur un nsecpcap utilise le diviseur 1e9."""
    from pcap_builders import synthetic_packets, write_pcap

    from pcap_parser.capfile import first_timestamp

    pkts = synthetic_packets(1, start_us=1_700_000_000_000_000)
    path = tmp_path / "ts_nsec.pcap"
    write_pcap(path, pkts, nsec=True)
    ts = first_timestamp(str(path))
    # synthetic_packets retourne des timestamps en microsecondes ; pcap_bytes
    # avec nsec=True les divise par 1e9 pour obtenir sec + frac nanosec.
    # 1_700_000_000_000_000 us / 1e9 = 1_700_000 s + 0 ns
    assert ts == 1_700_000.0


# -- _split_pcap : issue #288 (ligne 414) -----------------------------------


def test_split_by_size_pcap_couvre_split_pcap(tmp_path):
    """split_by_size sur un pcap classique passe par _split_pcap (ligne 414)."""
    from pcap_builders import synthetic_packets, write_pcap

    from pcap_parser.capfile import split_by_size

    pkts = synthetic_packets(5, size=100)
    path = tmp_path / "split.pcap"
    write_pcap(path, pkts)
    segments = split_by_size(str(path), str(tmp_path / "out"), max_bytes=500)
    assert len(segments) >= 1
    for seg in segments:
        assert os.path.exists(seg)
