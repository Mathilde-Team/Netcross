# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.tls_diagnostics -- parsing bas niveau de messages TLS
construits a la main (memes principes que la validation manuelle
decrite dans claude.md Session 3 : "ClientHello TLS minimal... injecte")
et logique de diagnostic multi-points (build_handshake_status/diagnose_tls).
"""

import struct

from netcross_core.tls_diagnostics import (
    HandshakeStatus,
    TlsEvent,
    TlsFinding,
    _iter_handshake_messages,
    _iter_tls_records,
    _looks_like_tls,
    _read_u16,
    _tls_version_str,
    build_handshake_status,
    diagnose_tls,
    parse_alert,
    parse_client_hello,
    parse_server_hello,
    print_tls_diagnostics,
)


def _u16(v):
    return struct.pack("!H", v)


def _client_hello(sni: str | None = "example.com", version=(3, 3)) -> bytes:
    body = bytes(version)  # client_version
    body += b"\x00" * 32  # random
    body += b"\x00"  # session_id_len = 0
    body += _u16(2) + b"\x13\x01"  # cipher_suites (len=2, 1 suite)
    body += b"\x01\x00"  # compression_methods (len=1, null)

    extensions = b""
    if sni is not None:
        name = sni.encode()
        server_name_entry = b"\x00" + _u16(len(name)) + name  # type=host_name(0)
        ext_body = _u16(len(server_name_entry)) + server_name_entry
        extensions += _u16(0) + _u16(len(ext_body)) + ext_body  # extension type 0 = server_name

    body += _u16(len(extensions)) + extensions
    return body


def _server_hello(version=(3, 3), cipher=0x1301) -> bytes:
    body = bytes(version)
    body += b"\x00" * 32
    body += b"\x00"  # session_id_len
    body += _u16(cipher)
    return body


# -- parse_client_hello -----------------------------------------------------


def test_parse_client_hello_extrait_sni_et_version():
    result = parse_client_hello(_client_hello(sni="example.com"))
    assert result["tls_version"] == "TLS 1.2"
    assert result["sni"] == "example.com"


def test_parse_client_hello_sans_sni():
    result = parse_client_hello(_client_hello(sni=None))
    assert result["sni"] is None


def test_parse_client_hello_trop_court_renvoie_dict_vide():
    assert parse_client_hello(b"\x03\x03") == {}


def test_parse_client_hello_tls13_version_str():
    result = parse_client_hello(_client_hello(sni=None, version=(3, 4)))
    assert result["tls_version"] == "TLS 1.3"


# -- parse_server_hello -------------------------------------------------------


def test_parse_server_hello_cipher_et_version():
    result = parse_server_hello(_server_hello(cipher=0x1301))
    assert result["tls_version"] == "TLS 1.2"
    assert result["cipher"] == "0x1301"


def test_parse_server_hello_trop_court():
    assert parse_server_hello(b"\x03\x03") == {}


# -- parse_alert --------------------------------------------------------------


def test_parse_alert_fatal_handshake_failure():
    result = parse_alert(bytes([2, 40]))
    assert result == {"level": "fatal", "description": "handshake_failure"}


def test_parse_alert_warning_close_notify():
    result = parse_alert(bytes([1, 0]))
    assert result == {"level": "warning", "description": "close_notify"}


def test_parse_alert_code_inconnu():
    result = parse_alert(bytes([1, 250]))
    assert result["description"] == "unknown(250)"


def test_parse_alert_trop_court():
    assert parse_alert(b"\x01") == {}


# -- build_handshake_status ----------------------------------------------------


def _ev(**overrides) -> TlsEvent:
    defaults = {
        "point": "A",
        "ts": 0.0,
        "src": "10.0.0.1",
        "sport": 50000,
        "dst": "10.0.0.2",
        "dport": 443,
        "record_type": "handshake",
    }
    defaults.update(overrides)
    return TlsEvent(**defaults)


def test_handshake_status_verdict_no_handshake_seen_par_defaut():
    st = HandshakeStatus(point="A", flow_id="x")
    assert st.verdict == "no_handshake_seen"


def test_handshake_status_verdict_progresse_client_hello_puis_complete():
    events = [
        _ev(ts=0.0, handshake_type="client_hello", sni="example.com"),
        _ev(ts=0.1, handshake_type="server_hello", tls_version="TLS 1.2"),
        _ev(ts=0.2, record_type="application_data"),
    ]
    status = build_handshake_status(events)
    st = status["A"][next(iter(status["A"]))]
    assert st.verdict == "complete"
    assert st.sni == "example.com"


def test_handshake_status_client_hello_no_reply():
    events = [_ev(ts=0.0, handshake_type="client_hello", sni="example.com")]
    status = build_handshake_status(events)
    st = next(iter(status["A"].values()))
    assert st.verdict == "client_hello_no_reply"


def test_handshake_status_alert_fatal_prioritaire_sur_application_data():
    events = [
        _ev(ts=0.0, handshake_type="client_hello"),
        _ev(ts=0.1, handshake_type="server_hello"),
        _ev(ts=0.2, record_type="alert", alert_level="fatal", alert_description="bad_certificate"),
    ]
    status = build_handshake_status(events)
    st = next(iter(status["A"].values()))
    assert st.verdict == "alert_fatal:bad_certificate"


def test_handshake_status_flux_bidirectionnel_meme_flow_id():
    # meme flux vu dans les deux sens (client->serveur, serveur->client)
    # doit produire UN SEUL HandshakeStatus (voir _flow_id, tri src/dst)
    events = [
        _ev(ts=0.0, src="10.0.0.1", sport=50000, dst="10.0.0.2", dport=443, handshake_type="client_hello"),
        _ev(ts=0.1, src="10.0.0.2", sport=443, dst="10.0.0.1", dport=50000, handshake_type="server_hello"),
    ]
    status = build_handshake_status(events)
    assert len(status["A"]) == 1


# -- diagnose_tls ---------------------------------------------------------------


def test_diagnose_tls_alerte_fatale_signalee_par_point():
    status = {"A": {"flow1": HandshakeStatus(point="A", flow_id="flow1", fatal_alert="bad_certificate", sni="x.com")}}
    findings = diagnose_tls(status, points_order=["A"])
    anomalies = [f for f in findings if f.severity == "anomalie"]
    assert any("alert fatal" in f.message for f in anomalies)


def test_diagnose_tls_degradation_entre_points_consecutifs():
    complete_a = HandshakeStatus(
        point="A",
        flow_id="f1",
        client_hello_seen=True,
        server_hello_seen=True,
        application_data_seen=True,
        sni="x.com",
    )
    broken_b = HandshakeStatus(
        point="B",
        flow_id="f1",
        client_hello_seen=True,
        fatal_alert=None,
    )
    status = {"A": {"f1": complete_a}, "B": {"f1": broken_b}}
    findings = diagnose_tls(status, points_order=["A", "B"])
    degradation = [f for f in findings if f.segment == "A -> B"]
    assert len(degradation) == 1
    assert degradation[0].severity == "anomalie"
    assert "x.com" in degradation[0].message


def test_diagnose_tls_pas_de_degradation_si_toujours_complete():
    complete = HandshakeStatus(
        point="A",
        flow_id="f1",
        client_hello_seen=True,
        server_hello_seen=True,
        application_data_seen=True,
    )
    status = {"A": {"f1": complete}, "B": {"f1": complete}}
    findings = diagnose_tls(status, points_order=["A", "B"])
    assert not [f for f in findings if f.segment == "A -> B"]


def test_diagnose_tls_info_ratio_handshakes_aboutis():
    complete = HandshakeStatus(
        point="A",
        flow_id="f1",
        client_hello_seen=True,
        server_hello_seen=True,
        application_data_seen=True,
    )
    status = {"A": {"f1": complete}}
    findings = diagnose_tls(status, points_order=["A"])
    info = [f for f in findings if f.severity == "info"]
    assert any("1/1" in f.message for f in info)


def test_diagnose_tls_ordre_par_defaut_alphabetique_sans_points_order():
    status = {"Z": {}, "A": {}}
    # ne doit pas lever meme sans points_order
    findings = diagnose_tls(status)
    assert isinstance(findings, list)


# -- Tests de couverture des branches partielles (issue #288) ------------------


# -- _tls_version_str ----------------------------------------------------------


def test_tls_version_str_connue():
    assert _tls_version_str(3, 1) == "TLS 1.0"
    assert _tls_version_str(3, 3) == "TLS 1.2"
    assert _tls_version_str(3, 4) == "TLS 1.3"


def test_tls_version_str_inconnue():
    assert _tls_version_str(3, 99) == "0x0363"
    assert _tls_version_str(2, 0) == "0x0200"


# -- _read_u16 -----------------------------------------------------------------


def test_read_u16_normal():
    assert _read_u16(b"\x12\x34", 0) == 0x1234


def test_read_u16_trop_court():
    assert _read_u16(b"\x12", 0) is None


def test_read_u16_hors_borne():
    assert _read_u16(b"\x12\x34", 5) is None


# -- _looks_like_tls -----------------------------------------------------------


def test_looks_like_tls_vrai():
    assert _looks_like_tls(b"\x16\x03\x01\x00\x00") is True


def test_looks_like_tls_faux_type():
    assert _looks_like_tls(b"\x99\x03\x01\x00\x00") is False


def test_looks_like_tls_faux_major():
    assert _looks_like_tls(b"\x16\x04\x01\x00\x00") is False


def test_looks_like_tls_trop_court():
    assert _looks_like_tls(b"\x16\x03") is False


# -- _iter_tls_records ---------------------------------------------------------


def _tls_record(content_type, version=(3, 3), body=b""):
    """Construit un enregistrement TLS binaire."""
    return bytes([content_type, version[0], version[1]]) + len(body).to_bytes(2, "big") + body


def _fake_raw_packet(payload, proto="TCP", sport=50000, dport=443, src="10.0.0.1", dst="10.0.0.2"):
    """Cree un faux RawPacket avec un payload donne."""

    class FakeRawPacket:
        pass

    pkt = FakeRawPacket()
    pkt.ts = 1.0
    pkt.src = src
    pkt.dst = dst
    pkt.sport = sport
    pkt.dport = dport
    pkt.proto = proto
    pkt.payload = payload
    return pkt


def test_iter_tls_records_unique():
    payload = _tls_record(22, body=b"\x01\x00\x00\x00")
    records = list(_iter_tls_records(payload))
    assert len(records) == 1
    _ct, _major, _minor, length, _body, _truncated = records[0]
    assert length == 4


def test_iter_tls_records_multiple():
    r1 = _tls_record(22, body=b"\x01\x00\x00\x00")
    r2 = _tls_record(23, body=b"\x00")
    payload = r1 + r2
    records = list(_iter_tls_records(payload))
    assert len(records) == 2


def test_iter_tls_records_tronque():
    """Un record dont le body depasse le payload est marque tronque."""
    payload = bytes([22, 3, 3]) + (100).to_bytes(2, "big") + b"\x01"  # body annonce 100, 1 octet present
    records = list(_iter_tls_records(payload))
    assert len(records) == 1
    _ct, _major, _minor, _length, body, truncated = records[0]
    assert truncated is True
    assert len(body) == 1


def test_iter_tls_records_stop_sur_type_invalide():
    """S'arrete des que le content_type n'est pas TLS."""
    payload = _tls_record(22, body=b"\x01") + b"\x99\x03\x01\x00\x04"
    records = list(_iter_tls_records(payload))
    assert len(records) == 1


def test_iter_tls_records_trop_court():
    """Payload trop court pour un en-tete de record."""
    assert list(_iter_tls_records(b"\x16\x03")) == []


# -- _iter_handshake_messages --------------------------------------------------


def test_iter_handshake_messages_unique():
    body = b"\x01" + (4).to_bytes(3, "big") + b"\x00" * 4
    msgs = list(_iter_handshake_messages(body))
    assert len(msgs) == 1
    htype, _msg_body, truncated = msgs[0]
    assert htype == 1
    assert truncated is False


def test_iter_handshake_messages_multiple():
    """Plusieurs messages handshake concatenes dans un record."""
    msg1 = b"\x01" + (4).to_bytes(3, "big") + b"\x00" * 4
    msg2 = b"\x02" + (4).to_bytes(3, "big") + b"\x00" * 4
    msgs = list(_iter_handshake_messages(msg1 + msg2))
    assert len(msgs) == 2


def test_iter_handshake_messages_tronque():
    """Un message dont le body depasse les donnees est marque tronque."""
    body = b"\x01" + (100).to_bytes(3, "big") + b"\x00"  # annonce 100, 1 octet present
    msgs = list(_iter_handshake_messages(body))
    assert len(msgs) == 1
    _htype, _msg_body, truncated = msgs[0]
    assert truncated is True


def test_iter_handshake_messages_trop_court():
    """Body trop court pour un en-tete de message."""
    assert list(_iter_handshake_messages(b"\x01")) == []


# -- parse_client_hello : branches de degradation -------------------------------


def test_parse_client_hello_body_exactement_34():
    """Body de exactement 34 octets : retourne version seule (ligne 146)."""
    body = b"\x03\x03" + b"\x00" * 32
    result = parse_client_hello(body)
    assert result == {"tls_version": "TLS 1.2"}


def test_parse_client_hello_session_id_trop_long():
    """Session ID depasse le body : retourne version seule (ligne 151)."""
    body = b"\x03\x03" + b"\x00" * 32 + b"\xff"  # session_id_len=255, pas de suite
    result = parse_client_hello(body)
    assert result == {"tls_version": "TLS 1.2"}


def test_parse_client_hello_cs_len_manquant():
    """Cipher suites length illisible : retourne version seule (ligne 154)."""
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00"  # session_id_len=0, pas de cs_len
    result = parse_client_hello(body)
    assert result == {"tls_version": "TLS 1.2"}


def test_parse_client_hello_comp_len_trop_long():
    """Compression length depasse le body (ligne 159)."""
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02" + b"\x13\x01" + b"\xff"
    result = parse_client_hello(body)
    assert result == {"tls_version": "TLS 1.2"}


def test_parse_client_hello_ext_len_manquant():
    """Extension total length illisible (ligne 167)."""
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02" + b"\x13\x01" + b"\x01\x00"
    result = parse_client_hello(body)
    assert result == {"tls_version": "TLS 1.2"}


def test_parse_client_hello_extension_tronquee():
    """Extension body trop court : break dans la boucle (ligne 169->173)."""
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02" + b"\x13\x01" + b"\x01\x00"
    body += b"\x00\x02"  # ext_total_len=2, pas assez pour un type+len
    result = parse_client_hello(body)
    assert result["tls_version"] == "TLS 1.2"
    assert result.get("sni") is None


def test_parse_client_hello_sni_extension_tronquee():
    """SNI avec ext_body trop court (< 5) : pas de SNI (ligne 171->173)."""
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02" + b"\x13\x01" + b"\x01\x00"
    # Extension type=0 (server_name), len=3, body=0x00 0x00 0x00 (trop court pour SNI)
    ext_body = b"\x00\x00\x00"
    body += (2 + len(ext_body)).to_bytes(2, "big") + b"\x00\x00" + ext_body
    result = parse_client_hello(body)
    assert result["tls_version"] == "TLS 1.2"
    assert result.get("sni") is None


# -- parse_server_hello : branches de degradation -------------------------------


def test_parse_server_hello_exactement_35():
    """Body de 35 octets : cipher a l'offset 35, readable (ligne 187 non atteint)."""
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x13\x01"
    result = parse_server_hello(body)
    assert result["tls_version"] == "TLS 1.2"
    assert result["cipher"] == "0x1301"


def test_parse_server_hello_cipher_manquant():
    """Session ID depasse le body : cipher illisible (ligne 187)."""
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00"  # session_id_len=0, pas de cipher
    result = parse_server_hello(body)
    assert result == {"tls_version": "TLS 1.2"}


# -- HandshakeStatus.verdict : branches manquantes ------------------------------


def test_verdict_server_hello_no_data():
    """ServerHello vu mais pas de application_data (ligne 351)."""
    st = HandshakeStatus(
        point="A",
        flow_id="f1",
        server_hello_seen=True,
        tls_version="TLS 1.2",
    )
    assert st.verdict == "server_hello_no_data"


def test_verdict_alert_fatal_prioritaire():
    """Alert fatal prioritaire sur tout le reste."""
    st = HandshakeStatus(
        point="A",
        flow_id="f1",
        client_hello_seen=True,
        server_hello_seen=True,
        application_data_seen=True,
        fatal_alert="bad_certificate",
    )
    assert st.verdict == "alert_fatal:bad_certificate"


# -- build_handshake_status : warning alert (ligne 383-384) ---------------------


def test_handshake_status_warning_alert():
    """Une alerte warning est enregistree mais ne change pas le verdict."""
    events = [
        _ev(ts=0.0, handshake_type="client_hello", sni="example.com"),
        _ev(ts=0.1, record_type="alert", alert_level="warning", alert_description="close_notify"),
    ]
    status = build_handshake_status(events)
    st = next(iter(status["A"].values()))
    assert st.warning_alert == "close_notify"
    assert st.verdict == "client_hello_no_reply"


# -- diagnose_tls : flux non vu au point suivant (ligne 439) -------------------


def test_diagnose_tls_flux_absent_point_suivant_ignored():
    """Un flux vu en A mais absent en B ne produit pas de degradation."""
    complete_a = HandshakeStatus(
        point="A",
        flow_id="f1",
        client_hello_seen=True,
        server_hello_seen=True,
        application_data_seen=True,
    )
    # f2 existe en A mais pas en B
    other_a = HandshakeStatus(
        point="A",
        flow_id="f2",
        client_hello_seen=True,
        server_hello_seen=True,
        application_data_seen=True,
    )
    complete_b = HandshakeStatus(
        point="B",
        flow_id="f1",
        client_hello_seen=True,
        server_hello_seen=True,
        application_data_seen=True,
    )
    status = {"A": {"f1": complete_a, "f2": other_a}, "B": {"f1": complete_b}}
    findings = diagnose_tls(status, points_order=["A", "B"])
    # Pas de degradation car f2 n'est pas vu en B (continue)
    assert not [f for f in findings if f.segment == "A -> B"]


def test_diagnose_tls_point_sans_handshakes():
    """Un point sans handshakes ne produit pas de constat info (ligne 460)."""
    status = {"A": {}}
    findings = diagnose_tls(status, points_order=["A"])
    assert not [f for f in findings if f.severity == "info"]


# -- print_tls_diagnostics (lignes 482-492) -------------------------------------


def test_print_tls_diagnostics_avec_findings(capsys):
    """print_tls_diagnostics affiche les constats."""
    findings = [
        TlsFinding("anomalie", "TLS", "A -> B", "Handshake TLS casse"),
        TlsFinding("info", "TLS", "A", "3/5 handshakes aboutis"),
    ]
    print_tls_diagnostics(findings)
    captured = capsys.readouterr()
    assert "DIAGNOSTIC TLS" in captured.out
    assert "Handshake TLS casse" in captured.out


def test_print_tls_diagnostics_sans_findings(capsys):
    """print_tls_diagnostics sans findings affiche un message d'absence."""
    print_tls_diagnostics([])
    captured = capsys.readouterr()
    assert "Aucun trafic TLS detecte" in captured.out


# -- parse_tls_capture (lignes 249-326) : via monkeypatch ----------------------


def test_parse_tls_capture_handshake_complet(monkeypatch):
    """parse_tls_capture extrait les evenements d'une capture TLS."""
    from netcross_core import tls_diagnostics

    # Construire un payload TLS avec ClientHello + ServerHello
    ch_body = _client_hello(sni="example.com")
    ch_record = _tls_record(22, body=b"\x01" + len(ch_body).to_bytes(3, "big") + ch_body)
    sh_body = _server_hello()
    sh_record = _tls_record(22, body=b"\x02" + len(sh_body).to_bytes(3, "big") + sh_body)
    app_record = _tls_record(23, body=b"\x00" * 10)

    payload = ch_record + sh_record + app_record

    # Faux RawPacket avec payload TLS
    pkt = _fake_raw_packet(payload, proto="TCP", sport=50000, dport=443)

    monkeypatch.setattr(
        tls_diagnostics.pcap_parser,
        "parse_capture",
        lambda path, raise_on_error=False: [pkt],
    )

    events = tls_diagnostics.parse_tls_capture("A", "fake.pcap")
    assert len(events) >= 3  # ClientHello + ServerHello + ApplicationData

    # Verifier les types
    types = [e.record_type for e in events]
    assert "handshake" in types
    assert "application_data" in types

    # Verifier le SNI
    ch_events = [e for e in events if e.handshake_type == "client_hello"]
    assert len(ch_events) == 1
    assert ch_events[0].sni == "example.com"


def test_parse_tls_capture_alert_en_cours_negociation(monkeypatch):
    """Alert TLS en cours de negotiation."""
    from netcross_core import tls_diagnostics

    alert_body = bytes([2, 40])  # fatal, handshake_failure
    alert_record = _tls_record(21, body=alert_body)

    pkt = _fake_raw_packet(alert_record, proto="TCP", sport=50000, dport=443)

    monkeypatch.setattr(
        tls_diagnostics.pcap_parser,
        "parse_capture",
        lambda path, raise_on_error=False: [pkt],
    )

    events = tls_diagnostics.parse_tls_capture("A", "fake.pcap")
    assert len(events) == 1
    assert events[0].record_type == "alert"
    assert events[0].alert_level == "fatal"
    assert events[0].alert_description == "handshake_failure"


def test_parse_tls_capture_change_cipher_spec(monkeypatch):
    """change_cipher_spec produit un evenement sans champs supplementaires."""
    from netcross_core import tls_diagnostics

    ccs_record = _tls_record(20, body=b"\x01")

    pkt = _fake_raw_packet(ccs_record, proto="TCP", sport=50000, dport=443)

    monkeypatch.setattr(
        tls_diagnostics.pcap_parser,
        "parse_capture",
        lambda path, raise_on_error=False: [pkt],
    )

    events = tls_diagnostics.parse_tls_capture("A", "fake.pcap")
    assert len(events) == 1
    assert events[0].record_type == "change_cipher_spec"


def test_parse_tls_capture_handshake_incomplet(monkeypatch):
    """ClientHello sans ServerHello : handshake incomplet."""
    from netcross_core import tls_diagnostics

    ch_body = _client_hello(sni="example.com")
    ch_record = _tls_record(22, body=b"\x01" + len(ch_body).to_bytes(3, "big") + ch_body)

    pkt = _fake_raw_packet(ch_record, proto="TCP", sport=50000, dport=443)

    monkeypatch.setattr(
        tls_diagnostics.pcap_parser,
        "parse_capture",
        lambda path, raise_on_error=False: [pkt],
    )

    events = tls_diagnostics.parse_tls_capture("A", "fake.pcap")
    assert len(events) == 1
    assert events[0].handshake_type == "client_hello"
    assert events[0].sni == "example.com"

    # Le verdict doit etre "client_hello_no_reply"
    status = build_handshake_status(events)
    st = next(iter(status["A"].values()))
    assert st.verdict == "client_hello_no_reply"


def test_parse_tls_capture_record_tronque(monkeypatch):
    """Un record TLS tronque est marque truncated."""
    from netcross_core import tls_diagnostics

    # ClientHello avec body tronque (annonce 100 octets, 4 presents)
    ch_msg = b"\x01" + (100).to_bytes(3, "big") + b"\x03\x03\x00\x00"
    ch_record = _tls_record(22, body=ch_msg)

    pkt = _fake_raw_packet(ch_record, proto="TCP", sport=50000, dport=443)

    monkeypatch.setattr(
        tls_diagnostics.pcap_parser,
        "parse_capture",
        lambda path, raise_on_error=False: [pkt],
    )

    events = tls_diagnostics.parse_tls_capture("A", "fake.pcap")
    assert len(events) == 1
    assert events[0].truncated is True


def test_parse_tls_capture_pas_tcp_ignored(monkeypatch):
    """Un paquet non-TCP est ignore."""
    from netcross_core import tls_diagnostics

    udp_payload = b"\x16\x03\x01\x00\x00"
    pkt = _fake_raw_packet(udp_payload, proto="UDP", sport=50000, dport=443)

    monkeypatch.setattr(
        tls_diagnostics.pcap_parser,
        "parse_capture",
        lambda path, raise_on_error=False: [pkt],
    )

    events = tls_diagnostics.parse_tls_capture("A", "fake.pcap")
    assert len(events) == 0


def test_parse_tls_capture_payload_non_tls_ignored(monkeypatch):
    """Un paquet TCP dont le payload n'est pas TLS est ignore."""
    from netcross_core import tls_diagnostics

    http_payload = b"GET / HTTP/1.1\r\n\r\n"
    pkt = _fake_raw_packet(http_payload, proto="TCP", sport=50000, dport=80)

    monkeypatch.setattr(
        tls_diagnostics.pcap_parser,
        "parse_capture",
        lambda path, raise_on_error=False: [pkt],
    )

    events = tls_diagnostics.parse_tls_capture("A", "fake.pcap")
    assert len(events) == 0


def test_parse_tls_capture_alert_tronque(monkeypatch):
    """Une alerte tronquee ne produit pas de niveau/description."""
    from netcross_core import tls_diagnostics

    # Alert record avec body annonce 2 mais 0 present
    alert_record = bytes([21, 3, 3]) + (2).to_bytes(2, "big")  # pas de body

    pkt = _fake_raw_packet(alert_record, proto="TCP", sport=50000, dport=443)

    monkeypatch.setattr(
        tls_diagnostics.pcap_parser,
        "parse_capture",
        lambda path, raise_on_error=False: [pkt],
    )

    events = tls_diagnostics.parse_tls_capture("A", "fake.pcap")
    assert len(events) == 1
    assert events[0].record_type == "alert"
    assert events[0].alert_level is None
    assert events[0].alert_description is None
    assert events[0].truncated is True


def test_parse_tls_capture_multi_messages_dans_un_record(monkeypatch):
    """Un record handshake contenant plusieurs messages (Certificate + ServerHelloDone)."""
    from netcross_core import tls_diagnostics

    # Certificate message (type 11)
    cert_body = b"\x00" * 10
    cert_msg = b"\x0b" + len(cert_body).to_bytes(3, "big") + cert_body
    # ServerHelloDone (type 14)
    shd_msg = b"\x0e" + (0).to_bytes(3, "big")
    record_body = cert_msg + shd_msg
    record = _tls_record(22, body=record_body)

    pkt = _fake_raw_packet(record, proto="TCP", sport=443, dport=50000)

    monkeypatch.setattr(
        tls_diagnostics.pcap_parser,
        "parse_capture",
        lambda path, raise_on_error=False: [pkt],
    )

    events = tls_diagnostics.parse_tls_capture("A", "fake.pcap")
    assert len(events) == 2
    assert events[0].handshake_type == "certificate"
    assert events[1].handshake_type == "server_hello_done"


def test_parse_tls_capture_unknown_handshake_type(monkeypatch):
    """Un type de handshake inconnu est affiche avec son code."""
    from netcross_core import tls_diagnostics

    unknown_body = b"\x00" * 4
    unknown_msg = b"\xff" + len(unknown_body).to_bytes(3, "big") + unknown_body
    record = _tls_record(22, body=unknown_msg)

    pkt = _fake_raw_packet(record, proto="TCP", sport=443, dport=50000)

    monkeypatch.setattr(
        tls_diagnostics.pcap_parser,
        "parse_capture",
        lambda path, raise_on_error=False: [pkt],
    )

    events = tls_diagnostics.parse_tls_capture("A", "fake.pcap")
    assert len(events) == 1
    assert "unknown" in events[0].handshake_type


# -- parse_client_hello : branches complementaires (issue #288) -------------


def test_parse_client_hello_body_se_termine_apres_cipher_suites():
    """Body qui s'arrete juste apres les cipher suites, sans compression
    methods : i >= len(body) est vrai, retourne version seule (ligne 154).
    """
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02" + b"\x13\x01"
    result = parse_client_hello(body)
    assert result == {"tls_version": "TLS 1.2"}
