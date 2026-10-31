# SPDX-License-Identifier: GPL-3.0-or-later
"""
pcap_parser.capture -- couche d'orchestration. On monkeypatch
iter_ek_records (jamais tshark lui-meme, cf. les autres fichiers de
test) pour verifier le cablage : gestion d'erreur, arret propre en
live, restauration de l'ordre d'entree en parallele.

CaptureRingBuffer (Job 37, issue #157) est teste separement en bas de
ce fichier : pas de tshark non plus, juste des fichiers vides (touch)
dans tmp_path -- la classe ignore volontairement le contenu des
fichiers, voir sa docstring.
"""

import io
import os
import threading
import time

import pytest

import pcap_parser.capture as capture_mod
from pcap_parser.ek_source import EkRecord, TsharkError, TsharkNotFoundError


def _record(ts=1.0, src="1.1.1.1", dst="2.2.2.2"):
    return EkRecord(
        ts=ts,
        layers={
            "ip": {"ip_ip_src": src, "ip_ip_dst": dst},
            "tcp": {"tcp_tcp_srcport": "1", "tcp_tcp_dstport": "2", "tcp_tcp_seq_raw": "0"},
        },
    )


# -- parse_capture ------------------------------------------------------------


def test_parse_capture_construit_les_raw_packets(monkeypatch):
    monkeypatch.setattr(capture_mod, "iter_ek_records", lambda path: iter([_record(), _record(ts=2.0)]))
    pkts = capture_mod.parse_capture("fichier.pcapng")
    assert len(pkts) == 2
    assert pkts[0].ts == 1.0 and pkts[1].ts == 2.0


def test_parse_capture_avale_erreur_par_defaut(monkeypatch, capsys):
    def boom(path):
        raise TsharkNotFoundError("absent")
        yield  # pragma: no cover -- fait de boom un generateur

    monkeypatch.setattr(capture_mod, "iter_ek_records", boom)
    result = capture_mod.parse_capture("fichier.pcapng")
    assert result == []
    assert "fichier.pcapng" in capsys.readouterr().err


def test_parse_capture_relaie_si_raise_on_error(monkeypatch):
    import pytest

    def boom(path):
        raise TsharkError("echec")
        yield  # pragma: no cover

    monkeypatch.setattr(capture_mod, "iter_ek_records", boom)
    with pytest.raises(TsharkError):
        capture_mod.parse_capture("fichier.pcapng", raise_on_error=True)


def test_parse_capture_ignore_les_paquets_non_decodables(monkeypatch):
    # une couche EK ni IP, ni ARP, ni STP -> build_packet renvoie None
    # (LLDP, CDP...). ARP (Session 24) et STP (Session 25), eux, sont
    # desormais decodes -- voir test_parsing_adapter.py/test_packet.py
    # pour la couverture ARP/STP dediee.
    monkeypatch.setattr(capture_mod, "iter_ek_records", lambda path: iter([EkRecord(ts=1.0, layers={"lldp": {}})]))
    assert capture_mod.parse_capture("fichier.pcapng") == []


# -- iter_live -----------------------------------------------------------------


def test_iter_live_yield_au_fil_de_l_eau(monkeypatch):
    monkeypatch.setattr(
        capture_mod,
        "iter_ek_records",
        lambda interface, bpf_filter=None, stop_event=None: iter([_record(), _record(ts=2.0)]),
    )
    pkts = list(capture_mod.iter_live("eth0"))
    assert len(pkts) == 2


def test_iter_live_transmet_interface_et_filtre(monkeypatch):
    captured_args = {}

    def fake_iter(interface, bpf_filter=None, stop_event=None):
        captured_args["interface"] = interface
        captured_args["bpf_filter"] = bpf_filter
        captured_args["stop_event"] = stop_event
        return iter([])

    monkeypatch.setattr(capture_mod, "iter_ek_records", fake_iter)
    sentinel = object()
    list(capture_mod.iter_live("eth0", bpf_filter="tcp", stop_event=sentinel))
    assert captured_args == {"interface": "eth0", "bpf_filter": "tcp", "stop_event": sentinel}


def test_iter_live_s_arrete_proprement_si_l_appelant_casse_la_boucle(monkeypatch):
    def fake_iter(interface, bpf_filter=None, stop_event=None):
        yield _record(ts=1.0)
        yield _record(ts=2.0)
        raise AssertionError("ne doit pas etre consomme apres le break")

    monkeypatch.setattr(capture_mod, "iter_ek_records", fake_iter)
    gen = capture_mod.iter_live("eth0")
    first = next(gen)
    assert first.ts == 1.0
    gen.close()  # simule l'arret du generateur cote appelant


# -- parse_captures_parallel : ordre restaure + stats toujours presentes ------
# _parse_capture_timed doit rester une fonction de MODULE (picklable pour
# ProcessPoolExecutor) : on la remplace par une fonction top-level, elle
# aussi picklable, plutot qu'une closure/lambda.


def _fake_parse_capture_timed(label, path):
    if path == "echoue.pcapng":
        raise ValueError("pcap corrompu")
    return [object()] * len(path), 0.01


def test_parse_captures_parallel_restaure_l_ordre_et_gere_les_echecs(monkeypatch):
    monkeypatch.setattr(capture_mod, "_parse_capture_timed", _fake_parse_capture_timed)
    captures = [("C", "c.pcapng"), ("A", "a.pcapng"), ("B", "echoue.pcapng")]
    _all_packets, stats = capture_mod.parse_captures_parallel(captures, max_workers=2)

    # l'ordre des stats doit correspondre a l'ordre d'entree, pas a l'ordre
    # d'achevement des taches paralleles
    assert [s["label"] for s in stats] == ["C", "A", "B"]
    assert stats[2]["error"] is not None and "ValueError" in stats[2]["error"]
    assert stats[2]["count"] == 0
    assert stats[0]["count"] == len("c.pcapng")


# -- CaptureRingBuffer (Job 37, issue #157) -----------------------------------


def test_ring_buffer_rejette_des_parametres_invalides(tmp_path):
    with pytest.raises(ValueError):
        capture_mod.CaptureRingBuffer(str(tmp_path), max_files=0)
    with pytest.raises(ValueError):
        capture_mod.CaptureRingBuffer(str(tmp_path), max_duration_per_file=0)


def test_ring_buffer_current_path_none_avant_premiere_rotation(tmp_path):
    ring = capture_mod.CaptureRingBuffer(str(tmp_path))
    assert ring.current_path is None
    assert ring.files == ()


def test_ring_buffer_rotate_cree_un_fichier_et_devient_courant(tmp_path):
    ring = capture_mod.CaptureRingBuffer(str(tmp_path), prefix="lan")
    path = ring.rotate(now=0.0)
    assert os.path.exists(path)
    assert ring.current_path == path
    assert ring.files == (path,)


def test_ring_buffer_simule_une_rotation_avec_de_petits_fichiers(tmp_path):
    """Test demande par l'issue : simuler une rotation avec des petits
    fichiers (ici, des fichiers vides -- la classe ne s'interesse pas a
    leur contenu) et verifier le nombre de fichiers conserves."""
    ring = capture_mod.CaptureRingBuffer(str(tmp_path), max_files=3)
    for i in range(10):
        ring.rotate(now=float(i))

    assert len(ring.files) == 3
    # tous les fichiers encore suivis existent reellement sur disque
    assert all(os.path.exists(p) for p in ring.files)
    # le plus recent est bien le dernier ouvert
    assert ring.current_path == ring.files[-1]


def test_ring_buffer_supprime_le_plus_ancien_a_la_limite(tmp_path):
    """Test demande par l'issue : verifier que le plus ancien fichier est
    bien supprime du DISQUE (pas juste retire de la liste suivie) des que
    max_files est depasse."""
    ring = capture_mod.CaptureRingBuffer(str(tmp_path), max_files=2)
    first = ring.rotate(now=0.0)
    second = ring.rotate(now=1.0)
    assert os.path.exists(first) and os.path.exists(second)

    third = ring.rotate(now=2.0)

    assert not os.path.exists(first)  # le plus ancien a ete supprime
    assert os.path.exists(second) and os.path.exists(third)
    assert ring.files == (second, third)


def test_ring_buffer_maybe_rotate_ne_tourne_pas_avant_la_duree_max(tmp_path):
    ring = capture_mod.CaptureRingBuffer(str(tmp_path), max_duration_per_file=10.0)
    first = ring.rotate(now=0.0)

    result = ring.maybe_rotate(now=5.0)  # 5s < 10s -- pas encore

    assert result is None
    assert ring.current_path == first
    assert len(ring.files) == 1


def test_ring_buffer_maybe_rotate_tourne_une_fois_la_duree_max_atteinte(tmp_path):
    ring = capture_mod.CaptureRingBuffer(str(tmp_path), max_duration_per_file=10.0)
    first = ring.rotate(now=0.0)

    result = ring.maybe_rotate(now=10.0)  # exactement la limite -- doit tourner

    assert result is not None
    assert result != first
    assert ring.current_path == result
    assert len(ring.files) == 2


def test_ring_buffer_maybe_rotate_ouvre_le_premier_fichier_si_jamais_tourne(tmp_path):
    ring = capture_mod.CaptureRingBuffer(str(tmp_path))
    result = ring.maybe_rotate(now=0.0)
    assert result is not None
    assert ring.current_path == result


# -- iter_live_multi : capture simultanee sur plusieurs interfaces (Job 48) ---
# Deux niveaux de test : (1) iter_ek_records remplace par des sources
# synthetiques (jamais tshark lui-meme, comme partout ici) pour verifier
# fusion, arret et erreurs ; (2) subprocess.Popen remplace pour verifier la
# vraie ligne de commande tshark construite pour CHAQUE interface.

_WAIT = 5.0  # garde-fou : un test qui bloquerait doit echouer, pas pendre


def _fake_sources(monkeypatch, behaviors):
    """Remplace iter_ek_records par un aiguilleur : `behaviors` associe
    chaque interface a une fonction (stop_event) -> iterateur de records.
    Renvoie la liste des appels recus (interface, bpf_filter, stop_event)."""
    calls = []

    def fake(*, interface, bpf_filter=None, stop_event=None, **_kwargs):
        calls.append({"interface": interface, "bpf_filter": bpf_filter, "stop_event": stop_event})
        return behaviors[interface](stop_event)

    monkeypatch.setattr(capture_mod, "iter_ek_records", fake)
    return calls


def _emit(*records):
    """Source qui rend ces records puis se termine (tshark qui finit)."""

    def behavior(_stop_event):
        yield from records

    return behavior


def _emit_then_wait_for_stop(exited, name, *records):
    """Source live : rend ses records puis reste silencieuse jusqu'a
    stop_event (comme tshark sur une interface sans trafic, que seul
    stop_event fait terminer). Note `name` dans `exited` en sortant."""

    def behavior(stop_event):
        try:
            yield from records
            assert stop_event.wait(_WAIT), f"[{name}] arret jamais propage a cette source"
        finally:
            exited.append(name)

    return behavior


def test_iter_live_multi_etiquette_chaque_paquet_par_son_interface(monkeypatch):
    _fake_sources(
        monkeypatch,
        {
            "eth0": _emit(_record(ts=1.0), _record(ts=2.0)),
            "eth1": _emit(_record(ts=3.0)),
        },
    )
    result = list(capture_mod.iter_live_multi([("LAN", "eth0"), ("WAN", "eth1")]))

    by_label = {}
    for label, pkt in result:
        by_label.setdefault(label, []).append(pkt.ts)
    # ordre relatif conserve au sein d'une interface ; aucun paquet perdu ni melange
    assert by_label == {"LAN": [1.0, 2.0], "WAN": [3.0]}


def test_iter_live_multi_ignore_les_paquets_non_decodables(monkeypatch):
    # couche ni IP, ni ARP, ni STP -> build_packet renvoie None (cf. test_parse_capture_...)
    _fake_sources(monkeypatch, {"eth0": _emit(EkRecord(ts=1.0, layers={"lldp": {}}), _record(ts=2.0))})
    result = list(capture_mod.iter_live_multi([("LAN", "eth0")]))
    assert [(label, pkt.ts) for label, pkt in result] == [("LAN", 2.0)]


def test_iter_live_multi_transmet_interface_filtre_et_un_meme_arret_a_toutes_les_sources(monkeypatch):
    calls = _fake_sources(monkeypatch, {"eth0": _emit(), "eth1": _emit()})
    list(capture_mod.iter_live_multi([("LAN", "eth0"), ("WAN", "eth1")], bpf_filter="tcp"))

    assert sorted((c["interface"], c["bpf_filter"]) for c in calls) == [("eth0", "tcp"), ("eth1", "tcp")]
    # meme evenement d'arret partage par tous les tshark (et non None : meme sans
    # stop_event cote appelant, la fermeture du generateur doit pouvoir les arreter)
    stop_events = {id(c["stop_event"]) for c in calls}
    assert len(stop_events) == 1
    assert all(c["stop_event"] is not None for c in calls)


def test_iter_live_multi_construit_les_arguments_tshark_de_chaque_interface(monkeypatch):
    launched = []

    class FakePopen:
        def __init__(self, args, **_kwargs):
            launched.append(list(args))
            self.stdout = io.StringIO("")  # tshark qui ne produit rien puis se termine
            self.stderr = io.StringIO("")
            self.returncode = 0

        def poll(self):
            return self.returncode

        def terminate(self):
            pass

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            pass

    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/tshark")
    monkeypatch.setattr("subprocess.Popen", FakePopen)

    result = list(capture_mod.iter_live_multi([("LAN", "eth0"), ("WAN", "eth1")], bpf_filter="tcp port 443"))

    assert result == []
    assert len(launched) == 2  # un processus tshark par interface
    by_interface = {args[args.index("-i") + 1]: args for args in launched}
    assert set(by_interface) == {"eth0", "eth1"}
    for args in by_interface.values():
        assert args[0] == "/usr/bin/tshark"
        assert "-r" not in args  # mode live, pas fichier
        assert "-l" in args  # flush ligne par ligne (indispensable au live)
        assert args[args.index("-f") + 1] == "tcp port 443"
        assert args[-2:] == ["-T", "ek"]


def test_iter_live_multi_fusionne_en_temps_reel_dans_l_ordre_d_arrivee(monkeypatch):
    # A et B se relaient : le paquet suivant n'est produit qu'apres que le
    # test a recu le precedent. Une implementation qui viderait une interface
    # apres l'autre (ou attendrait la fin des sources) ne passerait pas.
    go_b1, go_a2, go_b2 = threading.Event(), threading.Event(), threading.Event()

    def source_a(_stop_event):
        yield _record(ts=1.0)
        assert go_a2.wait(_WAIT)
        yield _record(ts=3.0)

    def source_b(_stop_event):
        assert go_b1.wait(_WAIT)
        yield _record(ts=2.0)
        assert go_b2.wait(_WAIT)
        yield _record(ts=4.0)

    _fake_sources(monkeypatch, {"a": source_a, "b": source_b})
    gen = capture_mod.iter_live_multi([("A", "a"), ("B", "b")])

    seen = [next(gen)]  # A1 arrive alors que B n'a encore rien produit
    go_b1.set()
    seen.append(next(gen))
    go_a2.set()
    seen.append(next(gen))
    go_b2.set()
    seen.append(next(gen))

    assert [(label, pkt.ts) for label, pkt in seen] == [("A", 1.0), ("B", 2.0), ("A", 3.0), ("B", 4.0)]
    assert list(gen) == []


def test_iter_live_multi_stop_event_arrete_toutes_les_interfaces_en_meme_temps(monkeypatch):
    exited = []
    ready = threading.Semaphore(0)

    def make_source(name):
        def source(stop_event):
            try:
                yield _record(ts=1.0)
                ready.release()
                # interface devenue silencieuse : seul l'arret la fait terminer
                assert stop_event.wait(_WAIT), f"[{name}] arret jamais propage"
            finally:
                exited.append(name)

        return source

    _fake_sources(monkeypatch, {f"eth{i}": make_source(f"eth{i}") for i in range(3)})
    sources = [("A", "eth0"), ("B", "eth1"), ("C", "eth2")]
    stop_event = threading.Event()
    result = []
    consumer = threading.Thread(target=lambda: result.extend(capture_mod.iter_live_multi(sources, stop_event)))
    consumer.start()
    for _ in sources:
        assert ready.acquire(timeout=_WAIT)  # les 3 interfaces tournent, chacune deja silencieuse

    t0 = time.monotonic()
    stop_event.set()  # UN seul evenement, depuis un autre thread que le consommateur
    consumer.join(timeout=_WAIT)

    assert not consumer.is_alive()
    assert time.monotonic() - t0 < 2.0
    assert sorted(exited) == ["eth0", "eth1", "eth2"]  # aucune interface laissee en route
    assert sorted(label for label, _pkt in result) == ["A", "B", "C"]  # paquets deja decodes rendus


def test_iter_live_multi_stop_event_deja_positionne_termine_sans_bloquer(monkeypatch):
    exited = []
    _fake_sources(monkeypatch, {"eth0": _emit_then_wait_for_stop(exited, "eth0")})
    stop_event = threading.Event()
    stop_event.set()

    assert list(capture_mod.iter_live_multi([("LAN", "eth0")], stop_event)) == []
    assert exited == ["eth0"]


def test_iter_live_multi_fermer_le_generateur_arrete_toutes_les_sources(monkeypatch):
    exited = []
    _fake_sources(
        monkeypatch,
        {
            "eth0": _emit_then_wait_for_stop(exited, "eth0", _record(ts=1.0)),
            "eth1": _emit_then_wait_for_stop(exited, "eth1", _record(ts=2.0)),
        },
    )
    stop_event = threading.Event()
    gen = capture_mod.iter_live_multi([("LAN", "eth0"), ("WAN", "eth1")], stop_event)
    next(gen)
    gen.close()  # l'appelant abandonne : break, exception ou close() explicite

    assert sorted(exited) == ["eth0", "eth1"]  # close() rend la main une fois tout arrete
    # fermer le generateur ne doit jamais positionner l'evenement de l'appelant :
    # il peut etre partage avec d'autres threads (GUI : un stop_event pour tous les points)
    assert not stop_event.is_set()


def test_iter_live_multi_fermeture_avec_file_pleine_ne_bloque_pas(monkeypatch):
    # file de 2 paquets et sources qui produisent sans arret : les producteurs
    # sont bloques sur put() quand l'appelant s'en va -- l'arret doit les debloquer.
    monkeypatch.setattr(capture_mod, "_LIVE_MULTI_QUEUE_MAXSIZE", 2)
    exited = []

    def endless(stop_event):
        try:
            while not stop_event.is_set():
                yield _record()
        finally:
            exited.append("eth0")

    _fake_sources(monkeypatch, {"eth0": endless})
    gen = capture_mod.iter_live_multi([("LAN", "eth0")])
    next(gen)
    t0 = time.monotonic()
    gen.close()

    assert time.monotonic() - t0 < 3.0
    assert exited == ["eth0"]


def test_iter_live_multi_contre_pression_ne_perd_aucun_paquet(monkeypatch):
    monkeypatch.setattr(capture_mod, "_LIVE_MULTI_QUEUE_MAXSIZE", 2)
    _fake_sources(
        monkeypatch,
        {
            "eth0": _emit(*[_record(ts=float(i)) for i in range(50)]),
            "eth1": _emit(*[_record(ts=float(i)) for i in range(50)]),
        },
    )
    result = list(capture_mod.iter_live_multi([("LAN", "eth0"), ("WAN", "eth1")]))
    assert sorted(label for label, _pkt in result).count("LAN") == 50
    assert sorted(label for label, _pkt in result).count("WAN") == 50


def test_iter_live_multi_erreur_sur_une_interface_arrete_les_autres_et_prefixe_le_label(monkeypatch):
    exited = []

    def failing(_stop_event):
        raise TsharkError("interface inconnue", returncode=1, stderr="no such device")
        yield  # pragma: no cover -- fait du corps un generateur

    _fake_sources(
        monkeypatch,
        {"eth0": _emit_then_wait_for_stop(exited, "eth0", _record(ts=1.0)), "eth1": failing},
    )
    with pytest.raises(TsharkError, match=r"^\[WAN\] interface inconnue") as exc_info:
        list(capture_mod.iter_live_multi([("LAN", "eth0"), ("WAN", "eth1")]))

    assert exc_info.value.returncode == 1
    assert exc_info.value.stderr == "no such device"
    assert exited == ["eth0"]  # l'interface saine a ete arretee, pas laissee capturer dans le vide


def test_iter_live_multi_releve_tshark_absent_tel_quel(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(TsharkNotFoundError):
        list(capture_mod.iter_live_multi([("LAN", "eth0"), ("WAN", "eth1")]))


def test_iter_live_multi_valide_ses_arguments_des_l_appel():
    # levee a l'appel meme, sans iterer : un appelant qui lance la capture
    # dans un thread (LiveDiffEngine.start_multi) doit l'apprendre tout de suite
    with pytest.raises(ValueError, match="au moins une interface"):
        capture_mod.iter_live_multi([])
    with pytest.raises(ValueError, match="en double"):
        capture_mod.iter_live_multi([("LAN", "eth0"), ("LAN", "eth1")])
    with pytest.raises(ValueError, match="obligatoires"):
        capture_mod.iter_live_multi([("LAN", "")])
    with pytest.raises(ValueError, match="obligatoires"):
        capture_mod.iter_live_multi([("", "eth0")])
