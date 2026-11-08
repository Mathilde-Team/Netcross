"""Issue #1151 : module commun de pseudonymisation (adresses + noms)."""

from __future__ import annotations

import csv
import io

import pytest
from conftest import make_pkt

from netcross_core.pseudonyms import (
    KIND_DOMAIN,
    KIND_NAME,
    NamePseudonymizer,
    PseudonymTable,
    host_pseudonym,
)
from netcross_core.redact import AddressRedactor, redaction_map_csv, write_redaction_map_csv
from netcross_core.support.scrubber import TextScrubber

# -- PseudonymTable -------------------------------------------------------------


def test_table_stable_par_categorie_et_idempotente():
    table = PseudonymTable({"a": lambda i: f"A{i}", "b": lambda i: f"B{i}"})
    assert [table.pseudonym(v, k) for v, k in (("x", "a"), ("y", "a"), ("x", "a"), ("z", "b"))] == [
        "A0",
        "A1",
        "A0",
        "B0",
    ]
    assert table.pseudonym("A1", "a") == "A1"  # deja produit -> traverse
    table.mark_own("A1.derive")
    assert table.pseudonym("A1.derive", "a") == "A1.derive"
    assert table.entries() == [("x", "A0", "a"), ("y", "A1", "a"), ("z", "B0", "b")]
    assert len(table) == 3


def test_table_non_idempotente_pour_les_adresses():
    table = PseudonymTable({"ipv4": lambda i: f"192.0.2.{i + 1}"}, idempotent=False)
    assert table.pseudonym("10.0.0.1", "ipv4") == "192.0.2.1"
    # Une adresse reelle dans la plage des pseudonymes n'est pas confondue
    # avec l'hote deja pseudonymise.
    assert table.pseudonym("192.0.2.1", "ipv4") == "192.0.2.2"


# -- NamePseudonymizer ------------------------------------------------------------


def test_noms_stables_dans_le_run_et_normalises():
    names = NamePseudonymizer()
    first = names.pseudonym("www.acme.fr")
    assert first == "host-1.domain-1.example.invalid"
    assert names.pseudonym("WWW.Acme.FR.") == first
    assert names.pseudonym(" www.acme.fr ") == first
    assert len(names) == 1


def test_meme_domaine_parent_meme_suffixe():
    names = NamePseudonymizer()
    www, mail, autre = (
        names.pseudonym("www.acme.fr"),
        names.pseudonym("mail.acme.fr"),
        names.pseudonym("www.exemple.org"),
    )
    assert www.split(".", 1)[1] == mail.split(".", 1)[1] == "domain-1.example.invalid"
    assert autre == "host-3.domain-2.example.invalid"
    assert len({www, mail, autre}) == 3
    # Sous-domaine plus profond : parent = nom prive du premier label.
    assert names.pseudonym("a.b.acme.fr") == "host-4.domain-3.example.invalid"
    assert names.pseudonym("c.b.acme.fr") == "host-5.domain-3.example.invalid"


@pytest.mark.parametrize("name", ["srv01", "acme.fr"])
def test_nom_sans_parent_utile(name):
    assert NamePseudonymizer().pseudonym(name) == "host-1.example.invalid"


def test_structure_rfc6761_et_idempotence():
    names = NamePseudonymizer()
    pseudo = names.pseudonym("intranet.acme.local")
    assert pseudo.endswith(".example.invalid")
    assert names.pseudonym(pseudo) == pseudo
    assert names.pseudonym("host-9.example.invalid") == "host-9.example.invalid"
    assert names.pseudonym("example.invalid") == "example.invalid"
    assert names.pseudonym("") == ""
    assert names.pseudonym("   ") == "   "
    assert host_pseudonym(0) == "host-1.example.invalid"


def test_entrees_noms_puis_domaines_tri_naturel():
    names = NamePseudonymizer()
    for i in range(11):
        names.pseudonym(f"h{i}.site.acme.fr")
    rows = names.entries()
    assert [r[1] for r in rows[:3]] == [
        "host-1.domain-1.example.invalid",
        "host-2.domain-1.example.invalid",
        "host-3.domain-1.example.invalid",
    ]
    assert rows[10] == ("h10.site.acme.fr", "host-11.domain-1.example.invalid", KIND_NAME)
    assert rows[11] == ("site.acme.fr", "domain-1.example.invalid", KIND_DOMAIN)
    assert len(rows) == 12


# -- AddressRedactor : table des noms et --redact-map ------------------------------


def test_redact_map_contient_la_table_des_noms(tmp_path):
    redactor = AddressRedactor()
    redactor.redact([make_pkt(proto="UDP", src="10.0.0.1", dst="10.0.0.2")])
    assert redactor.pseudonymize_name("www.acme.fr") == "host-1.domain-1.example.invalid"
    assert redactor.pseudonymize_name("www.acme.fr") == "host-1.domain-1.example.invalid"
    assert len(redactor) == 2  # adresses seulement
    assert len(redactor.names) == 1
    assert redactor.mapping == {"10.0.0.1": "192.0.2.1", "10.0.0.2": "192.0.2.2"}

    path = tmp_path / "map.csv"
    write_redaction_map_csv(redactor, str(path))
    rows = list(csv.reader(io.StringIO(path.read_text(encoding="utf-8"))))
    assert rows == [
        ["adresse_reelle", "pseudonyme", "type"],
        ["10.0.0.1", "192.0.2.1", "ipv4"],
        ["10.0.0.2", "192.0.2.2", "ipv4"],
        ["www.acme.fr", "host-1.domain-1.example.invalid", "nom"],
        ["acme.fr", "domain-1.example.invalid", "domaine"],
    ]


def test_redact_map_sans_nom_inchangee():
    redactor = AddressRedactor()
    redactor.redact([make_pkt(proto="UDP", src="10.0.0.1", dst="10.0.0.2")])
    assert redaction_map_csv(redactor.entries()).splitlines() == [
        "adresse_reelle,pseudonyme,type",
        "10.0.0.1,192.0.2.1,ipv4",
        "10.0.0.2,192.0.2.2,ipv4",
    ]


def test_redacteur_adresse_reelle_dans_la_plage_des_pseudonymes():
    redactor = AddressRedactor()
    a = make_pkt(proto="UDP", src="10.0.0.1", dst="192.0.2.1")
    redactor.redact([a])
    assert (a.src, a.dst) == ("192.0.2.1", "192.0.2.2")


# -- scrubber de support : non-regression ---------------------------------------

_TEXTE = [
    "Traceback: /home/jdupont/captures/client_acme_site3.pcapng introuvable sur srv-compta.acme.local",
    "GET https://intranet.acme.fr/api?id=3 depuis 10.1.2.3:443 vers fe80::1%eth0, MAC aa:bb:cc:dd:ee:ff",
    "password=hunter2 Authorization: Bearer abcdefghijklmnop contact jean.dupont@acme.fr",
    "C:\\Users\\mdurand\\Desktop\\trace.pcap ; 10.1.2.3 encore ; srv-compta.acme.local ; config.yaml",
    "deja anonyme : host-1.example.invalid 192.0.2.1 capture-1.pcapng",
]

# Sortie EXACTE du scrubber avant la factorisation (origin/dev, capturee
# en executant l'ancienne version du module sur _TEXTE).
GOLDEN_OUT = [
    "Traceback: /home/user-1/captures/capture-1.pcapng introuvable sur host-1.example.invalid",
    "GET https://host-1.example.invalid/redacted depuis 192.0.2.1:443 vers 2001:db8::1, MAC 02:00:00:00:00:00",
    "password=[SECRET-REDIGE] Authorization: [SECRET-REDIGE] [SECRET-REDIGE] contact user-1@example.invalid",
    "C:\\Users\\user-2\\Desktop\\capture-2.pcap ; 192.0.2.1 encore ; host-1.example.invalid ; config.yaml",
    "deja anonyme : host-1.example.invalid 192.0.2.1 capture-1.pcapng.pcapng",
]
GOLDEN_ROWS = [
    ("10.1.2.3", "192.0.2.1", "ipv4"),
    ("aa:bb:cc:dd:ee:ff", "02:00:00:00:00:00", "mac"),
    ("client_acme_site3.pcapng", "capture-1", "capture"),
    ("fe80::1%eth0", "2001:db8::1", "ipv6"),
    ("https://intranet.acme.fr/api?id=3", "https://host-1.example.invalid/redacted", "url"),
    ("jdupont", "user-1", "path"),
    ("jean.dupont@acme.fr", "user-1@example.invalid", "email"),
    ("mdurand", "user-2", "path"),
    ("srv-compta.acme.local", "host-1.example.invalid", "hostname"),
    ("trace.pcap", "capture-2", "capture"),
]
GOLDEN_REP = {
    "statut": "redige",
    "total_occurrences": 17,
    "valeurs_distinctes": 10,
    "par_categorie": {
        "capture": 3,
        "email": 1,
        "hostname": 2,
        "ipv4": 3,
        "ipv6": 1,
        "mac": 1,
        "path": 2,
        "secret": 3,
        "url": 1,
    },
    "limites": [
        "un nom d'hote sans point (ex. SRVCOMPTA01) reste en clair : indissociable d'un mot ordinaire du texte",
        "un identifiant metier libre (numero de dossier, nom de site) reste "
        "en clair : aucun motif ne permet de le reconnaitre",
    ],
}


def test_scrubber_de_support_inchange():
    scrubber = TextScrubber()
    out, report = scrubber.scrub_lines(_TEXTE)
    assert out == GOLDEN_OUT
    assert scrubber.mapping_csv_rows() == GOLDEN_ROWS
    assert report.to_dict() == GOLDEN_REP
