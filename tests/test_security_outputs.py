# SPDX-License-Identifier: GPL-3.0-or-later
"""
Issue #218 -- les constats de securite doivent atteindre les sorties
machine (JSON), le document partage (PDF) et le rendu consultable (HTML),
pas seulement le terminal.

Ces tests sont ecrits dans l'esprit du constat de l'issue #259 : une
valeur correctement calculee mais jamais rendue passe inapercue si les
tests s'arretent avant le rendu. Ils partent donc tous du `Report` et
verifient ce qui sort **du fichier produit**, jamais un objet
intermediaire.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime

import pytest

from netcross_core.models import Report
from netcross_report.json_report import generate_json_report
from netcross_report.security_html import render_security_html
from netcross_report.security_report import (
    MAX_READABLE_LEN,
    build_security_report,
    security_report_to_dict,
)

JA4 = "t13i3012h2_1d37bd780c83_8537cf56674e"
HASSH = "eeca2460550b9ded084ecf2f70a75356"
LISIBLE = "ciphers=[0x1302,0x1303,0x1301] extensions=[0x000d,0x002b] alpn=[h2,http/1.1] sni=False"


def _report_garni() -> Report:
    """Un Report portant un de chaque : service avec empreinte, service
    issu d'une banniere, CVE, exploit, anomalie. Sert de reference commune
    aux trois sorties, pour qu'aucune n'en perde un en route."""
    r = Report(points=["POINT_A"])
    r.service_fingerprints = [
        {
            "service": "TLS/JA4",
            "version": "curl 8.18.0",
            "host": "10.0.0.5",
            "port": None,
            "point": "POINT_A",
            "protocol": "tls",
            "fingerprint": JA4,
            "banner": LISIBLE,
        },
        {
            "service": "SSH/HASSH",
            "version": "OpenSSH 10.2p1",
            "host": "10.0.0.7",
            "port": 22,
            "point": "POINT_A",
            "protocol": "ssh",
            "fingerprint": HASSH,
            "banner": "kex=[curve25519-sha256] enc=[aes128-ctr]",
        },
        {"service": "nginx", "version": "1.18.0", "host": "10.0.0.9", "port": 80, "point": "POINT_A"},
    ]
    r.security_findings = [
        {
            "category": "cve",
            "severity": "critique",
            "detail": "nginx 1.18.0 vulnerable a une lecture hors limites du resolveur",
            "cve_id": "CVE-2021-23017",
            "cvss": 9.4,
            "service": "nginx",
            "version": "1.18.0",
            "host": "10.0.0.9",
            "port": 80,
            "point": "POINT_A",
        },
        {
            "category": "exploit",
            "severity": "elevee",
            "detail": "signature Log4Shell dans l'en-tete User-Agent",
            "host": "10.0.0.9",
            "port": 80,
            "point": "POINT_A",
        },
        {
            "category": "anomalie",
            "severity": "moyenne",
            "detail": "retransmissions TCP repetees",
            "host": "10.0.0.5",
            "point": "POINT_A",
        },
    ]
    return r


@pytest.fixture
def rapport():
    return build_security_report(_report_garni())


# -- socle de serialisation ------------------------------------------------


def test_la_serialisation_conserve_les_champs_nuls(rapport):
    """Les cles valant None sont conservees, pas retirees : un consommateur
    doit pouvoir distinguer « non renseigne » de « cle que cette version de
    netcross ne produit pas »."""
    d = security_report_to_dict(rapport)
    tls = next(s for s in d["services"] if s["service"] == "TLS/JA4")
    assert "port" in tls
    assert tls["port"] is None


def test_la_serialisation_ne_tronque_pas_la_forme_lisible(rapport):
    """Le rendu texte tronque a 120 caracteres pour rester lisible ; une
    sortie machine n'a pas cette contrainte et tronquer y priverait le
    consommateur de la liste complete des ciphers."""
    d = security_report_to_dict(rapport)
    tls = next(s for s in d["services"] if s["service"] == "TLS/JA4")
    assert tls["fingerprint_readable"] == LISIBLE


def test_la_serialisation_expose_les_quatre_sections_et_le_tableau_de_bord(rapport):
    d = security_report_to_dict(rapport)
    assert set(d) == {"dashboard", "services", "exploits", "anomalies", "cves", "notifications", "plugins", "assets"}
    assert d["notifications"] == []  # aucune notification demandee (issue #280)
    assert d["plugins"] == []  # aucun plugin demande (issue #284)
    assert d["dashboard"]["cves"] == 1
    assert d["dashboard"]["level"] == "critique"
    assert d["dashboard"]["services_vulnerable"] == 1


def test_la_serialisation_est_json_serialisable(rapport):
    """Une sortie machine qui ne passe pas json.dumps ne sert a rien --
    et un dataclass oublie dans la structure ne se verrait pas autrement."""
    json.dumps(security_report_to_dict(rapport))


# -- sortie JSON -----------------------------------------------------------


def test_le_json_porte_le_rapport_de_securite(tmp_path):
    chemin = tmp_path / "r.json"
    generate_json_report(_report_garni(), str(chemin), security_report=build_security_report(_report_garni()))
    doc = json.loads(chemin.read_text(encoding="utf-8"))
    sr = doc["security_report"]
    assert sr is not None
    # Comparaison par ensemble : l'ordre des services suit la criticite
    # decroissante, pas l'ordre de detection.
    assert {s["fingerprint"] for s in sr["services"] if s["fingerprint"]} == {JA4, HASSH}
    assert sr["cves"][0]["cve_id"] == "CVE-2021-23017"
    assert sr["dashboard"]["score"] > 0


def test_le_json_dit_pourquoi_le_rapport_de_securite_est_absent(tmp_path):
    """Regle de tracabilite : la cle est ecrite meme sans analyse de
    securite, avec le motif. Omettre la cle rendrait indistinguables
    « non demande », « rien trouve » et « version de netcross qui ne
    produit pas cette cle »."""
    chemin = tmp_path / "r.json"
    generate_json_report(_report_garni(), str(chemin))
    doc = json.loads(chemin.read_text(encoding="utf-8"))
    assert "security_report" in doc
    assert doc["security_report"] is None
    assert "non demande" in doc["security_report_absent"]


def test_le_json_distingue_rien_trouve_de_non_demande(tmp_path):
    """Un rapport de securite vide (analyse faite, rien trouve) produit un
    objet, pas None -- c'est precisement la distinction que l'issue
    reclame."""
    chemin = tmp_path / "r.json"
    vide = Report(points=["POINT_A"])
    generate_json_report(vide, str(chemin), security_report=build_security_report(vide))
    doc = json.loads(chemin.read_text(encoding="utf-8"))
    assert doc["security_report"] is not None
    assert doc["security_report"]["services"] == []
    assert "security_report_absent" not in doc


# -- sortie HTML -----------------------------------------------------------


def test_le_html_contient_les_hashs_et_les_cve(rapport):
    page = render_security_html(rapport)
    assert JA4 in page
    assert HASSH in page
    assert "CVE-2021-23017" in page
    assert "9.4" in page


def test_le_html_est_autonome(rapport):
    """Aucune ressource externe : un rapport d'incident est archive dans un
    ticket et relu des mois plus tard, parfois sur un poste isole. Une
    dependance a un CDN en ferait une page cassee au moment ou on la
    ressort."""
    page = render_security_html(rapport)
    assert "http://" not in page
    assert "https://" not in page
    assert "<script src" not in page
    assert "<link" not in page


def test_le_html_n_echappe_pas_les_apostrophes_francaises(rapport):
    """`html.escape(quote=True)` transformait chaque apostrophe en `&#x27;`,
    rendant la source illisible et desalignant le HTML du rendu texte pour
    des messages comme « aucune tentative d'exploitation detectee ». Les
    valeurs n'allant jamais dans un attribut, l'echappement des guillemets
    n'apporte rien ici."""
    page = render_security_html(rapport)
    assert "&#x27;" not in page
    assert "&#39;" not in page


def test_le_html_echappe_les_donnees_hostiles():
    """Un rapport de securite contient par construction des chaines
    controlees par un attaquant (banniere forgee, detail d'exploit). Les
    injecter sans echappement ferait du rapport lui-meme un vecteur."""
    r = Report(points=["A"])
    charge = "<script>alert('xss')</script>"
    r.security_findings = [
        {"category": "exploit", "severity": "elevee", "detail": f"motif dans User-Agent {charge}", "point": "A"}
    ]
    r.service_fingerprints = [
        {"service": charge, "host": charge, "point": "A", "fingerprint": charge, "banner": charge}
    ]
    page = render_security_html(build_security_report(r))
    assert charge not in page
    assert "&lt;script&gt;" in page


def test_le_html_ecrit_ses_sections_vides():
    """Une section omise et une section vide ne disent pas la meme chose :
    la premiere fait douter de l'outil, la seconde est un resultat."""
    page = render_security_html(build_security_report(Report(points=["A"])))
    for message in (
        "aucun service identifie",
        "aucune tentative d'exploitation detectee",
        "aucun constat des detecteurs Netcross",
        "aucune alerte Expert Info correlee",
        "aucune CVE confirmee",
    ):
        assert message in page


def test_le_html_affiche_un_service_sans_empreinte_sans_inventer_de_valeur(rapport):
    """Les services issus d'une banniere n'ont pas d'empreinte : leur
    cellule doit porter un tiret, jamais « None »."""
    page = render_security_html(rapport)
    assert "nginx" in page
    assert "None" not in page


def test_le_html_est_reproductible_a_horodatage_fixe(rapport):
    """Deux rendus du meme rapport doivent etre identiques : une difference
    residuelle empecherait de comparer deux rapports ou de detecter une
    derive."""
    t = datetime(2026, 9, 22, 15, 0, 0)
    assert render_security_html(rapport, generated_at=t) == render_security_html(rapport, generated_at=t)


def test_le_html_reporte_les_metadonnees(rapport):
    page = render_security_html(rapport, meta={"Ticket": "INC-1234"})
    assert "INC-1234" in page


def test_le_html_rappelle_la_nature_passive_de_l_analyse(rapport):
    """Le lecteur d'un rapport doit savoir ce qu'il tient : une empreinte
    peut etre forgee, et un service absent de la capture n'est pas un
    service absent du reseau."""
    page = render_security_html(rapport)
    assert "passive" in page
    assert "forgee" in page


def test_le_html_est_bien_forme(rapport):
    """Analyse par un parseur reel : une balise non fermee ou un attribut
    casse passerait inapercu dans un test de sous-chaine, et casserait
    l'affichage chez le lecteur."""
    from html.parser import HTMLParser

    class Verificateur(HTMLParser):
        def __init__(self):
            super().__init__()
            self.pile = []
            self.erreurs = []

        def handle_starttag(self, tag, attrs):
            if tag not in ("meta", "br", "input", "img", "link", "hr"):
                self.pile.append(tag)

        def handle_endtag(self, tag):
            if not self.pile or self.pile.pop() != tag:
                self.erreurs.append(tag)

    v = Verificateur()
    v.feed(render_security_html(rapport))
    assert not v.erreurs, f"balises mal imbriquees : {v.erreurs}"
    assert not v.pile, f"balises non fermees : {v.pile}"


# -- sortie PDF ------------------------------------------------------------

reportlab = pytest.importorskip("reportlab", reason="reportlab absent : --pdf-report indisponible")


def _texte_pdf(chemin) -> str:
    """Texte reellement contenu dans le PDF produit.

    C'est le niveau de verification qui manquait (#246/#286) : tous les
    tests de PDF existants s'arretaient avant le fichier. On ne verifie
    jamais la mise en page -- fragile et sans valeur -- mais le fait que
    la donnee arrive.
    """
    try:
        proc = subprocess.run(["pdftotext", str(chemin), "-"], capture_output=True, text=True)
    except FileNotFoundError:
        # Message normalise : le workflow ci.yml echoue si cette chaine
        # apparait dans la sortie de pytest (meme garde-fou que pour
        # tshark/editcap, issue #262). La CI installe poppler-utils, donc
        # un saut ici signifierait que la seule verification regardant le
        # fichier PDF livre a disparu sans bruit -- exactement le silence
        # qui a laisse passer l'issue #259.
        pytest.skip("pdftotext non installe : contenu du PDF non verifiable")
    if proc.returncode != 0:
        pytest.skip(f"pdftotext non installe correctement (code {proc.returncode}) : contenu du PDF non verifiable")
    return proc.stdout


def test_le_pdf_porte_la_section_de_securite(tmp_path):
    from netcross_report.pdf import generate_pdf

    chemin = tmp_path / "r.pdf"
    generate_pdf(_report_garni(), str(chemin), security_report=build_security_report(_report_garni()))
    texte = _texte_pdf(chemin)
    assert "Rapport de securite" in texte
    assert "Score de risque" in texte
    assert JA4 in texte, "l'empreinte JA4 n'atteint pas le PDF"
    assert "CVE-2021-23017" in texte
    assert "Log4Shell" in texte


def test_le_pdf_sans_analyse_de_securite_ne_porte_aucune_section_de_securite(tmp_path):
    """Une section vide laisserait croire qu'une analyse de securite a eu
    lieu sans rien trouver, alors qu'elle n'a pas tourne. Ici l'absence est
    le message juste, et la CLI refuse deja les combinaisons trompeuses."""
    from netcross_report.pdf import generate_pdf

    chemin = tmp_path / "r.pdf"
    generate_pdf(_report_garni(), str(chemin))
    assert "Rapport de securite" not in _texte_pdf(chemin)


def test_le_pdf_ecrit_ses_sections_de_securite_vides(tmp_path):
    from netcross_report.pdf import generate_pdf

    chemin = tmp_path / "r.pdf"
    vide = Report(points=["POINT_A"])
    generate_pdf(vide, str(chemin), security_report=build_security_report(vide))
    texte = _texte_pdf(chemin)
    assert "Aucun service identifie" in texte
    assert "Aucune CVE confirmee" in texte


def test_le_pdf_annonce_le_total_quand_il_tronque(tmp_path):
    """Un tableau plafonne sans dire combien de lignes manquent fait croire
    a une liste exhaustive -- c'est un rapport faux, pas un rapport
    abrege."""
    from netcross_report.pdf import MAX_SECURITY_ROWS, generate_pdf

    r = Report(points=["POINT_A"])
    total = MAX_SECURITY_ROWS + 15
    r.security_findings = [
        {
            "category": "anomalie",
            "severity": "faible",
            "detail": f"retransmission {n}",
            "host": f"10.0.{n // 256}.{n % 256}",
            "point": "POINT_A",
        }
        for n in range(total)
    ]
    chemin = tmp_path / "r.pdf"
    generate_pdf(r, str(chemin), security_report=build_security_report(r))
    texte = _texte_pdf(chemin)
    assert str(total) in texte
    assert "au total" in texte


def test_la_troncature_de_la_forme_lisible_reste_visible_dans_le_pdf(tmp_path):
    from netcross_report.pdf import MAX_PDF_READABLE_LEN, generate_pdf

    r = Report(points=["POINT_A"])
    longue = "ciphers=[" + ",".join(f"0x{i:04x}" for i in range(60)) + "]"
    assert len(longue) > MAX_PDF_READABLE_LEN
    r.service_fingerprints = [
        {
            "service": "TLS/JA4",
            "host": "10.0.0.5",
            "point": "POINT_A",
            "fingerprint": JA4,
            "banner": longue,
        }
    ]
    chemin = tmp_path / "r.pdf"
    generate_pdf(r, str(chemin), security_report=build_security_report(r))
    texte = _texte_pdf(chemin)
    assert "..." in texte
    assert longue not in texte


# -- coherence entre les sorties -------------------------------------------


def test_les_trois_sorties_rapportent_le_meme_score(tmp_path, rapport):
    """Trois rendus d'un meme rapport ne doivent pas raconter trois
    histoires. Le socle `security_report_to_dict` existe pour cela ; ce
    test verifie qu'il est bien la source unique."""
    from netcross_report.pdf import generate_pdf

    attendu = rapport.dashboard.score

    json_path = tmp_path / "r.json"
    generate_json_report(_report_garni(), str(json_path), security_report=rapport)
    assert json.loads(json_path.read_text(encoding="utf-8"))["security_report"]["dashboard"]["score"] == attendu

    assert f"{attendu}" in render_security_html(rapport)

    pdf_path = tmp_path / "r.pdf"
    generate_pdf(_report_garni(), str(pdf_path), security_report=rapport)
    assert f"{attendu}/100" in _texte_pdf(pdf_path)


def test_toutes_les_empreintes_atteignent_les_trois_sorties(tmp_path, rapport):
    """Verification directe du constat de l'issue #259, etendue aux trois
    nouvelles sorties : ce qui est calcule doit arriver partout."""
    from netcross_report.pdf import generate_pdf

    json_path, pdf_path = tmp_path / "r.json", tmp_path / "r.pdf"
    generate_json_report(_report_garni(), str(json_path), security_report=rapport)
    generate_pdf(_report_garni(), str(pdf_path), security_report=rapport)
    sorties = {
        "json": json_path.read_text(encoding="utf-8"),
        "html": render_security_html(rapport),
        "pdf": _texte_pdf(pdf_path),
    }
    for nom, contenu in sorties.items():
        for empreinte in (JA4, HASSH):
            assert empreinte in contenu, f"{empreinte} absente de la sortie {nom}"


def test_le_rendu_texte_reste_tronque_lui(rapport):
    """Garde-fou : la sortie texte garde sa troncature a 120 caracteres,
    les sorties machine non. Les deux regles doivent coexister."""
    assert MAX_READABLE_LEN == 120
    d = security_report_to_dict(rapport)
    assert len(d["services"][0]["fingerprint_readable"] or "") <= len(LISIBLE)
