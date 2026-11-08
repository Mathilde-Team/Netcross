# SPDX-License-Identifier: GPL-3.0-or-later
"""
netcross_core.redact -- anonymisation des adresses (IP/MAC) d'une liste
de paquets deja chargee, en vue d'un partage externe (ticket support
vendeur, rapport transmis a un tiers) sans exposer l'adressage reel du
reseau du client.

Perimetre assume, volontairement etroit (nom du flag CLI : --redact,
"adresses" au sens strict, voir FEATURES.md section 5.2) :

- adresses IP (Pkt.src/dst -- SAUF sur un paquet STP, ou ces deux champs
  portent en realite une adresse MAC Ethernet, pas une IP, voir
  pcap_parser.packet ; Pkt.dhcp_server_id ; et les adresses media SDP
  de Pkt.sip_sdp_media, issue #1120) -> plage de documentation
  RFC 5737 (IPv4, TEST-NET-1/2/3) ou RFC 3849 (IPv6, 2001:db8::/32) --
  jamais routable sur le vrai Internet, signal univoque que la donnee a
  ete anonymisee (convention deja largement utilisee par les outils de
  redaction de captures) ;
- adresses MAC (Pkt.arp_sender_mac, la partie MAC de Pkt.stp_root_id
  "prio/mac", et Pkt.src/dst sur un paquet STP) -> OUI localement
  administre 02:00:00:00:00:00 + compteur (bit "locally administered"
  actif, RFC/IEEE 802 -- jamais une vraie adresse assignee par un
  constructeur).

Portee (issue #1153, option --redact-scope, defaut ``tout``) :

- ``adresses`` : uniquement les adresses ci-dessus (comportement historique),
  plus les adresses IP du SAN des certificats (tls_cert_san_ip) ;
- ``noms`` : uniquement les champs nommes, via la table de noms commune
  (netcross_core.pseudonyms, #1151) : noms DNS (dns_qry_name), cible HTTP
  (http_uri : hote pseudonymise, chemin et requete remplaces par
  ``/res-N``), SAN de certificat TLS (tls_cert_san, joker conserve),
  sujet/emetteur (tls_cert_subject/tls_cert_issuer -> ``CN=dn-N``),
  identifiants SIP (sip_call_id -> ``call-N@example.invalid``,
  sip_user_agent/sip_server -> ``agent-N``) ;
- ``tout`` : les deux.

Chaque valeur reelle garde un pseudonyme stable pendant tout le run : les
regroupements (dialogue SIP par Call-ID, certificat auto-signe quand sujet =
emetteur, requetes vers un meme hote) restent exacts apres anonymisation.

Egalement HORS PERIMETRE, par construction architecturale plutot que
par choix : les diagnostics TLS/QUIC (netcross_core.tls_diagnostics/
quic_diagnostics) et la comparaison client vs client
(netcross_core.client_diff) operent chacun sur leur PROPRE reparse
independant des fichiers (voir leurs docstrings respectives) ou sur des
adresses IP fournies explicitement par l'operateur sur la ligne de
commande (--client-group) -- aucun des deux ne passe par la liste
`all_packets` redigee ici. Combiner --redact avec --tls/--quic/
--client-group laisserait donc filtrer des adresses reelles par ces
canaux : les deux CLI refusent explicitement cette combinaison plutot
que de produire un rapport partiellement redige sans le signaler (voir
cross_capture_analyzer_cli.py/cross_capture_diff_cli.py, meme discipline
que le refus deja existant de --tls/--quic/--parallel avec --live).

Mapping deterministe et partage : une meme adresse d'origine produit
toujours le meme pseudonyme, sur tout l'appel a AddressRedactor.redact()
-- y compris a travers plusieurs appels successifs sur le MEME
AddressRedactor (necessaire pour cross_capture_diff_cli.py : baseline et
courant doivent partager un mapping identique, sans quoi le diff entre
les deux perdrait tout son sens). L'ordre d'attribution suit l'ordre de
premiere apparition dans la ou les listes de paquets fournies --
deterministe pour un meme jeu de paquets, mais PAS reproductible d'une
capture a l'autre (pas un besoin identifie ici : le mapping n'a de sens
que le temps d'un run, voir --redact-map pour le conserver).

Mutation EN PLACE des objets Pkt/RawPacket fournis (pas de copie) :
coherent avec l'esprit "reecrit des adresses dans des paquets deja
charges" de cette fonctionnalite, et evite de doubler transitoirement
la memoire d'une grosse capture (voir la piste "gestion memoire des
grosses captures", Session 19). Fonctionne indifferemment sur une liste
de Pkt (netcross_core.models) ou de RawPacket (pcap_parser.packet) :
les deux dataclasses partagent exactement les memes noms de champs pour
src/dst/proto/arp_sender_mac/stp_root_id/dhcp_server_id -- aucun
isinstance ici, uniquement de l'acces par attribut.
"""

from __future__ import annotations

import csv
import ipaddress
import re
from urllib.parse import urlsplit

from netcross_core.logging_config import get_logger, summarize
from netcross_core.pseudonyms import PSEUDO_DOMAIN, NamePseudonymizer, PseudonymTable

logger = get_logger(__name__)

_IPV4_DOC_BLOCKS = (
    (192, 0, 2),  # RFC 5737 TEST-NET-1
    (198, 51, 100),  # RFC 5737 TEST-NET-2
    (203, 0, 113),  # RFC 5737 TEST-NET-3
)
_IPV4_BLOCK_SIZE = 254  # .1 a .254 par bloc -- .0/.255 evites (reseau/diffusion)
_IPV4_DOC_CAPACITY = len(_IPV4_DOC_BLOCKS) * _IPV4_BLOCK_SIZE  # 762

_MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")
# Adresse IPv4, ou IPv6 entre crochets (forme imposee dans une URI SIP,
# RFC 3261 25.1), dans le texte d'un en-tete Via/Contact (issue #1125).
_SIP_ADDR_RE = re.compile(r"\[([0-9A-Fa-f:.]+)\]|(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")


def _ipv4_pseudonym(index: int) -> str:
    """192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737) d'abord --
    762 adresses distinctes, tres largement suffisant pour une capture de
    depannage reseau (2, 4, 9... points, pas un releve d'annuaire
    Internet). Au-dela (jamais atteint par aucune capture de ce projet a
    ce jour), bascule sur 240.0.0.0/4 (RFC 1112, "reserved for future
    use", jamais assigne ni routable) -- ~268M adresses, marge large."""
    if index < _IPV4_DOC_CAPACITY:
        block = _IPV4_DOC_BLOCKS[index // _IPV4_BLOCK_SIZE]
        octet = 1 + (index % _IPV4_BLOCK_SIZE)
        logger.debug("_ipv4_pseudonym: si index < _IPV4_DOC_CAPACITY -> retour chaîne formatée")
        return f"{block[0]}.{block[1]}.{block[2]}.{octet}"
    overflow = index - _IPV4_DOC_CAPACITY
    logger.debug("_ipv4_pseudonym: retour chaîne formatée")
    return f"240.{(overflow >> 16) & 0xFF}.{(overflow >> 8) & 0xFF}.{overflow & 0xFF}"


def _ipv6_pseudonym(index: int) -> str:
    """2001:db8::/32 (RFC 3849, documentation) -- ~2**96 adresses, aucun
    overflow realiste pour une capture reseau. index+1 (pas index) pour
    ne jamais produire l'adresse "2001:db8::" toute seule (suffixe nul),
    lisible mais inutilement ambigue avec le prefixe lui-meme."""
    logger.debug("_ipv6_pseudonym: retour chaîne formatée")
    return f"2001:db8::{index + 1:x}"


def _mac_pseudonym(index: int) -> str:
    """02:00:00:00:00:00 + compteur -- premier octet 0x02 = bit
    "locally administered" actif / bit multicast inactif (IEEE 802) :
    convention standard pour une MAC synthetique, jamais une vraie
    adresse issue d'un OUI constructeur."""
    logger.debug("_mac_pseudonym: retour chaîne formatée")
    return f"02:00:00:{(index >> 16) & 0xFF:02x}:{(index >> 8) & 0xFF:02x}:{index & 0xFF:02x}"


_GENERATORS = {"ipv4": _ipv4_pseudonym, "ipv6": _ipv6_pseudonym, "mac": _mac_pseudonym}

SCOPE_ADDRESSES = "adresses"
SCOPE_NAMES = "noms"
SCOPE_ALL = "tout"
SCOPES = (SCOPE_ADDRESSES, SCOPE_NAMES, SCOPE_ALL)
SCOPE_LABELS = {
    SCOPE_ADDRESSES: "adresses IP/MAC anonymisees (--redact)",
    SCOPE_NAMES: "noms DNS/HTTP/TLS/SIP anonymises (--redact --redact-scope noms)",
    SCOPE_ALL: "adresses IP/MAC et noms DNS/HTTP/TLS/SIP anonymises (--redact)",
}

KIND_DN = "dn"
KIND_CALL_ID = "call-id"
KIND_AGENT = "agent"
KIND_RESOURCE = "ressource"


def _dn_pseudonym(index: int) -> str:
    logger.debug("_dn_pseudonym: index={}", index)
    result = f"CN=dn-{index + 1}"
    logger.debug("_dn_pseudonym: retour {}", result)
    return result


def _call_id_pseudonym(index: int) -> str:
    logger.debug("_call_id_pseudonym: index={}", index)
    result = f"call-{index + 1}@{PSEUDO_DOMAIN}"
    logger.debug("_call_id_pseudonym: retour {}", result)
    return result


def _agent_pseudonym(index: int) -> str:
    logger.debug("_agent_pseudonym: index={}", index)
    result = f"agent-{index + 1}"
    logger.debug("_agent_pseudonym: retour {}", result)
    return result


def _resource_pseudonym(index: int) -> str:
    logger.debug("_resource_pseudonym: index={}", index)
    result = f"/res-{index + 1}"
    logger.debug("_resource_pseudonym: retour {}", result)
    return result


_LABEL_GENERATORS = {
    KIND_DN: _dn_pseudonym,
    KIND_CALL_ID: _call_id_pseudonym,
    KIND_AGENT: _agent_pseudonym,
    KIND_RESOURCE: _resource_pseudonym,
}


def scope_label(scope: str) -> str:
    """Mention « Anonymisation » des rapports pour la portee ``scope``."""
    logger.debug("scope_label: {}", scope)
    label = SCOPE_LABELS[scope]
    logger.debug("scope_label: retour {}", label)
    return label


def _ip_kind(value: str) -> str | None:
    """ "ipv4"/"ipv6" si `value` est une adresse IP syntaxiquement valide,
    None sinon (champ deja vide/malforme -- laisse tel quel par
    l'appelant plutot que de lever une exception sur une capture reelle
    imparfaite, meme discipline defensive que le reste du projet)."""
    try:
        logger.debug("_ip_kind: retour 'ipv6' if ipaddress.ip_address(value).version == …")
        return "ipv6" if ipaddress.ip_address(value).version == 6 else "ipv4"
    except ValueError:
        logger.exception("échec dans _ip_kind")
        logger.debug("_ip_kind: except ValueError -> retour None")
        return None


def _is_mac(value: str) -> bool:
    logger.debug("_is_mac: retour bool(…)")
    return bool(_MAC_RE.match(value))


class AddressRedactor:
    """Etat partage pour anonymiser une ou plusieurs listes de paquets
    avec un mapping coherent. Un mapping neuf = un nouveau pseudonyme
    pour chaque adresse encore jamais vue par CET objet ; reappeler
    .redact() sur une autre liste avec le MEME objet reutilise les
    pseudonymes deja attribues pour toute adresse deja rencontree."""

    def __init__(self, scope: str = SCOPE_ALL) -> None:
        # Issue #1151 : table commune (netcross_core.pseudonyms), adresse
        # reelle -> (pseudonyme, type). Non idempotente : une adresse
        # reelle situee dans la plage des pseudonymes recoit son propre
        # pseudonyme (voir PseudonymTable).
        logger.debug("AddressRedactor.__init__: debut (portée {})", scope)
        if scope not in SCOPES:
            logger.debug("AddressRedactor.__init__: levée ValueError (portée)")
            raise ValueError(f"portée d'anonymisation inconnue : {scope!r} (attendu : {', '.join(SCOPES)})")
        self.scope = scope
        self.addresses = scope in (SCOPE_ADDRESSES, SCOPE_ALL)
        self.named_fields = scope in (SCOPE_NAMES, SCOPE_ALL)
        self._table = PseudonymTable(_GENERATORS, idempotent=False)
        # Table des NOMS (host-N[.domain-M].example.invalid), partagee par
        # tous les champs nommes et exportee avec --redact-map ; appliquee
        # aux champs types DNS/HTTP/TLS/SIP par #1153.
        self.names = NamePseudonymizer()
        # Valeurs nommees qui ne sont pas des noms d'hote (#1153).
        self._labels = PseudonymTable(_LABEL_GENERATORS)
        logger.debug("AddressRedactor.__init__: fin")

    def _pseudonym(self, addr: str, kind: str) -> str:
        logger.debug("AddressRedactor._pseudonym: kind={}", kind)
        pseudo = self._table.pseudonym(addr, kind)
        logger.debug("AddressRedactor._pseudonym: retour pseudo={}", summarize(pseudo, "pseudo"))
        return pseudo

    def pseudonymize_name(self, name: str) -> str:
        """Pseudonyme stable d'un nom d'hote/DNS (voir NamePseudonymizer) :
        meme table pour tous les points et tous les champs du run."""
        logger.debug("AddressRedactor.pseudonymize_name: debut")
        pseudo = self.names.pseudonym(name)
        logger.debug("AddressRedactor.pseudonymize_name: retour {}", summarize(pseudo, "pseudo"))
        return pseudo

    def pseudonymize_address(self, value: str) -> str:
        """Pseudonyme d'une adresse IP ou MAC isolee (meme table que les
        paquets) ; une valeur qui n'est pas une adresse est rendue telle
        quelle. Sert aux sorties dont une etiquette peut reprendre une
        adresse, comme les metriques Prometheus (#1112)."""
        logger.debug("AddressRedactor.pseudonymize_address: debut")
        kind = "mac" if _is_mac(value) else _ip_kind(value)
        if kind is None:
            logger.debug("AddressRedactor.pseudonymize_address: si pas une adresse -> retour inchange")
            return value
        pseudo = self._pseudonym(value, kind)
        logger.debug("AddressRedactor.pseudonymize_address: retour pseudonyme")
        return pseudo

    def redact(self, packets) -> None:
        """Mutation en place de chaque paquet de `packets` (Pkt ou
        RawPacket, voir docstring de module), selon la portee."""
        logger.debug("AddressRedactor.redact: portée {}", self.scope)
        for pk in packets:
            if self.addresses:
                self._redact_one(pk)
            if self.named_fields:
                self._redact_names(pk)
        logger.debug("AddressRedactor.redact: fin")

    def _label(self, value: str, kind: str) -> str:
        logger.debug("AddressRedactor._label: kind={}", kind)
        pseudo = self._labels.pseudonym(value, kind)
        logger.debug("AddressRedactor._label: retour {}", summarize(pseudo, "pseudo"))
        return pseudo

    def _host(self, host: str) -> str:
        """Hote d'une URI ou d'un SAN : adresse IP -> pseudonyme d'adresse,
        sinon pseudonyme de nom."""
        logger.debug("AddressRedactor._host: debut")
        kind = _ip_kind(host.strip("[]"))
        if kind is not None:
            pseudo = self._pseudonym(host.strip("[]"), kind)
            result = f"[{pseudo}]" if host.startswith("[") else pseudo
            logger.debug("AddressRedactor._host: retour adresse pseudonymisée")
            return result
        result = self.pseudonymize_name(host)
        logger.debug("AddressRedactor._host: retour nom pseudonymisé")
        return result

    def _san_name(self, name: str) -> str:
        """Nom du SAN ; un joker garde son ``*.`` et un joker de TLD seul
        (``*.fr``, non identifiant) reste tel quel pour l'audit."""
        logger.debug("AddressRedactor._san_name: debut")
        if name.startswith("*."):
            rest = name[2:]
            if "." not in rest.strip("."):
                logger.debug("AddressRedactor._san_name: retour joker de TLD inchangé")
                return name
            result = f"*.{self.pseudonymize_name(rest)}"
            logger.debug("AddressRedactor._san_name: retour joker pseudonymisé")
            return result
        result = self._host(name)
        logger.debug("AddressRedactor._san_name: retour")
        return result

    def _uri(self, uri: str) -> str:
        """Cible HTTP : forme absolue (hote pseudonymise, chemin ``/res-N``),
        forme autorite de CONNECT (``hote:port``), chemin seul ou ``*``."""
        logger.debug("AddressRedactor._uri: debut")
        if uri in ("", "/", "*"):
            logger.debug("AddressRedactor._uri: retour cible neutre inchangée")
            return uri
        if "://" in uri:
            parts = urlsplit(uri)
            host = parts.hostname or ""
            port = f":{parts.port}" if parts.port else ""
            shown = f"[{host}]" if ":" in host else host
            target = uri.split("://", 1)[1][len(parts.netloc) :]
            path = self._label(target, KIND_RESOURCE) if target not in ("", "/") else target
            result = f"{parts.scheme}://{self._host(shown) if host else ''}{port}{path}"
            logger.debug("AddressRedactor._uri: retour forme absolue")
            return result
        if not uri.startswith("/"):
            host, sep, port = uri.rpartition(":")
            result = f"{self._host(host)}:{port}" if sep and port.isdigit() else self._host(uri)
            logger.debug("AddressRedactor._uri: retour forme autorité")
            return result
        result = self._label(uri, KIND_RESOURCE)
        logger.debug("AddressRedactor._uri: retour chemin pseudonymisé")
        return result

    def _redact_names(self, pk) -> None:
        """Champs nommes DNS/HTTP/TLS/SIP (issue #1153)."""
        logger.debug("AddressRedactor._redact_names: debut")
        if getattr(pk, "dns_qry_name", None):
            pk.dns_qry_name = self.pseudonymize_name(pk.dns_qry_name)
        if getattr(pk, "http_uri", None):
            pk.http_uri = self._uri(pk.http_uri)
        if getattr(pk, "tls_cert_san", None):
            pk.tls_cert_san = tuple(self._san_name(n) if n else n for n in pk.tls_cert_san)
        for field in ("tls_cert_subject", "tls_cert_issuer"):
            if getattr(pk, field, None):
                setattr(pk, field, self._label(getattr(pk, field), KIND_DN))
        if getattr(pk, "sip_call_id", None):
            pk.sip_call_id = self._label(pk.sip_call_id, KIND_CALL_ID)
        for field in ("sip_user_agent", "sip_server"):
            if getattr(pk, field, None):
                setattr(pk, field, self._label(getattr(pk, field), KIND_AGENT))
        logger.debug("AddressRedactor._redact_names: fin")

    def _redact_one(self, pk) -> None:
        logger.debug("AddressRedactor._redact_one: debut")
        if pk.proto == "STP":
            # src/dst portent ici une adresse MAC Ethernet (eth.src/
            # eth.dst), pas une IP -- voir pcap_parser.packet.build_packet.
            if pk.src is not None and _is_mac(pk.src):
                pk.src = self._pseudonym(pk.src, "mac")
            if pk.dst is not None and _is_mac(pk.dst):
                pk.dst = self._pseudonym(pk.dst, "mac")
        else:
            if pk.src is not None:
                kind = _ip_kind(pk.src)
                if kind is not None:
                    pk.src = self._pseudonym(pk.src, kind)
            if pk.dst is not None:
                kind = _ip_kind(pk.dst)
                if kind is not None:
                    pk.dst = self._pseudonym(pk.dst, kind)

        if pk.arp_sender_mac is not None and _is_mac(pk.arp_sender_mac):
            pk.arp_sender_mac = self._pseudonym(pk.arp_sender_mac, "mac")

        if pk.dhcp_server_id is not None:
            kind = _ip_kind(pk.dhcp_server_id)
            if kind is not None:
                pk.dhcp_server_id = self._pseudonym(pk.dhcp_server_id, kind)

        sdp_media = getattr(pk, "sip_sdp_media", ())
        if sdp_media:
            # Issue #1120 : meme pseudonyme que src/dst, pour que
            # l'association SIP/RTP par SDP reste exacte apres --redact.
            pk.sip_sdp_media = tuple(
                (self._pseudonym(addr, kind) if (kind := _ip_kind(addr)) is not None else addr, port)
                for addr, port in sdp_media
            )

        san_ip = getattr(pk, "tls_cert_san_ip", None)
        if san_ip:
            pk.tls_cert_san_ip = tuple(
                self._pseudonym(addr, kind) if (kind := _ip_kind(addr)) is not None else addr for addr in san_ip
            )
        # Issue #1125 : adresses des en-tetes Via/Contact, meme pseudonyme
        # que src/dst pour que la comparaison entre points reste exacte.
        if getattr(pk, "sip_via", None):
            pk.sip_via = self._redact_sip_header(pk.sip_via)
        if getattr(pk, "sip_contact", None):
            pk.sip_contact = self._redact_sip_header(pk.sip_contact)

        if pk.stp_root_id is not None and "/" in pk.stp_root_id:
            prio, _sep, mac = pk.stp_root_id.partition("/")
            if _is_mac(mac):
                pk.stp_root_id = f"{prio}/{self._pseudonym(mac, 'mac')}"
        logger.debug("AddressRedactor._redact_one: fin")

    def _redact_sip_header(self, text: str) -> str:
        """Remplace chaque adresse IP d'un en-tete Via/Contact par son
        pseudonyme ; le reste du texte (utilisateur, parametres) est garde,
        comme les autres identifiants SIP (voir le perimetre ci-dessus)."""
        logger.debug("AddressRedactor._redact_sip_header: entrée ({} caractere(s))", len(text))

        def remplace(m: re.Match) -> str:
            logger.debug("AddressRedactor._redact_sip_header.remplace: entrée")
            addr = m.group(1) or m.group(2)
            kind = _ip_kind(addr)
            if kind is None:
                logger.debug("AddressRedactor._redact_sip_header.remplace: si pas une IP -> retour texte inchange")
                return m.group(0)
            pseudo = self._pseudonym(addr, kind)
            logger.debug("AddressRedactor._redact_sip_header.remplace: retour pseudonyme")
            return f"[{pseudo}]" if m.group(1) else pseudo

        resultat = _SIP_ADDR_RE.sub(remplace, text)
        logger.debug("AddressRedactor._redact_sip_header: retour texte redige")
        return resultat

    def entries(self):
        """Tuples (valeur_reelle, pseudonyme, type) : adresses triees par
        type puis par pseudonyme -- ordre stable pour un export
        reproductible (--redact-map, tests) --, puis table des noms
        (types "nom" et "domaine", issue #1151), absente si aucun nom n'a
        ete pseudonymise."""
        logger.debug("AddressRedactor.entries()")
        addresses = sorted(self._table.entries(), key=lambda t: (t[2], t[1]))
        logger.debug("AddressRedactor.entries: retour {} adresse(s) + noms", len(addresses))
        return addresses + self.names.entries() + self._labels.entries()

    def __len__(self) -> int:
        """Nombre d'ADRESSES pseudonymisees (messages « N adresse(s)
        anonymisee(s) ») ; les noms se comptent avec len(self.names)."""
        logger.debug("AddressRedactor.__len__: retour len(…)")
        return len(self._table)

    @property
    def mapping(self) -> dict[str, str]:
        """Vue simplifiee adresse_reelle -> pseudonyme (sans le type),
        pour un usage programmatique simple (tests notamment)."""
        logger.debug("AddressRedactor.mapping: retour dictionnaire")
        return {addr: pseudo for addr, pseudo, _kind in self._table.entries()}


def redact_packets(packets, scope: str = SCOPE_ALL) -> AddressRedactor:
    """Raccourci pour le cas simple (un seul appel, un seul jeu de
    paquets) : construit un AddressRedactor neuf, redige `packets`,
    renvoie le redacteur (mapping/entries() consultables ensuite,
    notamment pour --redact-map)."""
    logger.debug("redact_packets: packets={}", summarize(packets, "packets"))
    redactor = AddressRedactor(scope)
    redactor.redact(packets)
    logger.debug("redact_packets: retour redactor={}", summarize(redactor, "redactor"))
    return redactor


def redaction_map_csv(entries) -> str:
    """Texte CSV (adresse_reelle, pseudonyme, type) de ``entries`` (voir
    ``AddressRedactor.entries``) -- meme format que --redact-map, pour la
    GUI et l'API (issue #876)."""
    import io

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["adresse_reelle", "pseudonyme", "type"])
    for addr, pseudo, kind in entries:
        writer.writerow([addr, pseudo, kind])
    logger.debug("redaction_map_csv: {} ligne(s)", len(entries))
    return buf.getvalue()


def write_redaction_map_csv(redactor: AddressRedactor, path: str) -> None:
    """Ecrit le mapping adresse reelle -> pseudonyme dans un CSV LOCAL
    (adresse_reelle, pseudonyme, type) -- a conserver uniquement par
    l'operateur, jamais transmis avec la capture/le rapport reidiges :
    permet de retrouver plus tard a quelle adresse reelle correspond un
    pseudonyme mentionne par un tiers (ex: un support vendeur qui cite
    192.0.2.4 dans sa reponse). Issue #1151 : la table des noms y figure
    aussi (types "nom" et "domaine") ; elle n'est jamais jointe a un
    rapport ni a un ticket de support."""
    logger.debug(
        "write_redaction_map_csv: redactor={} path={}",
        summarize(redactor, "redactor"),
        summarize(path, "path"),
    )
    with open(path, "w", newline="", encoding="utf-8") as fh:
        fh.write(redaction_map_csv(redactor.entries()))
    logger.debug("write_redaction_map_csv: fin")
