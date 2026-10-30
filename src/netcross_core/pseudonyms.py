"""Module commun de pseudonymisation : adresses et noms (issue #1151).

Factorise la mecanique de pseudonymisation jusque-la propre a
``support/scrubber.py`` (texte libre des tickets de support) pour qu'elle
serve aussi aux champs types des paquets (``redact.py``, chantier #1007) :

- ``PseudonymTable`` : table valeur reelle -> pseudonyme, un compteur et un
  generateur par categorie, pseudonyme stable dans le run (la meme valeur
  recoit toujours le meme pseudonyme), et idempotence (une valeur produite
  par la table se traverse elle-meme sans etre renumerotee). Le scrubber et
  le redacteur d'adresses l'utilisent avec leurs propres generateurs : leurs
  sorties historiques sont inchangees.
- ``NamePseudonymizer`` : noms DNS/hotes en ``host-N.example.invalid``
  (``.invalid`` est reserve par la RFC 6761, jamais resolu), avec
  conservation de la structure utile au diagnostic : deux noms du MEME
  domaine parent recoivent le MEME suffixe pseudonyme
  (``www.acme.fr`` -> ``host-1.domain-1.example.invalid``,
  ``mail.acme.fr`` -> ``host-2.domain-1.example.invalid``).

La table n'est jamais ecrite ailleurs que dans le fichier local
``--redact-map`` (ou le mapping local du ticket de support) : elle annulerait
l'anonymisation si elle etait jointe a un rapport ou a un ticket.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

from netcross_core.logging_config import get_logger, summarize

logger = get_logger(__name__)

PSEUDO_DOMAIN = "example.invalid"
KIND_NAME = "nom"
KIND_DOMAIN = "domaine"


def host_pseudonym(index: int) -> str:
    """``host-N.example.invalid`` (N a partir de 1)."""
    logger.debug("host_pseudonym: index={}", index)
    result = f"host-{index + 1}.{PSEUDO_DOMAIN}"
    logger.debug("host_pseudonym: retour {}", result)
    return result


class PseudonymTable:
    """Valeur reelle -> pseudonyme, par categorie.

    ``generators`` associe a chaque categorie une fonction ``index ->
    pseudonyme`` (index a partir de 0, propre a la categorie). Une valeur
    deja rencontree garde son pseudonyme ; une valeur que la table a
    elle-meme produite (ou declaree via ``mark_own``) est renvoyee telle
    quelle, ce qui rend toute passe idempotente.

    ``idempotent=False`` desactive ce court-circuit : indispensable pour les
    ADRESSES de paquets, ou une adresse reelle peut legitimement appartenir
    a la plage des pseudonymes (192.0.2.0/24 dans un labo) et doit tout de
    meme recevoir son propre pseudonyme, sans etre confondue avec l'hote
    deja pseudonymise en 192.0.2.1."""

    def __init__(self, generators: Mapping[str, Callable[[int], str]], *, idempotent: bool = True) -> None:
        logger.debug("PseudonymTable.__init__: {} catégorie(s)", len(generators))
        self._generators = generators
        self._idempotent = idempotent
        self._map: dict[str, tuple[str, str]] = {}  # reel -> (pseudonyme, categorie)
        self._own: set[str] = set()
        self._counters: dict[str, int] = dict.fromkeys(generators, 0)
        logger.debug("PseudonymTable.__init__: fin")

    def pseudonym(self, real: str, kind: str) -> str:
        """Pseudonyme stable de ``real`` dans la categorie ``kind``."""
        logger.debug("PseudonymTable.pseudonym: kind={}", kind)
        if self._idempotent and real in self._own:
            logger.debug("PseudonymTable.pseudonym: valeur déjà anonyme -> retour inchangée")
            return real
        entry = self._map.get(real)
        if entry is not None:
            logger.debug("PseudonymTable.pseudonym: déjà connue -> retour {}", summarize(entry[0], "pseudo"))
            return entry[0]
        index = self._counters[kind]
        self._counters[kind] += 1
        pseudo = self._generators[kind](index)
        self._map[real] = (pseudo, kind)
        self._own.add(pseudo)
        logger.debug("PseudonymTable.pseudonym: retour {}", summarize(pseudo, "pseudo"))
        return pseudo

    def mark_own(self, value: str) -> None:
        """Declare ``value`` comme deja anonyme (forme derivee d'un
        pseudonyme, ex. ``capture-1.pcapng``) : elle se traversera."""
        logger.debug("PseudonymTable.mark_own: debut")
        self._own.add(value)
        logger.debug("PseudonymTable.mark_own: fin")

    def entries(self) -> list[tuple[str, str, str]]:
        """``(valeur_reelle, pseudonyme, categorie)`` dans l'ordre de
        premiere rencontre (les appelants trient selon leur besoin)."""
        logger.debug("PseudonymTable.entries: {} entrée(s)", len(self._map))
        return [(real, pseudo, kind) for real, (pseudo, kind) in self._map.items()]

    def __len__(self) -> int:
        logger.debug("PseudonymTable.__len__: retour {}", len(self._map))
        return len(self._map)


def _domain_pseudonym(index: int) -> str:
    logger.debug("_domain_pseudonym: index={}", index)
    result = f"domain-{index + 1}"
    logger.debug("_domain_pseudonym: retour {}", result)
    return result


def _label_pseudonym(index: int) -> str:
    logger.debug("_label_pseudonym: index={}", index)
    result = f"host-{index + 1}"
    logger.debug("_label_pseudonym: retour {}", result)
    return result


class NamePseudonymizer:
    """Noms d'hotes/DNS -> ``host-N[.domain-M].example.invalid``.

    Normalisation : casse ignoree et point final retire, donc ``WWW.Acme.FR.``
    et ``www.acme.fr`` ont le meme pseudonyme. Le domaine parent est le nom
    prive de son premier label, retenu s'il compte au moins deux labels
    (``www.acme.fr`` -> ``acme.fr``) ; un nom a un ou deux labels
    (``srv01``, ``acme.fr``) n'a pas de parent pseudonymise et devient
    ``host-N.example.invalid`` -- un TLD seul (``fr``) n'est pas un domaine
    commun utile au diagnostic. Limite connue : sans liste des suffixes
    publics, ``a.co.uk`` et ``b.co.uk`` partagent le parent ``co.uk``.

    ``host-N`` est unique par nom complet, ``domain-M`` par parent : deux
    noms differents ont toujours deux pseudonymes differents."""

    def __init__(self) -> None:
        logger.debug("NamePseudonymizer.__init__: debut")
        self._hosts = PseudonymTable({KIND_NAME: _label_pseudonym})
        self._domains = PseudonymTable({KIND_DOMAIN: _domain_pseudonym})
        self._names: dict[str, str] = {}  # nom normalise -> pseudonyme complet
        self._own: set[str] = set()
        logger.debug("NamePseudonymizer.__init__: fin")

    def pseudonym(self, name: str) -> str:
        """Pseudonyme stable de ``name`` ; une chaine vide est renvoyee telle
        quelle, un nom deja pseudonyme (``*.example.invalid``) aussi."""
        logger.debug("NamePseudonymizer.pseudonym: debut")
        key = name.strip().rstrip(".").lower()
        if not key:
            logger.debug("NamePseudonymizer.pseudonym: nom vide -> retour inchangé")
            return name
        if key in self._own or key == PSEUDO_DOMAIN or key.endswith("." + PSEUDO_DOMAIN):
            logger.debug("NamePseudonymizer.pseudonym: déjà anonyme -> retour inchangé")
            return key
        known = self._names.get(key)
        if known is not None:
            logger.debug("NamePseudonymizer.pseudonym: déjà connu -> retour {}", summarize(known, "pseudo"))
            return known
        label = self._hosts.pseudonym(key, KIND_NAME)
        _first, _sep, parent = key.partition(".")
        if parent.count(".") >= 1:
            result = f"{label}.{self._domains.pseudonym(parent, KIND_DOMAIN)}.{PSEUDO_DOMAIN}"
        else:
            result = f"{label}.{PSEUDO_DOMAIN}"
        self._names[key] = result
        self._own.add(result)
        logger.debug("NamePseudonymizer.pseudonym: retour {}", summarize(result, "pseudo"))
        return result

    def entries(self) -> list[tuple[str, str, str]]:
        """Table pour ``--redact-map`` : ``(nom_reel, pseudonyme, "nom")``
        puis ``(domaine_parent_reel, "domain-M.example.invalid",
        "domaine")``, chaque groupe trie par pseudonyme."""
        logger.debug("NamePseudonymizer.entries: debut")
        names = sorted(((real, pseudo, KIND_NAME) for real, pseudo in self._names.items()), key=_natural_key)
        domains = sorted(
            ((real, f"{pseudo}.{PSEUDO_DOMAIN}", KIND_DOMAIN) for real, pseudo, _kind in self._domains.entries()),
            key=_natural_key,
        )
        logger.debug("NamePseudonymizer.entries: retour {} nom(s), {} domaine(s)", len(names), len(domains))
        return names + domains

    def __len__(self) -> int:
        logger.debug("NamePseudonymizer.__len__: retour {}", len(self._names))
        return len(self._names)


def _natural_key(row: tuple[str, str, str]) -> tuple[int, str]:
    """Tri ``host-2`` avant ``host-10`` (numero du premier label)."""
    logger.debug("_natural_key: debut")
    head = row[1].split(".", 1)[0]
    number = head.rsplit("-", 1)[-1]
    result = (int(number) if number.isdigit() else 0, row[1])
    logger.debug("_natural_key: retour {}", result)
    return result
