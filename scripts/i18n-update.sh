#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# scripts/i18n-update.sh -- maintenance des catalogues gettext (issue #299).
#
#   scripts/i18n-update.sh              xgettext -> lang/messages.pot,
#                                       msgmerge --update lang/*.po (cree les
#                                       .po manquants avec msginit),
#                                       msgfmt --check
#   scripts/i18n-update.sh --check      verifie sans rien ecrire : .pot et .po
#                                       a jour par rapport aux sources,
#                                       catalogues valides (CI)
#   scripts/i18n-update.sh --compile [DIR]
#                                       msgfmt --check puis compilation en
#                                       DIR/<locale>/LC_MESSAGES/netcross.mo
#                                       (defaut : src/netcross_core/locale,
#                                       embarque par le packaging)
#
# Langue source : le francais (msgid). Les nouvelles chaines arrivent avec
# msgstr "" : aucune traduction automatique n'est inseree. Les langues sont
# lues dans lang/LINGUAS, nulle part ailleurs.
#
# Prerequis : gettext (apt-get install gettext).

set -euo pipefail
export LC_ALL=C.UTF-8

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LANG_DIR="$ROOT/lang"
POT="$LANG_DIR/messages.pot"
DOMAIN="netcross"
MODE="update"
DEST="$ROOT/src/netcross_core/locale"

case "${1:-}" in
    "") ;;
    --check) MODE="check" ;;
    --compile) MODE="compile"; DEST="${2:-$DEST}" ;;
    -h|--help) sed -n '2,21p' "$0"; exit 0 ;;
    *) echo "option inconnue : $1" >&2; exit 2 ;;
esac

for tool in xgettext msgmerge msgfmt msginit msgfilter; do
    command -v "$tool" >/dev/null || { echo "gettext requis ($tool introuvable)" >&2; exit 2; }
done

linguas() { sed -e 's/#.*//' -e 's/[[:space:]]//g' "$LANG_DIR/LINGUAS" | grep -v '^$'; }

# Lignes sans effet sur le contenu : dates de generation.
strip_dates() { grep -vE '^"(POT-Creation-Date|PO-Revision-Date):' "$1"; }

# Sources suivies par git (les fichiers generes ou ignores n'entrent pas).
sources() { (cd "$ROOT" && git ls-files 'src/*.py' 'src/**/*.py' | sort -u); }

generate_pot() {
    local out="$1"
    (cd "$ROOT" && sources | xgettext --files-from=- --output="$out" \
        --language=Python --from-code=UTF-8 \
        --keyword=_ --keyword=N_ --keyword=ngettext:1,2 \
        --add-comments=Traducteurs --add-location=file --sort-by-file \
        --package-name=netcross --msgid-bugs-address="https://github.com/MathildeDec/Netcross/issues" \
        --copyright-holder="Netcross")
    # xgettext laisse CHARSET dans l'en-tete du modele ; les .po heritent d'UTF-8.
    sed -i 's/charset=CHARSET/charset=UTF-8/' "$out"
}

merge_po() {  # $1 = .po existant, $2 = .pot, $3 = sortie
    msgmerge --quiet --add-location=file --sort-by-file --previous --output-file="$3" "$1" "$2"
}

check_all() {
    local rc=0 po
    for loc in $(linguas); do
        po="$LANG_DIR/$loc.po"
        if [ ! -f "$po" ]; then echo "manquant : lang/$loc.po (lancer scripts/i18n-update.sh)" >&2; rc=1; continue; fi
        msgfmt --check --output-file=/dev/null "$po" || { echo "invalide : lang/$loc.po" >&2; rc=1; }
    done
    for po in "$LANG_DIR"/*.po; do
        [ -e "$po" ] || continue
        loc="$(basename "$po" .po)"
        linguas | grep -qx "$loc" || { echo "lang/$loc.po absent de lang/LINGUAS" >&2; rc=1; }
    done
    return $rc
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

case "$MODE" in
update)
    generate_pot "$TMP/messages.pot"
    if [ -f "$POT" ] && diff -q <(strip_dates "$POT") <(strip_dates "$TMP/messages.pot") >/dev/null; then
        echo "lang/messages.pot inchange"
    else
        cp "$TMP/messages.pot" "$POT"; echo "lang/messages.pot mis a jour"
    fi
    for loc in $(linguas); do
        po="$LANG_DIR/$loc.po"
        if [ ! -f "$po" ]; then
            msginit --no-translator --no-wrap --locale="$loc" --input="$POT" --output-file="$po" 2>/dev/null
            sed -i 's/charset=ASCII/charset=UTF-8/' "$po"
            # msginit recopie les msgid pour l'anglais : la source etant en
            # francais, ce seraient de fausses traductions. Tout repart vide.
            msgfilter --keep-header --no-wrap --input="$po" --output-file="$po" true
            if grep -q 'nplurals=INTEGER' "$po"; then
                echo "lang/$loc.po cree : msginit ne connait pas les pluriels de '$loc'," \
                     "renseigner l'en-tete Plural-Forms avant de relancer" >&2
                exit 1
            fi
            echo "lang/$loc.po cree"
        fi
        merge_po "$po" "$POT" "$TMP/$loc.po"
        if ! diff -q <(strip_dates "$po") <(strip_dates "$TMP/$loc.po") >/dev/null; then
            cp "$TMP/$loc.po" "$po"; echo "lang/$loc.po mis a jour"
        fi
    done
    check_all
    ;;
check)
    rc=0
    generate_pot "$TMP/messages.pot"
    if [ ! -f "$POT" ] || ! diff -u <(strip_dates "$POT") <(strip_dates "$TMP/messages.pot") >"$TMP/pot.diff"; then
        echo "::error::lang/messages.pot n'est plus a jour avec les sources : lancer scripts/i18n-update.sh" >&2
        cat "$TMP/pot.diff" >&2 || true
        rc=1
    fi
    for loc in $(linguas); do
        po="$LANG_DIR/$loc.po"
        [ -f "$po" ] || continue
        merge_po "$po" "$TMP/messages.pot" "$TMP/$loc.po"
        if ! diff -q <(strip_dates "$po") <(strip_dates "$TMP/$loc.po") >/dev/null; then
            echo "::error::lang/$loc.po n'est plus synchronise avec messages.pot" >&2
            rc=1
        fi
    done
    check_all || rc=1
    exit $rc
    ;;
compile)
    check_all
    for loc in $(linguas); do
        mkdir -p "$DEST/$loc/LC_MESSAGES"
        msgfmt --check --output-file="$DEST/$loc/LC_MESSAGES/$DOMAIN.mo" "$LANG_DIR/$loc.po"
    done
    echo "$(linguas | wc -l) catalogue(s) compile(s) dans $DEST"
    ;;
esac
