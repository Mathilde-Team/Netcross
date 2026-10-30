# Journaux de flux Zeek conn.log (issue #1115)

Netcross écrit ses flux au format `conn.log` de [Zeek](https://docs.zeek.org/en/master/logs/conn.html),
lisible par tout l'écosystème Zeek : `zeek-cut`, Splunk (TA Zeek), Elastic (module Zeek),
RITA, Brim/Zui. Sous-issue 4/5 du chantier #1003 (export observabilité).

```bash
cross_capture_analyzer_cli.py --capture LAN=lan.pcapng --capture WAN=wan.pcapng \
    --order LAN,WAN --zeek-conn conn.log
zeek-cut ts id.orig_h id.resp_h conn_state netcross_segment_lost_pkts < conn.log

# variante JSON (un objet par ligne, comme LogAscii::use_json=T)
cross_capture_analyzer_cli.py --capture LAN=lan.pcapng --zeek-conn conn.json --zeek-format json
```

Module : `netcross_report.zeek_export` (`build_conn_records`, `to_tsv`, `to_json_lines`,
`write_zeek_conn`).

## Une ligne par connexion et par point

Comme si Zeek avait tourné sur chaque sonde : une connexion vue en `LAN` et en `WAN` donne deux
lignes, chacune avec les compteurs observés à son point. Une connexion est identifiée par le
protocole et le couple de points d'extrémité (ICMP : couple d'adresses, type et code dans
`id.orig_p`/`id.resp_p` comme Zeek). L'initiateur est l'émetteur du SYN sans ACK s'il est vu,
sinon celui du premier paquet. ARP, STP et IP sans transport connu ne sont pas des connexions
au sens de Zeek et sont ignorés, ainsi que les paquets marqués doublons.

## Format TSV

En-têtes Zeek complets : `#separator \x09`, `#set_separator ,`, `#empty_field (empty)`,
`#unset_field -`, `#path conn`, `#open`, `#fields`, `#types`, puis une ligne par connexion et
`#close`. `#open` et `#close` portent les bornes de la capture (premier et dernier paquet),
pas l'heure de l'export : deux exports d'une même capture sont identiques octet pour octet.
Tabulation, fins de ligne et antislash d'une valeur sont échappés en `\xNN`.

Colonnes standard de Zeek, dans l'ordre de Zeek :

| Colonne | Type | Valeur Netcross |
|---|---|---|
| `ts`, `duration` | `time`, `interval` | premier paquet au point, écart au dernier |
| `uid` | `string` | `C` + 17 caractères base 62, stable d'un export à l'autre |
| `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p` | `addr`, `port` | initiateur et répondeur |
| `proto` | `enum` | `tcp`, `udp`, `icmp` |
| `service` | `string` | `dns`, `ssl`, `http`, `sip`, `dhcp`, `ssh` si un champ disséqué l'atteste |
| `orig_bytes`, `resp_bytes` | `count` | charge utile observée |
| `conn_state` | `string` | `S0`, `S1`, `SF`, `REJ`, `RSTO`, `RSTR`, `SH`, `OTH` |
| `history` | `string` | lettres Zeek `S H A D F R` (majuscule : initiateur) |
| `orig_pkts`, `resp_pkts`, `orig_ip_bytes`, `resp_ip_bytes` | `count` | paquets et longueur de trame |
| `local_orig`, `local_resp`, `missed_bytes` | | non renseignés (`-`) |
| `tunnel_parents` | `set[string]` | vide |

Colonnes propres à Netcross, après les colonnes standard :

| Colonne | Type | Signification |
|---|---|---|
| `netcross_point` | `string` | point de capture de la ligne |
| `netcross_points` | `set[string]` | points qui voient la connexion, dans l'ordre `--order` |
| `netcross_segment` | `string` | segment amont → point (`LAN->WAN`), avec `--order` |
| `netcross_segment_delay_ms` | `double` | médiane des écarts entre les deux observations d'un même paquet |
| `netcross_segment_lost_pkts` | `count` | paquets vus en amont et absents à ce point |
| `netcross_loss_segment` | `string` | premier segment du chemin où la connexion perd des paquets |

Sans `--order`, le chemin n'est pas connu : les colonnes de segment restent non renseignées.
Les pertes suivent la convention du rapport : un paquet vu au point amont et absent au point
de la ligne.

## Format JSON

Un objet par ligne, clés dans l'ordre des colonnes ; champs non renseignés et ensembles vides
omis, ensembles en listes, `ts` en secondes flottantes.

## Anonymisation

Avec `--redact`, les paquets sont pseudonymisés avant l'analyse : adresses du `conn.log` et
`uid` (dérivé des valeurs pseudonymisées) n'exposent aucune adresse réelle.

## Limites

- `orig_bytes`/`resp_bytes` additionnent la charge utile vue, retransmissions comprises (Zeek
  les déduit des numéros de séquence) ; `*_ip_bytes` est la longueur de trame capturée.
- `history` note chaque lettre une fois par sens, sans les répétitions de Zeek.
- `service` ne s'appuie que sur la dissection, jamais sur le numéro de port.
- `local_orig`, `local_resp` (réseaux locaux de Zeek) et `missed_bytes` ne sont pas calculés.
