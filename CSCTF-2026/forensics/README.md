# CSCTF 2026 : catégorie Forensics

Mes writeups de la catégorie forensics du **CSCTF 2026** (Chronos Security), du 6 au 8 novembre 2026.


## Challenges

| # | Challenge | Thème | Ce que j'y ai appris | État |
|---|---|---|---|---|
| 1 | [Night Clerk](01-night-clerk.md) | Image NTFS, docx | Fichiers supprimés, modifications suivies Word, XOR à clair connu | ✅ |
| 2 | [Operation Dawn: Relay Snapshot](02-relay-snapshot.md) | Core dump ELF | Adresse mémoire → offset fichier, liste chaînée dans le tas | ✅ |
| 3 | [Operation Dawn: The Burnt Server](03-burnt-server.md) | RAID 5, FAT16 | Reconstruire un disque perdu avec la parité, valider avec un CRC | ✅ |
| 4 | [Operation Dawn: The Relay Tap](04-relay-tap.md) | PCAP | Checksums TCP pour écarter les paquets forgés | ✅ |
| 5 | [Code Red Freight](05-code-red-freight.md) | Logs Entra / M365 | Phishing par device code, chronologie d'un compte compromis | ✅ |
| 6 | [Interlock Witness](06-interlock-witness.md) | Modbus/TCP | Rejouer un état industriel requête par requête | ✅ |
| 7 | [Signal Reconciliation](07-signal-reconciliation.md) | Télémétrie | Calcul entier strict et rapport canonique hashé | ✅ |
| 8 | [Briefing for One](08-briefing-for-one.md) | LNK, registre, WebDAV | Refaire hors ligne la dérivation de clé d'un raccourci malveillant | ✅ |

## Boîte à outils

| Outil | Usage dans ces challenges |
|---|---|
| The Sleuth Kit (`fsstat`, `fls`, `icat`, `istat`) | Lire NTFS et FAT sans monter l'image |
| `xxd`, `strings`, `file` | Regarder les octets bruts avant de croire un outil |
| `readelf` | Segments et notes d'un core ELF |
| `tshark`, `capinfos` | Analyse de captures en ligne de commande |
| `mlr` (Miller), `jq` | Filtrer des CSV et le JSON imbriqué des journaux M365 |
| `hivex` | Lire une ruche de registre Windows hors ligne |
| `exiftool` | Décoder un `.lnk` |
| `7z`, `unzip` | Archives |
| Python | Chaque fois qu'un calcul devait être exact |


> Les organisations, adresses et scénarios de ces challenges sont fictifs, et les adresses IP appartiennent aux plages réservées à la documentation.
