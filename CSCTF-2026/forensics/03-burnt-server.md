# Operation Dawn: The Burnt Server

**Catégorie :** Forensics · **Pièce jointe :** `server-remains.tar`

> Deux « storage members » ont survécu à l'incendie d'un serveur. Le registre recherché était sur cette machine.

Mon challenge préféré de la session : reconstruire un disque **détruit** à partir des deux survivants, avec un simple XOR.

## 1. Ce que contient l'archive

```bash
sha256sum server-remains.tar
mkdir remains && tar -xf server-remains.tar -C remains
file remains/*
cat remains/SALVAGE.txt
```

```text
The box held three identical drives in a hot rack. The centre drive (slot 1) was burnt through and would not
spin; its platters are gone. Slots 0 and 2 came out intact and were imaged here as disk0.img and disk2.img.
The controller and its labels did not survive, so the array settings are not recorded.
```

Trois disques, deux restants (slots 0 et 2), et aucun paramètre de la baie.

## 2. Une fausse clé PGP

`file` annonçait une clé PGP sur `disk0.img`, et j'ai d'abord cru à du chiffrement. Vérification :

```bash
gpg --list-packets remains/disk0.img 2>&1 | head -20
```

```text
gpg: [don't know]: invalid packet (ctb=65)
gpg: [don't know]: invalid packet (ctb=63)
gpg: [don't know]: invalid packet (ctb=6b)
...
```

`65 63 6b 20 20 70 6f 73 74` est de l'ASCII (`eck  post`) : `gpg` lit du texte. `file` ne regarde que les premiers octets, et ceux-ci ressemblaient par hasard à un en-tête PGP.

> Sans `2>&1`, `head` ne filtre pas la sortie d'erreur de `gpg` : j'ai pris 46 000 lignes d'erreurs dans le terminal.

## 3. RAID 1, 0 ou 5 ?

```bash
cmp -l remains/disk0.img remains/disk2.img | wc -l
strings -a -n 8 remains/disk0.img | head -30
```

- 15 221 octets différents sur 2 097 152 : pas de RAID 1 (les disques ne sont pas identiques).
- Des noms 8.3 (`ROSTER  TXT`, `WARDS   TXT`, `DAWN ARCH`) : un système de fichiers FAT.
- Un nom incomplet, `RAIN   GZ` : son premier octet n'est pas imprimable, probablement `0xE5`, le marqueur d'entrée supprimée en FAT.

Le déclic : un XOR des premiers octets des deux disques.

```text
disk0 : 95 da 7c be 03 35 55 77 04 d8 4a
disk2 : 7e e6 ec d3 68 53 26 59 62 b9 3e
XOR   : eb 3c 90 6d 6b 66 73 2e 66 61 74   →   ".<.mkfs.fat"
```

`eb 3c 90` est le saut d'un secteur de boot FAT, suivi de `mkfs.fat`. Le début du volume était sur le disque perdu, et la parité permet de le recalculer. C'est un **RAID 5** :

```text
parité = D0 ^ D1   →   disk1 = disk0 ^ disk2
```

## 4. Recréer le disque 1

J'ai créé un script Python qui lit `disk0.img` et `disk2.img`, applique un XOR octet par octet, et écrit le résultat dans `disk1.img`. Il travaille par morceaux de 4 Mio pour ne pas charger les images entières en mémoire. Vérification :

```bash
xxd -l 64 disk1.img
```

```text
00000000: eb3c 906d 6b66 732e 6661 7400 0201 0100  .<.mkfs.fat.....
00000010: 0200 0200 20f8 2000 2000 0200 0000 0000  .... . . .......
00000020: 0000 0000 8000 294c 2535 aa44 4157 4e20  ......)L%5.DAWN
00000030: 4152 4348 2020 4641 5431 3620 2020 0e1f  ARCH  FAT16   ..
```

Un secteur de boot FAT16 valide. Il donne aussi la preuve du RAID 5 : 8192 secteurs × 512 octets = 4 194 304 octets, soit exactement **la capacité de deux disques**.

## 5. Trouver la taille de bloc et l'ordre

Avoir les trois disques ne suffit pas : il faut savoir comment les données sont réparties (taille de bloc, ordre, position de la parité).

```bash
grep -abo 'DAWN ARCH' disk*.img
```

`DAWN ARCH` (le répertoire racine) est à `0x8200` dans le volume **et** à `0x8200` sur `disk0` et `disk1`. Il est donc dans la rangée 0, ce qui impose un bloc plus grand que `0x8200` : **64 Kio ou plus**.

Rangée 0 :

| Disque | Rôle |
|---|---|
| `disk0` | Parité |
| `disk1` | D0 (le secteur de boot) |
| `disk2` | D1 |

J'ai créé un second script qui reconstruit le volume RAID 5 et essaie toutes les combinaisons :

- les 6 ordres possibles des disques ;
- les 4 dispositions (`left`/`right`, `symmetric`/`asymmetric`) ;
- des tailles de bloc de 64 Kio à 1 Mio.

Pour chaque rangée, il calcule quel disque porte la parité, puis recolle les blocs de données dans l'ordre. Il ne garde que les volumes qui commencent par un secteur de boot FAT16 valide (`55 AA` à l'offset 510 et `FAT16` à `0x36`). Il reste 40 images candidates.

| Disposition | Parité | Données |
|---|---|---|
| `left` | Part du dernier disque et recule à chaque rangée | — |
| `right` | Part du premier disque et avance à chaque rangée | — |
| `asymmetric` | — | Remplissent les disques de gauche à droite en sautant la parité |
| `symmetric` | — | Commencent juste après la parité et font le tour |

## 6. Le bon test : le CRC du gzip

Premier essai avec `fsck.fat` : les 40 candidats donnent tous `5 files, 14/8095 clusters`. Normal, car le secteur de boot, les FAT et le répertoire tiennent dans le premier bloc, identique partout.

Il faut une donnée vérifiable **au-delà** du premier bloc. Le fichier supprimé est un gzip, qui contient un CRC32 de son contenu :

```bash
fls -r -p candidats/disk1-disk2-disk0_left-symmetric_64K.img
```

```text
r/r * 8:   _RAIN.GZ
```

```bash
for f in candidats/*.img; do
  icat "$f" 8 | gzip -t 2>/dev/null && echo "OK $f"
done
```

Seuls des candidats en **64K** passent, et ces quatre noms décrivent la même image (même SHA-256) : la reconstruction est unique.

## 7. Le registre

```bash
icat candidats/disk0-disk1-disk2_right-asymmetric_64K.img 8 | gunzip > train.out
grep -an 'CSCTF' train.out
```

```text
0000  wagon 01  berth 191  ward 6  tag 174254  stretcher
...
948:MOVEMENT ORDER: CSCTF{04_flint_arc_eastward_relay_6aa299}
```

## Flag

```text
CSCTF{04_flint_arc_eastward_relay_6aa299}
```

## Ce que j'ai appris

- En RAID 5 à 3 disques, n'importe quel disque perdu se recalcule par XOR des deux autres.
- La signature `file` d'un disque RAID ne veut rien dire : il faut la vérifier.
- Pour valider une reconstruction, il faut un test qui porte sur des données hors du premier bloc, et un CRC est idéal.
