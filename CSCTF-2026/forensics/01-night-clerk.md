# Night Clerk

**Catégorie :** Forensics · **Pièce jointe :** `terminal.dd`

> Un employé de nuit a caché un message sur une clé USB. L'énoncé précise que la photo et la capture réseau évoquées dans les preuves ne sont ni fournies ni nécessaires, et qu'il ne faut rien ouvrir dans Office.

Mon tout premier challenge de la session, et il m'a fait découvrir comment un fichier « supprimé » reste lisible sur le disque.

## 1. Identifier l'image

```bash
sha256sum terminal.dd
file terminal.dd
```

```text
terminal.dd: DOS/MBR boot sector, code offset 0x52+2, OEM-ID "NTFS    ", sectors/cluster 8, ...
NTFS, sectors 16383, $MFT start cluster 4, ..., bytes/RecordSegment 2^(-1*246)
```

Ce que j'en retiens :

- **`OEM-ID "NTFS"`** : c'est un volume NTFS.
- **Le secteur 0 est déjà le secteur de boot NTFS**, donc il n'y a pas de table de partitions. `mmls` est inutile, et `fsstat` se lance sans `-o`.
- **`code offset 0x52+2`** n'est pas un offset de partition : c'est le saut `eb 52 90` vers le code de boot. J'ai d'abord tenté `fsstat -o 52+2`, ce qui était une erreur.
- **`bytes/RecordSegment 2^(-1*246)`** : l'octet `0xF6` est signé et vaut -10, donc une entrée MFT fait 2^10 = 1024 octets.

Deux `xxd` pour vérifier sur les octets : `eb 52 90 4e 54 46 53` au début, puis `FILE` (signature d'une entrée MFT) au cluster 4, soit l'offset `4 × 4096 = 0x4000`.

```bash
xxd -l 96 terminal.dd
xxd -s 16384 -l 16 terminal.dd
```

## 2. Lister tout, même ce qui est supprimé

```bash
fsstat terminal.dd
fls -r -p terminal.dd
```

```text
r/r 64-128-2:   README.TXT
-/r * 65-128-2: audit-0214.log
-/r * 66-128-2: night_audit.docx
V/V 67:         $OrphanFiles
-/r * 16:       $OrphanFiles/OrphanFile-16
...
```

L'astérisque marque une entrée **supprimée**. Le log et le document ont été effacés, mais leurs entrées MFT et leurs données sont encore là.

Les `OrphanFile-16` à `-23` sont une fausse piste : NTFS réserve les entrées 16 à 23, elles n'ont pas d'attribut `$DATA`, et `$OrphanFiles` est un répertoire virtuel ajouté par The Sleuth Kit.

## 3. Récupérer les fichiers

```bash
icat terminal.dd 64
icat terminal.dd 65
icat terminal.dd 66 > night_audit.docx
```

`README.TXT` affirme `No redline was saved.` Le log supprimé dit exactement le contraire, et il donne toute la méthode :

```text
The Word file on this stick is a redline. Read the insertion, not the paragraph on screen.
DateTimeOriginal plus OffsetTimeOriginal is UTC.
Subtract that UTC time from the NTP transmit timestamp.
The difference, in whole seconds, XORs each ciphertext byte.
Hex-decode the tracked insertion first.
```

## 4. Lire l'insertion du docx

Un `.docx` est une archive ZIP de fichiers XML : pas besoin d'Office.

```bash
unzip -p night_audit.docx word/document.xml
```

```xml
<w:del w:author="M. Keene" w:date="2026-04-03T02:14:00Z"><w:r><w:delText>The key locker was checked at the start of shift.</w:delText></w:r></w:del>
<w:ins w:author="M. Keene" w:date="2026-04-03T02:14:11Z"><w:r><w:t>7a6a7a6d7f4251505d664a525c4e664b5c5d5550575c44</w:t></w:r></w:ins>
```

Le paragraphe affiché est un leurre supprimé (`w:del`), et le contenu utile est dans l'insertion suivie (`w:ins`).

## 5. Retrouver la clé sans la photo ni la capture

C'est le moment que j'ai préféré. Le log calcule la clé avec deux horodatages que je n'ai pas, et pourtant je n'en ai pas besoin :

- **La clé tient sur un octet.** L'écart en secondes peut dépasser 255, mais seuls ses 8 bits de poids faible agissent sur un octet. Il n'y a donc que 256 clés possibles.
- **Je connais le début du clair** : le flag commence par `C` (`0x43`).

Avec `c = p ^ k`, on a `k = c ^ p` :

```text
k = 0x7a ^ 0x43 = 0x39
```

Appliquer `0x39` à chaque octet donne le flag. Un brute force des 256 clés, en gardant la sortie qui contient `CSCTF{`, donne le même résultat.

## Flag

```text
CSCTF{hid_skew_redline}
```

## Ce que j'ai appris

- `fls` montre les fichiers supprimés, et `icat` les extrait par numéro d'entrée MFT.
- Un `.docx` se lit avec `unzip -p`, et les modifications suivies vivent dans `w:ins` / `w:del`.
- Un XOR sur un octet avec un clair connu se casse sans connaître la façon dont la clé a été fabriquée.
- Les pièces « non nécessaires » de l'énoncé l'étaient vraiment.
