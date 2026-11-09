# Operation Dawn: Relay Snapshot

**Catégorie :** Forensics · **Pièce jointe :** `relay.core`

> Un instantané mémoire d'un relais de transmission. Il faut retrouver l'ordre complet caché parmi les « relay records ».

Premier core dump de ma vie : j'ai découvert qu'un fichier de crash contient la mémoire du processus, et qu'on peut y suivre des pointeurs à la main.

## 1. Qu'est-ce que c'est ?

```bash
file relay.core
```

```text
relay.core: ELF 64-bit LSB core file, x86-64, version 1 (SYSV), SVR4-style, from '/t'
```

Un core ELF contient des segments `LOAD` (les plages mémoire du processus : pile, tas, données) et un segment `NOTE` (registres, signal, fichiers mappés).

## 2. Chercher le texte

```bash
strings -a -t x -n 6 relay.core | grep -i csctf
```

```text
8bbec burn_it_bridgefall_backat_dawnstand_doburn_itrelieve_hold_thewn_nowregroup_fall_back_at_two59c}k_866_dusgroveelm_hard_e_orc_movdock{20_CSCTF
```

Tout est là, mais dans le désordre : `CSCTF` à la fin, `59c}` au milieu, et des faux ordres (`burn_it`, `fall_back`, `regroup`) mélangés aux morceaux du flag. Réassembler à l'œil donnerait plusieurs résultats plausibles.

## 3. Le moment « suspicieux de fou »

```bash
xxd -s 0x8bb00 -l 0x300 relay.core
```

```text
0008bc70: 3230 5f43 5343 5446 c073 f1af a755 0000  20_CSCTF.s...U..
0008bc80: 5074 f1af a755 0000 7075 f1af a755 0000  Pt...U..pu...U..
0008bc90: e074 f1af a755 0000 3073 f1af a755 0000  .t...U..0s...U..
...
```

Juste après les fragments, une rangée de valeurs de 8 octets qui finissent toutes par `55 00 00` : des **pointeurs** x86-64 en little-endian. Par exemple, `c0 73 f1 af a7 55 00 00` se lit `0x000055a7aff173c0`. Il y en a 23, tous espacés de `0x30` : 23 structures de même taille, allouées à la suite.

## 4. Passer d'une adresse mémoire à un offset dans le fichier

Un pointeur contient une adresse mémoire, alors que `xxd` lit des offsets. `readelf -l` donne la correspondance :

```bash
readelf -l relay.core
```

```text
LOAD  Offset 0x33f8  VirtAddr 0x55a7aff17000  FileSiz 0x21000  RW
```

```text
offset fichier = Offset du segment + (adresse - VirtAddr du segment)
0x33f8 + (0x55a7aff173c0 - 0x55a7aff17000) = 0x37b8
```

## 5. La structure d'un bloc

```bash
xxd -e -g 8 -s 0x3690 -l 0x460 relay.core
```

Le bloc qui contient `CSCTF` :

| Offset | Taille | Valeur | Sens |
|---|---|---|---|
| `0x37b0` | 8 | `0x31` | En-tête de l'allocateur (bloc de `0x30` + drapeau) |
| `0x37b8` | 8 | `0x55a7aff17450` | **Adresse du bloc suivant** |
| `0x37c0` | 4 | `5` | **Longueur du texte** |
| `0x37c4` | 5 | `CSCTF` | **Texte** |

C'est une **liste chaînée** dans le tas. La pile ne contient qu'une copie des fragments, dans le désordre.

## 6. Suivre la chaîne

On part du bloc `CSCTF` (`0x55a7aff173c0`) et on répète jusqu'à un pointeur nul :

1. convertir l'adresse en offset ;
2. lire 8 octets : l'adresse suivante ;
3. lire 4 octets : la longueur ;
4. lire le texte et l'ajouter au résultat.

Le suivant de `CSCTF` est `{20_` (offset `0x3848`), et la chaîne compte 11 fragments jusqu'à `59c}`.

**Le piège :** il y a d'autres chaînes, et certaines rejoignent la même fin (`regroup_` → `_bridge` → `59c}`). Il faut partir de `CSCTF`. Si `burn_it` ou `fall_back` apparaissent dans le résultat, on n'est pas parti du bon bloc.

## Flag

```text
CSCTF{20_dock_move_orchard_elm_grove_dusk_86659c}
```

## Ce que j'ai appris

- `readelf -l` est la carte qui relie adresses mémoire et offsets d'un core.
- Des valeurs de 8 octets en `xx xx xx xx 55 55 00 00` ou `xx xx xx xx xx 7f 00 00` sont presque toujours des pointeurs.
- `strings` colle les fragments voisins sans séparateur : l'ordre réel est dans les structures, pas dans le texte.
