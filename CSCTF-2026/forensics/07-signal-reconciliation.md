# Signal Reconciliation

**Catégorie :** Forensics · **Pièce jointe :** `signal-reconciliation.zip`

> Un vol de reconnaissance fictif : une trace de récepteur GNSS et une estimation de navigation locale intégrée à part. Il faut comparer les deux selon une procédure stricte et rendre un rapport canonique, dont on soumet le hash.

Comme Interlock Witness, c'est un calcul, mais cette fois tout se joue sur la rigueur : entiers uniquement, format au caractère près.

## 1. Les pièces

| Fichier | Contenu |
|---|---|
| `flight.ndjson` | 601 lignes JSON : vitesses (`ve_mmps`, `vn_mmps`) et position GPS (`gps_e_mm`, `gps_n_mm`) toutes les 100 ms |
| `reconciliation-sop.txt` | La procédure exacte |
| `mission-note.txt` | Le contexte |
| `manifest.txt` | Les SHA-256 des trois fichiers |

```text
{"i":0,"t_ms":0,"ve_mmps":30580,"vn_mmps":-7780,"gps_e_mm":0,"gps_n_mm":0}
{"i":1,"t_ms":100,"ve_mmps":32040,"vn_mmps":-7040,"gps_e_mm":3131,"gps_n_mm":-741}
```

## 2. La procédure

**Reconstruire la position estimée** (intégration par trapèzes, en millimètres) :

```text
ins[0] = 0
ins[i+1] = ins[i] + (v[i] + v[i+1]) / 20
res[i] = gps[i] - ins[i]          (pour l'est et le nord)
```

La SOP précise : « exact mathematical integer division », sans flottant ni arrondi. J'ai vérifié que chaque somme est bien divisible par 20 : c'est le cas pour les 600 pas.

**Repérer les fenêtres suspectes.** Pour `i` de 0 à 591, `Q(i)` est vrai si :

- sur 10 points `j = i..i+9` : `res_e² + res_n² >= 625 000 000` (écart d'au moins 25 m) ;
- sur 9 transitions `j = i..i+8` : `res_e` augmente d'au moins 1000 et `res_n` varie d'au plus 500.

`qset` est la liste **complète** des `i` vrais, pas seulement le premier.

**Décider.** `QUARANTINE_GNSS_PROFILE` si `qset` n'est pas vide et si l'écart final est d'au moins 100 m (`res_e[600]² + res_n[600]² >= 10¹⁰`), sinon `REVIEW_ONLY`.

**Écrire le rapport** : exactement 603 lignes, chacune terminée par `\n`.

```text
RECONCILIATION/2|samples=601|qset=<liste ou NONE>|decision=<décision>
E|<i>|<t_ms>|<ins_e>|<ins_n>|<gps_e>|<gps_n>|<res_e>|<res_n>     (× 601)
SUMMARY|qset=<même liste>|final_res_e=<n>|final_res_n=<n>|decision=<décision>
```

**Encoder** : Base32 majuscule, sans `=`, des 24 premiers octets du SHA-256 du rapport. 24 octets donnent 39 caractères.

## 3. Valider le format d'abord

La SOP fournit un vecteur de test : 601 lignes à zéro, `qset=NONE`, `REVIEW_ONLY`. Le rapport doit faire **14 329 octets** et son SHA-256 commencer par `cc8c52dc`. Je l'ai reproduit avant de toucher aux vraies données : ça valide l'écriture du rapport indépendamment du calcul.

## 4. Résultat sur le vol

```text
qset     : 5,35,50,66,84,95,182,214,247,287,309,357,387,453,465,542,567,588
decision : QUARANTINE_GNSS_PROFILE
final    : res_e = 100000, res_n = 1000   (≈ 100,005 m)
```

18 fenêtres qualifiantes, dispersées sur tout le vol, et un écart final juste au-dessus du seuil de 100 m : le profil part en quarantaine.

## Flag

```text
CSCTF{EOSL5C6VZ54TN2PWXUO2B5TVHMVY5G3NWPILLYY}
```

## Ce que j'ai appris

- `//` en Python arrondit vers le bas, ce qui diffère d'une troncature pour les négatifs : avant de choisir, vérifier si la division est exacte.
- Bornes inclusives (`>=`, `<=`) et `i` jusqu'à 591 : chaque détail de l'énoncé compte.
- Un vecteur de test public permet de valider le format séparément du calcul.
