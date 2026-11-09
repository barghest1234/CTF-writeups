# Interlock Witness

**Catégorie :** Forensics · **Pièce jointe :** `interlock-witness.zip`

> Une capture Modbus/TCP entre un poste de maintenance et un automate. Il faut retrouver les écritures acceptées qui ont modifié des consignes de protection alors que les verrous de sécurité n'étaient pas tous en place, puis produire un « witness » de 64 caractères hexadécimaux.

Pas de flag caché ici : un calcul exact. J'ai découvert le protocole Modbus, et le plaisir de voir un script tomber pile sur les compteurs annoncés par l'auteur.

## 1. Les règles du jeu

```bash
sha256sum -c SHA256SUMS
cat register-map.md interlock-policy.md witness-format.md
```

**Les registres** (adresses PDU, base zéro) :

| Adresse | Nom | Valeurs |
|---|---|---|
| `0x000A` | `maintenance_permit` | 0 absent, 1 actif |
| `0x000B` | `isolation_state` | 0 connecté, 1 isolé |
| `0x000C` | `protection_armed` | 0 contourné, 1 armé |
| `0x0013` | `trip_limit` | consigne |
| `0x0014` | `restore_delay` | consigne |

**La politique :**

| Élément | Règle |
|---|---|
| FC03 accepté | Réponse à la requête précédente, mêmes transaction/protocole/unité/fonction, `byte count = 2 × quantité`. Met à jour les registres lus |
| FC16 accepté | Réponse normale avec les mêmes champs, qui répète adresse et quantité |
| Exception | Ne change jamais l'état |
| Cible | FC16 accepté, `quantité = 1`, adresse `0x0013` ou `0x0014` |
| Dangereuse | L'un des trois verrous n'est pas à `1` **juste avant la réponse** |

**Le witness :**

```text
T = requête PDU 1 || réponse PDU 1 || requête PDU 2 || réponse PDU 2 ...   (cibles dangereuses, dans l'ordre)
W = SHA-256("INTERLOCK-WITNESS/1\x00" || T)
flag = CSCTF{W en hexadécimal minuscule}
```

L'auteur fournit deux contrôles : un vecteur de test pour le hash, et le nombre attendu de FC16 acceptés hors cibles (8, dont 5 sur les verrous).

## 2. Vocabulaire Modbus

| Terme | Sens |
|---|---|
| MBAP | En-tête Modbus/TCP de 7 octets : transaction (2), protocole (2), longueur (2), unité (1) |
| PDU | Ce qui suit le MBAP : code fonction + données |
| FC03 / FC16 | Lecture / écriture de registres |
| Exception | Code fonction + `0x80` |

## 3. Extraire les données

```bash
tshark -r interlock.pcapng -Y 'tcp.len>0' -T fields \
  -e frame.number -e tcp.stream -e tcp.srcport -e tcp.dstport -e tcp.seq -e tcp.len \
  -e tcp.analysis.retransmission -e tcp.payload > payloads.tsv
```

Un exemple tiré des premières lignes :

| Trame | Données après le MBAP | Sens |
|---|---|---|
| 4 | `03 000a 000b` | Lit 11 registres à partir de `0x000A` |
| 6 | `03 16 0000 0000 0001 ...` | `permit=0`, `isolation=0`, `armed=1` |
| 12 → 13 | `10 0013 0001 02 040d` → `10 0013 0001` | **Cible** : `trip_limit = 1037` |

Avec `permit=0` et `isolation=0`, cette première cible est déjà dangereuse.

## 4. Rejouer la capture

J'ai créé un script Python qui :

1. vérifie le hash avec le vecteur de test ;
2. lit `payloads.tsv` et écarte les retransmissions ;
3. découpe les messages avec le champ longueur du MBAP ;
4. forme les paires requête/réponse et applique les règles ;
5. pour une cible, teste les trois verrous **avant** de mettre à jour l'état.

```text
[+] Vecteur OK : b6e58fa962e382b112eb596e416d5680495fc4bd02141f2389797f194df34786
[+] 504 segments lus, 0 retransmissions écartées
[+] 504 ADU découpées — 1 ADU par segment partout

  FC03 acceptés                    124
  FC16 acceptés                    128
  FC16 cibles                      120
  FC16 non cibles                  8      (attendu 8)
  Sur registres d'état             5      (attendu 5)

=== Cibles dangereuses : 16 ===
  frame   13  trip_limit     <- 1037   état avant : permit 0, isolation 0, armed 1
  ...
  frame  259  trip_limit     <- 3077   état avant : permit 1, isolation 0, armed 1
  ...
T = 208 o
```

## 5. Lire l'incident

| Trames | `permit` | `isolation` | `armed` | Ce qui manque |
|---|---|---|---|---|
| 13 → 41 | 0 | 0 | 1 | Ni permis ni isolation |
| 259 → 287 | 1 | 0 | 1 | Le poste n'est plus isolé |

Le piège est dans la seconde fenêtre : le permis de maintenance est actif, donc les écritures **ont l'air** légitimes. Mais il suffit d'un seul verrou à 0 pour qu'elles soient dangereuses.

Contrôle de taille : 16 cibles × (8 octets de requête + 5 de réponse) = 208 octets. J'ai aussi recalculé le hash à part à partir des 16 valeurs, avec le même résultat.

## Flag

```text
CSCTF{1198b297c84064fab89d0f3e3e5308791165333c1b64da17185dd51493b6f339}
```

## Ce que j'ai appris

- Le MBAP, le PDU, et le pairage requête/réponse par transaction.
- Dans ce genre de challenge, un octet de travers change tout le hash sans message d'erreur : les vecteurs de test et les compteurs de l'auteur sont précieux.
- L'état se teste **avant** d'appliquer l'écriture.
