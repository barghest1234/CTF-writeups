# Operation Dawn: The Relay Tap

**Catégorie :** Forensics · **Pièce jointe :** `relay-tap.zip` → `relay-tap.pcap`

> Une écoute sur un relais. L'adversaire a injecté du trafic forgé, certaines données apparaissent plusieurs fois, et le protocole se décrit lui-même dans la capture. Il faut l'ordre **réellement livré**.

J'ai découvert ici que le checksum TCP n'est pas un détail : c'est lui qui dit quel paquet a vraiment été accepté.

> Petit incident au départ : mon premier « zip » faisait 16 octets et contenait `error code: 502`. `curl -f` évite d'enregistrer une page d'erreur sous le nom du fichier.

## 1. Vue d'ensemble

```bash
capinfos relay-tap.pcap
tshark -r relay-tap.pcap -q -z io,phs
tshark -r relay-tap.pcap -q -z conv,tcp
```

Six conversations HTTP sur le port 80 (du statut, sans intérêt) et une seule différente : `192.0.2.37:39605 <-> 198.51.100.9:7443`, plus tard dans la capture et avec plus de données. C'est le flux numéro 6.

## 2. Le protocole se décrit lui-même

```bash
tshark -r relay-tap.pcap -q -z follow,tcp,ascii,6
```

Le relais envoie sa propre spécification :

```text
ARLY relay v2 :: frame = "ARLY" | type(1) | len(2, big-endian) | body;
types 0=descriptor 1=client_nonce(16) 2=server_nonce(16) 3=order;
key = SHA-256(client_nonce || server_nonce), 32 raw bytes;
ks = SHA-256(key || uint32be(i)) for i = 0,1,2,..., raw 32-byte digests concatenated and cut to len(body);
order = body XOR ks, byte by byte
```

Ce chiffrement n'a aucun secret : les deux nonces passent en clair, et ils suffisent pour recalculer la clé.

## 3. Trouver les paquets forgés

`follow` reconstitue une seule version du flux et masque donc les doublons. Il faut regarder les paquets un par un, en demandant à `tshark` de vérifier les checksums :

```bash
tshark -r relay-tap.pcap -o tcp.check_checksum:TRUE -Y 'tcp.stream==6' -T fields -E header=y \
  -e frame.number -e ip.src -e ip.ttl -e ip.id -e tcp.seq -e tcp.len -e tcp.flags.str -e tcp.checksum.status
```

| Trame | Sens | `seq` | `len` | Checksum | Contenu |
|---|---|---|---|---|---|
| 110 | Client → relais | 1 | 23 | ✅ 1 | `client_nonce` |
| 112 | Relais → client | 1 | 366 | ✅ 1 | Description + `server_nonce` |
| **114** | Relais → client | 1 | 366 | ❌ 0 | Doublon de 112 |
| 115 | Relais → client | 367 | 53 | ✅ 1 | Ordre chiffré |
| **117** | Relais → client | 367 | 53 | ❌ 0 | Doublon de 115, **contenu différent** |

Une pile TCP rejette un segment dont le checksum est faux. **112 et 115 ont été livrés, 114 et 117 non.** Les accusés de réception (113, 116) vont dans le même sens.

## 4. Déchiffrer

```bash
tshark -r relay-tap.pcap -Y 'tcp.stream==6 && tcp.len>0' -T fields -e frame.number -e tcp.payload
```

Le script :

1. découpe les trames ARLY (le paquet 112 en contient deux, donc il faut une boucle) ;
2. calcule `key = sha256(client_nonce + server_nonce)` ;
3. concatène `sha256(key + i.to_bytes(4, "big"))` jusqu'à la longueur du corps ;
4. applique le XOR.

Résultat :

```text
115 → CSCTF{16_cobalt_ingot_rowan_fathom_ca8f4addb0}
117 → S\x8e\xae\xa8\x03\xf1... (du bruit)
```

L'ordre forgé ne se déchiffre même pas proprement, ce qui confirme la lecture des checksums.

## Flag

```text
CSCTF{16_cobalt_ingot_rowan_fathom_ca8f4addb0}
```

## Ce que j'ai appris

- `-o tcp.check_checksum:TRUE` puis `tcp.checksum.status` (1 = bon, 0 = mauvais) pour savoir ce qui a été accepté.
- Même `tcp.seq` sur deux paquets = des données répétées, à départager.
- `follow` reconstitue une seule version du flux : pour des doublons, il faut descendre au niveau des trames.
