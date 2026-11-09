# Code Red Freight

**Catégorie :** Forensics · **Pièce jointe :** `code_red_freight.zip`

> Le compte de Patti Fernandez a été compromis, et elle n'a rien remarqué. Format du flag : `CSCTF{<device_name>_<rule_name>_<download_count>}`.

Ma première enquête sur des journaux Microsoft Entra et Microsoft 365. J'y ai découvert le **phishing par device code**, une attaque qui ne vole aucun mot de passe.

## 1. Les pièces

```text
code_red_freight/
├── lure/      devicecode_phish.png, email_phish.png
└── logs/      InteractiveSignIns_…csv, NonInteractiveSignIns_…csv,
               AuditLogs_2026-10-29-Patti_Fernandez.csv, UnifiedAuditLog_Patti.csv
```

## 2. Le leurre

| Indice | Valeur |
|---|---|
| Expéditeur | `Jordan Smith <ragubarden@proton.me>`, un compte externe qui se présente comme un collègue |
| Lien | `5harepoint.cz`, avec un `5` à la place du `S` |
| Date du mail | Jeudi 29/10/2026, 14:58 |
| Page | `microsoft.com/devicelogin`, code `CXR7QK2WD`, valable 15 minutes |

Le principe : la victime saisit un code sur la **vraie** page Microsoft, et ce faisant elle autorise la session de l'attaquant. Pas de faux site de connexion, pas de mot de passe volé, d'où le « noticed nothing ».

Fenêtre de recherche : entre 14:58 et 15:13, le 29/10.

## 3. Lire les CSV correctement

Les champs contiennent des virgules entre guillemets, donc `cut` et `awk` les découpent mal. Miller (`mlr`) les lit proprement :

```bash
mlr --icsv --opprint count-distinct -f Operation then sort -nr count UnifiedAuditLog_Patti.csv
```

Seulement 2 `New-InboxRule` et 4 `FileDownloaded`. Mais ces totaux ne sont pas la réponse : il faut séparer ce qui vient de Patti de ce qui vient de l'attaquant.

## 4. La connexion de l'attaquant

```bash
mlr --icsv --oxtab filter '${Authentication Protocol} =~ "device"i' \
  then cut -o -f 'Date (UTC),IP address,Application,Resource,Status,Session ID' Interactive*.csv
```

```text
Date (UTC)  2026-10-29T15:04:55Z
IP address  203.0.113.77
Application Microsoft Authentication Broker
Resource    Device Registration Service
Status      Success
Session ID  009d0b3a-d06c-faef-2c03-cf5e09419567
```

Dans la fenêtre des 15 minutes, et vers le service d'enregistrement d'appareils.

## 5. L'appareil

```bash
mlr --icsv --opprint cut -o -f 'Date (UTC),Activity,Result,IPAddress,Target1DisplayName' AuditLogs*.csv
```

```text
2026-10-29T15:05:03  Register device  Success  203.0.113.77  D3VC0DE-R3L4Y
```

8 secondes après la connexion, depuis la même IP. L'autre appareil du journal, `R3M0TE-W0RK-PC`, date du 28/10 et vient de l'IP habituelle de Patti.

## 6. La règle de boîte mail

```bash
mlr --icsv --ojson filter '$Operation == "New-InboxRule"' then cut -o -f CreationDate,AuditData UnifiedAuditLog_Patti.csv
```

| Règle | Heure | Action | Origine |
|---|---|---|---|
| `Newsletters` | 28/10 | Déplacement vers un dossier | Patti |
| `M4N1F3ST-L3AK` | 29/10 15:28:57 | `ForwardTo` `ragubarden@proton.me` | **Attaquant** |

Le destinataire du transfert est l'expéditeur du mail de phishing : le lien est direct.

## 7. Les téléchargements

`AuditData` est du JSON dans une colonne CSV. Mon `mlr` n'avait pas `json_decode`, donc je passe par `jq` et `fromjson` :

```bash
mlr --icsv --ojson filter '$Operation == "FileDownloaded"' UnifiedAuditLog_Patti.csv \
  | jq -r '.[] | (.AuditData | fromjson) as $a | [.CreationDate, $a.ClientIP, $a.SourceFileName] | @tsv'
```

```text
2026-10-29T15:20:24  203.0.113.77  Notes.docx
2026-10-29T15:20:30  203.0.113.77  Investor Relations Meeting Presentation.pptx
2026-10-29T15:20:49  203.0.113.77  aerialshot.jpg
2026-10-29T15:21:36  203.0.113.77  Local Resource Guide.docx
```

Quatre fichiers différents, tous depuis l'IP de l'attaquant.

## Chronologie

| Heure (UTC) | Événement |
|---|---|
| 14:58 | Mail de phishing (`5harepoint.cz`) |
| 15:04:55 | Connexion par device code depuis `203.0.113.77` |
| 15:05:03 | Enregistrement de l'appareil `D3VC0DE-R3L4Y` |
| 15:20:24 → 15:21:36 | Téléchargement de 4 fichiers |
| 15:28:57 | Règle `M4N1F3ST-L3AK`, transfert vers `ragubarden@proton.me` |

## Flag

```text
CSCTF{D3VC0DE-R3L4Y_M4N1F3ST-L3AK_4}
```

## Ce que j'ai appris

- Le device code phishing se repère avec `Authentication Protocol = Device Code` dans les sign-ins.
- **L'identifiant de session ne suffisait pas ici** : la même session `009d0b3a…` apparaissait déjà à 12:43, avant le mail. C'est l'IP et la chronologie qui séparent l'attaquant de Patti.
- `mlr` pour les CSV, puis `jq` avec `fromjson` pour le JSON imbriqué.
