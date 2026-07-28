# Uploading Findings

There are **four distinct methods** to upload findings into ArmorCode from Python, differing by **input format** (JSON objects vs CSV vs a native scanner report) and **transport** (direct POST vs presigned-S3). Only Method 1 is wrapped in the SDK today; the rest are called via `ac._session` until wrapped.

| # | Method | Endpoint | Input | Transport | In SDK? |
|---|--------|----------|-------|-----------|---------|
| 1 | **Generic JSON** | `POST /api/findings/upload` | JSON array of finding objects | Direct POST | ✅ `upload_findings()` |
| 2 | **CSV multipart** | `POST /user/findings/upload/csv` | CSV file on disk | `multipart/form-data` | ❌ |
| 3 | **CSV → custom tool** | `POST /user/tools/generic/configurations/{tool_name}/upload` (also `POST /api/v2/findings/csv/upload`) | CSV mapped to a named custom tool config | Presigned S3 (presign → PUT) | ❌ |
| 4 | **Native scan report** | `POST /api/v2/scans/upload/initiate` → `.../presign` → `.../complete` (legacy: `POST /api/scanUploadUrl`) | Raw scanner output (Snyk/Semgrep/Trivy/…) | Multipart presigned S3 | ❌ |

## How to choose

| Your input | Use |
|---|---|
| Finding objects built in code | **1 — Generic JSON** |
| A normalized findings CSV, one-shot | **2 — CSV multipart** |
| A CSV that should attribute to a specific custom tool (saved field mapping) and/or large files | **3 — CSV → custom tool** |
| A raw native scanner report ArmorCode should parse itself | **4 — Native scan report** |

---

## Method 1 — Generic JSON (implemented)

POST a JSON array of findings in ArmorCode's Generic Finding format. `product`, `sub_product`, and `environment` are query params; names resolve to ids automatically.

```python
ac.upload_findings(
    {
        "Title": "Hardcoded secret in config",
        "Severity": "High",                 # Critical / High / Medium / Low / Info
        "Description": "...",
        "ToolFindingId": "my-unique-id-001",  # dedup key
        "Category": "SECURITY",
        "FindingUrl": "https://example.com/finding/001",
    },
    product="my-product",
    sub_product="my-subproduct",
    environment="Production",
)
# -> {"scanId": 137746107}   # ingest is async; scanId confirms acceptance
```

- **Body:** `ArrayNode` — a JSON array of finding objects (a single dict is auto-wrapped).
- **Targeting:** `product` / `subproduct` / `env` query params.
- **Gotcha:** the sub-product must belong to the product, or the API returns `500 "No such product/sub-product/environment found"`.

## Method 2 — CSV multipart (not wrapped)

Direct `multipart/form-data` upload of a CSV file. No S3 hop.

```python
files = {"file": ("findings.csv", open("findings.csv", "rb"), "text/csv")}
resp = ac._session.post(f"{ac.base_url}/user/findings/upload/csv", files=files)
resp.raise_for_status()
```

- **Body:** `object` with a single `file` (binary) part.
- Simplest CSV path when you don't need custom-tool attribution.

## Method 3 — CSV → custom tool via presigned S3 (not wrapped)

Uploads a CSV bound to a **named custom tool configuration** (with its saved field mapping). Same presign→PUT idiom the asset upload uses.

```python
import json, requests

# 1. presign — body is ScanUploadRequest
body = {
    "product": 843798,           # product id (required)
    "subProduct": 530718,        # sub-product id (required)
    "environment": "Production", # (required)
    "fileName": "sca-findings.csv",  # (required)
    "customTool": True,
}
tool_name = "custom-SCA-Sample-Findings"   # existing sandbox config (id 1001, SCA)
r = ac._session.post(
    f"{ac.base_url}/user/tools/generic/configurations/{tool_name}/upload",
    json=body,
)
r.raise_for_status()
signed_url = r.json()["signedUrl"]

# 2. PUT raw CSV bytes to S3 — NO auth header (signature is in the URL)
with open("sca-findings.csv", "rb") as f:
    requests.put(signed_url, data=f.read(), headers={"Content-Type": "text/csv"}).raise_for_status()

# 3. ArmorCode ingests asynchronously.
```

- **Body:** `ScanUploadRequest` — required `product` (int id), `subProduct` (int id), `environment`, `fileName`; optional `customTool`, `scanDate`, `scanIdentifier`, `tags`, `armorcodeProjects`.
- **Alternative endpoint:** `POST /api/v2/findings/csv/upload` uses `MultiScanUploadRequest` (required `fileName`, `toolName`).
- **CSV format:** columns are always comma-separated; the field delimiter (`;` or `|`) only splits multi-value values *within* a single cell.

## Method 4 — Native scan report (not wrapped)

For a raw scanner output file that ArmorCode parses itself. Three-step multipart-to-S3.

```python
# 1. initiate — query params toolName + totalParts, body ScanUploadRequest
init = ac._session.post(
    f"{ac.base_url}/api/v2/scans/upload/initiate",
    params={"toolName": "Snyk", "totalParts": 1},
    json={"product": 843798, "subProduct": 530718, "environment": "Production", "fileName": "snyk-report.json"},
).json()

s3_key, upload_id, scan_id = (init["data"][k] for k in ("s3Key", "uploadId", "scanId"))

# 2. presign part N -> `data` is the URL as a BARE STRING, not an object
url = ac._session.post(
    f"{ac.base_url}/api/v2/scans/upload/presign",
    json={"s3Key": s3_key, "uploadId": upload_id, "partNumber": 1},
).json()["data"]

# 3. PUT the bytes straight to S3 — no auth header; the URL is pre-signed
put = requests.put(url, data=open("snyk-report.json", "rb").read())
etag = put.headers["ETag"].strip('"')

# 4. complete with the collected ETags
ac._session.post(
    f"{ac.base_url}/api/v2/scans/upload/complete",
    json={"s3Key": s3_key, "uploadId": upload_id, "scanId": scan_id,
          "parts": [{"partNumber": 1, "eTag": etag}]},
).raise_for_status()
```

- **Legacy single-shot:** `POST /api/scanUploadUrl` (`S3UploadUrlRequest`).
- **Name-based alternative:** `POST /client/utils/scan/upload` takes group/subgroup
  **names** instead of numeric ids, but needs a different token type — see below.

---

## Which endpoint, which token

Two request schemas, and the choice is forced by **what kind of API token you hold**.
Verified against three tokens on JulianSandbox (2026-07-28):

| Endpoint | Schema | Names? | Standard token | Report Ingestion token |
|---|---|---|---|---|
| `POST /client/utils/scan/upload` | `S3UploadUrlRequest` | ✅ | ❌ 403 | ✅ **200** |
| `POST /api/scanUploadUrl` | `S3UploadUrlRequest` | ✅ | ❌ 403 | ❌ 403 |
| `POST /api/v2/scans/upload/initiate` | `ScanUploadRequest` | ❌ ids | ✅ 200 | ❌ 403 |
| `POST /user/tools/generic/configurations/{tool}/upload` | `ScanUploadRequest` | ❌ ids | ✅ 200 | ❌ 403 |
| `GET /user/product`, `POST /api/findings` (reads) | — | — | ✅ 200 | ❌ 403 |

### The token type is chosen at creation

`ROLE_REPORT_INGESTION` comes from creating the key with API token type
**"Report Ingestion"** in ArmorCode. It is *not* a permission you can add to an
existing standard token — to use the name-based endpoint you must mint a new key of
that type.

### The two token types are disjoint, not nested

A Report Ingestion token is **not** a superset of a standard token. It is 403 on
*everything* except `/client/utils/scan/upload` — including `GET /user/product` and
`POST /api/findings`. Consequences for any upload script:

- **You cannot resolve names to ids with a Report Ingestion token** — but you don't
  need to, since that endpoint accepts names and resolves them server-side
  (`"juice-shop"` → `843798`, returned as `productId`/`subProductId` on the `scan`
  object).
- **You cannot verify the upload with the same token.** Neither the findings query
  nor the scan-status read is permitted. Verifying ingestion needs a second,
  standard token — or the UI.
- Conversely, a standard token can resolve ids and read findings but is 403 on the
  name-based endpoint. Pick the flow to match the token you have; there is no single
  token that does both.

### Don't infer the gate from the schema

`/api/scanUploadUrl` uses the same `S3UploadUrlRequest` schema as
`/client/utils/scan/upload` but is 403 for **both** token types, with a different
error — a URL allowlist rejection naming the user
(`"User <email> not allowed to access url /api/scanUploadUrl requested method POST"`)
rather than `"You don't have required role to perform this action."` Two separate
mechanisms; same-schema does not imply same-access. Treat `/api/scanUploadUrl` as
unavailable.

### 403 fires before body validation

On any of these, the 403 precedes deserialization, so a correctly-formed payload is
still rejected. If you get 403, the body is not the problem — don't tune it. Note
also that the two schemas are not interchangeable: `ScanUploadRequest` rejects name
strings outright (`Cannot deserialize value of type 'Long' from String "juice-shop"`)
and uses `environment` where `S3UploadUrlRequest` uses `env`.

### The name-based flow (Report Ingestion token)

Two steps, no id resolution, no `complete` call. This is the simplest upload path
when you hold a Report Ingestion token:

```python
import requests

BASE = "https://app.armorcode.com"
H = {"Authorization": f"Bearer {REPORT_INGESTION_TOKEN}",
     "Content-Type": "application/json"}

# 1. presign — group/subgroup by NAME, resolved server-side
r = requests.post(f"{BASE}/client/utils/scan/upload", headers=H, json={
    "product": "juice-shop",                        # name, not id
    "subProduct": "jwayte-armorcode/juice-shop",    # name, not id
    "fileName": "findings.csv",
    "fileSizeBytes": 846,
    "scanTool": "custom-SCA-Sample-Findings",       # custom tools ARE allowed here
    "env": "Production",                            # `env`, not `environment`
    "toolType": "PUSH",
    "triggerby": "PUSH_UPLOAD",
    "tags": ["batch:nightly"],
})
r.raise_for_status()
signed_url = r.json()["signedUrl"]                  # top level, no `data` envelope
scan_id = r.json()["scan"]["id"]

# 2. PUT the bytes to S3 — no auth header; signature is in the URL
requests.put(signed_url, data=open("findings.csv", "rb"),
             headers={"Content-Type": "text/csv"}).raise_for_status()
```

- Response nests the scan under `scan` and the URL at the **top level** as
  `signedUrl` — a third response shape, distinct from both v2 (`data.*`) and
  `GET /api/scans/{id}` (unwrapped).
- The `scan` object echoes the resolved ids (`productId`, `subProductId`), which is
  the cleanest way to confirm the names matched what you intended.
- **Custom tools work here.** Unlike the v2 endpoint, `scanTool` accepts a custom
  tool name (verified with `custom-SCA-Sample-Findings`); no `Custom-` prefix or
  `customTool: true` flag needed.
- **Required** (per `S3UploadUrlRequest`): `env`, `fileName`, `product`, `scanTool`,
  `subProduct`. Useful optionals: `fileSizeBytes`, `tags`, `scanDate`,
  `scanIdentifier`, `toolConfigId`, `uploadTimezone`, `processThroughXlParser`.
- The Swagger *example* shows `tagz`, which is a typo in the docs — no such field
  exists in the schema. Use `tags`. A misspelled key is silently ignored rather than
  rejected, so tags would just vanish.
- `product`/`subProduct` carry the names; the schema also lists separate
  `productName`/`subProductName` fields, which are not needed for this flow.

### Checking the result

```python
scan = ac._session.get(f"{ac.base_url}/api/scans/{scan_id}").json()
scan["status"], scan["totalCount"], scan["totalNew"], scan["totalDuplicate"]
```

- **No `data` envelope:** `GET /api/scans/{scanId}` returns the scan object
  **unwrapped**, unlike the upload endpoints which nest under `data`. Using
  `.get("data", {})` here silently yields `{}`.
- **Status values** are `INITIATED`, `PROCESSING`, `IMPORTING`, `COMPLETED`,
  `FAILED`. There is no `PENDING` or `IN_PROGRESS` — polling for those spins
  until timeout.
- Severity breakdown lives in `allFindingStats.severity`; re-uploading an
  identical file yields `totalNew: 0` with `totalDuplicate` equal to the finding
  count.

---

## Verification status

Tested on JulianSandbox (2026-07). Note the distinction between *transport
verified* (HTTP 200s, scan reaches `COMPLETED`) and *ingestion verified* (findings
confirmed present by querying them) — see the warning below.

| Method | Transport | Findings confirmed |
|--------|-----------|--------------------|
| 1. Generic JSON | ✅ `{"scanId": ...}` | — |
| 2. CSV multipart | ✅ HTTP 200 "File uploaded successfully" | — |
| 3. CSV → custom tool (`custom-SCA-Sample-Findings`) | ✅ presign 200 + PUT 200 | ✅ 10 findings, ids `16770102044`–`53` |
| 4. Native scan report (4-step v2 flow) | ✅ all 4 steps 200, `COMPLETED` | ❌ **none created** |
| Name-based (`/client/utils/scan/upload`) | ✅ presign 200 + PUT 200 | ⚠️ scan `COMPLETED`, not independently confirmed |

Runnable examples: **`examples/upload_findings.py`** (methods 1–4),
**`examples/upload_scan_v2.py`** (method 4 CLI).

> ### `COMPLETED` does not mean findings were created
>
> Method 4 was run with a hand-written Trivy JSON file. All four HTTP steps returned
> 200, `GET /api/scans/{id}` reported `status: COMPLETED`, `totalCount: 5`,
> `totalNew: 5` and a per-severity breakdown matching the file exactly — and **zero
> findings were created**. A tenant-wide findings query returned nothing for any of
> those CVEs.
>
> The counts appear to be derived from parsing the uploaded file, not from rows
> written to the database. A schema ArmorCode's parser doesn't fully recognise can
> yield a plausible-looking `COMPLETED` scan with real-looking statistics and no
> findings at all.
>
> **Always verify by querying the findings**, not by reading scan counters. Method 3
> was confirmed this way (10 findings, ids listed above, `source:
> custom-SCA-Sample-Findings`); Method 4 was not, which is how the discrepancy
> surfaced.
>
> Corollary: model new upload files on a format known to ingest in the target tenant
> (Method 3's CSV mapping, or a real scanner's output) rather than hand-rolling one
> from the format's public docs.

**Reconciling scans and findings** — two traps when checking your work:

- `filters.scanId` on `POST /api/findings` is **silently ignored**. It returns
  unrelated findings rather than an error, which reads as a successful lookup.
- Findings stay attributed to the scan that **first created** them, not the most
  recent scan that touched them. Re-uploading the same findings leaves them under
  the original scan id in the UI (`S-<scanId>`), so a new scan can legitimately show
  `totalNew: N` while the UI still lists those findings under an older scan.
- The findings query itself has been observed returning `0` for a subgroup whose
  findings were confirmed present minutes earlier — likely async reindexing. Retry,
  and cross-check in the UI before concluding an upload failed.

Two gotchas the testing surfaced:
- **Method 2** must NOT send `Content-Type: application/json` — the client session pins that header, which breaks the multipart boundary (HTTP 415). Send only the auth header and let `requests` set the multipart content-type (see the example).
- **Method 4** `toolName` must be a **native** ArmorCode scanner (Snyk, Trivy, Semgrep, SonarQube, Dependabot all accepted) — a custom tool name is rejected with `400 "Custom tool is not supported yet"`. Not every native name passes either: `OWASP ZAP` returns `400 "Tool is not supported yet"`.
- **Method 4** the presign response puts the URL in `data` as a **bare string**, not an object — `json()["data"]["url"]` raises `TypeError`.
- **Method 4** `GET /api/scans/{scanId}` returns the scan **unwrapped** (no `data` key), and its status enum has no `PENDING`/`IN_PROGRESS` — see *Checking the result* above. Both bugs are easy to write and fail silently rather than loudly.
