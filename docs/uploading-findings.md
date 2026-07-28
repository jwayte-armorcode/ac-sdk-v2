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
- **Not usable from an API token:** `POST /client/utils/scan/upload` (the endpoint
  Swagger presents most prominently for scan upload) is gated by
  `ROLE_REPORT_INGESTION` at the security-filter layer and returns
  `403 "You don't have required role to perform this action."` The 403 fires
  *before* body validation, so a correctly-formed payload is still rejected —
  don't burn time tuning the body. Note it also takes `product`/`subProduct` as
  **name strings**, unlike the v2 endpoint's numeric ids, so payloads are not
  interchangeable.

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

**All four methods verified end-to-end on JulianSandbox (2026-07):**

| Method | Result |
|--------|--------|
| 1. Generic JSON | ✅ `{"scanId": ...}` |
| 2. CSV multipart | ✅ HTTP 200 "File uploaded successfully" |
| 3. CSV → custom tool (`custom-SCA-Sample-Findings`) | ✅ presign 200 + S3 PUT 200 |
| 4. Native scan report (full 4-step flow) | ✅ scan `COMPLETED`, 5 findings ingested |

Runnable examples for all four: **`examples/upload_findings.py`**.
Method 4 as a standalone CLI: **`examples/upload_scan_v2.py`**.

Method 4 detail (2026-07-28, tool `Trivy`, group `juice-shop` / subgroup
`jwayte-armorcode/juice-shop`): initiate → presign → S3 PUT → complete all
returned 200; `GET /api/scans/{id}` then reported `status: COMPLETED`,
`totalCount: 5`, `totalNew: 5`, severity `{Critical: 1, High: 2, Medium: 1,
Low: 1}`, `scanType: ["SCA"]`, processed in 376 ms. A second upload of the same
file returned `totalNew: 0` / `totalDuplicate: 5`, confirming dedup.

Two gotchas the testing surfaced:
- **Method 2** must NOT send `Content-Type: application/json` — the client session pins that header, which breaks the multipart boundary (HTTP 415). Send only the auth header and let `requests` set the multipart content-type (see the example).
- **Method 4** `toolName` must be a **native** ArmorCode scanner (Snyk, Trivy, Semgrep, SonarQube, Dependabot all accepted) — a custom tool name is rejected with `400 "Custom tool is not supported yet"`. Not every native name passes either: `OWASP ZAP` returns `400 "Tool is not supported yet"`.
- **Method 4** the presign response puts the URL in `data` as a **bare string**, not an object — `json()["data"]["url"]` raises `TypeError`.
- **Method 4** `GET /api/scans/{scanId}` returns the scan **unwrapped** (no `data` key), and its status enum has no `PENDING`/`IN_PROGRESS` — see *Checking the result* above. Both bugs are easy to write and fail silently rather than loudly.
