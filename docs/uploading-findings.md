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

# 2. presign each part (PartPresignRequest) -> signed URL(s); PUT each part to S3
# 3. complete (CompleteMultipartRequest) with the returned ETags
```

- **Legacy single-shot:** `POST /api/scanUploadUrl` (`S3UploadUrlRequest`).

---

## Verification status

The presign → PUT → async-ingest pattern is **verified end-to-end** via the sibling asset upload `POST /api/v2/assets/upload` → `{"signedUrl": ...}` → `PUT` CSV → ingest (0 → 100 assets on JulianSandbox, 2026-07). Methods 2–4 for findings share the same request shapes (pulled from the live OpenAPI spec) but have not each been driven end-to-end. **Verify on JulianSandbox before any customer use.**
