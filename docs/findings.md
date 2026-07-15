# Findings

## Filter Cheatsheet

| Filter | Format | Example values |
|--------|--------|----------------|
| `severities` | uppercase list | `["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]` |
| `statuses` | uppercase list | `["OPEN", "CONFIRMED", "FALSEPOSITIVE", "ACCEPTRISK", "MITIGATED", "SUPPRESSED", "TRIAGE", "IN_PROGRESS", "CONTROLLED"]` |
| `days_back` | integer | `14` — SDK converts to epoch-ms internally |
| `tags` | full `key:value` strings | `["superowner:user@example.com", "env:prod"]` — key-only returns 0 results |
| `extra_filters` | dict of field → list | `{"source": ["Tenable.sc"], "scanType": ["SAST"]}` |

> **Tags:** always pass the full `key:value` string. Passing just a key (e.g. `"superowner"`) silently returns 0 results — this is an API behaviour, not an SDK bug.

> **Filter key gotchas:** the ArmorCode API uses plural forms (`severities`, `statuses`) when combined with other filters. Singular forms (`severity`, `status`) silently return 0 results. The SDK always sends the correct plural keys internally.

## Basic Usage

```python
findings = ac.get_findings(
    severities=["Critical", "High"],
    statuses=["OPEN", "CONFIRMED"],
    days_back=14,
)

for repo, count in ac.list_repos():
    print(f"{repo}: {count}")
```

## Extra Filters

Pass any additional ArmorCode filter field via `extra_filters`:

```python
findings = ac.get_findings(
    severities=["Critical"],
    days_back=30,
    extra_filters={
        "source": ["Tenable.sc"],
        "tags": ["superowner:owner@example.com"],
    },
)
```

## 10K Finding Limit & Auto-Chunking

The ArmorCode API enforces a **10,000 record hard limit** per query. The SDK handles this automatically:

1. **Probe** — a `size=1` request checks the total count before fetching
2. **Under 10K** — normal paginated fetch
3. **Over 10K** — the date range is split into time slices, each fetched separately
4. **Recursive** — any slice still over 10K is split again
5. **Dedup** — results merged with duplicate finding IDs removed

This is transparent to the caller:

```python
# Works fine even if results exceed 10K
findings = ac.get_findings(
    severities=["Critical", "High", "Medium", "Low", "Info"],
    days_back=90,
)
```

> **Note:** ArmorCode's `totalElements` can be higher than records actually returned — this is an API-side discrepancy, not data loss.

## Two Findings Endpoints — `/user/findings/` vs `/api/findings`

There are **two** findings endpoints with different pagination models and different filter conventions. `get_findings()` uses `/user/findings/`. For bulk export past 10K, `/api/findings` (cursor) is the better path.

| Approach | Result |
|----------|--------|
| `/user/findings/` + `page`/`size` | ❌ **Broken for bulk** — `page` and `size` params are ignored; every page returns the same first ~10 rows. This is where a "10K limit" *would* bite, but you can't even walk that deep. Fine for reading `totalElements` (a count) only. |
| `/api/findings` + `?afterKey=` cursor | ✅ **Correct bulk-export path.** Verified live crossing 12,000 records on a large tenant: 0 dups, 0 errors. Keyset cursor has **no 10K offset limit** — offset-based limits don't apply. |
| CVE filter key | ✅ `cve` (list). ❌ `cveId` is **silently ignored** and returns the entire unfiltered tenant (matched 8.67M records on a large tenant). Use `cve` on both endpoints. |

> **Correction to older notes:** the CVE key is **not** tenant-dependent (`cveId` vs `cve` by tenant was wrong — all tenants share `app.armorcode.com`). Use `cve` everywhere. `cveId` is a silent no-op.

### `/api/findings` request/response shape

- **Pagination:** cursor via the **query param** `?afterKey=<value>`. Read `data.afterKey` from each response and pass it back on the next call. Body fields `afterKey`/`after`/`searchAfter` are **silently ignored** — it must be the query param.
- **Response:** `data.findings` (list) + `data.afterKey` (cursor). Loop until `findings` is empty or `afterKey` stops advancing.
- **Page size is fixed at 10** regardless of `maxSize`/`size`. A large pull = many round-trips (12K ≈ 1,200 requests). Parallelise by chunking on `severity`/date for **throughput**, not to dodge a limit.
- **All filter values must be JSON arrays.** A scalar (bare string/int) returns `HTTP 400: Cannot deserialize value of type ArrayList<Object> from String/Integer`.

### `/api/findings` filters (verified live)

Filters go under `filters`, **singular** keys, values as arrays:

| Filter | Format | Verified |
|--------|--------|----------|
| `severity` | title-case list | ✅ `["Critical","High"]` — bad value → 0 |
| `status` | uppercase list | ✅ `["OPEN","CONFIRMED","TRIAGE","IN_PROGRESS"]` |
| `cve` | list | ✅ `["CVE-2026-53492"]` — narrowed 8.67M → 4,016 |
| **date range** | `[startMs, endMs]` list | ✅ honored on `createdAt`, `lastUpdated`, `publishedDate`, `lastSeenDate`, `lastModifiedDate`. Wide window = full set; future/past window = 0. **No `filterOperations` object** — that 400s here (unlike `/user/findings/`); the two-element array *is* the range. |

```python
# /api/findings cursor walk — bulk export past 10K, no chunking needed
def iter_api_findings(ac, filters, page_hint=100):
    after = None
    while True:
        params = f"?afterKey={after}" if after is not None else ""
        resp = ac._post(f"/api/findings{params}", {"filters": filters, "maxSize": page_hint})
        data = resp.get("data", {})
        rows = data.get("findings", [])
        if not rows:
            return
        yield from rows
        nxt = data.get("afterKey")
        if nxt is None or nxt == after:
            return
        after = nxt

# CVE + severity + a 2024 date window (epoch ms arrays)
for f in iter_api_findings(ac, {
    "cve": ["CVE-2026-53492"],
    "severity": ["Critical", "High"],
    "createdAt": [1704067200000, 1735689599000],
}):
    ...
```

## Page Size

The `size` param controls results per API page (default: 2000, max: 10000). Larger pages reduce API calls but increase per-request latency. 2000–3000 is the practical sweet spot.

## Hierarchy Filter

`get_findings_by_hierarchy()` lets you scope a findings query to any combination of product (group), sub-product, and team — using **names**, not IDs. The SDK resolves each name to its numeric ID in a pre-step before querying.

```python
# Any combination of the three hierarchy levels is valid
findings = ac.get_findings_by_hierarchy(
    product="Risk Platform",
    sub_product="airml-dx-suggestions-service",
    team="team-Risk Platform",
    severities=["CRITICAL", "HIGH"],
    statuses=["OPEN"],
    sources=["Semgrep"],
)

# Product only
findings = ac.get_findings_by_hierarchy(
    product="Foundations",
    statuses=["OPEN"],
)

# Sub-product only
findings = ac.get_findings_by_hierarchy(
    sub_product="airml-dx-suggestions-service",
)
```

All three hierarchy filters are ANDed together with any `severities`, `statuses`, and `sources` you supply. Additional filters can be passed via `extra_filters`.

A `ValueError` is raised if any name can't be resolved to a unique ID:

```python
# Raises: ValueError: No product found with name 'DoesNotExist'
ac.get_findings_by_hierarchy(product="DoesNotExist")

# Raises: ValueError: Multiple sub-products named 'shared-lib' found: [123, 456].
# Pass sub_product_id via extra_filters to disambiguate.
ac.get_findings_by_hierarchy(sub_product="shared-lib")
```

To bypass name resolution and pass IDs directly, use `extra_filters`:

```python
findings = ac.get_findings_by_hierarchy(
    extra_filters={"product": [416643], "subProduct": [530718]},
    statuses=["OPEN"],
)
```

> **Note:** `product` and `subProduct` filters require numeric IDs as arrays. `productId` / `subProductId` are silently ignored by the API.

## Engagement Filter

`get_findings_by_engagement()` pulls all findings tied to an **engagement** (the API's internal name is "project"). Pass the engagement name (resolved to its id automatically) or an integer id.

```python
# By name
findings = ac.get_findings_by_engagement("engage1", statuses=["OPEN"])

# By id (skips the name lookup)
findings = ac.get_findings_by_engagement(34464)

# Stack severity / source filters
findings = ac.get_findings_by_engagement(
    "engage1",
    severities=["CRITICAL", "HIGH"],
    sources=["Trivy", "Dependabot"],
)

# List engagements first
for e in ac.get_engagements():
    print(e["id"], e["name"])
```

A `ValueError` is raised if a name can't be resolved to a unique engagement.

> **Engagement vs assessment:** these are two **independent** finding associations, not a parent/child hierarchy. Engagements filter on `armorcodeProjects`; pentests/assessments filter on `assessments`. A finding can carry one, both, or neither. There is no engagement→assessment foreign key in the API — the assessment's `scope` (product/sub-product) is what ties it to assets.

> **Note:** the filter key is `armorcodeProjects` (plural). `armorcodeProject`, `engagement`, and `project` are silently ignored by the API.

> **Status/severity key quirk:** alongside `armorcodeProjects` the API honours the **singular** `status` / `severity` keys — the plural `statuses` / `severities` (used with the hierarchy filters) are silently ignored here. Status values must be UPPERCASE, severity values Title-case. The SDK sends the singular keys and normalises casing, so `statuses=["open"]` and `severities=["MEDIUM"]` both work. Findings with a resolved status (e.g. `FALSEPOSITIVE`) stay tagged to the engagement, so an unfiltered call returns them — pass `statuses` to match the UI's active-only view.

## Bulk Tagging Findings (write)

`PUT /user/findings/findingTags`. SDK method exists — `update_finding_tags(finding_ids, tags, update_type)` — **but its docstring is wrong, see below.**

```python
resp = ac.update_finding_tags(
    finding_ids=["15128178363", "15128178362"],
    tags=["mykey:myvalue"],  # key:value format
)
```

> ⚠️ **SDK docstring is stale/incorrect.** `update_finding_tags()` claims `update_type` accepts `"ADD"` (default) / `"REMOVE"` / `"REPLACE"`. Live-tested against `app.armorcode.com`: **`"ADD"` returns `400 Bad Request: "Invalid value 'ADD' in the request"`.** The API's actual (OpenAPI-declared) enum for this field is `RULE_BASED` / `TAG_BASED` — an unrelated axis, not an add/replace toggle. `TAG_BASED` returns `200` but does **not** append a tag to a finding's existing tag list either (tested). Omitting `updateType` entirely (as the raw endpoint call below does) is the only mode verified to actually write tags. Don't trust the docstring's semantics until someone finds the real add-without-overwrite mechanism (if one exists) — file a fix in `client.py` when found.

```python
# What's actually verified to work — no updateType field at all:
resp = ac._session.put(
    f"{ac.base_url}/user/findings/findingTags",
    json={
        "findingIds": ["15128178363", "15128178362"],  # strings, not ints
        "findingTags": ["mykey:myvalue"],                 # key:value format
        "scope": "FINDING",
    },
    timeout=ac._timeout,
)
```

| Aspect | Verified behavior |
|--------|--------------------|
| Batch size | ✅ **15,000 finding IDs in one call** succeeded (`200 OK`, no rate-limit, no truncation) against a live 50,031-finding set (Julian Sandbox). No `maxItems` declared in the OpenAPI schema for this endpoint (contrast with `POST /api/v2/findings/tags/bulk`'s `HeterogeneousBulkTagUpdateRequest`, capped at `maxItems: 10000`). Untested above 15,000 — real ceiling unknown. |
| Semantics | ⚠️ **Overwrites, not appends — confirmed, and no working add-only mode found yet** (see docstring warning above). Tagging the same 50,031 findings with `messi:wins`, then `test:5000`, then `test:15000` (each a separate full-coverage call, no `updateType` sent) left **only** `test:15000` present afterward on every finding — the two earlier custom tags were gone. Tool-native tags (`snyk`, `superowner:...`) were untouched throughout, so it's specifically the custom-tag layer managed via this endpoint that gets replaced per call, not a wholesale wipe. **Workaround:** fetch each finding's current `tags` first and include them alongside the new tag in `findingTags` so the "overwrite" preserves what you want kept. |
| Verifying a bulk write | ❌ Don't trust `totalElements` from a `POST /user/findings/` call filtered on `filters.tags` — it undercounted by 3–6% in testing even though every finding actually had the tag. ✅ Fetch the findings themselves (`get_findings()` / cursor walk) and check each one's `tags` array directly. |

## Example — Vulnerabilities by Repo

See `examples/vuln_by_repo.py` for a complete workflow: pull findings → list repos → export to Excel.

```bash
python examples/vuln_by_repo.py           # top 3 repos
python examples/vuln_by_repo.py repo_a repo_b  # specific repos
```
