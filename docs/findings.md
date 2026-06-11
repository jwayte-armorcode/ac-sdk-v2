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

## Example — Vulnerabilities by Repo

See `examples/vuln_by_repo.py` for a complete workflow: pull findings → list repos → export to Excel.

```bash
python examples/vuln_by_repo.py           # top 3 repos
python examples/vuln_by_repo.py repo_a repo_b  # specific repos
```
