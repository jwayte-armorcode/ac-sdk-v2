# Findings

## Filter Cheatsheet

| Filter | Format | Example values |
|--------|--------|----------------|
| `severities` | title-case list | `["Critical", "High", "Medium", "Low", "Info"]` |
| `statuses` | uppercase list | `["OPEN", "CONFIRMED", "FALSEPOSITIVE", "ACCEPTRISK", "MITIGATED", "SUPPRESSED", "TRIAGE", "IN_PROGRESS", "CONTROLLED"]` |
| `days_back` | integer | `14` — SDK converts to epoch-ms internally |
| `tags` | full `key:value` strings | `["superowner:user@example.com", "env:prod"]` — key-only returns 0 results |
| `extra_filters` | dict of field → list | `{"source": ["Tenable.sc"], "scanType": ["SAST"]}` |

> **Tags:** always pass the full `key:value` string. Passing just a key (e.g. `"superowner"`) silently returns 0 results — this is an API behaviour, not an SDK bug.

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

## Example — Vulnerabilities by Repo

See `examples/vuln_by_repo.py` for a complete workflow: pull findings → list repos → export to Excel.

```bash
python examples/vuln_by_repo.py           # top 3 repos
python examples/vuln_by_repo.py repo_a repo_b  # specific repos
```
