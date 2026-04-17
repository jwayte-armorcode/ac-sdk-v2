# Findings — Filters & Pagination

## Filter Values

- **Severity** values are title-case: `Critical`, `High`, `Medium`, `Low`, `Info`
- **Status** values are uppercase: `OPEN`, `CONFIRMED`, `FALSEPOSITIVE`, `ACCEPTRISK`, `MITIGATED`, `SUPPRESSED`, `TRIAGE`, `IN_PROGRESS`, `CONTROLLED`
- Date filters use epoch milliseconds internally — just pass `days_back` as an integer.

## 10K Finding Limit & Auto-Chunking

The ArmorCode API enforces a **10,000 record hard limit** per query. Requests that
exceed this return a `400 Bad Request` with:

> "Only 10k matching records are displayed. Please add more filters to view specific findings"

The SDK handles this automatically. When `get_findings()` detects a query would
return more than 10K results, it splits the date range into smaller chunks that
each stay under the limit:

1. **Probe** — a `size=1` request checks the total count before fetching
2. **Under 10K** — normal paginated fetch, no chunking
3. **Over 10K** — the date range is divided into even time slices, each fetched separately
4. **Recursive** — if any single chunk still exceeds 10K, it's split again
5. **Dedup** — results are merged with duplicate finding IDs removed

This is transparent to the caller — just use `get_findings()` as normal:

```python
# This would fail raw (11K+ results) but the SDK chunks it automatically
findings = ac.get_findings(
    severities=["Critical", "High", "Medium", "Low", "Info"],
    days_back=90,
)
```

> **Note:** ArmorCode's `totalElements` count can be higher than the number of
> records actually returned. This is an API-side discrepancy, not a data loss issue.

## Example — Vulnerabilities by Repo

See `examples/vuln_by_repo.py` for a complete workflow that pulls findings, lists
repos, and exports to Excel.

```bash
# Use default top 3 repos
python examples/vuln_by_repo.py

# Specify repos
python examples/vuln_by_repo.py repo_a repo_b
```
