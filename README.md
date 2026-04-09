# ArmorCode SDK (ac-sdk-v2)

Lightweight Python SDK for the ArmorCode REST API.

## Quick Start

```python
from armorcode import ArmorCodeClient

# Connect from env file (reads TENANT_URL + *_TOKEN)
ac = ArmorCodeClient.from_env("env")

# Pull Critical + High findings from the last 14 days
findings = ac.get_findings(severities=["Critical", "High"], days_back=14)

# List repos with finding counts
for repo, count in ac.list_repos():
    print(f"{repo}: {count}")

# Drill into a specific repo
for f in ac.get_findings_by_repo("my-repo"):
    print(f"{f['severity']} - {f['title']}")

# List teams, products, runbooks
teams = ac.get_teams()
products = ac.get_products()
runbooks = ac.get_runbooks()
```

For a runnable end-to-end example: `python examples/demo.py`

## Installation

```bash
pip install requests
```

For the Excel export example:
```bash
pip install openpyxl
```

## Env File Format

```
TENANT_URL=app.armorcode.com
MYCOMPANY_TOKEN=<bearer-token>
```

## API Methods

### Findings

| Method | Description |
|--------|-------------|
| `get_findings(severities, statuses, days_back, extra_filters, dump_path)` | Bulk pull findings with filters; caches results locally |
| `list_repos(findings)` | Repo names + finding counts from cached data |
| `get_findings_by_repo(repo_name, findings)` | Filter cached findings to one repo |
| `dump_json(path)` | Write cached findings to JSON |
| `export_findings_csv(output_path, filters, filter_operations)` | Export findings as CSV file |

### Finding Statistics

| Method | Description |
|--------|-------------|
| `get_finding_stats(filters)` | Severity-by-status summary |
| `get_finding_stats_by_team(filters)` | Stats broken down by team |
| `get_finding_stats_by_product(filters)` | Stats broken down by product |

### Repositories (SCM)

| Method | Description |
|--------|-------------|
| `get_repos(states, sources, page, size)` | List repos by state/source |
| `get_repo_filters()` | Available filter options for repo discovery |
| `get_repo_details(status_type, include_ignored)` | Detailed repo info |
| `get_repo_contributors(repo_id)` | Contributors for a repo |

### Teams

| Method | Description |
|--------|-------------|
| `get_teams()` | List all teams (id + name) |
| `get_team(team_id)` | Full team detail (members, owners, lead) |
| `get_team_stats()` | Statistics for all teams |
| `get_team_leads()` | Users eligible as team leads |

### Products & Sub-Products

| Method | Description |
|--------|-------------|
| `get_products(page, size)` | Paginated product/application listing |
| `get_sub_products()` | All sub-products (repos/components) — lightweight id + name |
| `get_sub_product(sub_product_id)` | Full detail for a sub-product (parent product, owners, env) |

### Users

| Method | Description |
|--------|-------------|
| `get_users()` | List all tenant users with roles and activity |

### Security Tools

| Method | Description |
|--------|-------------|
| `get_tools()` | Configured scanners (SAST, DAST, SCA, etc.) |
| `get_integration_tools()` | Integrations (Jira, GitHub, ServiceNow, etc.) |

### Runbooks

| Method | Description |
|--------|-------------|
| `get_runbooks()` | List all automation runbooks |

### SLA

| Method | Description |
|--------|-------------|
| `get_sla_tiers()` | SLA tier definitions and policies |
| `get_sla_stats()` | Overall SLA compliance stats |
| `get_team_sla_stats(filters)` | Per-team SLA stats |
| `get_mttr_stats(filters)` | Mean-time-to-remediate stats |

### Tenant Configuration

| Method | Description |
|--------|-------------|
| `get_tenant_config(config_type)` | Read a tenant feature flag or config value |

### API Discovery

| Method | Description |
|--------|-------------|
| `get_api_docs()` | Fetch the full OpenAPI spec |

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

## Filter Notes

- **Severity** values are title-case: `Critical`, `High`, `Medium`, `Low`, `Info`
- **Status** values are uppercase: `OPEN`, `CONFIRMED`, `FALSEPOSITIVE`, `ACCEPTRISK`, `MITIGATED`, `SUPPRESSED`, `TRIAGE`, `IN_PROGRESS`, `CONTROLLED`
- Date filters use epoch milliseconds internally — just pass `days_back` as an integer

## Examples

See `examples/vuln_by_repo.py` for a complete workflow that pulls findings, lists repos, and exports to Excel.

```bash
# Use default top 3 repos
python examples/vuln_by_repo.py

# Specify repos
python examples/vuln_by_repo.py repo_a repo_b 
```
