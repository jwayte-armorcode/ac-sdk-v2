# ArmorCode SDK (ac-sdk-v2)

Lightweight Python SDK for the ArmorCode REST API.

## Quick Start

```python
from armorcode import ArmorCodeClient

# Connect with explicit credentials
ac = ArmorCodeClient("app.armorcode.com", token="your-bearer-token")

# Or load from an env file (reads TENANT_URL and *_TOKEN)
ac = ArmorCodeClient.from_env("env")

# Pull all Critical + High findings from the last 14 days
findings = ac.get_findings(
    severities=["Critical", "High"],
    days_back=14,
    dump_path="findings.json",   # optional: save raw JSON locally
)

# List repos with finding counts
for repo, count in ac.list_repos():
    print(f"{repo}: {count}")

# Get findings for a specific repo
for f in ac.get_findings_by_repo("my-repo"):
    print(f"{f['severity']} - {f['title']}")
```

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

### Products

| Method | Description |
|--------|-------------|
| `get_products(page, size)` | Paginated product/application listing |

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
