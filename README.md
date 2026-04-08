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

| Method | Description |
|--------|-------------|
| `get_findings(severities, statuses, days_back, extra_filters, dump_path)` | Bulk pull findings with filters; caches results locally |
| `list_repos(findings)` | Repo names + finding counts from cached data |
| `get_findings_by_repo(repo_name, findings)` | Filter cached findings to one repo |
| `dump_json(path)` | Write cached findings to JSON |
| `get_finding_stats(filters)` | Severity-by-status summary stats |
| `get_repos(states, page, size)` | List SCM repositories |
| `get_teams()` | List all teams |
| `get_products(page, size)` | List products/applications |
| `get_tools()` | List configured security tools |
| `get_runbooks()` | List runbook automations |

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
