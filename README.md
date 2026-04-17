# ArmorCode SDK (ac-sdk-v2)

Lightweight Python SDK for the ArmorCode REST API.

## Quick Start

```python
from armorcode import ArmorCodeClient

ac = ArmorCodeClient.from_env("env")

# Pull Critical + High findings from the last 14 days
findings = ac.get_findings(severities=["Critical", "High"], days_back=14)

for repo, count in ac.list_repos():
    print(f"{repo}: {count}")
```

Runnable demo: `python examples/demo.py`

## Installation

```bash
pip install requests            # core
pip install PyYAML              # for AIEM triage
pip install anthropic           # optional: AIEM ai-review --mode api
pip install openpyxl            # optional: Excel export example
```

## Env File Format

```
TENANT_URL=<https://my-tenant-url>
API_TOKEN=<api-token>
```

## Documentation

- **[docs/methods.md](docs/methods.md)** — every SDK method, grouped by resource (findings, repos, teams, products, SLA, …)
- **[docs/aiem.md](docs/aiem.md)** — AI Exposure Management: SDK calls, rule-based + AI triage, CLI reference
- **[docs/findings.md](docs/findings.md)** — finding filters, the 10K limit + auto-chunking, date handling
- **[examples/](examples/)** — runnable scripts (`demo.py`, `vuln_by_repo.py`, `aiem_triage_demo.py`)

## Filter Cheatsheet

- **Severity** — title-case in filters: `Critical`, `High`, `Medium`, `Low`, `Info`
- **Status** — uppercase: `OPEN`, `CONFIRMED`, `FALSEPOSITIVE`, `ACCEPTRISK`, `MITIGATED`, `SUPPRESSED`, `TRIAGE`, `IN_PROGRESS`, `CONTROLLED`
- Date filters — pass `days_back` as an integer; SDK handles epoch-ms conversion.
