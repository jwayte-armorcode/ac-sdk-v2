# ArmorCode SDK (ac-sdk-v2)

Lightweight Python SDK for the ArmorCode REST API.

## Quick Start

1. Create an `env` file in the repo root (see [Env File Format](#env-file-format) below).
2. Install the core dependency: `pip install requests`.
3. Run the demo to verify connectivity:

   ```bash
   python examples/demo.py
   ```

   Prints findings counts, repos, teams, products, and runbooks for the configured tenant.

4. Or use the SDK directly:

   ```python
   from armorcode import ArmorCodeClient

   ac = ArmorCodeClient.from_env("env")

   # Pull Critical + High findings from the last 14 days
   findings = ac.get_findings(severities=["Critical", "High"], days_back=14)

   for repo, count in ac.list_repos():
       print(f"{repo}: {count}")
   ```

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
- **Tags** — always use full `key:value` strings (e.g. `"superowner:user@example.com"`); key-only filters return 0 results
- Date filters — pass `days_back` as an integer; SDK handles epoch-ms conversion.

## Tickets

Query tickets by product, sub-product, and/or assignee — all filters are optional and combinable:

```python
ac.get_tickets(product="my-app")
ac.get_tickets(product="my-app", assignee="Julian Wayte")
ac.get_tickets(sub_product="my-api")
ac.get_tickets(sub_product="my-api", assignee="Julian Wayte")
ac.get_tickets(assignee="Julian Wayte")
ac.get_tickets()  # all tickets
```

Product and sub-product accept names (resolved to IDs internally) or integer IDs. Assignee is the display name from the ticketing system.

## Products & Sub-Products

Create and update products/sub-products with tags in a single call:

```python
# Create with tags
p = ac.create_product(
    name="my-app",
    description="My application",
    tags=["env:production", "superowner:owner@example.com"],
)

sub = ac.create_sub_product(
    name="my-api",
    product_name="my-app",
    tags=["env:production", "team:security"],
)

# Update tags (full replacement — include all tags you want to keep)
ac.update_product(product_name="my-app", tags=["env:production", "superowner:newowner@example.com"])
ac.update_sub_product(sub["id"], tags=["env:production", "team:appsec"])
```
