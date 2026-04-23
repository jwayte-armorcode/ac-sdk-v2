# ArmorCode SDK (ac-sdk-v2)

Lightweight Python SDK for the ArmorCode REST API.

## Quick Start

1. Create an `env` file in the repo root (see [Env File Format](#env-file-format) below).
2. Install the core dependency: `pip install requests`.
3. Run the demo to verify connectivity:

   ```bash
   python examples/demo.py
   ```

4. Or use the SDK directly:

   ```python
   from armorcode import ArmorCodeClient

   ac = ArmorCodeClient.from_env("env")

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
TENANT_URL=https://my-tenant-url
API_TOKEN=<api-token>
```

## Documentation

- **[docs/methods.md](docs/methods.md)** — complete method reference, grouped by resource
- **[docs/findings.md](docs/findings.md)** — finding filters, filter cheatsheet, 10K limit & auto-chunking
- **[docs/aiem.md](docs/aiem.md)** — AI Exposure Management: SDK calls, rule-based + AI triage, CLI reference
- **[examples/](examples/)** — runnable scripts (`demo.py`, `vuln_by_repo.py`, `aiem_triage_demo.py`)
