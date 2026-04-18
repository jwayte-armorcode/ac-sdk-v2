---
name: ac_sdk
description: >
  Expert knowledge of the ac-sdk-v2 Python SDK for ArmorCode. Covers all SDK methods
  (findings, repos, teams, products, SLA, AIEM), the deterministic + AI triage workflow
  for AIEM inventory, the CLI (cli/aiem.py), YAML rule files, filter conventions,
  auto-chunking for 10K+ results, and env file format.
  Triggers: "ac-sdk", "ac sdk", "sdk", "aiem triage", "aiem cli", "triage rules",
  "aiem inventory", "aiem scan", "aiem plan", "aiem apply", "aiem review", "aiem ai-review",
  "apply-ai", "aiem_triage", "load_rules", "plan_triage", "TriageAction"
user_invocable: true
---

# ac-sdk-v2 SDK Expert

Comprehensive knowledge of the ArmorCode Python SDK (ac-sdk-v2).

GitHub: `https://github.com/jwayte-armorcode/ac-sdk-v2`

---

## Setup

### Env file format

```
TENANT_URL=https://my-tenant.armorcode.com
API_TOKEN=<bearer-token>
```

Place as `env` in the SDK root (or pass the path to `from_env()`).

### Installation

```bash
pip install requests            # core — always required
pip install PyYAML              # AIEM triage engine
pip install anthropic           # AIEM ai-review --mode api (optional)
pip install openpyxl            # Excel export example (optional)
```

### Connect

```python
from armorcode import ArmorCodeClient

ac = ArmorCodeClient.from_env("env")
# or explicit:
ac = ArmorCodeClient("https://app.armorcode.com", token="<bearer-token>")
```

---

## Findings Methods

| Method | Description |
|--------|-------------|
| `get_findings(severities, statuses, days_back, extra_filters, dump_path, size)` | Bulk pull with filters; auto-chunks if >10K; caches locally |
| `list_repos(findings)` | Repo names + finding counts from cached data |
| `get_findings_by_repo(repo_name, findings)` | Filter cached findings to one repo |
| `dump_json(path)` | Write cached findings to JSON |
| `export_findings_csv(output_path, filters, filter_operations)` | Bulk export to CSV |
| `get_finding_stats(filters)` | Severity-by-status summary |
| `get_finding_stats_by_team(team_name, environments)` | Stats for a specific team |
| `get_finding_stats_by_product(product_name, environments)` | Stats for a specific product |

**Filter casing rules (CRITICAL):**
- Severity in filters: title-case — `Critical`, `High`, `Medium`, `Low`, `Info`
- Status in filters: uppercase — `OPEN`, `CONFIRMED`, `FALSEPOSITIVE`, `ACCEPTRISK`, `MITIGATED`, `SUPPRESSED`, `TRIAGE`, `IN_PROGRESS`, `CONTROLLED`
- Wrong casing returns 0 results with no error.
- Date filters: pass `days_back` as int — SDK converts to epoch-ms internally.

**10K auto-chunking:** If a query would return >10K results the SDK probes total count first, then splits the date range into chunks that each stay under the limit. Transparent to the caller.

```python
findings = ac.get_findings(
    severities=["Critical", "High"],
    statuses=["OPEN", "CONFIRMED"],
    days_back=14,
)
for repo, count in ac.list_repos():
    print(f"{repo}: {count}")
```

---

## Other SDK Methods

### Repositories
| Method | Description |
|--------|-------------|
| `get_repos(states, sources, page, size)` | List repos by state/source |
| `get_repo_filters()` | Available filter options |
| `get_repo_details(status_type, include_ignored)` | Detailed repo info |
| `get_repo_contributors(repo_id)` | Contributors for a repo |

### Teams
| Method | Description |
|--------|-------------|
| `get_teams()` | All teams (id + name) |
| `get_team(team_id)` | Full detail |
| `get_team_stats(environment)` | All teams with risk scores; `environment` required (default: `"Production"`) |
| `get_team_leads()` | Users eligible as team leads |

### Products & Sub-Products
| Method | Description |
|--------|-------------|
| `get_products(page, size, search)` | Paginated product listing |
| `create_product(name, description, type_id, extra)` | Create a new product |
| `get_sub_products()` | All sub-products — lightweight id + name |
| `get_sub_product(sub_product_id)` | Full detail |
| `create_sub_product(name, product_name, product_id, description, environment_id, tier, extra)` | Create sub-product under parent |

### SLA
| Method | Description |
|--------|-------------|
| `get_sla_tiers()` | SLA tier definitions |
| `get_sla_stats(filters)` | Overall SLA stats |
| `get_team_sla_stats(filters, agg_fields)` | Per-team SLA stats; `agg_fields` defaults to `["teamId"]` |
| `get_mttr_stats(filters)` | Mean-time-to-remediate |

### Other
| Method | Description |
|--------|-------------|
| `get_users()` | All tenant users |
| `get_tools()` | Configured security scanners |
| `get_integration_tools()` | Integrations (Jira, GitHub, etc.) |
| `get_runbooks()` | All automation runbooks |
| `get_tenant_config(config_type)` | Feature flags / config values |
| `get_api_docs()` | Full OpenAPI spec |

---

## AIEM — AI Exposure Management

AIEM wraps `/api/v1/aiem/*` endpoints. Two surfaces:
- **Inventory** — tenant-specific, mutable; the triage target.
- **Catalog** — shared AI-app reference database (4000+ apps).

### AIEM SDK Methods

| Method | Description |
|--------|-------------|
| `aiem_list_inventory(status, risk_level, type_, detection_source, department, search, sort_by, sort_dir, page, page_size)` | One page of inventory |
| `aiem_get_all_inventory(**filters)` | Auto-paginate all matching inventory items |
| `aiem_get_inventory_item(item_id)` | Full detail for one item |
| `aiem_update_inventory_item(item_id, status, risk_level, notes, approval, compliance_tags, risk_sort_rank)` | **Write** — update status/approval/risk |
| `aiem_create_inventory_item(app_name, type_, catalog_domain, custom_app, status, risk_level, …)` | Add a new inventory item |
| `aiem_inventory_filters(**scope)` | Faceted filter options |
| `aiem_inventory_stats(agg_field, metric, …)` | Aggregation stats |
| `aiem_inventory_timeline(metric, aggregate_by, …)` | Timeline trend data |
| `aiem_list_catalog(search, sort_by, sort_dir, page, page_size, **extra_filters)` | Query shared catalog |
| `aiem_catalog_filters(**scope)` | Catalog facets |
| `aiem_catalog_approval_candidates(**filters)` | Catalog entries not yet in tenant inventory |

**Enum constants on `ArmorCodeClient`:**
- `AIEM_STATUSES` — `pending`, `approved`, `conditional`, `rejected`, `reassessment`
- `AIEM_RISK_LEVELS` — `critical`, `high`, `moderate`, `low`
- `AIEM_APPROVAL_SCOPES` — `organization`, `department`, `individual`

**Filter format:** flat camelCase query params, single value per filter (e.g. `status=pending`, `riskLevel=moderate`). Multi-value arrays are not supported by the API.

### AIEM Triage Workflow

Two-stage pipeline:
1. **Deterministic rules** (YAML) — first matching rule wins; fast, auditable.
2. **AI review** — items no rule matched go to an LLM for a recommendation; human approves before any write.

**Key files:**
- `armorcode/aiem_triage.py` — pure rule engine (no HTTP)
- `rules/aiem_default.yaml` — 7 starter rules
- `cli/aiem.py` — CLI for all stages

### CLI Commands

```bash
# Run from the SDK repo root with an env file path

# 1. Summarize current inventory (read-only)
python -m cli.aiem --env env scan

# 2. Dry-run rules — overall counts (read-only)
python -m cli.aiem --env env plan

# 3. Dry-run rules — per-item detail (read-only)
python -m cli.aiem --env env plan -v

# 4. Apply rule-based decisions (writes; prompts per item)
python -m cli.aiem --env env apply
python -m cli.aiem --env env apply --yes   # skip prompts

# 5. Queue rule-unmatched items for AI review (read-only; writes local file)
python -m cli.aiem --env env review --out queue.json

# 6a. AI review — hand off to Claude Code / any LLM (read-only)
python -m cli.aiem --env env ai-review --mode file --queue queue.json

# 6b. AI review — call Anthropic API directly (needs ANTHROPIC_API_KEY)
python -m cli.aiem --env env ai-review --mode api --queue queue.json --out proposals.json

# 7. Apply AI proposals (writes; prompts per item)
python -m cli.aiem --env env apply-ai proposals.json
python -m cli.aiem --env env apply-ai proposals.json --yes
```

Commands 1–3 and 5–6 are **read-only** against the tenant. Only `apply` and `apply-ai` write.

### YAML Rule Format

```yaml
meta:
  name: my-rules
  version: 1

rules:
  - id: R1_trusted_vendor
    description: Auto-approve trusted vendors with SOC 2 Type II
    match:
      vendor_in: [Adobe Inc., Microsoft, Google LLC, Anthropic, OpenAI]
      has_compliance_cert: SOC 2 Type II
      eu_ai_act_tier_in: [Minimal Risk, Limited Risk]
    action:
      status: approved
      approval:
        scope: organization
      notes: "Auto-approved: trusted vendor with SOC 2 Type II"

  - id: R4_elevated_risk
    match:
      risk_level_in: [high, critical]
    action:
      status: reassessment
      notes: "Elevated risk — security review required"
```

Rules evaluate top-to-bottom; first match wins. Items matching no rule → AI review.

**Supported match conditions:**

| Condition | What it checks |
|-----------|---------------|
| `status_in`, `risk_level_in` | Item's own fields |
| `vendor_in`, `vendor_not_in` | Exact vendor match |
| `type_in` | Any of item's `type[]` values |
| `detection_source_in` | Scanner that detected the app |
| `name_contains_any` | Substring match on item name |
| `eu_ai_act_tier_in` | From `catalog.tags.risk_tier` |
| `deployment_model_in` | From catalog tags |
| `data_handling_has`, `data_handling_any` | From catalog tags |
| `security_feature_has`, `security_features_all` | Catalog security tags |
| `has_compliance_cert`, `has_any_compliance_cert` | Catalog compliance certs |
| `user_count_gte`, `user_count_lt` | From `usage.user_count` |

**Action fields** map 1:1 to `aiem_update_inventory_item`:
`status`, `risk_level`, `notes`, `approval`, `compliance_tags`.

### Python Triage API

```python
from armorcode.aiem_triage import load_rules, plan_triage, summarize_plan

items = ac.aiem_get_all_inventory()
rules = load_rules("rules/aiem_default.yaml")
matched, unmatched = plan_triage(items, rules)
summary = summarize_plan(matched, unmatched)

# matched  — list of TriageAction; apply with:
for a in matched:
    if not a.is_noop(by_id[a.item_id]):
        ac.aiem_update_inventory_item(a.item_id, **a.to_update_payload())

# unmatched — list of raw inventory dicts → route to AI review
```

---

## Gotchas

- `get_repos()` response is wrapped in a `data` envelope — SDK unwraps automatically.
- `get_products()` uses `pageNumber`/`pageSize` params internally (not `page`/`size`).
- `get_team_stats()` requires `environment` param or returns 400.
- `get_team_sla_stats()` requires `aggFields` (default `["teamId"]`) or returns 400.
- AIEM filter params are camelCase single-value query params — JSON body filters are ignored by the API.
- `totalElements` from the findings API can be higher than actual returned records (API-side discrepancy).
