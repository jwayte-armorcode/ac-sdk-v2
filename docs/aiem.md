# AIEM — AI Exposure Management

The SDK wraps the `/api/v1/aiem/*` endpoints for ArmorCode's AI Exposure
Management. Two concept surfaces:

- **Inventory** — tenant-specific, mutable; the triage target.
- **Catalog** — shared AI-app knowledge base (4000+ apps); reference data.

## SDK Methods

| Method | Description |
|--------|-------------|
| `aiem_list_inventory(status, risk_level, type_, detection_source, department, search, sort_by, sort_dir, page, page_size)` | One page of inventory |
| `aiem_get_all_inventory(**filters)` | Auto-paginate all matching inventory items |
| `aiem_get_inventory_item(item_id)` | Full detail for one item |
| `aiem_update_inventory_item(item_id, status, risk_level, notes, approval, compliance_tags, risk_sort_rank)` | **Triage write** — update status/approval/etc. |
| `aiem_create_inventory_item(app_name, type_, catalog_domain | custom_app, status, risk_level, …)` | Add a new inventory item |
| `aiem_inventory_filters(**scope)` | Faceted filter options, optionally scoped |
| `aiem_inventory_stats(agg_field, metric, …)` | Aggregation stats for dashboards |
| `aiem_inventory_timeline(metric, aggregate_by, …)` | Timeline data for trend charts |
| `aiem_list_catalog(search, sort_by, sort_dir, page, page_size, **extra_filters)` | Query the shared AI-app catalog |
| `aiem_catalog_filters(**scope)` | Catalog facets |
| `aiem_catalog_approval_candidates(**filters)` | Catalog entries not yet in this tenant's inventory |

### Enum constants on `ArmorCodeClient`

- `AIEM_STATUSES` — `pending`, `approved`, `conditional`, `rejected`, `reassessment`
- `AIEM_RISK_LEVELS` — `critical`, `high`, `moderate`, `low`
- `AIEM_APPROVAL_SCOPES` — `organization`, `department`, `individual`

## Quick Example

```python
from armorcode import ArmorCodeClient

ac = ArmorCodeClient.from_env("env")

# Look up an app in the shared catalog
results = ac.aiem_list_catalog(search="Claude")

# Pull full tenant inventory (auto-paginated)
items = ac.aiem_get_all_inventory()

# Approve one item
ac.aiem_update_inventory_item(
    items[0]["id"],
    status="approved",
    approval={"scope": "organization"},
    notes="Reviewed and approved by security",
)
```

## Deterministic + AI Triage

The SDK ships with a two-stage triage workflow:

1. **Deterministic rules** (YAML) evaluate each inventory item. The first matching rule wins.
2. **AI review** handles the long tail — items no rule matched go to an LLM for a recommendation, which a human then approves/rejects before anything is written back.

Components:

- **`armorcode/aiem_triage.py`** — pure rule engine (no HTTP), evaluates YAML rules against inventory items and returns a plan.
- **`rules/aiem_default.yaml`** — 7 starter rules (trusted-vendor auto-approve, SSO/MFA conditional, EU AI Act tier-based reassessment, etc.).
- **`cli/aiem.py`** — the CLI.

### CLI

```bash
# Summarize current inventory
python -m cli.aiem --env env scan

# Dry-run the default rules (no writes)
python -m cli.aiem --env env plan -v

# Apply rule-based triage (prompts per item; --yes to skip)
python -m cli.aiem --env env apply

# Queue rule-unmatched items for AI review
python -m cli.aiem --env env review --out queue.json

# Option A — call Anthropic directly (needs ANTHROPIC_API_KEY + anthropic pkg)
python -m cli.aiem ai-review --mode api --queue queue.json --out proposals.json

# Option B — hand the queue to Claude Code (or any LLM), save its JSON output
python -m cli.aiem ai-review --mode file --queue queue.json

# Apply AI proposals (same write path as 'apply')
python -m cli.aiem --env env apply-ai proposals.json
```

### Rule File Format

```yaml
meta:
  name: my-tenant-rules
  version: 1

rules:
  - id: R1_trusted_vendor
    description: Auto-approve trusted vendors with SOC 2 Type II
    match:
      vendor_in: [Adobe Inc., Microsoft, Google LLC, Anthropic]
      has_compliance_cert: SOC 2 Type II
      eu_ai_act_tier_in: [Minimal Risk, Limited Risk]
    action:
      status: approved
      approval:
        scope: organization
      notes: "Auto-approved: trusted vendor with SOC 2 Type II"
```

**Supported match conditions** (see `armorcode/aiem_triage.py` for the full list):

| Condition | Checks |
|-----------|--------|
| `status_in`, `risk_level_in` | Inventory item's own fields |
| `vendor_in`, `vendor_not_in` | Exact vendor match |
| `type_in` | Any of item's `type[]` values in the list |
| `detection_source_in` | Which scanner detected the app |
| `name_contains_any` | Substring match on item name |
| `eu_ai_act_tier_in` | From `catalog.tags.risk_tier` |
| `deployment_model_in`, `data_handling_has`, `data_handling_any` | From catalog tags |
| `security_feature_has`, `security_features_all` | Catalog security tags |
| `has_compliance_cert`, `has_any_compliance_cert` | Catalog compliance certs |
| `user_count_gte`, `user_count_lt` | From `usage.user_count` |

**Action fields** map 1-to-1 to `aiem_update_inventory_item` arguments:
`status`, `risk_level`, `notes`, `approval`, `compliance_tags`.

Items that match no rule are routed to AI review — they are not modified.

## Requirements

- `PyYAML` — always required for the triage engine
- `anthropic` — only required for `ai-review --mode api`
