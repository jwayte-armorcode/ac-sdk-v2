---
name: ac_sdk
description: >
  Expert knowledge of the ac-sdk-v2 Python SDK for ArmorCode. Covers all SDK methods
  (findings, repos, teams, products, SLA), filter conventions,
  auto-chunking for 10K+ results, and env file format.
  Triggers: "ac-sdk", "ac sdk", "sdk"
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
| `analyze_risk_scoring_tags(finding_age, severities, statuses=None, findings=None)` | For each tag in the tenant's `ASSET_SCORE` config, count matching findings in the age window. Returns rows of `{tag_key, tag_value, weight, count}` plus a final `(none — finding had no scoring tag)` summary row |
| `upload_findings(findings, product, sub_product, environment)` | **Write** — insert custom findings via `POST /api/findings/upload` (Generic JSON). Returns `{scanId}` |

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

### Inserting findings (`upload_findings`)

`POST /api/findings/upload` accepts a JSON **array** of findings in ArmorCode's
Generic JSON format. `product`, `sub_product`, and `environment` are query params;
names are resolved to ids automatically.

```python
ac.upload_findings(
    {
        "Title": "Hardcoded secret in config",
        "Severity": "High",          # Critical / High / Medium / Low / Info
        "Description": "...",
        "ToolFindingId": "my-unique-id-001",   # dedup key
        "Category": "SECURITY",
        "FindingUrl": "https://example.com/finding/001",
    },
    product="my-product",
    sub_product="my-subproduct",
    environment="Production",
)
# -> {"scanId": 137746107}   # ingest is async; the scanId confirms acceptance
```

Ruby: `ac.upload_findings(finding, product: "my-product", sub_product: "my-subproduct", environment: "Production")`.

**The sub-product must belong to the product** — otherwise the API returns
`500 "No such product/sub-product/environment found"`. The returned `scanId`
means the upload was accepted; findings surface asynchronously via the scan
pipeline, so they may not appear in `get_findings()` immediately.

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
| `create_product(...)` / `update_product(...)` | Create / update a product (tags, description) |
| `get_sub_products()` | All sub-products — lightweight id + name |
| `get_sub_product(sub_product_id)` | Full detail |
| `create_sub_product(name, product_name, product_id, description, environment_id, tier, extra)` | Create sub-product under parent |
| `update_sub_product(...)`, `update_*_add_tags(...)`, `update_*_set_tag(...)` | Update sub-product / add or set `key:value` tags on products & sub-products |

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
| `get_assets(source, limit, filters)` | Paginated asset listing |
| `get_tickets(product, sub_product, assignee, page, size)` | Tickets (names resolved to ids) |
| `get_tools()` | Configured security scanners |
| `get_integration_tools()` | Integrations (Jira, GitHub, etc.) |
| `get_feature_flags()` | Tenant feature flags |
| `get_runbooks()` / `get_runbook(id)` / `export_runbooks(name, output_dir)` | Automation runbooks (list / detail / export to JSON) |
| `get_tenant_config(config_type)` | Config values (e.g. `ASSET_SCORE`) |
| `get_api_docs()` | Full OpenAPI spec |

---

## Gotchas

- `get_repos()` response is wrapped in a `data` envelope — SDK unwraps automatically.
- `get_products()` uses `pageNumber`/`pageSize` params internally (not `page`/`size`).
- `get_team_stats()` requires `environment` param or returns 400.
- `get_team_sla_stats()` requires `aggFields` (default `["teamId"]`) or returns 400.
- `totalElements` from the findings API can be higher than actual returned records (API-side discrepancy).
