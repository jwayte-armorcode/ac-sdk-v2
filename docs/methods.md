# SDK Methods

All methods are on the `ArmorCodeClient` class. See the docstrings in
`armorcode/client.py` for full parameter details.

For AIEM-specific methods, see [aiem.md](aiem.md).

## Findings

| Method | Description |
|--------|-------------|
| `get_findings(severities, statuses, days_back, extra_filters, dump_path)` | Bulk pull findings with filters; caches results locally; auto-chunks if >10K ([details](findings.md)) |
| `list_repos(findings)` | Repo names + finding counts from cached data |
| `get_findings_by_repo(repo_name, findings)` | Filter cached findings to one repo |
| `dump_json(path)` | Write cached findings to JSON |
| `export_findings_csv(output_path, filters, filter_operations)` | Export findings as CSV file |

## Finding Statistics

| Method | Description |
|--------|-------------|
| `get_finding_stats(filters)` | Severity-by-status summary |
| `get_finding_stats_by_team(team_name, environments)` | Stats for a specific team |
| `get_finding_stats_by_product(product_name, environments)` | Stats for a specific product |

## Repositories (SCM)

| Method | Description |
|--------|-------------|
| `get_repos(states, sources, page, size)` | List repos by state/source |
| `get_repo_filters()` | Available filter options for repo discovery |
| `get_repo_details(status_type, include_ignored)` | Detailed repo info |
| `get_repo_contributors(repo_id)` | Contributors for a repo |

## Teams

| Method | Description |
|--------|-------------|
| `get_teams()` | List all teams (id + name) |
| `get_team(team_id)` | Full team detail (members, owners, lead) |
| `get_team_stats(environment)` | Statistics for all teams |
| `get_team_leads()` | Users eligible as team leads |

## Products & Sub-Products

| Method | Description |
|--------|-------------|
| `get_products(page, size, search)` | Paginated product/application listing |
| `create_product(name, description, type_id, extra)` | Create a new product (returns the new id) |
| `get_sub_products()` | All sub-products (repos/components) — lightweight id + name |
| `get_sub_product(sub_product_id)` | Full detail for a sub-product (parent product, owners, env) |
| `create_sub_product(name, product_name, product_id, description, environment_id, tier, extra)` | Create a new sub-product under a parent product |

```python
# Create a product, then a sub-product under it (by name — id is looked up)
ac.create_product(name="payments-platform", description="Payments group")
sub = ac.create_sub_product(
    name="payments-api",
    product_name="payments-platform",
    description="REST API service",
    tier="Tier 1",
)
print(sub["id"])
```

## Users

| Method | Description |
|--------|-------------|
| `get_users()` | List all tenant users with roles and activity |

## Security Tools

| Method | Description |
|--------|-------------|
| `get_tools()` | Configured scanners (SAST, DAST, SCA, etc.) |
| `get_integration_tools()` | Integrations (Jira, GitHub, ServiceNow, etc.) |

## Runbooks

| Method | Description |
|--------|-------------|
| `get_runbooks()` | List all automation runbooks |

## SLA

| Method | Description |
|--------|-------------|
| `get_sla_tiers()` | SLA tier definitions and policies |
| `get_sla_stats(filters)` | Overall SLA compliance stats |
| `get_team_sla_stats(filters, agg_fields)` | Per-team SLA stats |
| `get_mttr_stats(filters)` | Mean-time-to-remediate stats |

## Tenant Configuration

| Method | Description |
|--------|-------------|
| `get_tenant_config(config_type)` | Read a tenant feature flag or config value |

## API Discovery

| Method | Description |
|--------|-------------|
| `get_api_docs()` | Fetch the full OpenAPI spec |
