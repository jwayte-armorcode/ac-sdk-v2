# SDK Methods

All methods are on the `ArmorCodeClient` class. For filter values and finding-specific behaviour see [findings.md](findings.md). For AIEM methods see [aiem.md](aiem.md).

## Findings

| Method | Description |
|--------|-------------|
| `get_findings(severities, statuses, days_back, extra_filters, dump_path, size)` | Bulk pull with filters; caches locally; auto-chunks if >10K — see [findings.md](findings.md) |
| `list_repos(findings)` | Repo names + finding counts from cached data |
| `get_findings_by_repo(repo_name, findings)` | Filter cached findings to one repo |
| `dump_json(path)` | Write cached findings to JSON |
| `export_findings_csv(output_path, filters, filter_operations)` | Bulk export to CSV |

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

Product and sub-product methods accept names wherever an ID is required — the SDK resolves names to IDs internally.

| Method | Description |
|--------|-------------|
| `get_products(page, size, search)` | Paginated product listing |
| `create_product(name, description, type_id, tags, extra)` | Create a product |
| `update_product(product_name, product_id, name, description, tags, extra)` | Update a product — `tags` replaces the full existing set |
| `update_product_add_tags(product_name, product_id, tags)` | Append tags without touching existing ones |
| `update_product_set_tag(key_value, product_name, product_id)` | Set one tag by key — adds if absent, replaces if key exists |
| `get_sub_products()` | All sub-products — lightweight id + name list |
| `get_sub_product(sub_product_id)` | Full sub-product detail |
| `create_sub_product(name, product_name, product_id, description, environment_id, tier, tags, extra)` | Create a sub-product under a parent product |
| `update_sub_product(sub_product_id, name, description, tags, extra)` | Update a sub-product — `tags` replaces the full existing set |
| `update_sub_product_add_tags(sub_product_id, tags)` | Append tags without touching existing ones |
| `update_sub_product_set_tag(sub_product_id, key_value)` | Set one tag by key — adds if absent, replaces if key exists |

```python
# Create with tags
ac.create_product("payments-platform", tags=["env:production", "superowner:owner@example.com"])
sub = ac.create_sub_product("payments-api", product_name="payments-platform", tags=["env:production"])

# Full tag replacement
ac.update_product(product_name="payments-platform", tags=["env:production", "superowner:new@example.com"])

# Append tags
ac.update_product_add_tags(product_name="payments-platform", tags=["team:security"])

# Set/overwrite a single tag key
ac.update_product_set_tag("superowner:new@example.com", product_name="payments-platform")
ac.update_sub_product_set_tag(sub["id"], "superowner:new@example.com")
```

## Tickets

Product and sub-product accept names (resolved to IDs internally) or integer IDs. Assignee is the display name from the ticketing system, not an email.

| Method | Description |
|--------|-------------|
| `get_tickets(product, sub_product, assignee, page, size)` | Retrieve tickets; all filters optional and combinable. Returns `{"tickets": [...], "totalElements": int, "totalPages": int}` |

```python
ac.get_tickets(product="payments-platform")
ac.get_tickets(product="payments-platform", assignee="Julian Wayte")
ac.get_tickets(sub_product="payments-api")
ac.get_tickets(sub_product="payments-api", assignee="Julian Wayte")
ac.get_tickets(assignee="Julian Wayte")
ac.get_tickets()                                        # all tickets
ac.get_tickets(product="payments-platform", page=1, size=50)  # paginate
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

## Tenant & Discovery

| Method | Description |
|--------|-------------|
| `get_tenant_config(config_type)` | Read a tenant feature flag or config value |
| `get_api_docs()` | Fetch the full OpenAPI spec |
