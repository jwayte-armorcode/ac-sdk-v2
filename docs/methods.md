# SDK Methods

All methods are on the `ArmorCodeClient` class. For filter values and finding-specific behaviour see [findings.md](findings.md).

## Findings

| Method | Description |
|--------|-------------|
| `get_findings(severities, statuses, days_back, extra_filters, dump_path, size)` | Bulk pull with filters; caches locally; auto-chunks if >10K — see [findings.md](findings.md) |
| `get_findings_by_hierarchy(product, sub_product, team, severities, statuses, sources, extra_filters, page_size)` | Fetch findings scoped to a product/sub-product/team hierarchy — names resolved to IDs automatically — see [findings.md](findings.md#hierarchy-filter) |
| `get_findings_by_engagement(engagement, severities, statuses, sources, extra_filters, page_size)` | Fetch findings associated with an engagement (accepts name or id) — filters on `armorcodeProjects` — see [findings.md](findings.md#engagement-filter) |
| `get_finding(finding_id)` | Full detail for a single finding by ID |
| `get_engagements()` | List all engagements (id + name); the API's internal name is "project" (`/user/project`) |
| `list_repos(findings)` | Repo names + finding counts from cached data |
| `get_findings_by_repo(repo_name, findings)` | Filter cached findings to one repo |
| `dump_json(path)` | Write cached findings to JSON |
| `export_findings_csv(output_path, filters, filter_operations)` | Bulk export to CSV |
| `upload_findings(findings, product, sub_product, environment)` | Insert custom findings via `POST /api/findings/upload` (Generic JSON). `product`/`sub_product` accept names (resolved to IDs). Returns `{"scanId": ...}` |

## Finding Actions (Bulk)

All bulk methods accept a list of finding IDs and act on them server-side.

| Method | Description |
|--------|-------------|
| `bulk_accept_risk(finding_ids, reason, notes)` | Accept risk on a set of findings |
| `bulk_false_positive(finding_ids, reason, notes)` | Mark findings as false positives |
| `bulk_suppress(finding_ids, reason, notes)` | Suppress findings |
| `bulk_reopen(finding_ids)` | Reopen findings |
| `bulk_confirm(finding_ids)` | Confirm findings |
| `bulk_change_severity(finding_ids, severity)` | Change severity (e.g. `"High"`) |
| `bulk_assign_owner(finding_ids, owner_id)` | Assign owner by user ID |
| `update_finding_tags(finding_ids, tags, update_type)` | Add/remove/replace tags on findings. `update_type` = `"ADD"` (default), `"REMOVE"`, or `"REPLACE"` |

## Finding Comments

| Method | Description |
|--------|-------------|
| `get_finding_comments(finding_id, page, size)` | Paginated comment list for a finding |
| `add_finding_comment(finding_id, text)` | Post a comment on a finding |
| `bulk_add_finding_comment(finding_ids, text)` | Post the same comment on multiple findings |

```python
# Insert a custom finding (single dict or a list of dicts)
ac.upload_findings(
    {
        "Title": "Hardcoded secret in config",
        "Severity": "High",                  # Critical / High / Medium / Low / Info
        "Description": "...",
        "ToolFindingId": "my-unique-id-001",  # dedup key
        "Category": "SECURITY",
        "FindingUrl": "https://example.com/finding/001",
    },
    product="my-product",
    sub_product="my-sub-product",
    environment="Production",
)
# -> {"scanId": 137746107}   # ingest is async; scanId confirms acceptance
```

> The sub-product must belong to the product passed, or the API returns
> `500 "No such product/sub-product/environment found"`. Findings surface
> asynchronously via the scan pipeline, so they may not appear in
> `get_findings()` immediately.

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
| `create_team(name, description, lead_id, members, extra)` | Create a new team |
| `update_team(team_id, name, description, members, extra)` | Update team — fetches current state first |
| `delete_team(team_id)` | Delete a team |
| `add_team_members(team_id, members)` | Add members to a team (list of `{"userId": int, "role": str}`) |
| `update_team_with_user(team, owners)` | Set team owners via `PUT /api/team/with-user`, preserving members + scope-of-access |

**Owner fields** (`update_team_with_user(team, owners={...})`): 5 keys —
`complianceOwner`, `securityOwner`, `engineeringOwner`, `businessOwner`,
`supportOwner`. The Aledade tenant relabels these in global-settings Titles:
AppSec Engineer → complianceOwner, Security Ambassador → securityOwner, Aledade
Director → engineeringOwner, Aledade PM → businessOwner, **Aledade VP →
supportOwner**.

**Scope-of-access gotcha:** `PUT /api/team/with-user` is a FULL REPLACE. Its
`members` and `properties` (scope) payloads use a DIFFERENT shape than the GET
returns — sending the GET shape back silently drops members/scope (returns 200
but wipes them). `update_team_with_user` handles the conversion: members use
`role` as a NAME string; scope uses flat `businessUnitId`/`businessUnitName` and
`product`/`subProduct` as bare ints. Always pass a fresh `get_team()` result so
existing owners/members/scope are round-tripped. Set an owner first as a team
*member* (`add_user_to_team`) BEFORE making them an owner, or the PUT can drop
existing members.

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
ac.create_product("my-product", tags=["env:production", "superowner:owner@example.com"])
sub = ac.create_sub_product("my-sub-product", product_name="my-product", tags=["env:production"])

# Full tag replacement
ac.update_product(product_name="my-product", tags=["env:production", "superowner:new@example.com"])

# Append tags
ac.update_product_add_tags(product_name="my-product", tags=["team:security"])

# Set/overwrite a single tag key
ac.update_product_set_tag("superowner:new@example.com", product_name="my-product")
ac.update_sub_product_set_tag(sub["id"], "superowner:new@example.com")
```

## Tickets

Product and sub-product accept names (resolved to IDs internally) or integer IDs. Assignee is the display name from the ticketing system, not an email.

| Method | Description |
|--------|-------------|
| `get_tickets(product, sub_product, assignee, page, size)` | Retrieve tickets; all filters optional and combinable. Returns `{"tickets": [...], "totalElements": int, "totalPages": int}` |

```python
ac.get_tickets(product="my-product")
ac.get_tickets(product="my-product", assignee="Jane Smith")
ac.get_tickets(sub_product="my-sub-product")
ac.get_tickets(sub_product="my-sub-product", assignee="Jane Smith")
ac.get_tickets(assignee="Jane Smith")
ac.get_tickets()                                           # all tickets
ac.get_tickets(product="my-product", page=1, size=50)     # paginate
```

## Users & Roles

| Method | Description |
|--------|-------------|
| `get_users()` | All tenant users via `/user/data/users` (roles + activity) |
| `get_users_flat()` | All users via `/user/get-users` (id, email, displayName, name) |
| `search_users(search_text, email, role, team, page, size)` | Filtered user search via `POST /api/v2/user/search` (one page) |
| `search_users_all(page_size)` | ALL users WITH teamInfo + tenantRole, auto-paginated |
| `get_roles()` | All tenant roles via `/user/roles` (id, name, permissionSet) |
| `email_available(email)` | True if email is free (pre-check before creating) |
| `create_user(name, email, tenant_role, disable_login, team_info, extra)` | Create a user via `POST /user/add/user` → returns created user dict |
| `create_team_member_user(email, disable_login, check_availability)` | Create an email-only user with a placeholder role → returns new id (clear role later via `add_user_to_team`) |
| `update_user(user_id, name, email, tenant_role, disable_login, team_info, extra)` | Per-field update via `PUT /user/update/user` |
| `delete_user(user_id)` | Delete via `DELETE /api/v2/user/{id}` |
| `add_user_to_team(user, team_id, team_name, role_name, role_id, clear_tenant_role)` | Append a team to a user's teamInfo (optionally clearing tenantRole in the same PUT) |

**tenantRole vs teamInfo role — two namespaces:**
- *teamInfo role* — per-team membership role (e.g. `"Aledade Executive"`,
  `"Aledada PM"`), used in `add_user_to_team` and team-owner assignment.
- *tenantRole* — account-level role for `create_user`. Only a SUBSET of role
  names are valid tenantRoles. Valid: Read Only, Admin, Developer, Security
  Engineer, DevOps, Executive, Aledade Security Engineer, Aledade Engineering
  Manager, Aledade Security Ambassadors, Aledada PM. **NOT valid:** "Aledade
  Executive", "Aledade IT Manager", "Aledade Software Engineer", "Aledade IT
  Engineer".

**Creating a plain team member (no account role):** `POST /user/add/user`
requires *some* tenantRole (null is rejected) and accepts no name field (display
name = email). To replicate the common owner shape (`tenantRole=null` + real
`teamInfo`): `create_team_member_user(email)` (creates with a `"Read Only"`
placeholder), then `add_user_to_team(..., clear_tenant_role=True)` — that PUT
clears the role AND adds the team in one call (a clear-to-null with an EMPTY
teamInfo is rejected, so they must happen together). If the team role isn't
assignable on the tenant the add fails — roll back with `delete_user` so no
half-created account is stranded with the placeholder role.

**Wipe safety:** `update_user` / `add_user_to_team` are FULL REPLACE — always
round-trip `teamInfo` and `tenantRole` (from `search_users_all`) or they are
nulled.

## Engagements (CRUD)

| Method | Description |
|--------|-------------|
| `get_engagements()` | List all engagements (id + name) |
| `get_engagement(engagement_id)` | Full detail for a single engagement |
| `create_engagement(name, description, type, start_date, end_date, status, tags, extra)` | Create a new engagement |
| `update_engagement(engagement_id, name, description, ...)` | Update engagement — fetches current state first |
| `delete_engagement(engagement_id)` | Delete an engagement |

## Assessments (Pentests)

| Method | Description |
|--------|-------------|
| `get_assessments(page, size)` | List all assessments |
| `get_assessment(assessment_id)` | Full detail for a single assessment |
| `create_assessment(name, type, start_date, end_date, status, scope, assessors, notes, extra)` | Create an assessment |
| `delete_assessment(assessment_id)` | Delete an assessment |

## Exceptions (Risk Register)

| Method | Description |
|--------|-------------|
| `get_exceptions()` | List all open exceptions |
| `get_exception(exception_id)` | Full detail for a single exception |
| `create_exception(name, description, start_date, end_date, reasons, extra)` | Create a new exception |
| `update_exception(exception_id, name, description, start_date, end_date, reasons, extra)` | Update an exception — fetches current state first |
| `delete_exception(exception_id)` | Delete an exception |

## Scans

| Method | Description |
|--------|-------------|
| `get_scans(page, size, filters)` | List scans for the tenant |
| `get_scan(scan_id)` | Detail for a single scan |

## Alerts

| Method | Description |
|--------|-------------|
| `get_alerts(severity, status, product, sub_product, page, size, extra_filters)` | Search alerts with optional filters |

## Security Tools

| Method | Description |
|--------|-------------|
| `get_tools()` | Configured scanners (SAST, DAST, SCA, etc.) |
| `get_integration_tools()` | Integrations (Jira, GitHub, ServiceNow, etc.) |

## Runbooks

| Method | Description |
|--------|-------------|
| `get_runbooks()` | List all automation runbooks |
| `get_runbook(runbook_id)` | Full runbook detail (tasks, filters, schedule) |
| `create_runbook(body)` | Create a new runbook — pass a full CreateRunbookRequest dict |
| `update_runbook(runbook_id, body)` | Update an existing runbook |
| `delete_runbook(runbook_id)` | Delete a runbook |
| `enable_runbook(runbook_id)` | Enable a disabled runbook |
| `disable_runbook(runbook_id)` | Disable a runbook |
| `run_runbook(runbook_id)` | Trigger an immediate on-demand run |

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
