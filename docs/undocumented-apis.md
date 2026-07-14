# Undocumented ArmorCode APIs

A living reference for ArmorCode REST endpoints that the SDK does **not** wrap
(and that the public OpenAPI spec documents incompletely or not at all), plus
the exact request shapes needed to drive them via `ac._session`.

These are endpoints the ArmorCode web app actually calls. Where the frontend
uses a **legacy path** that differs from the OpenAPI-documented `/api/v2/...`
path, this doc records what the UI really sends — because that is the
combination known to work, verified from live network captures.

Call them through the authenticated session the SDK already holds:

```python
from armorcode import ArmorCodeClient
ac = ArmorCodeClient.from_env("env")

resp = ac._session.post(f"{ac.base_url}/user/tickets/jira/configuration", json=body)
resp.raise_for_status()
```

## Index

| Area | Endpoints | Status |
|------|-----------|--------|
| [Ticketing — Azure Boards mappings](#ticketing--azure-boards-mappings) | `/user/tickets/jira/*` CRUD | Verified from UI (Delinea, 2026-07) |

---

## Ticketing — Azure Boards mappings

In ArmorCode, an **Azure Boards mapping** is a *ticket configuration* — it ties
an ArmorCode scope (whole tenant, a product, or a sub-product) to an Azure
DevOps project and its default field values (Area Path, Iteration, Product,
Due Date, severity → priority, labels, etc.). Azure Boards is not a dedicated
API; it rides the shared ticketing endpoints with `ticketSystemType: "AZURE_BOARD"`.

### The path surprise

The SDK's read helpers (`get_azure_board_configs`, `get_azure_board_login_configs`,
`get_azure_board_projects`) use the OpenAPI-documented `/api/v2/tickets/*`
paths. **The web app's create/edit/delete flow does not** — it uses the older
`/user/tickets/jira/*` family. Both likely reach the same backend, but the
legacy path is the one verified to work for writes, so it is what this doc uses.

| Documented (OpenAPI, used by SDK reads) | Legacy (used by the UI for writes) |
|---|---|
| `GET /api/v2/tickets/configuration` | `POST /user/tickets/jira/projects` (form load) |
| `POST /api/v2/tickets/configuration` | `POST /user/tickets/jira/configuration` (create) |
| `PUT /api/v2/tickets/configuration/{id}` | `PUT /user/tickets/jira/configuration/{id}` (edit) |
| `DELETE /api/v2/tickets/configuration/{id}` | `DELETE /user/tickets/jira/configuration/{id}` (delete) |

### CRUD summary

| Action | Method + path | Body | In SDK? |
|--------|---------------|------|---------|
| List mappings | `GET /api/v2/tickets/configuration?ticketSystem=AZURE_BOARD` | — | ✅ `get_azure_board_configs()` |
| List connections | `GET /api/v2/tickets/configuration/login/AZURE_BOARD` | — | ✅ `get_azure_board_login_configs()` |
| Load add-mapping form | `POST /user/tickets/jira/projects` | `{"loginConfigId": <id>}` | ❌ |
| **Create mapping** | `POST /user/tickets/jira/configuration` | full config object | ✅ `create_azure_board_config()` (SUBPRODUCT-scoped, with repo-conflict pre-check) |
| **Edit mapping** | `PUT /user/tickets/jira/configuration/{id}` | full config object | ❌ |
| **Delete mapping** | `DELETE /user/tickets/jira/configuration/{id}` | — | ❌ |

### Step 0 — connection (login config)

Every mapping hangs off a **login config** (`loginConfigId`) — one connected
Azure DevOps organization (org URL + PAT). List them with the SDK:

```python
for c in ac.get_azure_board_login_configs():
    print(c["id"], c["name"], c["organisation"], f'({c["configCount"]} mappings)')
# 43917 Boards thycotic (53 mappings)
```

### Step 1 — load the form (project + field metadata)

Clicking **Add Mapping** in the UI first fetches the Azure DevOps projects and
their available fields (with `allowedValues` trees) for the chosen connection:

```python
resp = ac._session.post(
    f"{ac.base_url}/user/tickets/jira/projects",
    json={"loginConfigId": 43917},
)
resp.raise_for_status()
projects = resp.json()   # projects + field metadata used to populate the form
```

You use this to discover valid `projectKey`, `issueType`, and the
`allowedValues` for select fields (Area Path, Iteration, Product) before saving.

### Step 2 — create the mapping

`POST /user/tickets/jira/configuration` with the full configuration object.
Verified example (a **GLOBAL** / tenant-wide mapping):

```python
body = {
    "projectKey": "Thycotic.FeatureRequests",
    "issueType": "Product Backlog Item",           # free-form, per project
    "loginConfigId": 43917,
    "ticketSystemType": "AZURE_BOARD",
    "configurationType": "GLOBAL",                 # GLOBAL | PRODUCT | SUBPRODUCT
    "ticketUnifiedSingleTemplateId": 351708,       # ticket-description templates
    "ticketUnifiedMultipleTemplateId": 351709,
    "labels": ["Armorcode_Associated_Finding"],

    # --- severity -> Azure priority ---
    "properties": {
        "critical": "1", "high": "2", "medium": "3", "low": "4", "info": "4",
        # create also sends paired empty *_ticket_severity_mapping keys; optional (see gotchas)
        "critical_ticket_severity_mapping": "", "high_ticket_severity_mapping": "",
        "medium_ticket_severity_mapping": "", "low_ticket_severity_mapping": "",
        "info_ticket_severity_mapping": "",
    },

    # --- field defaults sent BOTH as flat keys AND in customFields[] (see gotchas) ---
    "/fields/System.AreaPath": "\\Thycotic.FeatureRequests\\UX Secret Server",
    "/fields/System.IterationPath": "\\Thycotic.FeatureRequests\\UX Secret Server",
    "/fields/ThycoticScrum.Product": "Architecture",
    "/fields/Custom.InRollingPatch": False,
    "/fields/Custom.DocsNeeded": False,
    "duedate": "${finding.resolutionDueDate}",

    "customFields": [
        {
            "key": "/fields/System.AreaPath", "name": "Area",
            "type": "select", "dataType": "string",
            "value": "\\Thycotic.FeatureRequests\\UX Secret Server",
            "defaultVal": "\\Thycotic.FeatureRequests\\UX Secret Server",
            "active": True, "isRequired": False,
            # allowedValues: nested id/name/children tree from Step 1 (trimmed here)
            "allowedValues": [ {"id": "\\Thycotic.FeatureRequests", "name": "Thycotic.FeatureRequests",
                "children": None, "allowedValues": [
                    {"id": "\\Thycotic.FeatureRequests\\UX Secret Server", "name": "UX Secret Server",
                     "children": None, "allowedValues": None} ]} ],
        },
        {
            "key": "/fields/ThycoticScrum.Product", "name": "Product",
            "type": "select", "dataType": "string",
            "value": "Architecture", "defaultVal": "Architecture",
            "active": True, "isRequired": True,
            "defaultValue": {"id": None, "name": None, "meta": {}, "otherProperties": {}},
            # allowedValues: full flat list of product names (trimmed here)
            "allowedValues": [{"id": "Architecture", "name": "Architecture",
                               "children": None, "allowedValues": None}],
        },
        {
            "key": "/fields/Custom.InRollingPatch", "name": "In Rolling Patch",
            "type": "boolean", "dataType": "boolean",
            "value": False, "defaultVal": False, "active": True, "isRequired": True,
            "allowedValues": [],
        },
        {
            "key": "/fields/Custom.DocsNeeded", "name": "Docs Needed",
            "type": "boolean", "dataType": "boolean",
            "value": False, "defaultVal": False, "active": True, "isRequired": True,
            "allowedValues": [],
        },
        {
            "key": "duedate", "name": "Due Date",
            "type": "duedate", "dataType": "duedate",
            "value": "${finding.resolutionDueDate}", "defaultVal": "${finding.resolutionDueDate}",
            "active": True, "isRequired": False, "allowedValues": None,
        },
    ],
}

resp = ac._session.post(f"{ac.base_url}/user/tickets/jira/configuration", json=body)
resp.raise_for_status()
```

For **PRODUCT** / **SUBPRODUCT** scoped mappings, set `configurationType`
accordingly and add `product` / `subProduct` id arrays:

```python
    "configurationType": "PRODUCT",
    "product": [771025, 966132],
    # or:
    "configurationType": "SUBPRODUCT",
    "product": [680985],
    "subProduct": [2130703],
```

#### SDK wrapper: `create_azure_board_config()` (with repo-conflict check)

The SUBPRODUCT case is wrapped in the SDK. In this tenant model a **repo is a
sub-product**, and mappings carry no repo field — only `product[]` and
`subProductIds[]` (names mirrored in `productNameId` / `subProductNameIds`).
A repo may belong to only one mapping, so the wrapper resolves the repo names
to sub-product ids, scans **every** existing Azure Boards mapping across **all**
connections, and refuses to create a duplicate — raising
`AzureBoardMappingConflict` (which carries the offending mapping's `id`,
`application`, and colliding `repos`) instead of double-mapping.

```python
from armorcode import ArmorCodeClient, AzureBoardMappingConflict

ac = ArmorCodeClient.from_env("env")
try:
    cfg = ac.create_azure_board_config(
        project_key="Delinea.Work",
        login_id=43917,
        repos=["My.Repo", "Other.Repo"],   # repo = sub-product (by name)
        issue_type="Bug",
        product="Cybersecurity",            # optional application (name or id)
    )
except AzureBoardMappingConflict as e:
    for c in e.conflicts:
        print(c["id"], c["application"], c["repos"])
```

`custom_fields` and `field_defaults` params let you pass the project-specific
field objects + flat keys (from the Step-1 form load) through untouched; the
wrapper fills the structural envelope (`ticketSystemType`, `configurationType`,
`properties`, `labels`, `subProduct`/`product`). Only the conflict check is
opinionated — everything else is a thin pass-through to the verified body shape.

### Step 3 — edit a mapping

`PUT /user/tickets/jira/configuration/{configId}`. The body is the **same full
object** as create — it is a full replace, not a partial patch. Send the whole
config with your changes. Differences the UI shows on edit vs create:

- `properties` omits the empty `*_ticket_severity_mapping` keys — just
  `{critical, high, medium, low, info}`. Those empties are optional/cosmetic.
- each `customFields[]` entry carries a populated `defaultValue`
  (`StringNameIdPair`) reflecting the previously-saved value, e.g.
  `{"id": "Auditing", "name": "Auditing", "meta": {}, "otherProperties": {}}`,
  where create sent `{"id": null, "name": null, ...}`.
- only the fields currently active on the form are sent; a field left untouched
  (e.g. `System.AreaPath`) is simply absent — both its flat key and its
  `customFields[]` entry. Unsent fields are not forced.

```python
resp = ac._session.put(
    f"{ac.base_url}/user/tickets/jira/configuration/1238346",
    json=body,   # same shape as create
)
resp.raise_for_status()
```

### Step 4 — delete a mapping

```python
resp = ac._session.delete(
    f"{ac.base_url}/user/tickets/jira/configuration/1238344"
)
resp.raise_for_status()   # no request body
```

### Gotchas

- **Legacy path for writes.** The UI writes via `/user/tickets/jira/*`, not the
  OpenAPI `/api/v2/tickets/*`. Use the legacy path to match verified behavior.
- **Dual field representation.** Each active field's value is sent **twice**:
  once as a flat top-level key (`"/fields/System.AreaPath": "..."`, `"duedate": "..."`)
  and once as a full object inside `customFields[]`. The UI always does both;
  replicate it rather than sending only one form.
- **`configurationType` has three values:** `GLOBAL` (tenant-wide),
  `PRODUCT`, `SUBPRODUCT`. Only the latter two carry `product`/`subProduct` arrays.
  (Read responses use the same values but also expose a `configurationType`
  field already, so round-tripping is consistent.)
- **`allowedValues` come from Step 1.** Select fields (Area Path, Iteration,
  Product) expect the nested `id/name/children/allowedValues` tree that the
  `POST /user/tickets/jira/projects` call returns. Area/Iteration values are
  backslash-delimited paths, e.g. `\\Thycotic.FeatureRequests\\UX Secret Server`.
- **`issueType` is per-project free text** (e.g. `"Bug"`, `"Product Backlog Item"`).
- **Field *keys* are project-specific — don't hardcode them.** The set of
  `customFields` (and their flat keys) is whatever the chosen Azure DevOps
  project exposes, discovered from Step 1. The due-date field is the clearest
  example: one project sends a bare `"duedate"` key with `type: "duedate"`,
  another sends `"/fields/Microsoft.VSTS.Scheduling.DueDate"` with
  `type: "dateTime"` — both carrying the same `${finding.resolutionDueDate}`
  value. Likewise a project may expose extra custom fields (`Source`, `RFE`,
  `Regression`, `Unreleased`, `InvestmentType`, `No_Code`, `ReleaseNotesNeeded`,
  …). Build the field list from the Step 1 response, not from a fixed template.
- **Path values are single backslashes on the wire.** Area/Iteration values are
  ADO tree paths like `\Delinea.Work\Operations\Security Team` — one backslash
  per separator in the actual JSON. In Python source you write `\\` (escape),
  but the value sent is single-backslash-delimited.
- **Request-side `CustomField` is richer than the read/response shape** — it adds
  `allowedValues`, `isRequired`, `level`, `nestedFields`, `originalFieldType`,
  `value`. The list/read shape (`get_azure_board_configs`) drops `allowedValues`
  and keeps `value`/`defaultVal`. Select fields carry `defaultValue` as a
  `StringNameIdPair` (`{"id": null, "name": null, "meta": {}, "otherProperties": {}}`
  on create); booleans and text fields set it too.

### Verification status

Verified from live web-app network captures on the **Delinea** tenant
(login config 43917 "Boards", org `thycotic`), 2026-07:

| Action | Endpoint | Result |
|--------|----------|--------|
| Load form | `POST /user/tickets/jira/projects` | ✅ returns projects + field metadata |
| Create (project `Thycotic.FeatureRequests`) | `POST /user/tickets/jira/configuration` | ✅ mapping created |
| Create (project `Delinea.Work`) | `POST /user/tickets/jira/configuration` | ✅ mapping created — confirmed dual-representation + project-specific field keys |
| Edit | `PUT /user/tickets/jira/configuration/1238346` | ✅ mapping updated |
| Delete | `DELETE /user/tickets/jira/configuration/1238344` | ✅ mapping removed |

Two create captures across **different ADO projects** confirm the model is
project-agnostic: the structural envelope (`loginConfigId`, `ticketSystemType`,
`configurationType`, `properties`, dual flat+`customFields` representation) is
constant, while the specific field keys and `allowedValues` trees vary per
project.
