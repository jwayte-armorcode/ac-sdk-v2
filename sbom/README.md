# Uptycs SBOM ingestion into ArmorCode

Tools for loading Uptycs (Osquery) CycloneDX SBOM exports into ArmorCode so that every finding carries a component name and version.

| Script | What it does |
|---|---|
| `convert_uptycs_sbom.py` | Removes the `vulnerabilities[]` array so ArmorCode ingests the file as a components-only SBOM (recommended) |
| `convert_uptycs_sbom_fixrefs.py` | Keeps the Uptycs vulnerability list and rewrites `affects[].ref` to real component `bom-ref` values (alternative) |
| `upload_sbom.py` | Uploads a CycloneDX file to any ArmorCode tenant and waits for the scan to finish |

All three need Python 3.7+. Only `upload_sbom.py` needs a package: `pip install -r requirements.txt`.

---

## 1. Summary

Uptycs exports CycloneDX SBOMs that include both a component inventory (`components[]`) and Uptycs's own vulnerability list (`vulnerabilities[]`). When the vulnerability list is present, ArmorCode builds findings from it, and with the current Uptycs format those findings arrive **without a component name or version**.

Removing `vulnerabilities[]` before upload switches ArmorCode to its components-only path. ArmorCode analyses each component itself and creates findings against the component they were found on, so every finding has a component name and version, along with CVSS, published date and CWE.

**Tested result** (Uptycs Linux host SBOM, 1,138 components): 153 findings created; 153/153 with component name and version, CVSS vector and published date; 148/153 with CWE. Processing time about 2.5 minutes.

## 2. Background: two CycloneDX ingestion paths

Both forms are valid CycloneDX. ArmorCode chooses the path based on whether the file has a top-level `vulnerabilities[]` array.

| | SBOM with `vulnerabilities[]` | Components-only SBOM |
|---|---|---|
| Vulnerability source | The list in the file (Uptycs) | ArmorCode's own analysis of `components[]` |
| Component on finding | Looked up via `affects[].ref` → `bom-ref` | Set directly from the analysed component |
| Uptycs export today | Component name / version blank | Component name / version populated |
| File change needed | Fix `affects[].ref` references | Remove `vulnerabilities[]` |

In Uptycs exports, `vulnerabilities[].affects[].ref` is a BOM-Link whose fragment is a purl, while each component's `bom-ref` is a hash, so the lookup in the first path never matches:

```json
"components": [{
  "name": "amazon-ssm-agent", "version": "3.3.4108.0",
  "bom-ref": "<hash>",
  "purl": "pkg:rpm/amazon-ssm-agent@3.3.4108.0"
}],
"vulnerabilities": [{
  "id": "CVE-2026-39834",
  "affects": [{ "ref": "urn:cdx:<serial-uuid>/1#pkg:rpm/amazon-ssm-agent@3.3.4108.0" }]
}]
```

The components-only path does not use that lookup at all.

## 3. How findings are created in the components-only path

1. **Upload**: the SBOM is uploaded through the CycloneDX security tool (UI or API).
2. **Detection**: ArmorCode's CycloneDX parser sees there is no `vulnerabilities[]` array and treats the file as a component inventory.
3. **Analysis**: the inventory is passed to ArmorCode's built-in Dependency-Track analysis, which identifies each component by its package URL (purl) and checks it against vulnerability data.
4. **Finding creation**: each vulnerability is returned together with the component it was found on. ArmorCode creates one finding per vulnerability per component.
5. **Completion**: findings are labelled Source = CycloneDX, Scan Type = SBOM.

**Why name and version are always present:** every finding is produced from a specific component, so its name and version come straight from that component. There is no reference to resolve. Titles take the form `CVE-2023-24056 - pkgconf : 1.8.0`.

The analysis also supplies details the Uptycs list does not carry: CVSS score and vector, published date (used for ageing and SLA clocks), CWE and description.

## 4. `convert_uptycs_sbom.py`

Removes `vulnerabilities[]` and writes a new file. Metadata, components and the dependency graph are copied through unchanged; the input file is never modified.

| Section of the SBOM | Action |
|---|---|
| `vulnerabilities[]` | Removed |
| `components[]` (name, version, purl, cpe, bom-ref) | Kept unchanged |
| `dependencies[]` | Kept unchanged |
| `metadata` | Kept unchanged |

```bash
# single file -> <input>.components_only.json next to the input
python3 convert_uptycs_sbom.py <input_sbom.json> [output.json]

# batch: every *.json in a folder -> <input_dir>/components_only/ by default
python3 convert_uptycs_sbom.py <input_dir> [output_dir]
```

Example output:

```
[uptycs_host_sbom.json]
  - vulnerabilities[] entries removed: 482
  - components kept: 1138 (pkg:rpm 1028, pkg:pip 110)
  -> wrote uptycs_host_sbom.components_only.json
```

Files that are not CycloneDX are skipped. If a component has no purl, the script warns, because it cannot be matched to vulnerability data.

## 5. Uploading to ArmorCode

### Through the UI

1. Go to **Manage > Security Tools** and search for **CycloneDX**.
2. Open the **Scan Upload** tab and click **Upload Scan**.
3. Select the target Group, Subgroup and Environment.
4. Upload the `*.components_only.json` file, set the Tool Scan Date, and click **Upload**.
5. When the scan shows Completed, open the Scan ID to view its findings.

### Through the API: `upload_sbom.py`

Uploads a CycloneDX file to any ArmorCode tenant and waits for the scan to finish. **The API token determines the tenant.** Uses the documented two-step flow: `POST /user/tools/generic/configurations/CycloneDX/upload` returns a pre-signed URL and scan ID, then the file is `PUT` to that URL.

```bash
export ARMORCODE_TOKEN=<api-token>
python3 upload_sbom.py <sbom.json> --group <group> --subgroup <subgroup> [options]

# example
python3 upload_sbom.py host.components_only.json \
    --group SBOM-Imports --subgroup linux-hosts --tag sbom_source:uptycs
```

| Option | Purpose |
|---|---|
| `--group`, `--subgroup` | Target group and subgroup, by exact name (required) |
| `--environment` | Environment name (default: Production) |
| `--tag KEY:VALUE` | Tag applied to the scan; repeatable |
| `--create` | Create the group and/or subgroup if they do not exist |
| `--token` / `ARMORCODE_TOKEN` / `--env-file` | API token; the environment variable keeps it out of shell history |
| `--url` | ArmorCode URL (default: `https://app.armorcode.com`) |
| `--no-wait`, `--wait-timeout` | Skip polling, or change the wait limit (default 900 s) |

The script checks the file is CycloneDX JSON, prints its component and `vulnerabilities[]` counts, then reports the scan status and finding totals. It exits non-zero if the group or subgroup is missing (without `--create`) or the scan fails.

### Verifying

- Component shows a package name and version, e.g. `pkgconf 1.8.0`.
- CVE, CVSS score and vector, and published date are populated.
- Source is CycloneDX and Scan Type is SBOM.

## 6. Test results

| Measure | Result |
|---|---|
| Input | Uptycs Linux host SBOM (CycloneDX 1.4) |
| Components analysed | 1,138 (1,028 rpm, 110 pip) |
| Scan status | Completed in about 2.5 minutes, no errors |
| Findings created | 153 across 20 packages |
| Component name and version | 153 / 153 |
| CVE and CVSS vector | 153 / 153 |
| Published date | 153 / 153 |
| CWE | 148 / 153 |
| Severity | 14 Critical, 52 High, 72 Medium, 15 Low |

Re-uploading the same file produced 153 duplicates and 0 new findings, so results are stable across scans.

## 7. What to expect from finding counts

Removing `vulnerabilities[]` changes where the vulnerability list comes from. Findings are produced by ArmorCode's analysis of the component inventory rather than taken from the list Uptycs embeds in the file, so the number of findings will differ from the number of CVEs in the Uptycs export.

| | Uptycs list (in file) | ArmorCode analysis |
|---|---|---|
| Vulnerability entries / findings | 482 CVEs | 153 findings (151 CVEs) |
| Packages with a vulnerability | 201 | 20 |
| Granularity | One entry per CVE, listing all affected packages | One finding per CVE per package |
| Component on each finding | Not resolved | Always present |

- **Different sources:** Uptycs and ArmorCode assess packages using different vulnerability sources and matching methods, so each produces its own CVE list. In this test 20 CVEs appear in both.
- **Per-package findings:** each ArmorCode finding names one package. A CVE affecting several packages becomes several findings, each of which can be routed, tracked and closed on its own.
- **New baseline:** the analysis runs the same way on every upload, so counts are consistent from scan to scan and suitable for trending and SLA tracking. Treat the first components-only upload as the baseline rather than comparing it directly with the Uptycs console.
- **Uptycs view retained:** the Uptycs console continues to show Uptycs's own assessment, so both views remain available.

## 8. Alternative: keep the Uptycs vulnerability list (`convert_uptycs_sbom_fixrefs.py`)

If you need the Uptycs CVE list itself in ArmorCode, this script keeps `vulnerabilities[]` and rewrites each `affects[].ref` to the matching component's real `bom-ref` (matched by the purl after `#`), and normalises severity casing.

```bash
python3 convert_uptycs_sbom_fixrefs.py <input.json> [output.json]   # -> <input>.armorcode.json
python3 convert_uptycs_sbom_fixrefs.py <input_dir> <output_dir>
```

Current parser limitations on this path: only the first `affects[]` entry per CVE is used, and ratings with method `CVSSv31` do not populate the CVSS v3 fields. Validate severity mapping on a test upload before relying on it.

## 9. Recommended next steps

1. **Validate on more hosts:** convert and upload SBOMs from two or three more hosts and confirm the same results.
2. **Set the baseline:** agree that the components-only finding count is the baseline for SLA and trend reporting.
3. **Automate:** run `convert_uptycs_sbom.py` in batch mode on each export before upload, then `upload_sbom.py`.
4. **Longer term:** once Uptycs emits `affects[].ref` values that match component `bom-ref`s, or ArmorCode's parser resolves BOM-Link/purl references, the Uptycs list can be ingested directly with component attribution.
