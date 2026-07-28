#!/usr/bin/env python3
"""Upload a native scanner report to ArmorCode (Method 4 in docs/uploading-findings.md).

POST /api/v2/scans/upload/* is a four-step multipart-to-S3 flow (not yet wrapped
by the SDK, so it goes through ac._session):
  1. initiate  -> uploadId + s3Key + scanId   (toolName/totalParts are QUERY params)
  2. presign   -> pre-signed URL for each part (returned as a bare string)
  3. PUT       -> the part bytes straight to S3, no auth header
  4. complete  -> hand back the ETags; ArmorCode then parses the report async

Prefer this over POST /client/utils/scan/upload: that endpoint is gated by
ROLE_REPORT_INGESTION and returns 403 for API tokens regardless of payload.

toolName must be a NATIVE scanner (Snyk, Trivy, Semgrep, SonarQube, Dependabot).
Custom tools are rejected with 400 "Custom tool is not supported yet" — use
Method 3 for those.

This WRITES to the tenant. Run only against a sandbox unless you mean it.

Usage:
    python examples/upload_scan_v2.py --env /path/to/env \
        --group juice-shop --subgroup jwayte-armorcode/juice-shop \
        [--file report.json] [--tool Trivy] [--environment Production] [--verify]

With no --file, a small sample Trivy SCA report is uploaded.
"""
import argparse
import json
import os
import sys
import tempfile
import time

import requests

# Allow running from the repo root without installing the package.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from armorcode import ArmorCodeClient

# S3 multipart requires >= 5 MB per part, except for the final part.
PART_SIZE = 10 * 1024 * 1024

# Non-terminal states from the ScanReportDto status enum. There is no PENDING or
# IN_PROGRESS — polling for those spins until timeout.
PENDING_STATES = ("INITIATED", "PROCESSING", "IMPORTING")

SAMPLE_REPORT = {
    "SchemaVersion": 2,
    "ArtifactName": "sample-repo",
    "ArtifactType": "repository",
    "Results": [
        {
            "Target": "package-lock.json",
            "Class": "lang-pkgs",
            "Type": "npm",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2019-10744",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.15",
                    "FixedVersion": "4.17.19",
                    "Severity": "CRITICAL",
                    "Title": "lodash: prototype pollution in defaultsDeep",
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2019-10744",
                    "CweIDs": ["CWE-1321"],
                },
                {
                    "VulnerabilityID": "CVE-2021-23337",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.15",
                    "FixedVersion": "4.17.21",
                    "Severity": "HIGH",
                    "Title": "lodash: command injection via template",
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2021-23337",
                    "CweIDs": ["CWE-78"],
                },
                {
                    "VulnerabilityID": "CVE-2020-7788",
                    "PkgName": "ini",
                    "InstalledVersion": "1.3.5",
                    "FixedVersion": "1.3.6",
                    "Severity": "LOW",
                    "Title": "ini: prototype pollution via ini.parse",
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-7788",
                    "CweIDs": ["CWE-1321"],
                },
            ],
        }
    ],
}


def load_client(env_path):
    """Build an ArmorCodeClient from either env shape (TENANT_URL/API_TOKEN
    or the lowercase url=/token= sandbox shape)."""
    kv = {}
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                kv[k.strip()] = v.strip()

    url = kv.get("TENANT_URL") or kv.get("url") or kv.get("tenant_url")
    token = kv.get("API_TOKEN") or kv.get("token") or kv.get("read_token")
    if not token:
        raise SystemExit(f"Could not find a token in {env_path}")

    host = (url or "app.armorcode.com").replace("https://", "").replace("http://", "").rstrip("/")
    return ArmorCodeClient(host, token=token)


def resolve_ids(ac, group, subgroup):
    """Resolve group/subgroup names to the numeric ids the v2 endpoint needs.

    GET /user/product embeds subgroups in subProductJpaDtos, so one call does
    both. The paged variant is unusable for this: its `size` body field is a
    T-shirt-size filter (HashSet<String>) that collides with the pagination
    `size` param, so every combination 400s.
    """
    resp = ac._session.get(f"{ac.base_url}/user/product")
    resp.raise_for_status()
    products = resp.json()

    grp = next((p for p in products if p.get("name") == group), None)
    if grp is None:
        names = ", ".join(sorted(p.get("name", "?") for p in products)) or "(none)"
        raise SystemExit(f"Group {group!r} not found. Available: {names}")

    subs = grp.get("subProductJpaDtos") or []
    sub = next((s for s in subs if s.get("name") == subgroup), None)
    if sub is None:
        names = ", ".join(sorted(s.get("name", "?") for s in subs)) or "(none)"
        raise SystemExit(f"Subgroup {subgroup!r} not in {group!r}. Available: {names}")

    return grp["id"], sub["id"]


def upload_scan(ac, path, tool, product_id, subproduct_id, environment):
    size = os.path.getsize(path)
    total_parts = max(1, (size + PART_SIZE - 1) // PART_SIZE)

    # 1. initiate — toolName and totalParts are query params, not body fields.
    resp = ac._session.post(
        f"{ac.base_url}/api/v2/scans/upload/initiate",
        params={"toolName": tool, "totalParts": total_parts},
        json={
            "environment": environment,
            "product": product_id,
            "subProduct": subproduct_id,
            "fileName": os.path.basename(path),
            "fileSizeBytes": size,
            "customTool": False,
        },
    )
    if not resp.ok:
        raise SystemExit(f"initiate failed [{resp.status_code}]: {resp.text[:500]}")
    init = resp.json()["data"]
    s3_key, upload_id, scan_id = init["s3Key"], init["uploadId"], init["scanId"]
    print(f"initiated scan {scan_id} ({total_parts} part(s), {size} bytes)")

    # 2 + 3. presign each part, then PUT it straight to S3.
    parts = []
    with open(path, "rb") as fh:
        for part_number in range(1, total_parts + 1):
            chunk = fh.read(PART_SIZE)

            resp = ac._session.post(
                f"{ac.base_url}/api/v2/scans/upload/presign",
                json={"s3Key": s3_key, "uploadId": upload_id, "partNumber": part_number},
            )
            if not resp.ok:
                raise SystemExit(f"presign part {part_number} failed: {resp.text[:500]}")
            # `data` is the URL as a bare string, not an object.
            url = resp.json()["data"]

            # Plain requests, not ac._session: the pre-signed URL carries its own
            # credentials, and the session's pinned auth/JSON headers break it.
            put = requests.put(url, data=chunk)
            if not put.ok:
                raise SystemExit(f"PUT part {part_number} failed [{put.status_code}]")

            parts.append({"partNumber": part_number, "eTag": put.headers["ETag"].strip('"')})
            print(f"  part {part_number}/{total_parts} uploaded")

    # 4. complete.
    resp = ac._session.post(
        f"{ac.base_url}/api/v2/scans/upload/complete",
        json={"s3Key": s3_key, "uploadId": upload_id, "scanId": scan_id, "parts": parts},
    )
    if not resp.ok:
        raise SystemExit(f"complete failed [{resp.status_code}]: {resp.text[:500]}")
    print("upload completed; ArmorCode is parsing the report asynchronously")
    return scan_id


def wait_for_scan(ac, scan_id, timeout=180):
    """Poll GET /api/scans/{id} until the scan reaches COMPLETED or FAILED."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = ac._session.get(f"{ac.base_url}/api/scans/{scan_id}")
        resp.raise_for_status()
        # This endpoint returns the scan object UNWRAPPED — unlike the upload
        # endpoints, there is no {"data": ...} envelope.
        body = resp.json()
        scan = body["data"] if isinstance(body.get("data"), dict) else body
        if scan.get("status") not in PENDING_STATES:
            return scan
        time.sleep(5)
    print(f"warning: scan {scan_id} still processing after {timeout}s", file=sys.stderr)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", required=True, help="path to an env file with url/token")
    ap.add_argument("--group", required=True, help="ArmorCode group (product) name")
    ap.add_argument("--subgroup", required=True, help="ArmorCode subgroup (sub-product) name")
    ap.add_argument("--file", help="scanner report to upload (default: sample Trivy report)")
    ap.add_argument("--tool", default="Trivy", help="native scanner name (default: Trivy)")
    ap.add_argument("--environment", default="Production")
    ap.add_argument("--verify", action="store_true", help="poll for status and finding counts")
    args = ap.parse_args()

    ac = load_client(args.env)

    product_id, subproduct_id = resolve_ids(ac, args.group, args.subgroup)
    print(f"{args.group} -> {product_id}, {args.subgroup} -> {subproduct_id}")

    tmp = None
    path = args.file
    if not path:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".json", prefix="trivy-sample-", delete=False)
        json.dump(SAMPLE_REPORT, tmp)
        tmp.close()
        path = tmp.name
        print(f"no --file given, uploading sample Trivy report ({path})")

    try:
        scan_id = upload_scan(ac, path, args.tool, product_id, subproduct_id, args.environment)
    finally:
        if tmp:
            os.unlink(tmp.name)

    if not args.verify:
        print(f"scan {scan_id} submitted; re-run with --verify to poll for findings")
        return

    scan = wait_for_scan(ac, scan_id)
    if not scan:
        return
    print(f"status: {scan.get('status')}")
    print(f"findings: {scan.get('totalCount')} total, {scan.get('totalNew')} new, "
          f"{scan.get('totalDuplicate')} duplicate")
    severity = (scan.get("allFindingStats") or {}).get("severity")
    if severity:
        print(f"severity: {severity}")
    if scan.get("scanType"):
        print(f"scanType: {scan['scanType']}")
    if scan.get("errorMessage"):
        print(f"error: {scan['errorMessage']}", file=sys.stderr)


if __name__ == "__main__":
    main()
