#!/usr/bin/env python3
"""
Upload a CycloneDX SBOM to an ArmorCode tenant and wait for the scan to finish.

The API token decides which tenant the file goes to. Pass it with --token, or
set the ARMORCODE_TOKEN environment variable (preferred: keeps it out of shell
history), or point --env-file at a file containing "token=<value>".

Usage:
    python3 upload_sbom.py <sbom.json> --group <group> --subgroup <subgroup> [options]

Examples:
    export ARMORCODE_TOKEN=<api-token>
    python3 upload_sbom.py host.components_only.json --group SBOM-Imports --subgroup linux-hosts

    # create the group/subgroup if they do not exist, tag the scan, don't wait
    python3 upload_sbom.py host.json --group SBOM-Imports --subgroup linux-hosts \\
        --create --tag sbom_source:uptycs --no-wait

Requires: Python 3.7+, requests (pip install requests).
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

import requests

DEFAULT_URL = "https://app.armorcode.com"
RUNNING_STATUSES = {"INITIATED", "PENDING", "QUEUED", "IN_PROGRESS", "PROCESSING", "INGESTING"}


def load_token(args):
    if args.token:
        return args.token
    if os.environ.get("ARMORCODE_TOKEN"):
        return os.environ["ARMORCODE_TOKEN"]
    if args.env_file:
        for line in Path(args.env_file).read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                if k.strip().lower() == "token":
                    return v.strip().strip('"\'')
    sys.exit("ERROR: no API token. Use --token, ARMORCODE_TOKEN, or --env-file.")


class ArmorCode:
    def __init__(self, base_url, token, timeout=60):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        })

    def _call(self, method, path, **kwargs):
        resp = self.session.request(method, f"{self.base_url}{path}", timeout=self.timeout, **kwargs)
        if resp.status_code == 401:
            sys.exit("ERROR: 401 Unauthorized. Check the API token.")
        resp.raise_for_status()
        return resp.json() if resp.content else {}

    def find_group(self, name):
        """Exact-name match; the search endpoint is a substring search."""
        page = self._call("GET", "/user/product/elastic/paged",
                          params={"pageNumber": 0, "pageSize": 100, "search": name})
        matches = [p for p in page.get("content", []) if p.get("name") == name]
        if len(matches) > 1:
            sys.exit(f"ERROR: {len(matches)} groups named {name!r}: "
                     f"{[m['id'] for m in matches]}. Rename one or use the UI.")
        return matches[0]["id"] if matches else None

    def find_subgroup(self, name, group_id):
        """The short list has only id and name, so confirm the parent per candidate."""
        for s in self._call("GET", "/user/sub-product/elastic/short"):
            if s.get("name") != name:
                continue
            detail = self._call("GET", f"/api/sub-product/{s['id']}")
            if str((detail.get("product") or {}).get("id")) == str(group_id):
                return s["id"]
        return None

    def create_group(self, name):
        return self._call("POST", "/user/product", json={"name": name})["id"]

    def create_subgroup(self, name, group_id):
        return self._call("POST", "/api/sub-product",
                          json={"name": name, "product": {"id": group_id}})["id"]

    def upload_cyclonedx(self, path, group_id, subgroup_id, environment, tags):
        """Two-step upload: register the scan and get a pre-signed URL, then PUT the file."""
        body = {
            "product": group_id,
            "subProduct": subgroup_id,
            "environment": environment,
            "fileName": path.name,
            "fileSizeBytes": path.stat().st_size,
        }
        if tags:
            body["tags"] = tags
        result = self._call("POST", "/user/tools/generic/configurations/CycloneDX/upload", json=body)
        put = requests.put(result["signedUrl"], data=path.read_bytes(),
                           headers={"Content-Type": "application/json"}, timeout=300)
        put.raise_for_status()
        return result["scan"]

    def scan_status(self, scan_id):
        return self._call("GET", f"/api/scans/{scan_id}")


def resolve_target(ac, group, subgroup, create):
    gid = ac.find_group(group)
    if gid is None:
        if not create:
            sys.exit(f"ERROR: group {group!r} not found. Use --create to create it.")
        gid = ac.create_group(group)
        print(f"  created group {group!r} ({gid})")
    sid = ac.find_subgroup(subgroup, gid)
    if sid is None:
        if not create:
            sys.exit(f"ERROR: subgroup {subgroup!r} not found under {group!r}. "
                     f"Use --create to create it.")
        sid = ac.create_subgroup(subgroup, gid)
        print(f"  created subgroup {subgroup!r} ({sid})")
    return gid, sid


def wait_for_scan(ac, scan_id, timeout_s, interval_s=10):
    deadline = time.time() + timeout_s
    while True:
        s = ac.scan_status(scan_id)
        status = s.get("status")
        if status not in RUNNING_STATUSES and status is not None:
            return s
        if time.time() >= deadline:
            print(f"  still {status} after {timeout_s}s; check the scan later in ArmorCode.")
            return s
        time.sleep(interval_s)


def main():
    p = argparse.ArgumentParser(description="Upload a CycloneDX SBOM to ArmorCode.",
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("Usage:")[1])
    p.add_argument("sbom", type=Path, help="CycloneDX JSON file to upload")
    p.add_argument("--group", required=True, help="Group (product) name")
    p.add_argument("--subgroup", required=True, help="Subgroup (sub-product) name")
    p.add_argument("--environment", default="Production", help="Environment (default: Production)")
    p.add_argument("--tag", action="append", dest="tags", metavar="KEY:VALUE",
                   help="Tag to apply to the scan; repeatable")
    p.add_argument("--create", action="store_true",
                   help="Create the group and/or subgroup if they do not exist")
    p.add_argument("--token", help="ArmorCode API token (or set ARMORCODE_TOKEN)")
    p.add_argument("--env-file", help="File containing token=<value>")
    p.add_argument("--url", default=DEFAULT_URL, help=f"ArmorCode URL (default: {DEFAULT_URL})")
    p.add_argument("--no-wait", action="store_true", help="Return after upload; don't poll the scan")
    p.add_argument("--wait-timeout", type=int, default=900,
                   help="Seconds to wait for the scan to finish (default: 900)")
    args = p.parse_args()

    if not args.sbom.is_file():
        sys.exit(f"ERROR: file not found: {args.sbom}")
    try:
        bom = json.loads(args.sbom.read_text(encoding="utf-8"))
    except ValueError as e:
        sys.exit(f"ERROR: {args.sbom} is not valid JSON: {e}")
    if bom.get("bomFormat") != "CycloneDX":
        sys.exit(f"ERROR: {args.sbom} is not a CycloneDX document (bomFormat != CycloneDX)")

    ac = ArmorCode(args.url, load_token(args))

    print(f"[{args.sbom.name}]")
    print(f"  components: {len(bom.get('components', []))}, "
          f"vulnerabilities[]: {len(bom['vulnerabilities']) if 'vulnerabilities' in bom else 'absent'}")
    gid, sid = resolve_target(ac, args.group, args.subgroup, args.create)
    print(f"  target: {args.group} ({gid}) / {args.subgroup} ({sid}) / {args.environment}")

    scan = ac.upload_cyclonedx(args.sbom, gid, sid, args.environment, args.tags)
    print(f"  uploaded, scan id {scan['id']}")
    if args.no_wait:
        return

    s = wait_for_scan(ac, scan["id"], args.wait_timeout)
    print(f"  status: {s.get('status')}")
    for k in ("totalCount", "totalNew", "totalDuplicate"):
        if s.get(k) is not None:
            print(f"  {k}: {s[k]}")
    err = s.get("errMessage") or s.get("errorMessage")
    if err:
        print(f"  error: {err}")
    if s.get("status") == "FAILED":
        sys.exit(1)


if __name__ == "__main__":
    main()
