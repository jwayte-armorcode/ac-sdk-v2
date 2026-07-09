#!/usr/bin/env python3
"""Upload findings to ArmorCode — small examples of all four methods.

Methods (see docs/uploading-findings.md):
  1. Generic JSON     — POST /api/findings/upload            (wrapped: upload_findings)
  2. CSV multipart    — POST /user/findings/upload/csv       (via ac._session)
  3. CSV -> custom tool via presigned S3
                      — POST /user/tools/generic/configurations/{tool}/upload
  4. Native scan report (multipart S3)
                      — POST /api/v2/scans/upload/initiate -> presign -> complete

These all WRITE to the tenant. Run only against a sandbox unless you mean it.

Usage:
    python examples/upload_findings.py --env /path/to/env \
        --product "sdk-test-product" --subproduct "api" --environment Production \
        [--method 1|2|3|4|all] [--tool custom-SCA-Sample-Findings]

The env file may use either the SDK's TENANT_URL/API_TOKEN shape or the
lowercase url=/token= sandbox shape; this script handles both.
"""
import argparse
import csv
import io
import json
import os
import sys

import requests

# Allow running from the repo root without installing the package.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from armorcode import ArmorCodeClient


def load_client(env_path):
    """Build an ArmorCodeClient from either env shape.

    SDK's from_env expects TENANT_URL (bare host) + API_TOKEN. The sandbox env
    uses lowercase url=https://host and token=. Parse manually and normalise.
    """
    kv = {}
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                kv[k.strip()] = v.strip()

    url = kv.get("TENANT_URL") or kv.get("url") or kv.get("tenant_url")
    token = kv.get("API_TOKEN") or kv.get("token") or kv.get("read_token")
    if not url or not token:
        raise SystemExit(f"Could not find url/token in {env_path}")

    host = url.replace("https://", "").replace("http://", "").rstrip("/")
    return ArmorCodeClient(host, token=token)


def sample_findings(n=2):
    """A couple of Generic-JSON findings."""
    out = []
    for i in range(1, n + 1):
        out.append({
            "Title": f"[SDK example] Hardcoded secret {i}",
            "Severity": "Medium",
            "Description": "Example finding created by examples/upload_findings.py",
            "ToolFindingId": f"sdk-example-upload-{i:03d}",  # dedup key
            "Category": "SECURITY",
        })
    return out


def sample_csv_bytes(n=5):
    """A tiny findings CSV (comma columns; ';' for multi-value cells)."""
    cols = ["ToolFindingId", "Title", "Severity", "Description", "Cve"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for i in range(1, n + 1):
        w.writerow([
            f"sdk-csv-example-{i:03d}",
            f"[SDK CSV example] Vulnerable dependency {i}",
            "Low",
            "Example CSV finding from examples/upload_findings.py",
            "CVE-2026-54291",
        ])
    return buf.getvalue().encode()


# --------------------------------------------------------------------------
# Method 1 — Generic JSON  (wrapped)
# --------------------------------------------------------------------------
def method_1_generic_json(ac, product, subproduct, environment):
    print("\n[1] Generic JSON  ->  POST /api/findings/upload")
    resp = ac.upload_findings(
        sample_findings(2),
        product=product,
        sub_product=subproduct,
        environment=environment,
    )
    print("    response:", resp)
    return resp


# --------------------------------------------------------------------------
# Method 2 — CSV multipart  (not wrapped)
# --------------------------------------------------------------------------
def method_2_csv_multipart(ac):
    print("\n[2] CSV multipart  ->  POST /user/findings/upload/csv")
    files = {"file": ("sdk-example.csv", sample_csv_bytes(), "text/csv")}
    # The client session pins Content-Type: application/json. For a multipart
    # upload we must let requests set the multipart boundary itself — so send
    # only the auth header, not the JSON content-type.
    headers = {"Authorization": ac._session.headers["Authorization"]}
    resp = requests.post(
        f"{ac.base_url}/user/findings/upload/csv",
        files=files,
        headers=headers,
        timeout=120,
    )
    print("    HTTP", resp.status_code, "->", (resp.text or "")[:200])
    return resp.status_code


# --------------------------------------------------------------------------
# Method 3 — CSV -> custom tool via presigned S3  (not wrapped)
# --------------------------------------------------------------------------
def method_3_csv_custom_tool(ac, product_id, subproduct_id, environment, tool_name):
    print(f"\n[3] CSV -> custom tool '{tool_name}'  ->  presign + PUT")
    body = {
        "product": product_id,
        "subProduct": subproduct_id,
        "environment": environment,
        "fileName": "sdk-example-sca.csv",
        "customTool": True,
    }
    r = ac._session.post(
        f"{ac.base_url}/user/tools/generic/configurations/{tool_name}/upload",
        json=body,
        timeout=90,
    )
    if r.status_code != 200:
        print("    presign HTTP", r.status_code, "->", (r.text or "")[:200])
        return r.status_code
    signed = r.json()["signedUrl"]
    print("    presign OK; signed host:", signed.split("/")[2])
    put = requests.put(signed, data=sample_csv_bytes(), headers={"Content-Type": "text/csv"}, timeout=120)
    print("    S3 PUT HTTP", put.status_code)
    return put.status_code


# --------------------------------------------------------------------------
# Method 4 — native scan report (multipart S3)  (not wrapped) — initiate only
# --------------------------------------------------------------------------
def method_4_native_scan(ac, product_id, subproduct_id, environment):
    print("\n[4] Native scan report  ->  POST /api/v2/scans/upload/initiate")
    body = {
        "product": product_id,
        "subProduct": subproduct_id,
        "environment": environment,
        "fileName": "sdk-example-report.json",
    }
    # toolName must be a NATIVE ArmorCode scanner (e.g. Snyk, Trivy, Semgrep),
    # not a custom tool — the initiate step rejects custom tools here.
    r = ac._session.post(
        f"{ac.base_url}/api/v2/scans/upload/initiate",
        params={"toolName": "Snyk", "totalParts": 1},
        json=body,
        timeout=90,
    )
    print("    initiate HTTP", r.status_code, "->", (r.text or "")[:160])
    if r.status_code == 200:
        upload_id = (r.json().get("data") or {}).get("uploadId")
        print("    uploadId:", (upload_id or "")[:40], "...")
    print("    (full flow: initiate -> presign each part -> PUT -> complete)")
    return r.status_code


def main():
    ap = argparse.ArgumentParser(description="Upload findings — 4 methods")
    ap.add_argument("--env", default="env", help="path to env file")
    ap.add_argument("--product", default="sdk-test-product")
    ap.add_argument("--subproduct", default="api")
    ap.add_argument("--environment", default="Production")
    ap.add_argument("--tool", default="custom-SCA-Sample-Findings")
    ap.add_argument("--method", default="all", choices=["1", "2", "3", "4", "all"])
    args = ap.parse_args()

    ac = load_client(args.env)
    print(f"Connected: {ac.base_url}")

    # Method 3/4 need numeric ids; resolve via the SDK's own lookups.
    pid = sid = None
    if args.method in ("3", "4", "all"):
        pid = ac._lookup_product_id(args.product)
        sid = ac._lookup_sub_product_id(args.subproduct)
        print(f"Resolved product={args.product!r}->{pid}, subproduct={args.subproduct!r}->{sid}")

    if args.method in ("1", "all"):
        method_1_generic_json(ac, args.product, args.subproduct, args.environment)
    if args.method in ("2", "all"):
        method_2_csv_multipart(ac)
    if args.method in ("3", "all"):
        method_3_csv_custom_tool(ac, pid, sid, args.environment, args.tool)
    if args.method in ("4", "all"):
        method_4_native_scan(ac, pid, sid, args.environment)


if __name__ == "__main__":
    main()
