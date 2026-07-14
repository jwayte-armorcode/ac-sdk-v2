#!/usr/bin/env python3
"""Bulk-import assets into ArmorCode via the pre-signed S3 upload flow.

POST /api/v2/assets/upload is a three-step asynchronous flow (wrapped by the
SDK's upload_assets()):
  1. POST metadata (toolName, assetType, delimiter, fileName) -> pre-signed S3 URL
  2. PUT the CSV bytes to that S3 URL
  3. ArmorCode ingests the file asynchronously; assets appear under
     Explore > Assets within a few minutes, tagged source == toolName.

This WRITES to the tenant. Run only against a sandbox unless you mean it.

Usage:
    python examples/upload_assets.py --env /path/to/env \
        [--tool-name Custom-CMDB] [--asset-type HOST] [--csv /path/to/assets.csv] \
        [--verify]

With no --csv, a couple of sample HOST assets are uploaded. --verify polls
get_assets() afterwards to confirm the async import landed.
"""
import argparse
import os
import sys
import time

# Allow running from the repo root without installing the package.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from armorcode import ArmorCodeClient


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
    if not url or not token:
        raise SystemExit(f"Could not find url/token in {env_path}")

    host = url.replace("https://", "").replace("http://", "").rstrip("/")
    return ArmorCodeClient(host, token=token)


def sample_assets():
    """A couple of HOST assets. Each row needs at least one of Name / IPv4 /
    DNS Name; unrecognized columns become asset Tags."""
    return [
        {"Name": "sdk-example-host-1", "IPv4": "10.77.0.1",
         "Operating System": "Ubuntu 22.04"},
        {"Name": "sdk-example-host-2", "IPv4": "10.77.0.2",
         "Operating System": "Windows Server 2019"},
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", default="env", help="Path to env file")
    ap.add_argument("--tool-name", default="SDK-Example-Assets",
                    help="Source identifier applied to imported assets")
    ap.add_argument("--asset-type", default="HOST",
                    choices=ArmorCodeClient.ASSET_TYPES)
    ap.add_argument("--csv", help="Path to an existing .csv to upload as-is")
    ap.add_argument("--verify", action="store_true",
                    help="Poll get_assets() to confirm the async import")
    args = ap.parse_args()

    ac = load_client(args.env)

    payload = args.csv if args.csv else sample_assets()
    file_name = os.path.basename(args.csv) if args.csv else "sdk-example-assets.csv"

    result = ac.upload_assets(
        payload,
        tool_name=args.tool_name,
        asset_type=args.asset_type,
        file_name=file_name,
    )
    print("upload_assets ->", {k: v for k, v in result.items() if k != "signedUrl"})
    print("File accepted. Ingestion is asynchronous.")

    if args.verify:
        for attempt in range(6):
            found = ac.get_assets(source=args.tool_name)
            print(f"poll {attempt + 1}: {len(found)} assets from {args.tool_name!r}")
            if found:
                for a in found:
                    print("   ->", {k: a.get(k) for k in ("name", "ipv4", "source", "id")})
                return
            time.sleep(30)
        print("Not visible yet — ingestion can take a few minutes; poll again later.")


if __name__ == "__main__":
    main()
