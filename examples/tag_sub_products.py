#!/usr/bin/env python3
"""Add tags to one, several, or hundreds of sub-groups (sub-products).

Sub-group names are taken from the command line, a CSV file, or both. Tagging is
non-destructive: existing tags are preserved and duplicates skipped.

Ambiguous names (more than one sub-group sharing a name) are skipped by default
and reported; pass --force to tag every match, or --id to target one precisely.

Examples::

    # preview against a couple of sub-groups, writing nothing
    python tag_sub_products.py --env ../JulianSandbox/env \
        --tag pci-scope --sub-group ac-sdk-v2 --sub-group api --dry-run

    # hundreds of sub-groups from a CSV
    python tag_sub_products.py --env ../JulianSandbox/env \
        --tag pci-scope --csv sub_groups.csv --dry-run

    # tag both sub-groups that share an ambiguous name
    python tag_sub_products.py --env ../JulianSandbox/env \
        --tag pci-scope --sub-group docusaurus --force
"""
import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from armorcode import ArmorCodeClient  # noqa: E402


def read_csv_names(path, column=None):
    """Read sub-group names from a CSV.

    Uses ``column`` if given, else a column named 'name'/'sub_group'/
    'sub_product' when a header is present, else the first column.
    """
    KNOWN = ("name", "sub_group", "sub-group", "sub_product", "subproduct",
             "sub group")

    with open(path, newline="") as f:
        rows = [row for row in csv.reader(f) if row and any(c.strip() for c in row)]

    if not rows:
        return []

    header = [c.strip() for c in rows[0]]
    # Treat the first row as a header only on explicit evidence: either the
    # caller named a column, or a cell matches a known column name. Sniffing is
    # deliberately avoided - it silently misreads single-column name lists and
    # drops the first sub-group.
    if column:
        if column not in header:
            raise SystemExit(f"Column {column!r} not in CSV header: {header}")
        idx = header.index(column)
        body = rows[1:]
    elif any(c.lower() in KNOWN for c in header):
        idx = next(i for i, c in enumerate(header) if c.lower() in KNOWN)
        body = rows[1:]
    else:
        idx = 0
        body = rows

    return [
        row[idx].strip() for row in body
        if len(row) > idx and row[idx].strip()
    ]


def main():
    p = argparse.ArgumentParser(
        description="Add tags to a set of ArmorCode sub-groups (sub-products).",
    )
    p.add_argument("--env", default="env", help="Path to env file (default: env)")
    p.add_argument("--tag", action="append", required=True, metavar="TAG",
                   help="Tag to add; repeat for several")
    p.add_argument("--sub-group", action="append", default=[], metavar="NAME",
                   help="Sub-group name; repeat, or use a comma-separated list")
    p.add_argument("--csv", metavar="PATH",
                   help="CSV of sub-group names (one per row)")
    p.add_argument("--csv-column", metavar="COL",
                   help="CSV column holding names (default: auto-detect)")
    p.add_argument("--id", action="append", default=[], type=int,
                   metavar="ID", help="Sub-group id, bypassing name lookup")
    p.add_argument("--force", action="store_true",
                   help="Tag all matches when a name is ambiguous")
    p.add_argument("--dry-run", action="store_true",
                   help="Resolve and report without writing")
    args = p.parse_args()

    names = []
    for entry in args.sub_group:
        names.extend(n.strip() for n in entry.split(",") if n.strip())
    if args.csv:
        names.extend(read_csv_names(args.csv, args.csv_column))

    # Preserve order, drop repeats so a name is not tagged twice.
    names = list(dict.fromkeys(names))

    if not names and not args.id:
        raise SystemExit("Nothing to do: pass --sub-group, --csv, or --id")

    client = ArmorCodeClient.from_env(args.env)
    print(f"tenant     : {client.base_url}")
    print(f"tags       : {args.tag}")
    print(f"sub-groups : {len(names)} by name, {len(args.id)} by id")
    if args.dry_run:
        print("mode       : DRY RUN - nothing will be written")
    print()

    result = client.bulk_add_sub_product_tags(
        args.tag,
        sub_product_names=names,
        sub_product_ids=args.id,
        force=args.force,
        dry_run=args.dry_run,
    )

    verb = "would tag" if args.dry_run else "tagged"
    for e in result["updated"]:
        print(f"  [{verb}] {e['name']} (id={e['id']}) += {e['tags_added']}")
    for e in result["skipped"]:
        label = e.get("name") or e.get("id")
        print(f"  [skip] {label}: {e['reason']}")
    for e in result["failed"]:
        label = e.get("name") or e.get("id")
        print(f"  [FAIL] {label}: {e['reason']}")

    print()
    print(f"{verb}: {len(result['updated'])}  "
          f"skipped: {len(result['skipped'])}  "
          f"failed: {len(result['failed'])}")

    if args.dry_run and result["updated"]:
        print("\nRe-run without --dry-run to apply.")

    return 1 if result["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
