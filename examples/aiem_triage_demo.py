#!/usr/bin/env python3
"""End-to-end AIEM triage demo.

Mirrors the ``demo.py`` pattern — reads from ``AC_ENV`` (or ``env``), pulls the
current AIEM inventory, runs the default rules, prints the plan, and (if
``--apply`` is passed) writes the rule-based changes back to the tenant.

Nothing is written unless ``--apply`` is explicitly given.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from armorcode import ArmorCodeClient
from armorcode.aiem_triage import load_rules, plan_triage, summarize_plan


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--rules", default=os.path.join(
        os.path.dirname(__file__), "..", "rules", "aiem_default.yaml",
    ))
    p.add_argument("--apply", action="store_true",
                   help="Write changes back to the tenant (otherwise dry-run)")
    args = p.parse_args()

    ac = ArmorCodeClient.from_env(os.environ.get("AC_ENV", "env"))

    print("Fetching AIEM inventory …")
    items = ac.aiem_get_all_inventory()
    print(f"  {len(items)} items")

    rules = load_rules(args.rules)
    matched, unmatched = plan_triage(items, rules)
    summary = summarize_plan(matched, unmatched)

    print(f"\nTriage plan ({summary['matched']} matched, "
          f"{summary['unmatched']} unmatched):")
    for rule, n in summary["by_rule"].items():
        print(f"  {rule:40s} {n}")

    if not args.apply:
        print("\nDry-run (no writes). Re-run with --apply to execute.")
        return

    by_id = {it["id"]: it for it in items}
    actionable = [a for a in matched if not a.is_noop(by_id[a.item_id])]
    print(f"\nApplying {len(actionable)} changes …")
    for a in actionable:
        ac.aiem_update_inventory_item(a.item_id, **a.to_update_payload())
        print(f"  ✓ {a.item_name}: {a.matched_rule}")

    if unmatched:
        print(f"\n{len(unmatched)} items unmatched — use "
              f"'python -m cli.aiem review' to queue them for AI triage.")


if __name__ == "__main__":
    main()
