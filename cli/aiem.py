"""AIEM triage CLI.

Usage::

    python -m cli.aiem scan
    python -m cli.aiem plan --rules rules/aiem_default.yaml
    python -m cli.aiem apply --rules rules/aiem_default.yaml [--yes]
    python -m cli.aiem review [--out queue.json]
    python -m cli.aiem ai-review --mode api|file [--queue ...] [--out ...]
    python -m cli.aiem apply-ai proposals.json [--yes]

Subcommands
-----------
scan        Summarize current inventory (status/risk/type/source breakdowns).
plan        Dry-run: show what each deterministic rule would do to each item.
apply       Execute the rule-based plan. Prompts per item unless --yes.
review      Collect rule-unmatched items into a JSON queue for AI review.
ai-review   Produce AI proposals from the queue.
              --mode api : call the Anthropic API directly (needs ANTHROPIC_API_KEY)
              --mode file: write the queue only; user runs claude externally,
                           then feeds proposals back via apply-ai.
apply-ai    Apply AI-produced proposals through the same write path.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

# Allow running as `python -m cli.aiem` OR directly as `python cli/aiem.py`
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from armorcode import ArmorCodeClient  # noqa: E402
from armorcode.aiem_triage import (  # noqa: E402
    TriageAction, load_rules, plan_triage, summarize_plan,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _client(env_path):
    return ArmorCodeClient.from_env(env_path)


def _fmt_action(a: TriageAction) -> str:
    parts = []
    if a.status: parts.append(f"status→{a.status}")
    if a.risk_level: parts.append(f"risk→{a.risk_level}")
    if a.approval: parts.append(f"scope={a.approval.get('scope')}")
    return " ".join(parts) or "(no-op)"


def _confirm(prompt: str) -> bool:
    try:
        return input(f"{prompt} [y/N] ").strip().lower() == "y"
    except EOFError:
        return False


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

def cmd_scan(args):
    ac = _client(args.env)
    items = ac.aiem_get_all_inventory()
    print(f"AIEM inventory: {len(items)} items on {ac.base_url}\n")

    def counts(field):
        if "." in field:
            head, tail = field.split(".", 1)
            c = Counter()
            for it in items:
                sub = it.get(head) or {}
                v = sub.get(tail) if isinstance(sub, dict) else None
                c[v] += 1
            return c
        return Counter(it.get(field) for it in items)

    def print_counts(label, c):
        print(f"  {label}:")
        for k, v in c.most_common():
            print(f"    {str(k):35s} {v}")
        print()

    print_counts("status", counts("status"))
    print_counts("risk_level", counts("risk_level"))
    print_counts("detection source", counts("source"))

    # type is a list field — flatten
    types = Counter()
    for it in items:
        for t in (it.get("type") or []): types[t] += 1
    print_counts("type (flattened)", types)

    # EU AI Act tier from catalog
    tiers = Counter()
    for it in items:
        rt = ((it.get("catalog") or {}).get("tags") or {}).get("risk_tier") or []
        if rt:
            for t in rt: tiers[t] += 1
        else:
            tiers["(none)"] += 1
    print_counts("EU AI Act tier", tiers)

    # total users + top items
    total_users = sum((it.get("usage") or {}).get("user_count") or 0 for it in items)
    print(f"  total user interactions: {total_users}\n")


# ---------------------------------------------------------------------------
# plan
# ---------------------------------------------------------------------------

def _build_plan(ac, rules_path):
    items = ac.aiem_get_all_inventory()
    rules = load_rules(rules_path)
    matched, unmatched = plan_triage(items, rules)
    return items, matched, unmatched


def cmd_plan(args):
    ac = _client(args.env)
    items, matched, unmatched = _build_plan(ac, args.rules)
    summary = summarize_plan(matched, unmatched)

    print(f"Triage plan — {summary['total_items']} items\n")
    print(f"  matched by rules:   {summary['matched']}")
    print(f"  unmatched (→ AI):   {summary['unmatched']}\n")

    print("  by rule:")
    for rule, n in summary["by_rule"].items():
        print(f"    {rule:40s} {n}")
    print("\n  by action status:")
    for st, n in summary["by_action_status"].items():
        print(f"    {str(st):40s} {n}")

    if args.verbose:
        # Build item_id → current-state map
        by_id = {it["id"]: it for it in items}
        print("\n--- per-item actions ---")
        for a in matched:
            cur = by_id[a.item_id]
            noop = " [no-op]" if a.is_noop(cur) else ""
            print(f"  {a.item_name[:40]:40s} {_fmt_action(a):35s} {a.matched_rule}{noop}")
        if unmatched:
            print("\n--- unmatched (→ AI review) ---")
            for it in unmatched:
                print(f"  {it.get('name','?')[:40]:40s} risk={it.get('risk_level')} type={(it.get('type') or [''])[0]}")


# ---------------------------------------------------------------------------
# apply
# ---------------------------------------------------------------------------

def cmd_apply(args):
    ac = _client(args.env)
    items, matched, unmatched = _build_plan(ac, args.rules)
    by_id = {it["id"]: it for it in items}

    actionable = [a for a in matched if not a.is_noop(by_id[a.item_id])]
    print(f"Plan: {len(matched)} rule matches — {len(actionable)} require a write "
          f"({len(matched) - len(actionable)} no-ops skipped)\n")

    applied = skipped = failed = 0
    for a in actionable:
        cur = by_id[a.item_id]
        print(f"  {a.item_name}")
        print(f"    current: status={cur.get('status')} risk={cur.get('risk_level')}")
        print(f"    action:  {_fmt_action(a)}  [{a.matched_rule}]")
        if not args.yes and not _confirm("    apply?"):
            skipped += 1
            continue
        try:
            ac.aiem_update_inventory_item(a.item_id, **a.to_update_payload())
            applied += 1
            print("    ✓ applied\n")
        except Exception as e:
            failed += 1
            print(f"    ✗ failed: {e}\n")

    print(f"\nDone. applied={applied} skipped={skipped} failed={failed}")


# ---------------------------------------------------------------------------
# review — dump unmatched to JSON queue
# ---------------------------------------------------------------------------

def _queue_payload(unmatched: list[dict]) -> dict:
    """Trim unmatched items to just the context the AI needs."""
    def trim(it):
        cat = it.get("catalog") or {}
        tags = cat.get("tags") or {}
        return {
            "id": it["id"],
            "name": it.get("name"),
            "vendor": it.get("vendor") or cat.get("vendor"),
            "description": it.get("description") or cat.get("description_short"),
            "type": it.get("type"),
            "status": it.get("status"),
            "risk_level": it.get("risk_level"),
            "source": it.get("source"),
            "user_count": (it.get("usage") or {}).get("user_count"),
            "catalog_tags": {
                "eu_ai_act_tier": tags.get("risk_tier"),
                "ai_type": tags.get("ai_type"),
                "data_handling": tags.get("data_handling"),
                "security_features": tags.get("security_features"),
                "compliance_certifications": tags.get("compliance_certifications"),
                "deployment_model": tags.get("deployment_model"),
                "use_case": tags.get("use_case"),
            },
            "compliance_certs": (cat.get("compliance") or {}).get("certifications"),
            "risk_classification_reason": cat.get("risk_classification_reason"),
        }
    return {
        "version": 1,
        "instructions": (
            "For each item below, recommend an AIEM triage decision. "
            "Allowed status values: pending, approved, conditional, rejected, reassessment. "
            "Allowed risk_level values: critical, high, moderate, low. "
            "If proposing 'approved' or 'conditional', include an 'approval' object "
            "with {scope: organization|department|individual, conditions: '<text>'}. "
            "Return a JSON array of {id, status, risk_level?, notes, approval?, reasoning} "
            "objects — one per input item. The 'reasoning' field is for the human reviewer."
        ),
        "items": [trim(it) for it in unmatched],
    }


def cmd_review(args):
    ac = _client(args.env)
    _, _, unmatched = _build_plan(ac, args.rules)
    payload = _queue_payload(unmatched)
    Path(args.out).write_text(json.dumps(payload, indent=2, default=str))
    print(f"Wrote {len(unmatched)} items to {args.out}")
    print("Next: python -m cli.aiem ai-review --mode api|file --queue", args.out)


# ---------------------------------------------------------------------------
# ai-review — produce proposals from the queue
# ---------------------------------------------------------------------------

_AI_REVIEW_SYSTEM_PROMPT = """\
You are assisting with AI governance triage for an enterprise security team.
You will receive a JSON payload describing AI apps detected in the company's
environment that did not match any deterministic rule. For each item,
produce a single JSON object with:

  - id                 (echoed from input)
  - status             ∈ approved | conditional | rejected | reassessment | pending
  - risk_level         ∈ critical | high | moderate | low  (optional; only if changing)
  - notes              short reviewer-facing explanation
  - approval           object, required if status is 'approved' or 'conditional':
                         {scope: 'organization'|'department'|'individual',
                          conditions: '<text>',  (optional)
                          departments: [<str>],   (optional)
                          expires_at: 'YYYY-MM-DD'} (optional)
  - reasoning          1-3 sentences justifying your decision

Be conservative: when in doubt, prefer 'reassessment' over 'approved'.
Return ONLY a valid JSON array of these objects. No prose, no markdown fences.
"""


def _ai_review_via_api(queue_payload: dict, model: str) -> list[dict]:
    """Call the Anthropic API to produce proposals. Lazy import."""
    try:
        import anthropic  # type: ignore
    except ImportError:
        raise SystemExit(
            "--mode api requires the 'anthropic' package. "
            "Install with: pip install anthropic"
        )

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise SystemExit("Set ANTHROPIC_API_KEY to use --mode api.")

    client = anthropic.Anthropic(api_key=api_key)
    user_msg = json.dumps(queue_payload, default=str)

    resp = client.messages.create(
        model=model,
        max_tokens=8192,
        system=_AI_REVIEW_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_msg}],
    )
    text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
    text = text.strip()
    # Strip code fences if the model ignored instructions
    if text.startswith("```"):
        text = text.split("```", 2)[1]
        if text.startswith("json"):
            text = text[4:]
    return json.loads(text)


def cmd_ai_review(args):
    queue = json.loads(Path(args.queue).read_text())
    out_path = Path(args.out)

    if args.mode == "file":
        # The queue *is* the input; just echo it out with a hint file
        instructions = (
            f"AI review queue written at {args.queue}.\n\n"
            "Run Claude Code (or any LLM) against this file and ask it to produce\n"
            "a JSON array of proposals matching the 'instructions' block in the file.\n"
            f"Save the resulting JSON to: {out_path}\n\n"
            "Then apply with:\n"
            f"  python -m cli.aiem apply-ai {out_path}\n"
        )
        print(instructions)
        return

    # --mode api
    print(f"Sending {len(queue['items'])} items to {args.model} …")
    proposals = _ai_review_via_api(queue, model=args.model)
    out_path.write_text(json.dumps(proposals, indent=2, default=str))
    print(f"Wrote {len(proposals)} proposals to {out_path}")
    print(f"Next: python -m cli.aiem apply-ai {out_path}")


# ---------------------------------------------------------------------------
# apply-ai — apply AI proposals through the SDK
# ---------------------------------------------------------------------------

def cmd_apply_ai(args):
    ac = _client(args.env)
    proposals = json.loads(Path(args.proposals).read_text())
    if not isinstance(proposals, list):
        raise SystemExit("Proposals file must contain a JSON array.")

    # Fetch current state so we can show diffs
    current = {it["id"]: it for it in ac.aiem_get_all_inventory()}

    applied = skipped = failed = 0
    for p in proposals:
        item_id = p.get("id")
        if item_id not in current:
            print(f"  [skip] unknown id {item_id}")
            skipped += 1
            continue
        cur = current[item_id]
        # Build a TriageAction so the no-op check is uniform
        action = TriageAction(
            item_id=item_id,
            item_name=cur.get("name", ""),
            matched_rule="AI",
            reasoning=p.get("reasoning", ""),
            status=p.get("status"),
            risk_level=p.get("risk_level"),
            notes=p.get("notes"),
            approval=p.get("approval"),
            compliance_tags=p.get("compliance_tags"),
        )
        if action.is_noop(cur):
            skipped += 1
            continue

        print(f"  {cur.get('name')}")
        print(f"    current: status={cur.get('status')} risk={cur.get('risk_level')}")
        print(f"    action:  {_fmt_action(action)}  [AI: {action.reasoning[:80]}]")
        if not args.yes and not _confirm("    apply?"):
            skipped += 1
            continue
        try:
            ac.aiem_update_inventory_item(item_id, **action.to_update_payload())
            applied += 1
            print("    ✓ applied\n")
        except Exception as e:
            failed += 1
            print(f"    ✗ failed: {e}\n")

    print(f"\nDone. applied={applied} skipped={skipped} failed={failed}")


# ---------------------------------------------------------------------------
# argparse wiring
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="cli.aiem",
        description="Deterministic + AI-assisted triage for AIEM inventory.",
    )
    p.add_argument("--env", default="env", help="Path to env file (default: ./env)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="Summarize current inventory")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("plan", help="Dry-run: show what rules would do")
    s.add_argument("--rules", default="rules/aiem_default.yaml")
    s.add_argument("-v", "--verbose", action="store_true",
                   help="Print per-item actions")
    s.set_defaults(func=cmd_plan)

    s = sub.add_parser("apply", help="Execute rule-based triage")
    s.add_argument("--rules", default="rules/aiem_default.yaml")
    s.add_argument("--yes", action="store_true",
                   help="Skip per-item confirmation")
    s.set_defaults(func=cmd_apply)

    s = sub.add_parser("review", help="Dump unmatched items to JSON queue")
    s.add_argument("--rules", default="rules/aiem_default.yaml")
    s.add_argument("--out", default="aiem_ai_review_queue.json")
    s.set_defaults(func=cmd_review)

    s = sub.add_parser("ai-review", help="Produce AI proposals from the queue")
    s.add_argument("--mode", choices=["api", "file"], required=True,
                   help="api: call Anthropic directly; file: print instructions")
    s.add_argument("--queue", default="aiem_ai_review_queue.json")
    s.add_argument("--out", default="aiem_ai_review_proposals.json")
    s.add_argument("--model", default="claude-opus-4-7",
                   help="Anthropic model ID (for --mode api)")
    s.set_defaults(func=cmd_ai_review)

    s = sub.add_parser("apply-ai", help="Apply AI proposals")
    s.add_argument("proposals", help="Path to the proposals JSON file")
    s.add_argument("--yes", action="store_true")
    s.set_defaults(func=cmd_apply_ai)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
