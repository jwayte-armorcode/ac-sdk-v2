"""AIEM triage rule engine.

Pure logic — no HTTP, no I/O beyond YAML parsing. Given a list of AIEM
inventory items (as returned by ``ArmorCodeClient.aiem_get_all_inventory``)
and a rules config, produce a list of :class:`TriageAction` objects that
describe what should be done to each item.

Rule config format (YAML)::

    meta:
      name: motleyfool-default
      version: 1
    rules:
      - id: R1_trusted_vendor
        description: Auto-approve well-known trusted vendors
        match:
          vendor_in: [Adobe Inc., Microsoft, Google]
          eu_ai_act_tier_in: [Minimal Risk, Limited Risk]
          has_compliance_cert: SOC 2 Type II
        action:
          status: approved
          approval:
            scope: organization
          notes: "Auto-approved: trusted vendor with SOC 2 Type II"
      - id: R4_high_risk_reassess
        match:
          risk_level_in: [high, critical]
        action:
          status: reassessment
          notes: "Elevated risk — security review required"

A rule matches an item when **every** condition under ``match`` evaluates
true. The first matching rule wins (rules are evaluated top-to-bottom).
Items that match no rule are "unmatched" and returned separately for
AI-assisted review.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Action + match result
# ---------------------------------------------------------------------------

@dataclass
class TriageAction:
    """One decision for one inventory item."""

    item_id: str
    item_name: str
    matched_rule: str | None              # None = unmatched
    reasoning: str

    # Fields that will be sent to aiem_update_inventory_item (all optional)
    status: str | None = None
    risk_level: str | None = None
    notes: str | None = None
    approval: dict | None = None
    compliance_tags: list[str] | None = None

    def to_update_payload(self) -> dict:
        """Kwargs for ``ArmorCodeClient.aiem_update_inventory_item``."""
        payload = {}
        for k in ("status", "risk_level", "notes", "approval", "compliance_tags"):
            v = getattr(self, k)
            if v is not None:
                payload[k] = v
        return payload

    def is_noop(self, current_item: dict) -> bool:
        """True if the action would not change this item's current state."""
        for k, v in self.to_update_payload().items():
            if current_item.get(k) != v:
                return False
        return True


# ---------------------------------------------------------------------------
# Rule conditions
# ---------------------------------------------------------------------------

def _catalog(item: dict) -> dict:
    return item.get("catalog") or {}


def _catalog_tags(item: dict, tag_group: str) -> list:
    return ((_catalog(item).get("tags") or {}).get(tag_group)) or []


def _vendor(item: dict) -> str | None:
    return item.get("vendor") or _catalog(item).get("vendor")


def _compliance_certs(item: dict) -> list[str]:
    return (_catalog(item).get("compliance") or {}).get("certifications") or []


_CONDITION_HANDLERS = {
    # Equality / membership
    "status_in":            lambda it, v: it.get("status") in v,
    "risk_level_in":        lambda it, v: it.get("risk_level") in v,
    "vendor_in":            lambda it, v: _vendor(it) in v,
    "vendor_not_in":        lambda it, v: _vendor(it) not in v,
    "type_in":              lambda it, v: any(t in v for t in (it.get("type") or [])),
    "detection_source_in":  lambda it, v: it.get("source") in v,
    "name_contains_any":    lambda it, v: any(s.lower() in (it.get("name") or "").lower() for s in v),
    # Catalog-derived tags
    "eu_ai_act_tier_in":    lambda it, v: any(t in v for t in _catalog_tags(it, "risk_tier")),
    "deployment_model_in":  lambda it, v: any(t in v for t in _catalog_tags(it, "deployment_model")),
    "data_handling_has":    lambda it, v: v in _catalog_tags(it, "data_handling"),
    "data_handling_any":    lambda it, v: any(t in _catalog_tags(it, "data_handling") for t in v),
    "security_feature_has": lambda it, v: v in _catalog_tags(it, "security_features"),
    "security_features_all":lambda it, v: all(t in _catalog_tags(it, "security_features") for t in v),
    "has_compliance_cert":  lambda it, v: v in _compliance_certs(it),
    "has_any_compliance_cert": lambda it, v: any(c in _compliance_certs(it) for c in v),
    # Thresholds
    "user_count_gte":       lambda it, v: (it.get("usage") or {}).get("user_count", 0) >= v,
    "user_count_lt":        lambda it, v: (it.get("usage") or {}).get("user_count", 0) < v,
}


def _match_rule(item: dict, rule: dict) -> bool:
    match = rule.get("match") or {}
    for cond, expected in match.items():
        handler = _CONDITION_HANDLERS.get(cond)
        if handler is None:
            raise ValueError(
                f"Unknown rule condition {cond!r} in rule "
                f"{rule.get('id','<unnamed>')}. "
                f"Supported: {sorted(_CONDITION_HANDLERS)}"
            )
        if not handler(item, expected):
            return False
    return True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_rules(path):
    """Load a rules file (YAML).

    Returns:
        dict: Parsed rules config with ``meta`` and ``rules`` keys.
    """
    import yaml  # lazy import — PyYAML only required when triage is used

    text = Path(path).read_text()
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or "rules" not in data:
        raise ValueError(f"{path}: expected a dict with a 'rules' key")
    return data


def plan_triage(items, rules_config):
    """Evaluate rules against items and return the triage plan.

    Args:
        items: List of inventory-item dicts.
        rules_config: Parsed rules config (from :func:`load_rules`).

    Returns:
        tuple: ``(matched_actions, unmatched_items)``

        * ``matched_actions`` — list of :class:`TriageAction`, one per item
          that matched a rule.
        * ``unmatched_items`` — list of the raw item dicts that no rule
          matched (candidates for AI review).
    """
    rules = rules_config.get("rules", [])
    matched: list[TriageAction] = []
    unmatched: list[dict] = []

    for item in items:
        hit = None
        for rule in rules:
            if _match_rule(item, rule):
                hit = rule
                break

        if hit is None:
            unmatched.append(item)
            continue

        action_spec = hit.get("action") or {}
        reasoning = _build_reasoning(item, hit)
        matched.append(TriageAction(
            item_id=item["id"],
            item_name=item.get("name", "<unnamed>"),
            matched_rule=hit.get("id", "<unnamed-rule>"),
            reasoning=reasoning,
            status=action_spec.get("status"),
            risk_level=action_spec.get("risk_level"),
            notes=action_spec.get("notes"),
            approval=action_spec.get("approval"),
            compliance_tags=action_spec.get("compliance_tags"),
        ))

    return matched, unmatched


def _build_reasoning(item: dict, rule: dict) -> str:
    """Build a short human-readable reason string for why a rule fired."""
    parts = [f"matched rule '{rule.get('id','?')}'"]
    if rule.get("description"):
        parts.append(rule["description"])
    signals = []
    match = rule.get("match") or {}
    if "vendor_in" in match:
        signals.append(f"vendor={_vendor(item)}")
    if "eu_ai_act_tier_in" in match:
        signals.append(f"eu_ai_act={_catalog_tags(item, 'risk_tier')}")
    if "risk_level_in" in match:
        signals.append(f"risk_level={item.get('risk_level')}")
    if "has_compliance_cert" in match:
        signals.append(f"cert={match['has_compliance_cert']}")
    if signals:
        parts.append("signals: " + ", ".join(signals))
    return " — ".join(parts)


def summarize_plan(matched, unmatched):
    """Return a dict summary of a triage plan, grouped by rule and by action."""
    from collections import Counter
    by_rule = Counter(a.matched_rule for a in matched)
    by_status = Counter(a.status for a in matched if a.status)
    return {
        "total_items": len(matched) + len(unmatched),
        "matched": len(matched),
        "unmatched": len(unmatched),
        "by_rule": dict(by_rule),
        "by_action_status": dict(by_status),
    }
