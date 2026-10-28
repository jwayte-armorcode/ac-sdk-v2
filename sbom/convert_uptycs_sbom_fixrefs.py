#!/usr/bin/env python3
"""
Convert Uptycs CycloneDX SBOM exports into a form ArmorCode ingests correctly.

Usage:
    python3 convert_uptycs_sbom_fixrefs.py <input.json> [output.json]
    python3 convert_uptycs_sbom_fixrefs.py <input_dir> <output_dir>   # batch mode

If output.json is omitted, "<input>.armorcode.json" is written next to the input.
In batch mode, every *.json file in input_dir is converted into output_dir with
the same filename.
"""
import json
import re
import sys
from pathlib import Path

PURL_REF_RE = re.compile(r"#(pkg:.+)$")

SEVERITY_TITLE_CASE = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
    "none": "Info",
    "unknown": "Info",
}


def build_purl_index(components):
    """Map purl -> bom-ref, and purl -> component name/version, for every
    component in the SBOM (including nested components, if any)."""
    purl_to_bomref = {}
    purl_to_name = {}

    def index(comp):
        purl = comp.get("purl")
        bom_ref = comp.get("bom-ref")
        if purl and bom_ref:
            purl_to_bomref[purl] = bom_ref
            purl_to_name[purl] = (comp.get("name"), comp.get("version"))
        for nested in comp.get("components", []) or []:
            index(nested)

    for c in components:
        index(c)
    return purl_to_bomref, purl_to_name


def fix_vulnerability_refs(sbom, stats):
    """Uptycs writes vulnerabilities[].affects[].ref as
    "urn:cdx:<serialNumber>/<version>#<purl>" instead of the component's
    actual bom-ref. ArmorCode (like any CycloneDX-conformant consumer)
    resolves a vulnerability's affected component by looking up that ref
    against components[].bom-ref, so every affected-component link silently
    fails to resolve and findings show up without correct module/component
    attribution. Rewrite each ref to the real bom-ref by extracting the
    embedded purl and looking it up."""
    components = sbom.get("components", [])
    bom_refs = set()

    def collect_bomrefs(comp):
        if comp.get("bom-ref"):
            bom_refs.add(comp["bom-ref"])
        for nested in comp.get("components", []) or []:
            collect_bomrefs(nested)

    for c in components:
        collect_bomrefs(c)

    purl_to_bomref, _ = build_purl_index(components)

    total = 0
    rewritten = 0
    unresolved = []

    for vuln in sbom.get("vulnerabilities", []):
        for affect in vuln.get("affects", []):
            total += 1
            ref = affect.get("ref", "")
            if ref in bom_refs:
                continue  # already a valid bom-ref
            match = PURL_REF_RE.search(ref)
            purl = match.group(1) if match else None
            new_ref = purl_to_bomref.get(purl) if purl else None
            if new_ref:
                affect["ref"] = new_ref
                rewritten += 1
            else:
                unresolved.append({"vulnId": vuln.get("id"), "ref": ref})

    stats["affects_total"] = total
    stats["affects_rewritten"] = rewritten
    stats["affects_unresolved"] = unresolved
    return sbom


def fix_severity_case(sbom, stats):
    """Uptycs writes rating severities lowercase ("high", "critical").
    ArmorCode's CycloneDX severity map keys on title case
    (Critical/High/Medium/Low/Info); normalize so severity mapping applies."""
    fixed = 0
    for vuln in sbom.get("vulnerabilities", []):
        for rating in vuln.get("ratings", []):
            sev = rating.get("severity")
            if sev is None:
                continue
            normalized = SEVERITY_TITLE_CASE.get(sev.lower())
            if normalized and normalized != sev:
                rating["severity"] = normalized
                fixed += 1
    stats["severities_normalized"] = fixed
    return sbom


def convert(sbom):
    stats = {}
    sbom = fix_vulnerability_refs(sbom, stats)
    sbom = fix_severity_case(sbom, stats)
    return sbom, stats


def print_report(name, stats):
    print(f"[{name}]")
    print(f"  - vulnerability affects refs: {stats.get('affects_rewritten', 0)}/"
          f"{stats.get('affects_total', 0)} rewritten to real component bom-refs")
    unresolved = stats.get("affects_unresolved", [])
    if unresolved:
        print(f"  - WARNING: {len(unresolved)} affects refs could not be resolved "
              f"to any component (left unchanged):")
        for item in unresolved[:10]:
            print(f"      {item['vulnId']}: {item['ref']}")
        if len(unresolved) > 10:
            print(f"      ... and {len(unresolved) - 10} more")
    print(f"  - severities normalized to title case: {stats.get('severities_normalized', 0)}")


def convert_file(in_path: Path, out_path: Path):
    with open(in_path, "r", encoding="utf-8") as f:
        sbom = json.load(f)
    sbom, stats = convert(sbom)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2)
    print_report(in_path.name, stats)
    print(f"  -> wrote {out_path}\n")


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        sys.exit(1)

    src = Path(argv[1])

    if src.is_dir():
        dst_dir = Path(argv[2]) if len(argv) > 2 else src / "armorcode"
        json_files = sorted(src.glob("*.json"))
        if not json_files:
            print(f"No .json files found in {src}")
            sys.exit(1)
        for jf in json_files:
            convert_file(jf, dst_dir / jf.name)
        return

    if not src.is_file():
        print(f"Input not found: {src}")
        sys.exit(1)

    if len(argv) > 2:
        dst = Path(argv[2])
    else:
        dst = src.with_suffix("")
        dst = dst.parent / f"{dst.name}.armorcode.json"

    convert_file(src, dst)


if __name__ == "__main__":
    main(sys.argv)
