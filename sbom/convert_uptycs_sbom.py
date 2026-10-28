#!/usr/bin/env python3
"""
Convert Uptycs CycloneDX SBOM exports into components-only SBOMs for ArmorCode.

Removes the top-level vulnerabilities[] array so ArmorCode treats the file as a
components-only SBOM and runs its own vulnerability analysis against
components[]. Everything else (metadata, components, dependencies) is kept.

Usage:
    python3 convert_uptycs_sbom.py <input.json> [output.json]
    python3 convert_uptycs_sbom.py <input_dir> [output_dir]   # batch mode

If output.json is omitted, "<input>.components_only.json" is written next to
the input. In batch mode, every *.json file in input_dir is converted into
output_dir (default: <input_dir>/components_only) with the same filename.
"""
import json
import sys
from collections import Counter
from pathlib import Path


def strip_vulnerabilities(sbom):
    """ArmorCode chooses its CycloneDX ingestion path on whether a top-level
    vulnerabilities[] array is present. Without it, the SBOM is analysed
    component by component and every finding is created against a resolved
    component, so name and version are always populated."""
    vulns = sbom.pop("vulnerabilities", None) or []
    components = sbom.get("components", [])
    stats = {
        "vulnerabilities_removed": len(vulns),
        "components": len(components),
        "purl_types": Counter(
            (c.get("purl") or "no-purl").split("/", 1)[0] for c in components
        ),
        "missing_purl": sum(1 for c in components if not c.get("purl")),
    }
    return sbom, stats


def print_report(name, stats):
    print(f"[{name}]")
    print(f"  - vulnerabilities[] entries removed: {stats['vulnerabilities_removed']}")
    types = ", ".join(f"{t} {n}" for t, n in stats["purl_types"].most_common())
    print(f"  - components kept: {stats['components']} ({types})")
    if stats["missing_purl"]:
        print(f"  - WARNING: {stats['missing_purl']} components have no purl and "
              f"cannot be matched to vulnerability data")


def convert_file(in_path: Path, out_path: Path):
    with open(in_path, "r", encoding="utf-8") as f:
        sbom = json.load(f)
    if sbom.get("bomFormat") != "CycloneDX":
        print(f"[{in_path.name}] skipped: not a CycloneDX document\n")
        return
    sbom, stats = strip_vulnerabilities(sbom)
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
        dst_dir = Path(argv[2]) if len(argv) > 2 else src / "components_only"
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
        dst = dst.parent / f"{dst.name}.components_only.json"

    convert_file(src, dst)


if __name__ == "__main__":
    main(sys.argv)
