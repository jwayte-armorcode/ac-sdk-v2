#!/usr/bin/env python3
"""Quick demo of the ArmorCode SDK — run this to verify your setup."""

import os
from armorcode import ArmorCodeClient


def main():
    env_path = os.environ.get("AC_ENV", "env")
    ac = ArmorCodeClient.from_env(env_path)

    # Pull all Critical + High findings from the last 14 days
    findings = ac.get_findings(
        severities=["Critical", "High"],
        days_back=14,
        dump_path="findings.json",
    )
    print(f"Findings: {len(findings)}")

    # List repos with finding counts
    print("\nRepos:")
    for repo, count in ac.list_repos():
        print(f"  {repo}: {count}")

    # Get findings for the top repo
    if findings:
        top_repo = ac.list_repos()[0][0]
        repo_findings = ac.get_findings_by_repo(top_repo)
        print(f"\nTop repo '{top_repo}': {len(repo_findings)} findings")

    # List teams
    teams = ac.get_teams()
    print(f"\nTeams: {len(teams)}")
    for t in teams[:5]:
        print(f"  {t['name']} (id: {t['id']})")
    if len(teams) > 5:
        print(f"  ... and {len(teams) - 5} more")

    # List products
    products = ac.get_products()
    total_products = products.get("totalElements", 0)
    print(f"\nProducts: {total_products}")
    for p in products.get("content", [])[:5]:
        print(f"  {p['name']} (id: {p['id']})")
    if total_products > 5:
        print(f"  ... and {total_products - 5} more")

    # List runbooks
    runbooks = ac.get_runbooks()
    print(f"\nRunbooks: {len(runbooks)}")
    for rb in runbooks[:5]:
        status = "enabled" if rb.get("enabled") else "disabled"
        print(f"  {rb['label']} ({status}, {rb.get('executionCount', 0)} runs)")
    if len(runbooks) > 5:
        print(f"  ... and {len(runbooks) - 5} more")


if __name__ == "__main__":
    main()
