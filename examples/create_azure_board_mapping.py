#!/usr/bin/env python3
"""Create an Azure Boards mapping, refusing to double-map an already-mapped repo.

In this tenant model a *repo* is a sub-product. `create_azure_board_config`
resolves the repo names to sub-product ids and, before creating anything,
checks every existing Azure Boards mapping (across all connections). If any
requested repo is already mapped it raises `AzureBoardMappingConflict` with the
offending mapping's id / application / repos — and creates nothing.

Usage:
    python examples/create_azure_board_mapping.py <login_id> <project_key> <repo> [<repo> ...]

Env file (default `env` in CWD): TENANT_URL + API_TOKEN.
"""
import sys

from armorcode import ArmorCodeClient, AzureBoardMappingConflict


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(2)

    login_id = int(sys.argv[1])
    project_key = sys.argv[2]
    repos = sys.argv[3:]

    ac = ArmorCodeClient.from_env("env")

    try:
        cfg = ac.create_azure_board_config(
            project_key=project_key,
            login_id=login_id,
            repos=repos,
            issue_type="Bug",
        )
    except AzureBoardMappingConflict as e:
        print("Refused — one or more repos are already mapped:\n")
        for c in e.conflicts:
            print(f"  mapping {c['id']}  application={c['application']!r}  "
                  f"repos={c['repos']}")
        sys.exit(1)
    except ValueError as e:
        print(f"Bad input: {e}")
        sys.exit(2)

    print(f"Created Azure Boards mapping: id={cfg.get('id')} "
          f"project={project_key} repos={repos}")


if __name__ == "__main__":
    main()
