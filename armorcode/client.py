"""ArmorCode API client for querying findings, repos, teams, and more."""

import json
import time
from collections import Counter, defaultdict
from pathlib import Path

import requests


class ArmorCodeClient:
    """Lightweight SDK for the ArmorCode REST API.

    Usage::

        from armorcode import ArmorCodeClient

        ac = ArmorCodeClient("app.armorcode.com", token="<bearer-token>")

        # Pull all Critical + High open findings from the last 14 days
        findings = ac.get_findings(
            severities=["Critical", "High"],
            statuses=["OPEN"],
            days_back=14,
        )

        # List repos with finding counts
        ac.list_repos()

        # Get findings for a specific repo
        repo_findings = ac.get_findings_by_repo("my-repo")
    """

    # Severity values are title-case in the ArmorCode API
    SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")

    # Status values are uppercase
    STATUSES = (
        "OPEN", "CONFIRMED", "ACCEPTRISK", "FALSEPOSITIVE",
        "MITIGATED", "SUPPRESSED", "TRIAGE", "IN_PROGRESS", "CONTROLLED",
    )

    def __init__(self, tenant_url, token, *, timeout=60):
        self.base_url = f"https://{tenant_url.rstrip('/')}"
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        })
        self._timeout = timeout

        # Local cache populated by get_findings()
        self._findings = []
        self._cache_params = {}

    @classmethod
    def from_env(cls, env_path="env", token_key=None, **kwargs):
        """Create a client from an env file.

        Args:
            env_path: Path to env file containing TENANT_URL and a token variable.
            token_key: Explicit key name for the token. If None, uses the first
                       key ending in ``_TOKEN``.
        """
        config = {}
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()

        tenant_url = config.get("TENANT_URL", "app.armorcode.com")

        if token_key:
            token = config[token_key]
        else:
            token = next(
                (v for k, v in config.items() if k.endswith("_TOKEN")),
                None,
            )
            if not token:
                raise ValueError("No *_TOKEN key found in env file")

        return cls(tenant_url, token, **kwargs)

    # ------------------------------------------------------------------
    # Core: get_findings — bulk pull with severity/status/date filters
    # ------------------------------------------------------------------

    def get_findings(
        self,
        severities=None,
        statuses=None,
        days_back=None,
        extra_filters=None,
        dump_path=None,
        page_size=500,
    ):
        """Fetch findings from ArmorCode with optional filters.

        Pulls all matching findings in bulk (paginated internally) and caches
        them locally.  Subsequent calls to :meth:`list_repos` and
        :meth:`get_findings_by_repo` operate on this cached data.

        Args:
            severities: List of severity levels, e.g. ``["Critical", "High"]``.
                        Must be title-case.
            statuses: List of statuses, e.g. ``["OPEN", "CONFIRMED"]``.
                      Must be uppercase.
            days_back: Only include findings discovered in the last N days.
            extra_filters: Additional filter dict merged into the request body's
                           ``filters`` map.
            dump_path: If provided, write the raw findings JSON to this path.
            page_size: Number of findings per API page (max 500).

        Returns:
            list[dict]: All matching findings.
        """
        filters = {}
        filter_ops = {}

        if severities:
            filters["severity"] = list(severities)
        if statuses:
            filters["status"] = list(statuses)
        if days_back is not None:
            cutoff_ms = str(int((time.time() - days_back * 86400) * 1000))
            filters["foundOn"] = [cutoff_ms]
            filter_ops["foundOn"] = "GREATER_THAN"
        if extra_filters:
            filters.update(extra_filters)

        url = f"{self.base_url}/user/findings/"
        all_findings = []
        page = 0

        while True:
            body = {
                "filters": filters,
                "filterOperations": filter_ops,
                "page": page,
                "size": page_size,
                "sortColumn": "foundOn",
                "sortOrder": "DESC",
            }
            resp = self._session.post(url, json=body, timeout=self._timeout)
            resp.raise_for_status()
            data = resp.json()

            content = data.get("content", [])
            total = data.get("totalElements", 0)
            all_findings.extend(content)

            if not content or len(all_findings) >= total:
                break
            page += 1

        self._findings = all_findings
        self._cache_params = {
            "severities": severities,
            "statuses": statuses,
            "days_back": days_back,
        }

        if dump_path:
            self.dump_json(dump_path)

        return all_findings

    # ------------------------------------------------------------------
    # list_repos — repo breakdown from cached findings
    # ------------------------------------------------------------------

    def list_repos(self, findings=None):
        """List repos with a count of findings per repo.

        Args:
            findings: Optional list of findings to analyze. Defaults to the
                      cached result from the last :meth:`get_findings` call.

        Returns:
            list[tuple[str, int]]: ``(repo_name, count)`` pairs sorted by count
            descending.
        """
        findings = findings if findings is not None else self._findings
        counts = Counter()
        for f in findings:
            repo = (f.get("subProduct") or {}).get("name", "(unmapped)")
            counts[repo] += 1
        return counts.most_common()

    # ------------------------------------------------------------------
    # get_findings_by_repo — filter cached findings to a single repo
    # ------------------------------------------------------------------

    def get_findings_by_repo(self, repo_name, findings=None):
        """Return findings for a specific repository.

        Args:
            repo_name: Repository name (matches ``subProduct.name``).
            findings: Optional list to filter. Defaults to cached findings.

        Returns:
            list[dict]: Findings belonging to the given repo.
        """
        findings = findings if findings is not None else self._findings
        return [
            f for f in findings
            if (f.get("subProduct") or {}).get("name", "") == repo_name
        ]

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def dump_json(self, path="findings.json"):
        """Write cached findings to a JSON file.

        Args:
            path: Output file path.
        """
        out = {
            "metadata": {
                "tenant": self.base_url,
                "total_findings": len(self._findings),
                "query_params": self._cache_params,
                "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            "findings": self._findings,
        }
        Path(path).write_text(json.dumps(out, indent=2, default=str))

    def get_finding_stats(self, filters=None):
        """Get severity-by-status statistics.

        Returns:
            dict: Stats object from the API.
        """
        body = {"filters": filters or {}}
        resp = self._session.post(
            f"{self.base_url}/user/findings/findingStats",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_repos(self, states=None, page=0, size=100):
        """List SCM repositories from the tenant.

        Args:
            states: Repo states to filter, e.g. ``["ACTIVE"]``.
            page: Page number (0-based).
            size: Page size.

        Returns:
            dict: API response with ``content`` and ``totalElements``.
        """
        body = {}
        if states:
            body["repositoryStates"] = list(states)
        resp = self._session.post(
            f"{self.base_url}/api/scm/discover/repos",
            params={"page": page, "size": size},
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_teams(self):
        """List all teams.

        Returns:
            list[dict]: Teams with ``id`` and ``name``.
        """
        resp = self._session.get(
            f"{self.base_url}/api/team/all-teams",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_products(self, page=0, size=100):
        """List products (applications).

        Returns:
            dict: Paginated response with ``content`` and ``totalElements``.
        """
        resp = self._session.get(
            f"{self.base_url}/user/product/elastic/paged",
            params={"page": page, "size": size},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_tools(self):
        """List configured security tools.

        Returns:
            list[dict]: Tool status objects.
        """
        resp = self._session.get(
            f"{self.base_url}/user/tools/appsec-tools/status",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_runbooks(self):
        """List all runbook automations.

        Returns:
            list[dict]: Runbook objects.
        """
        resp = self._session.get(
            f"{self.base_url}/api/runbook",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()
