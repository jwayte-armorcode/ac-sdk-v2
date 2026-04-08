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

    # ArmorCode API hard limit per query
    _MAX_RESULTS = 10000

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

        If a query would return more than 10,000 results (the API hard limit),
        the request is automatically split into smaller date-range chunks and
        the results are merged.  This requires ``days_back`` to be set; if it
        is ``None`` the method will first probe the total count and, when it
        exceeds 10K, default to 365 days and chunk from there.

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
        if extra_filters:
            filters.update(extra_filters)

        if days_back is not None:
            cutoff_ms = str(int((time.time() - days_back * 86400) * 1000))
            filters["foundOn"] = [cutoff_ms]
            filter_ops["foundOn"] = "GREATER_THAN"

        # Probe total count first
        total = self._probe_count(filters, filter_ops)

        if total <= self._MAX_RESULTS:
            all_findings = self._paginated_fetch(filters, filter_ops, page_size)
        else:
            # Auto-chunk by date range
            effective_days = days_back if days_back is not None else 365
            all_findings = self._chunked_fetch(
                filters, filter_ops, effective_days, total, page_size,
            )

        self._findings = all_findings
        self._cache_params = {
            "severities": severities,
            "statuses": statuses,
            "days_back": days_back,
        }

        if dump_path:
            self.dump_json(dump_path)

        return all_findings

    def _probe_count(self, filters, filter_ops):
        """Fetch page 0 with size=1 to get totalElements."""
        body = {
            "filters": filters,
            "filterOperations": filter_ops,
            "page": 0,
            "size": 1,
        }
        resp = self._session.post(
            f"{self.base_url}/user/findings/",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json().get("totalElements", 0)

    def _paginated_fetch(self, filters, filter_ops, page_size):
        """Standard paginated fetch (under 10K results)."""
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

        return all_findings

    def _chunked_fetch(self, base_filters, base_filter_ops, days_back, total, page_size):
        """Split a large query into date-range chunks under 10K each.

        Uses binary-style splitting: starts by dividing the date range into
        even chunks sized to stay under 10K, then fetches each chunk.
        """
        now_ms = int(time.time() * 1000)
        start_ms = now_ms - (days_back * 86400 * 1000)

        # Estimate chunks needed (with headroom)
        num_chunks = max(2, (total // (self._MAX_RESULTS // 2)) + 1)
        chunk_duration = (now_ms - start_ms) // num_chunks

        all_findings = []
        seen_ids = set()

        for i in range(num_chunks):
            chunk_start = start_ms + (i * chunk_duration)
            # Overlap by 1ms to avoid boundary gaps
            chunk_end = start_ms + ((i + 1) * chunk_duration) + 1 if i < num_chunks - 1 else now_ms

            # Build clean filter copies, replacing any existing foundOn
            chunk_filters = {k: v for k, v in base_filters.items() if k != "foundOn"}
            chunk_ops = {k: v for k, v in base_filter_ops.items() if k != "foundOn"}
            chunk_filters["foundOn"] = [str(chunk_start), str(chunk_end)]
            chunk_ops["foundOn"] = "BETWEEN"

            # Check chunk size first
            chunk_total = self._probe_count(chunk_filters, chunk_ops)

            if chunk_total > self._MAX_RESULTS:
                # Recursively split this chunk further
                chunk_days = (chunk_end - chunk_start) / (86400 * 1000)
                sub_findings = self._chunked_fetch(
                    chunk_filters, chunk_ops, chunk_days, chunk_total, page_size,
                )
                for f in sub_findings:
                    fid = f.get("id")
                    if fid not in seen_ids:
                        seen_ids.add(fid)
                        all_findings.append(f)
            else:
                chunk_findings = self._paginated_fetch(chunk_filters, chunk_ops, page_size)
                for f in chunk_findings:
                    fid = f.get("id")
                    if fid not in seen_ids:
                        seen_ids.add(fid)
                        all_findings.append(f)

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

    # ------------------------------------------------------------------
    # Finding Statistics
    # ------------------------------------------------------------------

    def get_finding_stats(self, filters=None):
        """Get severity-by-status statistics.

        Args:
            filters: Optional filter dict to scope the stats.

        Returns:
            dict: Stats object with severity counts per status.
        """
        body = {"filters": filters or {}}
        resp = self._session.post(
            f"{self.base_url}/user/findings/findingStats",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_finding_stats_by_team(self, team_name, environments=None):
        """Get finding statistics for a specific team.

        Args:
            team_name: Team name (e.g. ``"team-Security"``).
            environments: Optional list of environment filters.

        Returns:
            dict: Team stats with ``id``, ``name``, ``count``, ``severity`` breakdown.
        """
        body = {
            "filters": {
                "name": team_name,
                "environmentName": environments or [],
            }
        }
        resp = self._session.post(
            f"{self.base_url}/user/findings/stat/team",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_finding_stats_by_product(self, product_name, environments=None):
        """Get finding statistics for a specific product.

        Args:
            product_name: Product name (e.g. ``"team-Security"``).
            environments: Optional list of environment filters.

        Returns:
            dict: Product stats with ``id``, ``name``, ``count``, ``severity`` breakdown.
        """
        body = {
            "filters": {
                "name": product_name,
                "environmentName": environments or [],
            }
        }
        resp = self._session.post(
            f"{self.base_url}/user/findings/stat/product",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # CSV Export
    # ------------------------------------------------------------------

    def export_findings_csv(self, output_path, filters=None, filter_operations=None):
        """Export findings as CSV.

        Args:
            output_path: File path to write the CSV to.
            filters: Filter dict (same format as ``get_findings``).
            filter_operations: Filter operations dict (e.g. ``{"foundOn": "GREATER_THAN"}``).

        Returns:
            str: The output path written.
        """
        body = {
            "filters": filters or {},
            "filterOperations": filter_operations or {},
        }
        resp = self._session.post(
            f"{self.base_url}/user/findings/download/csv",
            json=body,
            timeout=self._timeout * 3,
        )
        resp.raise_for_status()
        Path(output_path).write_bytes(resp.content)
        return output_path

    # ------------------------------------------------------------------
    # Repositories (SCM)
    # ------------------------------------------------------------------

    def get_repos(self, states=None, sources=None, page=0, size=100):
        """List SCM repositories from the tenant.

        Args:
            states: Repo states, e.g. ``["ACTIVE", "INACTIVE", "DORMANT"]``.
            sources: SCM sources, e.g. ``["GITHUB", "GITLAB", "BITBUCKET"]``.
            page: Page number (0-based).
            size: Page size.

        Returns:
            dict: Paginated response with ``content`` and ``totalElements``.
                  The API wraps this in a ``data`` envelope which is unwrapped
                  automatically.
        """
        body = {}
        if states:
            body["repositoryStates"] = list(states)
        if sources:
            body["sources"] = list(sources)
        resp = self._session.post(
            f"{self.base_url}/api/scm/discover/repos",
            params={"page": page, "size": size},
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        result = resp.json()
        # Unwrap the data envelope if present
        if "data" in result and isinstance(result["data"], dict):
            return result["data"]
        return result

    def get_repo_filters(self):
        """Get available filter options for repository discovery.

        Returns:
            dict: Filter options (states, sources, tiers, etc.).
        """
        resp = self._session.get(
            f"{self.base_url}/api/scm/discover/repo-filters",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_repo_details(self, status_type="ACTIVE", include_ignored=False):
        """Get detailed repository information.

        Args:
            status_type: One of ``ACTIVE``, ``INACTIVE``, ``DORMANT``.
            include_ignored: Include ignored repos.

        Returns:
            list[dict] or dict: Repository details.
        """
        resp = self._session.get(
            f"{self.base_url}/user/tools/git/repos/details",
            params={
                "gitReposStatusType": status_type,
                "includeIgnored": include_ignored,
            },
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_repo_contributors(self, repo_id):
        """Get contributors for a specific repository.

        Args:
            repo_id: Repository ID.

        Returns:
            list[dict]: Contributors.
        """
        resp = self._session.get(
            f"{self.base_url}/api/tools/git/repo/{repo_id}/contributors",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Teams
    # ------------------------------------------------------------------

    def get_teams(self):
        """List all teams (id + name).

        Returns:
            list[dict]: Teams.
        """
        resp = self._session.get(
            f"{self.base_url}/api/team/all-teams",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_team(self, team_id):
        """Get full detail for a specific team.

        Args:
            team_id: Team ID.

        Returns:
            dict: Team detail (members, owners, lead, description, properties).
        """
        resp = self._session.get(
            f"{self.base_url}/api/team/{team_id}",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_team_stats(self, environment="Production"):
        """Get statistics for all teams.

        Args:
            environment: Environment name (required by the API).
                         Defaults to ``"Production"``.

        Returns:
            list[dict]: Per-team stats with risk scores, member counts, products.
        """
        resp = self._session.get(
            f"{self.base_url}/api/team/all-team-stats",
            params={"environment": environment},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_team_leads(self):
        """Get users who can be team leads.

        Returns:
            list[dict]: Team lead users.
        """
        resp = self._session.get(
            f"{self.base_url}/user/team-leads",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Products
    # ------------------------------------------------------------------

    def get_products(self, page=0, size=100, search=None):
        """List products (applications).

        Args:
            page: Page number (0-based).
            size: Page size (max 100).
            search: Optional search string to filter by name.

        Returns:
            dict: Paginated response with ``content`` and ``totalElements``.
        """
        params = {"pageNumber": page, "pageSize": size}
        if search:
            params["search"] = search
        resp = self._session.get(
            f"{self.base_url}/user/product/elastic/paged",
            params=params,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Sub-Products
    # ------------------------------------------------------------------

    def get_sub_products(self):
        """List all sub-products (repos/components mapped under products).

        Returns a lightweight list of all sub-products with ``id`` and ``name``.

        Returns:
            list[dict]: Sub-products with ``id`` and ``name``.
        """
        resp = self._session.get(
            f"{self.base_url}/user/sub-product/elastic/short",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_sub_product(self, sub_product_id):
        """Get full detail for a specific sub-product.

        Args:
            sub_product_id: Sub-product ID.

        Returns:
            dict: Sub-product detail including parent product, description,
            owners, environment, and configuration.
        """
        resp = self._session.get(
            f"{self.base_url}/api/sub-product/{sub_product_id}",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    def get_users(self):
        """List all users in the tenant.

        Returns:
            list[dict]: Users with roles and activity status.
        """
        resp = self._session.get(
            f"{self.base_url}/user/data/users",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Security Tools
    # ------------------------------------------------------------------

    def get_tools(self):
        """List configured application security tools (scanners).

        Returns:
            list[dict]: Tool status objects with config/operational status.
        """
        resp = self._session.get(
            f"{self.base_url}/user/tools/appsec-tools/status",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_integration_tools(self):
        """List configured integration tools (ticketing, notifications, etc.).

        Returns:
            list[dict]: Integration tool status objects.
        """
        resp = self._session.get(
            f"{self.base_url}/user/tools/integration-tools/status",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Runbooks
    # ------------------------------------------------------------------

    def get_runbooks(self):
        """List all runbook automations.

        Returns:
            list[dict]: Runbooks with id, label, type, enabled, status,
            executionCount.
        """
        resp = self._session.get(
            f"{self.base_url}/api/runbook",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # SLA
    # ------------------------------------------------------------------

    def get_sla_tiers(self):
        """Get SLA tier definitions.

        Returns:
            list[dict]: SLA tiers with policies and thresholds.
        """
        resp = self._session.get(
            f"{self.base_url}/user/findingSla/tiers",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_sla_stats(self, filters=None):
        """Get overall SLA statistics (breach trends, severity breakdown).

        Args:
            filters: Optional filter dict to scope the stats.

        Returns:
            dict: SLA stats with ``slaBreached`` trend data and severity counts.
        """
        body = {"filters": filters or {}}
        resp = self._session.post(
            f"{self.base_url}/user/findingSla/sla-stats",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_team_sla_stats(self, filters=None, agg_fields=None):
        """Get SLA statistics broken down by team.

        Args:
            filters: Optional filter dict.
            agg_fields: Aggregation fields, e.g. ``["teamId"]``.
                        Defaults to ``["teamId"]``.

        Returns:
            list[dict]: Per-team SLA stats. May be empty if not configured.
        """
        body = {
            "filters": filters or {},
            "aggFields": agg_fields or ["teamId"],
        }
        resp = self._session.post(
            f"{self.base_url}/user/findingSla/team-sla-stats",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_mttr_stats(self, filters=None):
        """Get mean-time-to-remediate statistics.

        Args:
            filters: Optional filter dict.

        Returns:
            dict: MTTR statistics.
        """
        body = {"filters": filters or {}}
        resp = self._session.post(
            f"{self.base_url}/api/finding-sla/mean-remediation-stats",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Tenant Configuration
    # ------------------------------------------------------------------

    def get_tenant_config(self, config_type):
        """Get a tenant configuration value.

        Args:
            config_type: Config key, e.g. ``"ENABLE_ANYA_AI_ASSISTANT"``.

        Returns:
            dict: Configuration value.
        """
        resp = self._session.get(
            f"{self.base_url}/api/tenant-config",
            params={"configType": config_type},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # API Discovery
    # ------------------------------------------------------------------

    def get_api_docs(self):
        """Fetch the full OpenAPI spec for the tenant.

        Returns:
            dict: OpenAPI 3.x specification.
        """
        resp = self._session.get(
            f"{self.base_url}/v3/api-docs",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()
