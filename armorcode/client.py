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

        Expected env format::

            TENANT_URL=<https://my-tenant-url>
            API_TOKEN=<api-token>

        ``TENANT_URL`` may be a bare hostname or a full ``https://...`` URL.

        For backward compatibility, this also accepts ``*_TOKEN`` (legacy
        per-tenant naming like ``ACME_TOKEN``) and lowercase ``token``/``url``.

        Args:
            env_path: Path to env file.
            token_key: Explicit key name for the token. If None, tries
                       ``API_TOKEN`` first, then any ``*_TOKEN`` key, then
                       lowercase ``token``.
        """
        config = {}
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()

        tenant_url = (
            config.get("TENANT_URL")
            or config.get("url", "app.armorcode.com")
        )
        # Accept raw hostname or full URL in the env file
        if tenant_url.startswith(("http://", "https://")):
            tenant_url = tenant_url.split("://", 1)[1]

        if token_key:
            token = config[token_key]
        else:
            # Preferred: API_TOKEN. Fall back to *_TOKEN (legacy) or token (lower).
            token = (
                config.get("API_TOKEN")
                or next(
                    (v for k, v in config.items() if k.endswith("_TOKEN")),
                    None,
                )
                or config.get("token")
            )
            if not token:
                raise ValueError(
                    "No token found in env file "
                    "(expected API_TOKEN, *_TOKEN, or token)"
                )

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
        page_size=2000,
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
            filters["severities"] = list(severities)
        if statuses:
            filters["statuses"] = list(statuses)
        if extra_filters:
            filters.update(extra_filters)

        now_ms = int(time.time() * 1000)
        effective_days = days_back if days_back is not None else 365
        start_ms = now_ms - int(effective_days * 86400 * 1000)

        if days_back is not None:
            filters["foundOn"] = [str(start_ms)]
            filter_ops["foundOn"] = "GREATER_THAN"

        # Probe total count first
        total = self._probe_count(filters, filter_ops)

        if total <= self._MAX_RESULTS:
            all_findings = self._paginated_fetch(filters, filter_ops, page_size)
        else:
            all_findings = self._chunked_fetch(
                filters, filter_ops, start_ms, now_ms, total, page_size,
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

    def _chunked_fetch(self, base_filters, base_filter_ops, start_ms, end_ms, total, page_size):
        """Split a large query into date-range chunks under 10K each.

        Uses even splitting: divides [start_ms, end_ms] into enough slices to
        keep each under 10K, then fetches each slice. Slices that are still
        over 10K are split recursively using the same window boundaries.
        """
        num_chunks = max(2, (total // (self._MAX_RESULTS // 2)) + 1)
        chunk_duration = (end_ms - start_ms) // num_chunks

        all_findings = []
        seen_ids = set()

        for i in range(num_chunks):
            chunk_start = start_ms + (i * chunk_duration)
            chunk_end = start_ms + ((i + 1) * chunk_duration) if i < num_chunks - 1 else end_ms

            chunk_filters = {k: v for k, v in base_filters.items() if k != "foundOn"}
            chunk_ops = {k: v for k, v in base_filter_ops.items() if k != "foundOn"}
            chunk_filters["foundOn"] = [str(chunk_start), str(chunk_end)]
            chunk_ops["foundOn"] = "BETWEEN"

            chunk_total = self._probe_count(chunk_filters, chunk_ops)

            if chunk_total > self._MAX_RESULTS:
                sub_findings = self._chunked_fetch(
                    chunk_filters, chunk_ops, chunk_start, chunk_end, chunk_total, page_size,
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

    def get_findings_by_hierarchy(
        self,
        product=None,
        sub_product=None,
        team=None,
        severities=None,
        statuses=None,
        sources=None,
        extra_filters=None,
        page_size=500,
    ):
        """Fetch findings scoped to a product/sub-product/team hierarchy.

        Accepts names — looks up numeric IDs automatically before querying.
        Any combination of the three hierarchy levels can be supplied; all
        provided levels are ANDed together.

        Args:
            product: Product (group) name, e.g. ``"Risk Platform"``.
            sub_product: Sub-product name, e.g. ``"airml-dx-suggestions-service"``.
            team: Team name, e.g. ``"team-Risk Platform"``.
            severities: List of severities, e.g. ``["CRITICAL", "HIGH"]``.
            statuses: List of statuses, e.g. ``["OPEN"]``.
            sources: List of tool sources, e.g. ``["GitHub", "Snyk"]``.
            extra_filters: Additional filters merged into the request body.
            page_size: Findings per page (max 500).

        Returns:
            list[dict]: All matching findings.

        Raises:
            ValueError: If a name cannot be resolved to a unique ID.

        Example::

            findings = client.get_findings_by_hierarchy(
                product="Risk Platform",
                sub_product="airml-dx-suggestions-service",
                team="team-Risk Platform",
                severities=["CRITICAL", "HIGH"],
                statuses=["OPEN"],
                sources=["GitHub"],
            )
        """
        filters = {}

        if product is not None:
            filters["product"] = [self._lookup_product_id(product)]
        if sub_product is not None:
            filters["subProduct"] = [self._lookup_sub_product_id(sub_product)]
        if team is not None:
            filters["team"] = [self._lookup_team_id(team)]
        if severities:
            filters["severities"] = list(severities)
        if statuses:
            filters["statuses"] = list(statuses)
        if sources:
            filters["source"] = list(sources)
        if extra_filters:
            filters.update(extra_filters)

        return self._paginated_fetch(filters, {}, page_size)

    def _lookup_sub_product_id(self, sub_product_name):
        """Resolve a sub-product name to its id via exact-match lookup."""
        resp = self._session.get(
            f"{self.base_url}/user/sub-product/elastic/short",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        items = resp.json()
        matches = [s for s in items if s.get("name") == sub_product_name]
        if not matches:
            raise ValueError(f"No sub-product found with name {sub_product_name!r}")
        if len(matches) > 1:
            ids = [m.get("id") for m in matches]
            raise ValueError(
                f"Multiple sub-products named {sub_product_name!r} found: {ids}. "
                f"Pass sub_product_id via extra_filters to disambiguate."
            )
        return int(matches[0]["id"])

    def _lookup_team_id(self, team_name):
        """Resolve a team name to its id via exact-match lookup."""
        resp = self._session.get(
            f"{self.base_url}/api/team/all-teams",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        teams = resp.json()
        matches = [t for t in teams if t.get("name") == team_name]
        if not matches:
            raise ValueError(f"No team found with name {team_name!r}")
        if len(matches) > 1:
            ids = [m.get("id") for m in matches]
            raise ValueError(
                f"Multiple teams named {team_name!r} found: {ids}. "
                f"Pass team_id via extra_filters to disambiguate."
            )
        return int(matches[0]["id"])

    def get_engagements(self):
        """List all engagements (a.k.a. "projects" in the API).

        Engagements are the top-level pentest/assessment containers. The API's
        internal name for them is "project" (endpoint ``/user/project``).

        Returns:
            list[dict]: Engagements with ``id``, ``name``, and detail fields.
        """
        resp = self._session.get(
            f"{self.base_url}/user/project",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else data.get("content", [])

    def get_findings_by_engagement(
        self,
        engagement,
        severities=None,
        statuses=None,
        sources=None,
        extra_filters=None,
        page_size=500,
    ):
        """Fetch findings associated with an engagement.

        Accepts an engagement name (resolved to its id automatically) or an
        integer id. Findings are filtered server-side on the
        ``armorcodeProjects`` filter key.

        Args:
            engagement: Engagement name (e.g. ``"engage1"``) or integer id.
            severities: List of severities, e.g. ``["CRITICAL", "HIGH"]``.
            statuses: List of statuses, e.g. ``["OPEN"]``.
            sources: List of tool sources, e.g. ``["Trivy", "Dependabot"]``.
            extra_filters: Additional filters merged into the request body.
            page_size: Findings per page (max 500).

        Returns:
            list[dict]: All matching findings.

        Raises:
            ValueError: If an engagement name cannot be resolved to a unique id.

        Example::

            findings = client.get_findings_by_engagement(
                "engage1",
                statuses=["OPEN"],
            )
        """
        if isinstance(engagement, int):
            engagement_id = engagement
        else:
            engagement_id = self._lookup_engagement_id(engagement)

        filters = {"armorcodeProjects": [engagement_id]}

        # Alongside the armorcodeProjects filter the API honours the SINGULAR
        # keys (status, severity) — the plural forms used elsewhere are
        # silently ignored here. Status values must be UPPERCASE; severity
        # values Title-case. Normalise so callers can pass either casing.
        if severities:
            filters["severity"] = [s.title() for s in severities]
        if statuses:
            filters["status"] = [s.upper() for s in statuses]
        if sources:
            filters["source"] = list(sources)
        if extra_filters:
            filters.update(extra_filters)

        return self._paginated_fetch(filters, {}, page_size)

    def _lookup_engagement_id(self, engagement_name):
        """Resolve an engagement name to its id via exact-match lookup."""
        engagements = self.get_engagements()
        matches = [e for e in engagements if e.get("name") == engagement_name]
        if not matches:
            raise ValueError(f"No engagement found with name {engagement_name!r}")
        if len(matches) > 1:
            ids = [m.get("id") for m in matches]
            raise ValueError(
                f"Multiple engagements named {engagement_name!r} found: {ids}. "
                f"Pass the engagement id instead to disambiguate."
            )
        return int(matches[0]["id"])

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

    def analyze_risk_scoring_tags(
        self,
        finding_age,
        severities,
        *,
        statuses=None,
        findings=None,
    ):
        """Count findings carrying each tag that contributes to the risk score.

        The tenant's risk-scoring config (``ASSET_SCORE`` tenant-config) lists
        ``(tag_key, tag_value, weight)`` triples. This method returns one row
        per configured triple, with the number of findings — within the given
        age window and severities — that carry the corresponding
        ``"key:value"`` tag.

        Args:
            finding_age: Age window in days (``foundOn > now - N days``).
            severities: List of severities (title-case, e.g. ``["Critical", "High"]``)
                        or a single comma-separated string (``"critical,high"``).
            statuses: Optional list of statuses; defaults to ``["OPEN"]``.
            findings: Optional pre-fetched findings list. If provided, skips
                      the API pull and just counts against the supplied data.

        Returns:
            list[dict]: Sorted by count descending. Each row::

                {"tag_key": str, "tag_value": str, "weight": float, "count": int}

            Plus a final summary row::

                {"tag_key": "(none — finding had no scoring tag)",
                 "tag_value": "", "weight": 0, "count": int}
        """
        if isinstance(severities, str):
            severities = [s.strip() for s in severities.split(",") if s.strip()]
        severities = [s[:1].upper() + s[1:].lower() for s in severities]

        if statuses is None:
            statuses = ["OPEN"]

        config = self.get_tenant_config("ASSET_SCORE") or []
        triples = [
            (entry.get("name"), str(entry.get("fieldValue")), entry.get("value", 0))
            for entry in config
            if entry.get("name") and entry.get("fieldValue") is not None
        ]

        if findings is None:
            findings = self.get_findings(
                severities=severities,
                statuses=statuses,
                days_back=finding_age,
            )

        counts = {(k, v): 0 for (k, v, _w) in triples}
        no_tag_count = 0
        for f in findings:
            tag_set = set(f.get("tags") or [])
            matched = False
            for (k, v, _w) in triples:
                if f"{k}:{v}" in tag_set:
                    counts[(k, v)] += 1
                    matched = True
            if not matched:
                no_tag_count += 1

        rows = [
            {"tag_key": k, "tag_value": v, "weight": w, "count": counts[(k, v)]}
            for (k, v, w) in triples
        ]
        rows.sort(key=lambda r: r["count"], reverse=True)
        rows.append({
            "tag_key": "(none — finding had no scoring tag)",
            "tag_value": "",
            "weight": 0,
            "count": no_tag_count,
        })
        return rows

    # ------------------------------------------------------------------
    # Custom Finding Upload (Generic JSON)
    # ------------------------------------------------------------------

    def upload_findings(self, findings, product, sub_product, environment):
        """Insert one or more custom findings via the Generic JSON upload endpoint.

        Hits ``POST /api/findings/upload`` with the target product, sub-product,
        and environment as query params and a JSON array of finding objects as
        the body. Each finding follows ArmorCode's Generic Finding JSON format,
        e.g. ``{"Title": "...", "Severity": "High", "Description": "..."}``.

        Args:
            findings: A single finding dict or a list of finding dicts.
            product: Product name (resolved to id) or product id (int).
            sub_product: Sub-product name (resolved to id) or sub-product id (int).
            environment: Environment name string, e.g. ``"Production"``.

        Returns:
            dict: The parsed API response (or ``{"status": <code>}`` if empty).
        """
        product_id = product if isinstance(product, int) else self._lookup_product_id(product)
        sub_product_id = (
            sub_product if isinstance(sub_product, int)
            else self._lookup_sub_product_id(sub_product)
        )

        payload = findings if isinstance(findings, list) else [findings]

        resp = self._session.post(
            f"{self.base_url}/api/findings/upload",
            params={"product": product_id, "subproduct": sub_product_id, "env": environment},
            json=payload,
            timeout=self._timeout * 3,
        )
        resp.raise_for_status()
        if not resp.content:
            return {"status": resp.status_code}
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

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

    def create_product(self, name, description=None, type_id=None, tags=None,
                       extra=None):
        """Create a new product (group/application).

        Args:
            name: Product name (required, 2-228 chars).
            description: Optional description.
            type_id: Optional product type id. If omitted the tenant default
                     ("N/A") is assigned by the server.
            tags: Optional list of tag strings (e.g. ``["env:prod", "team:security"]``).
            extra: Optional dict merged into the request body for advanced
                   fields (e.g. ``status``, ``versionNumber``, owners).

        Returns:
            dict: The newly created product, including its server-assigned
            ``id``.
        """
        body = {"name": name}
        if description is not None:
            body["description"] = description
        if type_id is not None:
            body["type"] = {"id": type_id}
        if tags is not None:
            body["tags"] = tags
        if extra:
            body.update(extra)
        resp = self._session.post(
            f"{self.base_url}/user/product",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def update_product(self, product_name=None, *, product_id=None, name=None,
                       description=None, tags=None, extra=None):
        """Update an existing product (group/application).

        Args:
            product_name: Product to update, resolved via exact-match lookup.
                          Either ``product_name`` or ``product_id`` is required.
            product_id: Product id (alternative to ``product_name``).
            name: New name (required by the API — defaults to current name if
                  not provided, fetched automatically).
            description: New description.
            tags: List of tag strings. Replaces all existing tags on the product.
            extra: Optional dict merged into the request body for advanced
                   fields (e.g. owners, ``tier``, ``status``).

        Returns:
            dict: The updated product.
        """
        if product_id is None:
            if not product_name:
                raise ValueError("Either product_name or product_id is required")
            product_id = self._lookup_product_id(product_name)

        # Fetch current state and send it back in full to satisfy the API's
        # "wide range update" validation (rejects requests missing >~50% of fields)
        resp = self._session.get(
            f"{self.base_url}/user/product/{product_id}",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        body["id"] = product_id

        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if tags is not None:
            body["tags"] = tags
        if extra:
            body.update(extra)

        resp = self._session.put(
            f"{self.base_url}/user/product",
            json=body,
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

    def _lookup_product_id(self, product_name):
        """Resolve a product name to its id via exact-match lookup.

        Raises ``ValueError`` if no product or multiple products match.
        """
        resp = self._session.get(
            f"{self.base_url}/user/product/elastic/paged",
            params={"pageNumber": 0, "pageSize": 100, "search": product_name},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        content = resp.json().get("content", [])
        matches = [p for p in content if p.get("name") == product_name]
        if not matches:
            raise ValueError(f"No product found with name {product_name!r}")
        if len(matches) > 1:
            ids = [m.get("id") for m in matches]
            raise ValueError(
                f"Multiple products named {product_name!r} found: {ids}. "
                f"Pass product_id explicitly to disambiguate."
            )
        return int(matches[0]["id"])

    def create_sub_product(self, name, product_name=None, *, product_id=None,
                           description=None, environment_id=None, tier=None,
                           tags=None, extra=None):
        """Create a new sub-product under an existing product.

        Args:
            name: Sub-product name (required, 2-228 chars).
            product_name: Parent product name. Looked up via exact match.
                          Either ``product_name`` or ``product_id`` is required.
            product_id: Parent product id (alternative to ``product_name``).
            description: Optional description.
            environment_id: Optional environment id.
            tier: Optional tier string (e.g. ``"Tier 1"``).
            tags: Optional list of tag strings (e.g. ``["env:prod", "team:security"]``).
            extra: Optional dict merged into the request body for advanced
                   fields (e.g. owners, ``classType``, ``hostedCloud``).

        Returns:
            dict: The newly created sub-product, including its server-assigned
            ``id``.
        """
        if product_id is None:
            if not product_name:
                raise ValueError("Either product_name or product_id is required")
            product_id = self._lookup_product_id(product_name)

        body = {
            "name": name,
            "product": {"id": product_id},
        }
        if description is not None:
            body["description"] = description
        if environment_id is not None:
            body["environment"] = {"id": environment_id}
        if tier is not None:
            body["tier"] = tier
        if tags is not None:
            body["tags"] = tags
        if extra:
            body.update(extra)
        resp = self._session.post(
            f"{self.base_url}/api/sub-product",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def update_sub_product(self, sub_product_id, *, name=None, description=None,
                           tags=None, extra=None):
        """Update an existing sub-product.

        Args:
            sub_product_id: Sub-product id to update (required).
            name: New name (if omitted, current name is preserved).
            description: New description.
            tags: List of tag strings. Replaces all existing tags on the sub-product.
            extra: Optional dict merged into the request body for advanced
                   fields (e.g. ``tier``, ``repoLink``, owners).

        Returns:
            dict: The updated sub-product.
        """
        # Fetch current state and send it back in full to satisfy the API's
        # "wide range update" validation
        body = self.get_sub_product(sub_product_id)
        body["id"] = sub_product_id

        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if tags is not None:
            body["tags"] = tags
        if extra:
            body.update(extra)

        resp = self._session.put(
            f"{self.base_url}/api/sub-product",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def update_product_add_tags(self, product_name=None, *, product_id=None,
                               tags):
        """Add one or more tags to a product without touching existing tags.

        Args:
            product_name: Product to update, resolved via exact-match lookup.
                          Either ``product_name`` or ``product_id`` is required.
            product_id: Product id (alternative to ``product_name``).
            tags: List of tag strings to add (e.g. ``["env:prod", "team:security"]``).

        Returns:
            dict: The updated product.
        """
        if product_id is None:
            if not product_name:
                raise ValueError("Either product_name or product_id is required")
            product_id = self._lookup_product_id(product_name)

        resp = self._session.get(
            f"{self.base_url}/user/product/{product_id}",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        current = resp.json()
        existing = list(current.get("tags") or [])
        merged = existing + [t for t in tags if t not in existing]

        return self.update_product(product_id=product_id, tags=merged)

    def update_sub_product_add_tags(self, sub_product_id, tags):
        """Add one or more tags to a sub-product without touching existing tags.

        Args:
            sub_product_id: Sub-product id to update (required).
            tags: List of tag strings to add (e.g. ``["env:prod", "team:security"]``).

        Returns:
            dict: The updated sub-product.
        """
        current = self.get_sub_product(sub_product_id)
        existing = list(current.get("tags") or [])
        merged = existing + [t for t in tags if t not in existing]
        return self.update_sub_product(sub_product_id, tags=merged)

    def update_product_set_tag(self, key_value, product_name=None, *,
                               product_id=None):
        """Set a tag value by key on a product, adding it if absent or
        replacing the existing tag with the same key.

        Args:
            key_value: Tag string in ``"key:value"`` format. The key portion
                       (everything before the first ``:``) is used to find and
                       replace any existing tag with the same key.
            product_name: Product to update, resolved via exact-match lookup.
                          Either ``product_name`` or ``product_id`` is required.
            product_id: Product id (alternative to ``product_name``).

        Returns:
            dict: The updated product.
        """
        if ":" not in key_value:
            raise ValueError(f"key_value must be in 'key:value' format, got {key_value!r}")

        if product_id is None:
            if not product_name:
                raise ValueError("Either product_name or product_id is required")
            product_id = self._lookup_product_id(product_name)

        resp = self._session.get(
            f"{self.base_url}/user/product/{product_id}",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        current = resp.json()
        key = key_value.split(":", 1)[0]
        existing = [t for t in (current.get("tags") or []) if not t.startswith(f"{key}:")]
        merged = existing + [key_value]
        return self.update_product(product_id=product_id, tags=merged)

    def update_sub_product_set_tag(self, sub_product_id, key_value):
        """Set a tag value by key on a sub-product, adding it if absent or
        replacing the existing tag with the same key.

        Args:
            sub_product_id: Sub-product id to update (required).
            key_value: Tag string in ``"key:value"`` format. The key portion
                       (everything before the first ``:``) is used to find and
                       replace any existing tag with the same key.

        Returns:
            dict: The updated sub-product.
        """
        if ":" not in key_value:
            raise ValueError(f"key_value must be in 'key:value' format, got {key_value!r}")

        current = self.get_sub_product(sub_product_id)
        key = key_value.split(":", 1)[0]
        existing = [t for t in (current.get("tags") or []) if not t.startswith(f"{key}:")]
        merged = existing + [key_value]
        return self.update_sub_product(sub_product_id, tags=merged)

    # ------------------------------------------------------------------
    # Tickets
    # ------------------------------------------------------------------

    def get_tickets(self, *, product=None, sub_product=None, assignee=None,
                    page=0, size=100):
        """Retrieve tickets, optionally filtered by product, sub-product, and/or assignee.

        All filters are optional and combinable. Product and sub-product can be
        passed as names (looked up to IDs internally) or as integer IDs directly.

        Args:
            product: Product name (str) or id (int) to filter by.
            sub_product: Sub-product name (str) or id (int) to filter by.
                         When passed as a name, the first matching sub-product id
                         is used (names are not guaranteed unique across products —
                         pass an int id to be precise).
            assignee: Assignee display name (str) to filter by
                      (e.g. ``"Julian Wayte"``). This is the name as it appears
                      in the ticketing system, not an email address.
            page: Page number (0-based, default 0).
            size: Page size (default 100).

        Returns:
            dict: ``{"tickets": [...], "totalElements": int, "totalPages": int}``
        """
        params = {"page": page, "size": size}

        if product is not None:
            if isinstance(product, str):
                product = self._lookup_product_id(product)
            params["product"] = product

        if sub_product is not None:
            if isinstance(sub_product, int):
                params["subProduct"] = sub_product
            else:
                # Resolve name → id via short listing
                sps = self.get_sub_products()
                matches = [sp for sp in sps if sp.get("name") == sub_product]
                if not matches:
                    raise ValueError(f"No sub-product found with name {sub_product!r}")
                params["subProduct"] = matches[0]["id"]

        if assignee is not None:
            params["assignee"] = assignee

        resp = self._session.get(
            f"{self.base_url}/api/v2/tickets",
            params=params,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        data = body.get("data", body) if isinstance(body, dict) else body
        return {
            "tickets": data.get("content", []),
            "totalElements": data.get("totalElements", 0),
            "totalPages": data.get("totalPages", 0),
        }

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

    def get_users_flat(self):
        """List all users via ``GET /user/get-users`` (id, email, displayName, name).

        Lighter than :meth:`search_users` — no teamInfo/tenantRole. Useful for
        name/email lookups. Note many Aledade accounts have no display name, so
        ``displayName`` equals the email (match on email for those).

        Returns:
            list[dict]: Users with ``id``, ``email``, ``displayName``, ``name``.
        """
        resp = self._session.get(
            f"{self.base_url}/user/get-users",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def search_users_all(self, page_size=200):
        """All users with full detail (teamInfo + tenantRole), auto-paginated
        via ``POST /api/v2/user/search``.

        Unlike :meth:`search_users` (which takes filters and returns one
        paginated page), this returns the FULL flattened list across all pages.
        These records carry the fields a bad ``PUT /user/update/user`` can
        silently wipe (teamInfo memberships, account-level tenantRole) — always
        round-trip them on updates.

        Returns:
            list[dict]: User records, each with ``userId``, ``email``,
            ``teamInfo`` (list of {teamId, teamName, role, roleId}), and
            ``tenantRole``.
        """
        users = []
        page = 0
        while True:
            resp = self._session.post(
                f"{self.base_url}/api/v2/user/search?page={page}&size={page_size}",
                json={},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            content = data.get("content", [])
            users.extend(content)
            if data.get("last") or not content:
                break
            page += 1
        return users

    def get_roles(self):
        """List all roles in the tenant via ``GET /user/roles``.

        Two role namespaces exist (they overlap but are not interchangeable):

        * **teamInfo roles** — per-team membership roles (e.g. ``"Aledade
          Executive"``, ``"Aledada PM"``) used in a user's ``teamInfo`` and in
          team-owner assignment.
        * **tenantRoles** — account-level roles accepted by :meth:`create_user`.
          Only a SUBSET of role names are valid tenantRoles. Confirmed valid:
          Read Only, Admin, Developer, Security Engineer, DevOps, Executive,
          Aledade Security Engineer, Aledade Engineering Manager, Aledade
          Security Ambassadors, Aledada PM. NOT valid as tenantRoles: "Aledade
          Executive", "Aledade IT Manager", "Aledade Software Engineer",
          "Aledade IT Engineer".

        Returns:
            list[dict]: Roles, each with ``id``, ``role`` (name),
            ``outOfBox``, ``permissionSet``, etc.
        """
        resp = self._session.get(
            f"{self.base_url}/user/roles",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def email_available(self, email):
        """Check whether ``email`` is free (no existing user) before creating.

        ``POST /api/v2/user/email/availability`` returns ``{"data": true}`` when
        the email is AVAILABLE and ``{"data": false}`` when it is already taken.

        Args:
            email: Email address to check.

        Returns:
            bool: True if available (safe to create), False if taken.
        """
        resp = self._session.post(
            f"{self.base_url}/api/v2/user/email/availability",
            json={"email": email},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return bool(resp.json().get("data"))

    # Lowest-privilege valid tenantRole, used as a transient placeholder when
    # creating a user that will become a plain team member (see
    # create_team_member_user).
    CREATE_PLACEHOLDER_TENANT_ROLE = "Read Only"

    def create_team_member_user(self, email, *, disable_login=False,
                                check_availability=True):
        """Create a user destined to be a plain team member (no account role),
        returning the new user id.

        Wraps the existing :meth:`create_user` with the conventions learned for
        team-owner accounts:

        * ``POST /user/add/user`` REQUIRES a tenantRole (``null`` is rejected
          with "User Mapping Info Is Missing"), so the user is created with the
          low-privilege placeholder ``CREATE_PLACEHOLDER_TENANT_ROLE``.
        * It accepts NO name field, so the display name will be the email (an
          "email-only" account, like many Aledade team-owner users).
        * The placeholder is cleared LATER by :meth:`add_user_to_team` (with
          ``clear_tenant_role=True``), which sets ``tenantRole=null`` and adds
          the team in one PUT — a clear-to-null with an EMPTY teamInfo is
          rejected, so they must happen together.

        Args:
            email: Email of the new user.
            disable_login: Sets ``disableLogin`` on the new user.
            check_availability: If True (default), return None without creating
                                when the email is already taken (no duplicate).

        Returns:
            int or None: New user id, or None if the email was already taken.
        """
        if check_availability and not self.email_available(email):
            return None
        created = self.create_user(
            name=email,
            email=email,
            tenant_role=self.CREATE_PLACEHOLDER_TENANT_ROLE,
            disable_login=disable_login,
        )
        return created.get("id") if isinstance(created, dict) else created

    def delete_user(self, user_id):
        """Delete a user via ``DELETE /api/v2/user/{id}``.

        Returns ``{"data": "deleted", "success": true}`` on success. Useful to
        roll back a freshly-created user when a follow-up team add can't complete.

        Args:
            user_id: User id (int or str).

        Returns:
            dict or None: API response body, or None if empty.
        """
        resp = self._session.delete(
            f"{self.base_url}/api/v2/user/{user_id}",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    def add_user_to_team(self, user, team_id, team_name, role_name, role_id,
                         *, clear_tenant_role=False):
        """Add ``team_id`` to a user's ``teamInfo`` with the given role.

        Sends a full-replace ``PUT /user/update/user`` that appends the new team
        entry to the user's existing teamInfo (so prior memberships are kept).

        IMPORTANT ordering: a user must be a MEMBER of a team (this call) BEFORE
        being set as an owner of it (:meth:`update_team_with_user`); setting the
        owner first can make the team PUT reconcile against a member list the new
        owner isn't in and DROP existing members.

        A non-null ``tenantRole`` makes a user account-level, which BLOCKS team
        membership. Pass ``clear_tenant_role=True`` to send ``tenantRole: None``
        in the same PUT as the team add — the only accepted way to convert a
        placeholder-role (freshly created) user into a plain team member.

        Args:
            user: User record from :meth:`search_users_all` (needs ``userId``,
                  ``email``, existing ``teamInfo``, ``tenantRole``, etc.).
            team_id: Team id to add.
            team_name: Team name (stored in the teamInfo entry).
            role_name: teamInfo role NAME (e.g. ``"Aledade Executive"``).
            role_id: teamInfo role id.
            clear_tenant_role: If True, also set ``tenantRole`` to None.

        Returns:
            dict or None: API response body.
        """
        existing = user.get("teamInfo") or []
        new_team_info = list(existing) + [{
            "teamId": team_id,
            "teamName": team_name,
            "canBeModified": True,
            "role": role_name,
            "roleId": role_id,
        }]
        # Sent as a full-replace body to PUT /user/update/user directly (the
        # generic update_user takes per-field kwargs and can't set tenantRole
        # back to None, which the clear step requires).
        body = {
            "id": user["userId"],
            "email": user["email"],
            "disableLogin": user.get("disableLogin", False),
            "teamInfo": new_team_info,
            "tenantRole": None if clear_tenant_role else user.get("tenantRole"),
            "name": user.get("name"),
            "isBasicAuthEnabled": user.get("isBasicAuthEnabled", False),
            "defaultBu": user.get("defaultBu"),
        }
        resp = self._session.put(
            f"{self.base_url}/user/update/user",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    # ------------------------------------------------------------------
    # Team update (owners / members / scope) — PUT /api/team/with-user
    # ------------------------------------------------------------------

    @staticmethod
    def _team_put_members(members):
        """Convert GET-shape team members to the PUT shape for
        ``/api/team/with-user``. ``role`` must be the NAME STRING (GET returns
        ``{id, name}``); sending the bare id makes the server drop the member."""
        out = []
        for m in members or []:
            role = m.get("role")
            role_name = role.get("name") if isinstance(role, dict) else role
            user = m.get("user") or {}
            out.append({
                "user": {"id": user.get("id")},
                "role": role_name,
                "disableLogin": (m.get("disableLogin")
                                 if m.get("disableLogin") is not None else False),
            })
        return out

    @staticmethod
    def _team_put_properties(properties):
        """Convert a team's GET-shape ``properties`` (scope-of-access) into the
        shape ``PUT /api/team/with-user`` requires. These shapes DIFFER — sending
        the GET shape back makes the server silently DROP the scope (the team
        becomes all-BU/all-product). Confirmed against a working UI payload::

            GET shape                          ->  PUT shape (required)
            businessUnit: {id, name}           ->  businessUnitId, businessUnitName (flat)
            productSubProductMap[].product:        product: <int>  (bare int)
              {id, name}
            productSubProductMap[].subProducts:    subProduct: [<int>...]  (singular key)
              [{id, name}]
        """
        def _int(v):
            try:
                return int(v)
            except (TypeError, ValueError):
                return v

        out = []
        for prop in properties or []:
            np = {
                "accessOnAllProduct": prop.get("accessOnAllProduct"),
                "groups": prop.get("groups") or [],
            }
            if prop.get("id") is not None:
                np["id"] = prop.get("id")
            bu = prop.get("businessUnit")
            if isinstance(bu, dict):
                np["businessUnitId"] = _int(bu.get("id"))
                np["businessUnitName"] = bu.get("name")
            else:
                if prop.get("businessUnitId") is not None:
                    np["businessUnitId"] = _int(prop.get("businessUnitId"))
                if prop.get("businessUnitName") is not None:
                    np["businessUnitName"] = prop.get("businessUnitName")
            maps = []
            for m in (prop.get("productSubProductMap") or []):
                product = m.get("product")
                product_id = product.get("id") if isinstance(product, dict) else product
                subs_in = m.get("subProducts")
                if subs_in is None:
                    subs_in = m.get("subProduct") or []
                maps.append({
                    "product": _int(product_id),
                    "subProduct": [_int(sp.get("id") if isinstance(sp, dict) else sp)
                                   for sp in subs_in],
                    "accessOnAllSubProduct": m.get("accessOnAllSubProduct"),
                })
            np["productSubProductMap"] = maps
            out.append(np)
        return out

    # The 5 team owner-field keys (UI labels in parens are the Aledade tenant's
    # global-settings Titles): complianceOwner (AppSec Engineer), securityOwner
    # (Security Ambassador), engineeringOwner (Aledade Director), businessOwner
    # (Aledade PM), supportOwner (Aledade VP).
    _TEAM_OWNER_KEYS = (
        "complianceOwner", "securityOwner", "engineeringOwner",
        "businessOwner", "supportOwner",
    )

    def update_team_with_user(self, team, *, owners=None):
        """Update a team's owners via ``PUT /api/team/with-user``, preserving
        members and scope-of-access.

        This is a FULL-REPLACE PUT: every owner, the member list, and the
        ``properties`` (scope) must be carried through or they are wiped. This
        method round-trips all of them from ``team`` (a GET response) and applies
        only the requested owner overrides. Members are re-serialized with role
        as a NAME string, and scope ``properties`` are converted to the flat PUT
        shape (see :meth:`_team_put_properties`) — both required to avoid silent
        member/scope wipes.

        Set an owner by passing ``owners={"businessOwner": user_id, ...}`` using
        any of the keys in ``_TEAM_OWNER_KEYS``.

        Args:
            team: Full team detail from :meth:`get_team`.
            owners: Optional dict of ``owner_field -> user_id`` overrides.

        Returns:
            dict: API response (the updated team).
        """
        team_id = team["id"]
        body = {
            "id": team_id,
            "name": team["name"],
            "description": team.get("description"),
            "members": self._team_put_members(team.get("members") or []),
            "properties": self._team_put_properties(team.get("properties") or []),
            "approvalWorkflow": team.get("approvalWorkflow") or {"approvers": []},
            "emailAlias": team.get("emailAlias"),
            "msTeamsLoginId": team.get("msTeamsLoginId"),
            "msTeamsChannel": team.get("msTeamsChannel") or [],
            "accessOnAllBusinessUnits": team.get("accessOnAllBusinessUnits", True),
        }
        # Preserve every existing owner (full-replace nulls omitted fields).
        for key in self._TEAM_OWNER_KEYS:
            existing = team.get(key)
            if existing and existing.get("id"):
                body[key] = {"id": existing["id"]}
        # Apply requested overrides.
        for key, user_id in (owners or {}).items():
            body[key] = {"id": user_id}

        resp = self._session.put(
            f"{self.base_url}/api/team/with-user",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Assets  (POST /api/v2/assets, max page size 100)
    # ------------------------------------------------------------------

    def get_assets(self, source=None, limit=None, filters=None):
        """Fetch assets from the v2 assets API.

        Args:
            source: Optional source name string to filter by (e.g. "CrowdStrike Falcon").
            limit: Max number of assets to return. None means fetch all.
            filters: Optional dict of extra filters to merge into the request body.

        Returns:
            list[dict]: Asset records. Key fields include ``name``, ``ipv4``,
            ``hostname``, ``hostnameNormalized``, ``dnsName``, ``source`` (list),
            ``mergedAssetsCount``, ``correlated``, ``assetIdFromTool``, ``id``.

        Notes:
            - API max page size is 100.
            - ``source`` and ``hostname`` fields are lists in the response.
            - Tenable assets often have no hostname — only IPs.
        """
        MAX_PAGE = 100
        req_filters = dict(filters or {})
        if source:
            req_filters["source"] = [source]

        assets = []
        page = 0
        while True:
            size = min(MAX_PAGE, (limit - len(assets)) if limit else MAX_PAGE)
            resp = self._session.post(
                f"{self.base_url}/api/v2/assets",
                json={"filters": req_filters, "page": page, "size": size},
                timeout=self._timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            batch = data.get("content", [])
            if not batch:
                break
            assets.extend(batch)
            total = data.get("totalElements", 0)
            if len(assets) >= total or (limit and len(assets) >= limit):
                break
            page += 1
        return assets

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

    def get_feature_flags(self):
        """Return the feature flags enabled for this tenant.

        Returns:
            dict: Feature flag map keyed by flag name with boolean/value state.
        """
        resp = self._session.get(
            f"{self.base_url}/user/feature-flags",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Runbooks
    # ------------------------------------------------------------------

    def get_runbooks(self):
        """List all runbook automations (summary, no task detail).

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

    def get_runbook(self, runbook_id):
        """Get full detail for a single runbook including tasks and filters.

        Args:
            runbook_id: Runbook ID (int or str).

        Returns:
            dict: Full runbook detail with tasks, filters, config, schedule.
        """
        resp = self._session.get(
            f"{self.base_url}/api/runbook/{runbook_id}",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def create_runbook(self, body):
        """Create a new runbook automation.

        Args:
            body: Full runbook definition dict (CreateRunbookRequest schema).
                  At minimum, include ``label``, ``type``, ``tasks``, and
                  ``filters``.

        Returns:
            dict: The created runbook with its server-assigned ``id``.
        """
        resp = self._session.post(
            f"{self.base_url}/api/runbook",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def update_runbook(self, runbook_id, body):
        """Update an existing runbook.

        Args:
            runbook_id: Runbook ID (int or str).
            body: Full runbook definition dict (same schema as create).

        Returns:
            dict: The updated runbook.
        """
        resp = self._session.put(
            f"{self.base_url}/api/runbook/{runbook_id}",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def delete_runbook(self, runbook_id):
        """Delete a runbook.

        Args:
            runbook_id: Runbook ID (int or str).

        Returns:
            dict or None: API response body, or None if empty.
        """
        resp = self._session.delete(
            f"{self.base_url}/api/runbook/{runbook_id}",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    def enable_runbook(self, runbook_id):
        """Enable a runbook.

        Args:
            runbook_id: Runbook ID (int or str).

        Returns:
            dict or None: API response body.
        """
        resp = self._session.put(
            f"{self.base_url}/api/runbook/{runbook_id}/enable",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    def disable_runbook(self, runbook_id):
        """Disable a runbook.

        Args:
            runbook_id: Runbook ID (int or str).

        Returns:
            dict or None: API response body.
        """
        resp = self._session.put(
            f"{self.base_url}/api/runbook/{runbook_id}/disable",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    def run_runbook(self, runbook_id):
        """Trigger an immediate on-demand run of a runbook.

        Args:
            runbook_id: Runbook ID (int or str).

        Returns:
            dict or None: API response body.
        """
        resp = self._session.post(
            f"{self.base_url}/api/runbook/{runbook_id}/run-now",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    def export_runbooks(self, name=None, output_dir="runbooks"):
        """Export all runbooks (or one by name) to JSON files.

        Fetches the summary list, then fetches full detail for each runbook
        and writes one <id>_<label>.json file per runbook into output_dir.
        Also writes an all_runbooks.json manifest.

        Args:
            name: Optional runbook label substring to filter (case-insensitive).
                  If None, exports all runbooks.
            output_dir: Directory path to write JSON files into.

        Returns:
            list[dict]: Full runbook detail objects that were exported.
        """
        import os, json, re, time

        os.makedirs(output_dir, exist_ok=True)

        summaries = self.get_runbooks()
        if name:
            summaries = [r for r in summaries if name.lower() in r.get("label", "").lower()]

        exported = []
        for summary in summaries:
            rid = summary["id"]
            try:
                detail = self.get_runbook(rid)
            except Exception:
                detail = summary  # fallback to summary if detail fails

            exported.append(detail)

            safe_label = re.sub(r"[^\w\-]", "_", detail.get("label", str(rid)))[:60]
            fname = os.path.join(output_dir, f"{rid}_{safe_label}.json")
            with open(fname, "w") as f:
                json.dump(detail, f, indent=2, default=str)

            time.sleep(0.15)  # avoid rate-limiting

        manifest = os.path.join(output_dir, "all_runbooks.json")
        with open(manifest, "w") as f:
            json.dump(exported, f, indent=2, default=str)

        return exported

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
    # Finding Actions (single-finding and bulk)
    # ------------------------------------------------------------------

    def get_finding(self, finding_id):
        """Get full detail for a single finding.

        Args:
            finding_id: Finding ID (int).

        Returns:
            dict: Full finding detail.
        """
        resp = self._session.get(
            f"{self.base_url}/user/findings/{finding_id}",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def _bulk_finding_action(self, endpoint, finding_ids, extra=None):
        """Internal helper for bulk finding status-change actions.

        Args:
            endpoint: Path suffix after /user/findings/bulk/.
            finding_ids: List of finding IDs to act on.
            extra: Extra fields to merge into the request body.

        Returns:
            dict or None: API response body.
        """
        body = {"findingIds": list(finding_ids)}
        if extra:
            body.update(extra)
        resp = self._session.put(
            f"{self.base_url}/user/findings/bulk/{endpoint}",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    def bulk_accept_risk(self, finding_ids, reason=None, notes=None):
        """Accept risk on a set of findings.

        Args:
            finding_ids: List of finding IDs.
            reason: Optional reason string.
            notes: Optional notes string.

        Returns:
            dict or None: API response body.
        """
        extra = {}
        if reason:
            extra["reason"] = reason
        if notes:
            extra["notes"] = notes
        return self._bulk_finding_action("accept-risk", finding_ids, extra)

    def bulk_false_positive(self, finding_ids, reason=None, notes=None):
        """Mark a set of findings as false positives.

        Args:
            finding_ids: List of finding IDs.
            reason: Optional reason string.
            notes: Optional notes string.

        Returns:
            dict or None: API response body.
        """
        extra = {}
        if reason:
            extra["reason"] = reason
        if notes:
            extra["notes"] = notes
        return self._bulk_finding_action("false-positive", finding_ids, extra)

    def bulk_suppress(self, finding_ids, reason=None, notes=None):
        """Suppress a set of findings.

        Args:
            finding_ids: List of finding IDs.
            reason: Optional reason string.
            notes: Optional notes string.

        Returns:
            dict or None: API response body.
        """
        extra = {}
        if reason:
            extra["reason"] = reason
        if notes:
            extra["notes"] = notes
        return self._bulk_finding_action("suppressed", finding_ids, extra)

    def bulk_reopen(self, finding_ids):
        """Reopen a set of findings.

        Args:
            finding_ids: List of finding IDs.

        Returns:
            dict or None: API response body.
        """
        return self._bulk_finding_action("reopen", finding_ids)

    def bulk_confirm(self, finding_ids):
        """Confirm a set of findings.

        Args:
            finding_ids: List of finding IDs.

        Returns:
            dict or None: API response body.
        """
        return self._bulk_finding_action("confirm", finding_ids)

    def bulk_change_severity(self, finding_ids, severity):
        """Change severity for a set of findings.

        Args:
            finding_ids: List of finding IDs.
            severity: New severity string, e.g. ``"High"``.

        Returns:
            dict or None: API response body.
        """
        return self._bulk_finding_action("severity", finding_ids, {"severity": severity})

    def bulk_assign_owner(self, finding_ids, owner_id):
        """Assign an owner to a set of findings.

        Args:
            finding_ids: List of finding IDs.
            owner_id: User ID (int) of the new owner.

        Returns:
            dict or None: API response body.
        """
        return self._bulk_finding_action("assign-owner", finding_ids, {"ownerId": owner_id})

    def update_finding_tags(self, finding_ids, tags, update_type="ADD"):
        """Update tags on a set of findings.

        Hits ``PUT /user/findings/findingTags``. Tags are a flat list of
        ``"key:value"`` strings. The ``update_type`` controls whether the
        provided tags are added to, removed from, or replace the existing set.

        Args:
            finding_ids: List of finding IDs (int).
            tags: List of tag strings, e.g. ``["env:prod", "team:security"]``.
            update_type: ``"ADD"`` (default), ``"REMOVE"``, or ``"REPLACE"``.

        Returns:
            dict or None: API response body.
        """
        body = {
            "findingIds": list(finding_ids),
            "findingTags": list(tags),
            "updateType": update_type,
        }
        resp = self._session.put(
            f"{self.base_url}/user/findings/findingTags",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    def get_finding_comments(self, finding_id, page=0, size=20):
        """Get comments on a finding.

        Args:
            finding_id: Finding ID (int).
            page: Page number (0-based).
            size: Page size.

        Returns:
            dict: Paginated comment list.
        """
        resp = self._session.get(
            f"{self.base_url}/user/findings/{finding_id}/comment",
            params={"page": page, "size": size},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def add_finding_comment(self, finding_id, text):
        """Add a comment to a finding.

        Args:
            finding_id: Finding ID (int).
            text: Comment text (plain or markdown).

        Returns:
            dict: The created comment object.
        """
        body = {"note": text, "markdownText": text}
        resp = self._session.post(
            f"{self.base_url}/user/findings/{finding_id}/comment",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def bulk_add_finding_comment(self, finding_ids, text):
        """Add the same comment to multiple findings at once.

        Args:
            finding_ids: List of finding IDs (int).
            text: Comment text (plain or markdown).

        Returns:
            dict or None: API response body.
        """
        body = {
            "findingIds": list(finding_ids),
            "findingCommentRequests": [{"note": text, "markdownText": text}],
        }
        resp = self._session.post(
            f"{self.base_url}/api/finding/bulk-comment",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    # ------------------------------------------------------------------
    # Exceptions (Risk Register)
    # ------------------------------------------------------------------

    def get_exceptions(self):
        """List all open exceptions (risk register entries).

        Returns:
            list[dict]: Open exceptions with id, name, scope, dates, status.
        """
        resp = self._session.get(
            f"{self.base_url}/api/risk-register/open",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else data.get("content", [])

    def get_exception(self, exception_id):
        """Get full detail for a single exception.

        Args:
            exception_id: Exception (risk register) ID (int).

        Returns:
            dict: Exception detail including scope, approvers, findings.
        """
        resp = self._session.get(
            f"{self.base_url}/api/risk-register/{exception_id}",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def create_exception(self, name, description=None, start_date=None,
                         end_date=None, reasons=None, extra=None):
        """Create a new exception (risk register entry).

        Args:
            name: Exception name.
            description: Optional description.
            start_date: ISO 8601 date string, e.g. ``"2025-01-01"``.
            end_date: ISO 8601 date string for when the exception expires.
            reasons: List of reason strings.
            extra: Optional dict merged into the request body (e.g. ``scope``,
                   ``subscribersUserIds``).

        Returns:
            dict: The created exception with its server-assigned ``id``.
        """
        body = {"name": name}
        if description is not None:
            body["description"] = description
        if start_date is not None:
            body["startDate"] = start_date
        if end_date is not None:
            body["endDate"] = end_date
        if reasons is not None:
            body["reasons"] = list(reasons)
        if extra:
            body.update(extra)
        resp = self._session.post(
            f"{self.base_url}/api/risk-register",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def update_exception(self, exception_id, *, name=None, description=None,
                         start_date=None, end_date=None, reasons=None,
                         extra=None):
        """Update an existing exception.

        Args:
            exception_id: Exception (risk register) ID (int).
            name: New name.
            description: New description.
            start_date: New start date ISO string.
            end_date: New end/expiry date ISO string.
            reasons: New reasons list.
            extra: Optional dict merged into the request body.

        Returns:
            dict: The updated exception.
        """
        current = self.get_exception(exception_id)
        body = dict(current)
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if start_date is not None:
            body["startDate"] = start_date
        if end_date is not None:
            body["endDate"] = end_date
        if reasons is not None:
            body["reasons"] = list(reasons)
        if extra:
            body.update(extra)
        resp = self._session.put(
            f"{self.base_url}/api/risk-register/{exception_id}",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def delete_exception(self, exception_id):
        """Delete an exception.

        Args:
            exception_id: Exception (risk register) ID (int).

        Returns:
            dict or None: API response body.
        """
        resp = self._session.delete(
            f"{self.base_url}/api/risk-register/{exception_id}",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    def get_scans(self, page=0, size=50, filters=None):
        """List scans for the tenant.

        Args:
            page: Page number (0-based).
            size: Page size.
            filters: Optional filter dict (e.g. ``{"subProduct": [123]}``)
                     passed as query params via ``scanReportReqDto``.

        Returns:
            dict: Paginated response with ``content`` and ``totalElements``.
        """
        params = {"page": page, "size": size}
        if filters:
            params.update(filters)
        resp = self._session.get(
            f"{self.base_url}/api/scans",
            params=params,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_scan(self, scan_id):
        """Get detail for a single scan.

        Args:
            scan_id: Scan ID (int or str).

        Returns:
            dict: Scan detail including status, tool, sub-product, timing.
        """
        resp = self._session.get(
            f"{self.base_url}/api/scans/{scan_id}",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def get_alerts(self, severity=None, status=None, product=None,
                   sub_product=None, page=0, size=50, extra_filters=None):
        """Search and retrieve alerts.

        Uses ``POST /api/alerts`` (the non-deprecated search endpoint).

        Args:
            severity: List of severity strings, e.g. ``["HIGH", "CRITICAL"]``.
            status: List of status strings, e.g. ``["OPEN"]``.
            product: List of product IDs (int) to filter by.
            sub_product: List of sub-product IDs (int) to filter by.
            page: Page number (0-based).
            size: Page size.
            extra_filters: Additional filter fields merged into the request body.

        Returns:
            dict: Paginated alerts response.
        """
        body = {}
        if severity:
            body["severity"] = list(severity)
        if status:
            body["status"] = list(status)
        if product:
            body["product"] = list(product)
        if sub_product:
            body["subProduct"] = list(sub_product)
        if extra_filters:
            body.update(extra_filters)
        resp = self._session.post(
            f"{self.base_url}/api/alerts",
            params={"page": page, "size": size},
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Engagements (CRUD)
    # ------------------------------------------------------------------

    def get_engagement(self, engagement_id):
        """Get full detail for a single engagement.

        Args:
            engagement_id: Engagement ID (int).

        Returns:
            dict: Engagement detail.
        """
        resp = self._session.get(
            f"{self.base_url}/user/project/{engagement_id}",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def create_engagement(self, name, description, *, type=None,
                          start_date=None, end_date=None, status=None,
                          tags=None, extra=None):
        """Create a new engagement.

        Args:
            name: Engagement name (required).
            description: Description (required by the API).
            type: Engagement type string (e.g. ``"pentest"``).
            start_date: ISO 8601 date string, e.g. ``"2025-01-01"``.
            end_date: ISO 8601 date string.
            status: Status string, e.g. ``"ACTIVE"``.
            tags: List of tag strings.
            extra: Optional dict merged into the request body.

        Returns:
            dict: The created engagement with its server-assigned ``id``.
        """
        body = {"name": name, "description": description}
        if type is not None:
            body["type"] = type
        if start_date is not None:
            body["startDate"] = start_date
        if end_date is not None:
            body["endDate"] = end_date
        if status is not None:
            body["status"] = status
        if tags is not None:
            body["tags"] = list(tags)
        if extra:
            body.update(extra)
        resp = self._session.post(
            f"{self.base_url}/user/project",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def update_engagement(self, engagement_id, *, name=None, description=None,
                          type=None, start_date=None, end_date=None,
                          status=None, tags=None, extra=None):
        """Update an existing engagement.

        Args:
            engagement_id: Engagement ID (int).
            name: New name.
            description: New description.
            type: New type string.
            start_date: New start date ISO string.
            end_date: New end date ISO string.
            status: New status string.
            tags: New tag list (replaces existing tags).
            extra: Optional dict merged into the request body.

        Returns:
            dict: The updated engagement.
        """
        current = self.get_engagement(engagement_id)
        body = dict(current)
        body["id"] = engagement_id
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if type is not None:
            body["type"] = type
        if start_date is not None:
            body["startDate"] = start_date
        if end_date is not None:
            body["endDate"] = end_date
        if status is not None:
            body["status"] = status
        if tags is not None:
            body["tags"] = list(tags)
        if extra:
            body.update(extra)
        resp = self._session.put(
            f"{self.base_url}/user/project",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def delete_engagement(self, engagement_id):
        """Delete an engagement.

        Args:
            engagement_id: Engagement ID (int).

        Returns:
            dict or None: API response body.
        """
        resp = self._session.delete(
            f"{self.base_url}/user/project/{engagement_id}",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    # ------------------------------------------------------------------
    # Teams (CRUD)
    # ------------------------------------------------------------------

    def create_team(self, name, description=None, lead_id=None, members=None,
                    extra=None):
        """Create a new team.

        Args:
            name: Team name (required).
            description: Optional description.
            lead_id: Optional user ID (int) of the team lead.
            members: Optional list of member dicts, each with ``userId`` and
                     ``role`` keys, e.g.
                     ``[{"userId": 123, "role": "MEMBER"}]``.
            extra: Optional dict merged into the request body.

        Returns:
            dict: The created team with its server-assigned ``id``.
        """
        body = {"name": name}
        if description is not None:
            body["description"] = description
        if lead_id is not None:
            body["leadId"] = lead_id
        if members is not None:
            body["members"] = list(members)
        if extra:
            body.update(extra)
        resp = self._session.post(
            f"{self.base_url}/api/team",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def create_team_scoped(self, name, group_scopes, *, description="",
                           members=None, business_unit_id=4255,
                           business_unit_name="Default Organization",
                           email_alias="", extra=None):
        """Create a team scoped to specific groups (products) / subgroups.

        Unlike :meth:`create_team`, this builds the ``properties`` access map
        that grants the team access to one or more groups, optionally limited
        to specific subgroups (sub-products) within each.

        Args:
            name: Team name (required).
            group_scopes: Iterable describing what the team can access. Each
                entry is either:

                  * a group **name** (str) or group **id** (int) — grants
                    whole-group access (``accessOnAllSubProduct: true`` with an
                    empty ``subProduct`` list), or
                  * a ``(group, subgroups)`` tuple where ``group`` is a name or
                    id and ``subgroups`` is a list of sub-product ids. An empty
                    or ``None`` ``subgroups`` also means whole-group access.

                Group names are resolved to ids via exact-match lookup.
            description: Optional team description.
            members: Optional list of member dicts (``userId``/``role``).
            business_unit_id / business_unit_name: Business unit the access map
                is created under (defaults to the tenant "Default Organization").
            email_alias: Optional team email alias.
            extra: Optional dict merged into the top-level request body.

        Returns:
            dict: The created team with its server-assigned ``id``.

        Note:
            The backend honours ``accessOnAllSubProduct``. This method sets it
            to ``False`` only when explicit ``subgroups`` are supplied, and
            ``True`` (whole-group) otherwise. When ``True``, the server stores
            an empty subProduct list regardless of any ids passed.
        """
        psp_map = []
        for entry in group_scopes:
            if isinstance(entry, (list, tuple)):
                group, subgroups = entry[0], (entry[1] if len(entry) > 1 else None)
            else:
                group, subgroups = entry, None

            if isinstance(group, int) or (isinstance(group, str) and group.isdigit()):
                pid = int(group)
            else:
                pid = self._lookup_product_id(group)

            subs = list(subgroups) if subgroups else []
            psp_map.append({
                "product": pid,
                "subProduct": subs,
                "accessOnAllSubProduct": not subs,
            })

        body = {
            "name": name,
            "description": description,
            "members": list(members) if members else [],
            "properties": [{
                "businessUnitId": business_unit_id,
                "businessUnitName": business_unit_name,
                "productSubProductMap": psp_map,
                "accessType": "individual",
                "groups": [],
            }],
            "emailAlias": email_alias,
            "accessOnAllBusinessUnits": False,
            "approvalWorkflow": {"approvers": []},
        }
        if extra:
            body.update(extra)
        resp = self._session.post(
            f"{self.base_url}/api/team",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def update_team(self, team_id, *, name=None, description=None,
                    members=None, extra=None):
        """Update an existing team.

        Fetches current team state and sends it back with requested changes.

        Args:
            team_id: Team ID (int).
            name: New name.
            description: New description.
            members: New members list (replaces existing).
            extra: Optional dict merged into the request body.

        Returns:
            dict: The updated team.
        """
        current = self.get_team(team_id)
        body = dict(current)
        body["id"] = team_id
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if members is not None:
            body["members"] = list(members)
        if extra:
            body.update(extra)
        resp = self._session.put(
            f"{self.base_url}/api/team",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def delete_team(self, team_id):
        """Delete a team.

        Args:
            team_id: Team ID (int).

        Returns:
            dict or None: API response body.
        """
        resp = self._session.delete(
            f"{self.base_url}/api/team/{team_id}",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    def add_team_members(self, team_id, members):
        """Add members to a team.

        Args:
            team_id: Team ID (int).
            members: List of member dicts, each with ``userId`` (int) and
                     ``role`` (str) keys, e.g.
                     ``[{"userId": 123, "role": "MEMBER"}]``.

        Returns:
            dict or None: API response body.
        """
        resp = self._session.post(
            f"{self.base_url}/api/v2/team/{team_id}/members",
            json={"members": list(members)},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    # ------------------------------------------------------------------
    # Users (CRUD)
    # ------------------------------------------------------------------

    def search_users(self, search_text=None, email=None, role=None, team=None,
                     page=0, size=50):
        """Search and filter users in the tenant.

        Args:
            search_text: Free-text search string (matches name or email).
            email: List of email addresses to filter by.
            role: List of role strings to filter by.
            team: List of team IDs (int) to filter by.
            page: Page number (0-based).
            size: Page size.

        Returns:
            dict: Paginated user list.
        """
        body = {}
        if search_text:
            body["searchText"] = [search_text] if isinstance(search_text, str) else list(search_text)
        if email:
            body["email"] = list(email)
        if role:
            body["role"] = list(role)
        if team:
            body["team"] = list(team)
        resp = self._session.post(
            f"{self.base_url}/api/v2/user/search",
            params={"pageRequest": f"page={page}&size={size}"},
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def create_user(self, name, email, tenant_role, *, disable_login=False,
                    team_info=None, extra=None):
        """Create a new user in the tenant.

        Args:
            name: User's display name.
            email: User's email address.
            tenant_role: Role string, e.g. ``"ADMIN"``, ``"USER"``.
            disable_login: If True, the user cannot log in interactively.
            team_info: Optional list of team assignment dicts, each with
                       ``teamId`` and ``role`` keys.
            extra: Optional dict merged into the request body.

        Returns:
            dict: The created user object.
        """
        body = {
            "name": name,
            "email": email,
            "tenantRole": tenant_role,
            "disableLogin": disable_login,
        }
        if team_info is not None:
            body["teamInfo"] = list(team_info)
        if extra:
            body.update(extra)
        resp = self._session.post(
            f"{self.base_url}/user/add/user",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def update_user(self, user_id, *, name=None, email=None, tenant_role=None,
                    disable_login=None, team_info=None, extra=None):
        """Update an existing user.

        Args:
            user_id: User ID (int, required).
            name: New display name.
            email: New email address.
            tenant_role: New role string.
            disable_login: Enable/disable interactive login.
            team_info: New team assignments list.
            extra: Optional dict merged into the request body.

        Returns:
            dict: The updated user object.
        """
        body = {"id": user_id}
        if name is not None:
            body["name"] = name
        if email is not None:
            body["email"] = email
        if tenant_role is not None:
            body["tenantRole"] = tenant_role
        if disable_login is not None:
            body["disableLogin"] = disable_login
        if team_info is not None:
            body["teamInfo"] = list(team_info)
        if extra:
            body.update(extra)
        resp = self._session.put(
            f"{self.base_url}/user/update/user",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # ------------------------------------------------------------------
    # Assessments (Pentests)
    # ------------------------------------------------------------------

    def get_assessments(self, page=0, size=50):
        """List all assessments (pentests).

        Args:
            page: Page number (0-based).
            size: Page size.

        Returns:
            dict: Paginated list of assessments.
        """
        resp = self._session.get(
            f"{self.base_url}/api/assessments",
            params={"page": page, "size": size},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_assessment(self, assessment_id):
        """Get full detail for a single assessment.

        Args:
            assessment_id: Assessment ID (int).

        Returns:
            dict: Assessment detail including scope, assessors, status, dates.
        """
        resp = self._session.get(
            f"{self.base_url}/api/assessments/{assessment_id}",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def create_assessment(self, name, type, start_date, end_date, status,
                          scope, assessors, *, notes=None, extra=None):
        """Create a new assessment (pentest).

        Args:
            name: Assessment name (required).
            type: Assessment type string (required), e.g. ``"External"``.
            start_date: ISO 8601 date string, e.g. ``"2025-01-01"`` (required).
            end_date: ISO 8601 date string (required).
            status: Status string, e.g. ``"IN_PROGRESS"`` (required).
            scope: Scope dict (required), e.g. ``{"subProducts": [123]}``.
            assessors: List of assessor user IDs (int) (required).
            notes: Optional notes string.
            extra: Optional dict merged into the request body.

        Returns:
            dict: The created assessment with its server-assigned ``id``.
        """
        body = {
            "name": name,
            "type": type,
            "startDate": start_date,
            "endDate": end_date,
            "status": status,
            "scope": scope,
            "assessors": list(assessors),
        }
        if notes is not None:
            body["notes"] = notes
        if extra:
            body.update(extra)
        resp = self._session.post(
            f"{self.base_url}/api/assessments",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def delete_assessment(self, assessment_id):
        """Delete an assessment.

        Args:
            assessment_id: Assessment ID (int).

        Returns:
            dict or None: API response body.
        """
        resp = self._session.delete(
            f"{self.base_url}/api/assessments/{assessment_id}",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        if not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

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

