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
            filters["severity"] = list(severities)
        if statuses:
            filters["status"] = list(statuses)
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

    # ------------------------------------------------------------------
    # AIEM — AI Exposure Management
    # ------------------------------------------------------------------
    #
    # AIEM governs the inventory of AI apps/agents detected across the
    # enterprise. Two concept surfaces:
    #   * Inventory — tenant-specific, mutable, the triage target
    #   * Catalog   — shared AI-app knowledge base, reference data
    #
    # Triage writes go through aiem_update_inventory_item (PUT /inventoryV2/id).

    AIEM_STATUSES = (
        "pending", "approved", "conditional", "rejected", "reassessment",
    )
    AIEM_RISK_LEVELS = ("critical", "high", "moderate", "low")
    AIEM_APPROVAL_SCOPES = ("organization", "department", "individual")

    def aiem_list_inventory(
        self,
        *,
        status=None,
        risk_level=None,
        type_=None,
        detection_source=None,
        department=None,
        search=None,
        sort_by=None,
        sort_dir=None,
        page=0,
        page_size=50,
    ):
        """List AIEM inventory items (one page).

        All filter args are optional. Filters are passed as flat query params
        with camelCase keys per the AIEM API contract (single value each;
        the API does not accept multi-value arrays for these filters).

        Returns:
            dict: ``{"items": [...], "page", "total_items", "has_next", ...}``
                  (the ``data`` envelope is unwrapped automatically).
        """
        params = {"page": page, "pageSize": page_size}
        if status: params["status"] = status
        if risk_level: params["riskLevel"] = risk_level
        if type_: params["type"] = type_
        if detection_source: params["detectionSource"] = detection_source
        if department: params["department"] = department
        if search: params["search"] = search
        if sort_by: params["sortBy"] = sort_by
        if sort_dir: params["sortDir"] = sort_dir

        resp = self._session.get(
            f"{self.base_url}/api/v1/aiem/inventoryV2",
            params=params,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        return body.get("data", body) if isinstance(body, dict) else body

    def aiem_get_all_inventory(self, *, page_size=50, **filters):
        """Fetch every AIEM inventory item matching the given filters.

        Auto-paginates. Accepts the same kwargs as ``aiem_list_inventory``.

        Returns:
            list[dict]: All matching inventory items.
        """
        all_items = []
        page = 0
        while True:
            data = self.aiem_list_inventory(page=page, page_size=page_size, **filters)
            items = data.get("items", [])
            all_items.extend(items)
            if not data.get("has_next"):
                break
            page += 1
        return all_items

    def aiem_get_inventory_item(self, item_id):
        """Get full detail for a single inventory item.

        Args:
            item_id: Inventory item ID (Mongo ObjectId string).

        Returns:
            dict: Inventory item detail.
        """
        resp = self._session.get(
            f"{self.base_url}/api/v1/aiem/inventoryV2/id/{item_id}",
            timeout=self._timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        return body.get("data", body) if isinstance(body, dict) else body

    def aiem_update_inventory_item(
        self,
        item_id,
        *,
        status=None,
        risk_level=None,
        notes=None,
        approval=None,
        compliance_tags=None,
        risk_sort_rank=None,
    ):
        """Update an AIEM inventory item (the triage write path).

        Only fields explicitly passed are sent. Pass ``None`` to leave a
        field untouched; pass an empty string/list to clear it.

        Args:
            item_id: Inventory item ID.
            status: One of ``AIEM_STATUSES``.
            risk_level: One of ``AIEM_RISK_LEVELS``.
            notes: Free-text triage note.
            approval: Dict matching the ApprovalInfo schema:
                      ``{"scope": "organization", "departments": [], "conditions": "...", "expires_at": "..."}``
            compliance_tags: List of compliance-tag strings.
            risk_sort_rank: Integer rank for risk-level sort tiebreak.

        Returns:
            dict: Updated inventory item.
        """
        if status is not None and status not in self.AIEM_STATUSES:
            raise ValueError(f"status must be one of {self.AIEM_STATUSES}")
        if risk_level is not None and risk_level not in self.AIEM_RISK_LEVELS:
            raise ValueError(f"risk_level must be one of {self.AIEM_RISK_LEVELS}")
        if approval is not None and approval.get("scope") not in self.AIEM_APPROVAL_SCOPES:
            raise ValueError(
                f"approval.scope must be one of {self.AIEM_APPROVAL_SCOPES}"
            )

        body = {}
        if status is not None: body["status"] = status
        if risk_level is not None: body["risk_level"] = risk_level
        if notes is not None: body["notes"] = notes
        if approval is not None: body["approval"] = approval
        if compliance_tags is not None: body["compliance_tags"] = compliance_tags
        if risk_sort_rank is not None: body["risk_sort_rank"] = risk_sort_rank

        resp = self._session.put(
            f"{self.base_url}/api/v1/aiem/inventoryV2/id/{item_id}",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        out = resp.json()
        return out.get("data", out) if isinstance(out, dict) else out

    def aiem_create_inventory_item(
        self,
        app_name,
        *,
        type_,
        catalog_domain=None,
        catalog_name=None,
        custom_app=None,
        status="pending",
        risk_level=None,
        notes=None,
        approval=None,
        compliance_tags=None,
    ):
        """Create a new AIEM inventory item.

        Either ``catalog_domain`` (pulls metadata from the shared catalog) or
        ``custom_app`` (manual entry) must be provided.

        Returns:
            dict: The newly created inventory item.
        """
        if not (catalog_domain or custom_app):
            raise ValueError("Either catalog_domain or custom_app is required")
        body = {
            "app_name": app_name,
            "type": type_ if isinstance(type_, list) else [type_],
            "status": status,
        }
        if catalog_domain: body["catalog_domain"] = catalog_domain
        if catalog_name: body["catalog_name"] = catalog_name
        if custom_app: body["custom_app"] = custom_app
        if risk_level: body["risk_level"] = risk_level
        if notes: body["notes"] = notes
        if approval: body["approval"] = approval
        if compliance_tags: body["compliance_tags"] = compliance_tags

        resp = self._session.post(
            f"{self.base_url}/api/v1/aiem/inventoryV2",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        out = resp.json()
        return out.get("data", out) if isinstance(out, dict) else out

    def aiem_inventory_filters(self, **scope):
        """Get available inventory filter options (with counts scoped by
        currently active filters).

        Pass kwargs like ``status='pending'`` to scope the facet counts
        (e.g. "how many of each risk_level within status=pending?").

        Returns:
            dict: ``{"statuses": [...], "risk_levels": [...], "types": [...],
                     "detection_sources": [...], "departments": [...],
                     "sort_options": [...]}``.
        """
        resp = self._session.get(
            f"{self.base_url}/api/v1/aiem/inventoryV2/filters",
            params=scope or None,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        return body.get("data", body) if isinstance(body, dict) else body

    def aiem_inventory_stats(
        self, agg_field, *, metric=None, sec_agg_field=None,
        top_n=None, filters=None, include_missing=None,
    ):
        """Get inventory statistics for dashboard widgets.

        Args:
            agg_field: Primary aggregation field (required by the API).
            metric: One of ``inventory_count``, ``user_count``, ``usage_count``.
            sec_agg_field: Optional secondary aggregation field.
            top_n: Cap on number of aggregation buckets.
            filters: Additional filter dict.
            include_missing: Include items missing the agg field.

        Returns:
            dict: Aggregation results.
        """
        body = {"aggField": agg_field}
        if metric: body["metric"] = metric
        if sec_agg_field: body["secAggField"] = sec_agg_field
        if top_n is not None: body["topN"] = top_n
        if filters: body["filters"] = filters
        if include_missing is not None: body["includeMissing"] = include_missing

        resp = self._session.post(
            f"{self.base_url}/api/v1/aiem/inventoryV2/stats",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        out = resp.json()
        return out.get("data", out) if isinstance(out, dict) else out

    def aiem_inventory_timeline(
        self, metric, *, aggregate_by="day", start_date=None, end_date=None,
        agg_field=None, top_n=None, filters=None,
    ):
        """Get inventory timeline data for trend charts.

        Args:
            metric: One of ``inventory_count``, ``user_count``, ``usage_count``.
            aggregate_by: Time bucket (e.g. ``"day"``, ``"week"``, ``"month"``).
            start_date, end_date: ISO-8601 strings (optional).
            agg_field: Optional grouping field.
            top_n: Cap on groupings.
            filters: Additional filter dict.

        Returns:
            dict: Timeline data.
        """
        body = {"metric": metric, "aggregateBy": aggregate_by}
        if start_date: body["startDate"] = start_date
        if end_date: body["endDate"] = end_date
        if agg_field: body["aggField"] = agg_field
        if top_n is not None: body["topN"] = top_n
        if filters: body["filters"] = filters

        resp = self._session.post(
            f"{self.base_url}/api/v1/aiem/inventoryV2/timeline",
            json=body,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        out = resp.json()
        return out.get("data", out) if isinstance(out, dict) else out

    def aiem_list_catalog(self, *, search=None, sort_by=None, sort_dir=None,
                          page=0, page_size=50, **extra_filters):
        """List entries from the shared AI-app catalog (reference data).

        Extra filter kwargs (e.g. ``riskLevel='high'``, ``type='CONVERSATIONAL_AI'``)
        are forwarded as flat query params.

        Returns:
            dict: ``{"items": [...], "page", "total_items", ...}``.
        """
        params = {"page": page, "pageSize": page_size}
        if search: params["search"] = search
        if sort_by: params["sortBy"] = sort_by
        if sort_dir: params["sortDir"] = sort_dir
        params.update(extra_filters)
        resp = self._session.get(
            f"{self.base_url}/api/v1/aiem/catalogV2",
            params=params,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        return body.get("data", body) if isinstance(body, dict) else body

    def aiem_catalog_filters(self, **scope):
        """Get faceted filter options for the catalog (counts scoped by
        any active filters passed as kwargs)."""
        resp = self._session.get(
            f"{self.base_url}/api/v1/aiem/catalogV2/filters",
            params=scope or None,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        return body.get("data", body) if isinstance(body, dict) else body

    def aiem_catalog_approval_candidates(
        self, *, search=None, sort_by=None, sort_dir=None,
        page=0, page_size=50, **extra_filters,
    ):
        """Catalog entries not yet present in this tenant's inventory.

        Useful for pre-populating the inventory with known-OK apps.
        """
        params = {"page": page, "pageSize": page_size}
        if search: params["search"] = search
        if sort_by: params["sortBy"] = sort_by
        if sort_dir: params["sortDir"] = sort_dir
        params.update(extra_filters)
        resp = self._session.get(
            f"{self.base_url}/api/v1/aiem/catalogV2/approval-candidates",
            params=params,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        body = resp.json()
        return body.get("data", body) if isinstance(body, dict) else body
