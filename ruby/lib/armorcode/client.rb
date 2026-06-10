require "faraday"
require "faraday/retry"
require "json"
require "time"
require "csv"
require "fileutils"

module Armorcode
  class Client
    SEVERITIES = %w[Critical High Medium Low Info].freeze
    STATUSES   = %w[OPEN CONFIRMED ACCEPTRISK FALSEPOSITIVE MITIGATED SUPPRESSED TRIAGE IN_PROGRESS CONTROLLED].freeze

    MAX_RESULTS = 10_000

    # Create a client from an env file.
    #
    #   TENANT_URL=<https://my-tenant-url>
    #   API_TOKEN=<api-token>
    #
    # TENANT_URL may be a bare hostname or full https:// URL.
    # For backward compatibility also accepts *_TOKEN (legacy) and lowercase token/url.
    def self.from_env(env_path = "env")
      config = {}
      File.foreach(env_path) do |line|
        line = line.strip
        next if line.empty? || line.start_with?("#") || !line.include?("=")
        k, v = line.split("=", 2)
        config[k.strip] = v.strip
      end

      tenant_url = config["TENANT_URL"] || config["url"] || "app.armorcode.com"
      tenant_url = tenant_url.sub(%r{^https?://}, "")

      token = config["API_TOKEN"] ||
              config.find { |k, _v| k.end_with?("_TOKEN") }&.last ||
              config["token"]

      raise "No token found in env file (expected API_TOKEN, *_TOKEN, or token)" unless token

      new(tenant_url, token)
    end

    def initialize(tenant_url, token, timeout: 60)
      @base_url = "https://#{tenant_url.gsub(%r{/$}, "")}"
      @timeout  = timeout
      @conn = Faraday.new(url: @base_url) do |f|
        f.request :json
        f.request :retry, max: 3, interval: 1, backoff_factor: 2,
                           exceptions: [Faraday::TimeoutError, Faraday::ConnectionFailed]
        f.response :raise_error
        f.adapter Faraday.default_adapter
        f.headers["Authorization"] = "Bearer #{token}"
        f.headers["Content-Type"]  = "application/json"
      end

      @findings      = []
      @cache_params  = {}
    end

    # ---------------------------------------------------------------
    # Findings
    # ---------------------------------------------------------------

    def get_findings(severities: nil, statuses: nil, days_back: nil,
                     extra_filters: nil, dump_path: nil, page_size: 2000)
      filters    = {}
      filter_ops = {}

      filters["severity"] = Array(severities) if severities
      filters["status"]   = Array(statuses)   if statuses
      filters.merge!(extra_filters)           if extra_filters

      now_ms           = (Time.now.to_f * 1000).to_i
      effective_days   = days_back || 365
      start_ms         = now_ms - (effective_days * 86_400 * 1000).to_i

      if days_back
        filters["foundOn"]    = [start_ms.to_s]
        filter_ops["foundOn"] = "GREATER_THAN"
      end

      total = probe_count(filters, filter_ops)

      all_findings = if total <= MAX_RESULTS
        paginated_fetch(filters, filter_ops, page_size)
      else
        chunked_fetch(filters, filter_ops, start_ms, now_ms, total, page_size)
      end

      @findings     = all_findings
      @cache_params = { severities: severities, statuses: statuses, days_back: days_back }

      dump_json(dump_path) if dump_path

      all_findings
    end

    def list_repos(findings: nil)
      findings ||= @findings
      counts = Hash.new(0)
      findings.each do |f|
        repo = (f["subProduct"] || {})["name"] || "(unmapped)"
        counts[repo] += 1
      end
      counts.sort_by { |_k, v| -v }
    end

    def get_findings_by_repo(repo_name, findings: nil)
      findings ||= @findings
      findings.select { |f| (f["subProduct"] || {})["name"] == repo_name }
    end

    def dump_json(path = "findings.json")
      out = {
        metadata: {
          tenant:         @base_url,
          total_findings: @findings.length,
          query_params:   @cache_params,
          exported_at:    Time.now.utc.iso8601,
        },
        findings: @findings,
      }
      File.write(path, JSON.pretty_generate(out))
    end

    # ---------------------------------------------------------------
    # Finding Statistics
    # ---------------------------------------------------------------

    def get_finding_stats(filters: nil)
      post("/user/findings/findingStats", filters: filters || {})
    end

    def get_finding_stats_by_team(team_name, environments: nil)
      post("/user/findings/stat/team",
           filters: { name: team_name, environmentName: environments || [] })
    end

    def get_finding_stats_by_product(product_name, environments: nil)
      post("/user/findings/stat/product",
           filters: { name: product_name, environmentName: environments || [] })
    end

    def analyze_risk_scoring_tags(finding_age, severities, statuses: nil, findings: nil)
      severities = severities.is_a?(String) ? severities.split(",").map(&:strip) : Array(severities)
      severities = severities.map { |s| s[0].upcase + s[1..].downcase }
      statuses ||= ["OPEN"]

      config  = get_tenant_config("ASSET_SCORE") || []
      triples = config.filter_map do |entry|
        next unless entry["name"] && !entry["fieldValue"].nil?
        [entry["name"], entry["fieldValue"].to_s, entry["value"] || 0]
      end

      findings ||= get_findings(severities: severities, statuses: statuses, days_back: finding_age)

      counts       = triples.each_with_object({}) { |(k, v, _w), h| h[[k, v]] = 0 }
      no_tag_count = 0

      findings.each do |f|
        tag_set = (f["tags"] || []).to_set
        matched = false
        triples.each do |k, v, _w|
          if tag_set.include?("#{k}:#{v}")
            counts[[k, v]] += 1
            matched = true
          end
        end
        no_tag_count += 1 unless matched
      end

      rows = triples.map { |k, v, w| { tag_key: k, tag_value: v, weight: w, count: counts[[k, v]] } }
      rows.sort_by! { |r| -r[:count] }
      rows << { tag_key: "(none — finding had no scoring tag)", tag_value: "", weight: 0, count: no_tag_count }
      rows
    end

    # ---------------------------------------------------------------
    # CSV Export
    # ---------------------------------------------------------------

    def export_findings_csv(output_path, filters: nil, filter_operations: nil)
      body = { filters: filters || {}, filterOperations: filter_operations || {} }
      resp = @conn.post("/user/findings/download/csv") { |req| req.body = body.to_json }
      File.binwrite(output_path, resp.body)
      output_path
    end

    # ---------------------------------------------------------------
    # Repositories
    # ---------------------------------------------------------------

    def get_repos(states: nil, sources: nil, page: 0, size: 100)
      body = {}
      body["repositoryStates"] = Array(states)  if states
      body["sources"]          = Array(sources) if sources
      resp = @conn.post("/api/scm/discover/repos") do |req|
        req.params = { page: page, size: size }
        req.body   = body.to_json
      end
      result = JSON.parse(resp.body)
      result.dig("data").is_a?(Hash) ? result["data"] : result
    end

    def get_repo_filters
      get("/api/scm/discover/repo-filters")
    end

    def get_repo_details(status_type: "ACTIVE", include_ignored: false)
      get("/user/tools/git/repos/details",
          gitReposStatusType: status_type, includeIgnored: include_ignored)
    end

    def get_repo_contributors(repo_id)
      get("/api/tools/git/repo/#{repo_id}/contributors")
    end

    # ---------------------------------------------------------------
    # Teams
    # ---------------------------------------------------------------

    def get_teams
      get("/api/team/all-teams")
    end

    def get_team(team_id)
      get("/api/team/#{team_id}")
    end

    def get_team_stats(environment: "Production")
      get("/api/team/all-team-stats", environment: environment)
    end

    def get_team_leads
      get("/user/team-leads")
    end

    # ---------------------------------------------------------------
    # Products
    # ---------------------------------------------------------------

    def get_products(page: 0, size: 100, search: nil)
      params = { pageNumber: page, pageSize: size }
      params[:search] = search if search
      get("/user/product/elastic/paged", **params)
    end

    def create_product(name, description: nil, type_id: nil, tags: nil, extra: nil)
      body = { name: name }
      body[:description] = description if description
      body[:type]        = { id: type_id } if type_id
      body[:tags]        = tags if tags
      body.merge!(extra) if extra
      post("/user/product", **body)
    end

    def update_product(product_name = nil, product_id: nil, name: nil,
                       description: nil, tags: nil, extra: nil)
      product_id ||= begin
        raise ArgumentError, "Either product_name or product_id is required" unless product_name
        lookup_product_id(product_name)
      end

      body = get("/user/product/#{product_id}")
      body["id"] = product_id
      body["name"]        = name        if name
      body["description"] = description if description
      body["tags"]        = tags        if tags
      body.merge!(extra) if extra

      resp = @conn.put("/user/product") { |req| req.body = body.to_json }
      JSON.parse(resp.body)
    end

    # ---------------------------------------------------------------
    # Sub-Products
    # ---------------------------------------------------------------

    def get_sub_products
      get("/user/sub-product/elastic/short")
    end

    def get_sub_product(sub_product_id)
      get("/api/sub-product/#{sub_product_id}")
    end

    def create_sub_product(name, product_name = nil, product_id: nil,
                           description: nil, environment_id: nil,
                           tier: nil, tags: nil, extra: nil)
      product_id ||= begin
        raise ArgumentError, "Either product_name or product_id is required" unless product_name
        lookup_product_id(product_name)
      end

      body = { name: name, product: { id: product_id } }
      body[:description]  = description              if description
      body[:environment]  = { id: environment_id }  if environment_id
      body[:tier]         = tier                     if tier
      body[:tags]         = tags                     if tags
      body.merge!(extra) if extra
      post("/api/sub-product", **body)
    end

    def update_sub_product(sub_product_id, name: nil, description: nil,
                           tags: nil, extra: nil)
      body = get_sub_product(sub_product_id)
      body["id"]          = sub_product_id
      body["name"]        = name        if name
      body["description"] = description if description
      body["tags"]        = tags        if tags
      body.merge!(extra) if extra

      resp = @conn.put("/api/sub-product") { |req| req.body = body.to_json }
      JSON.parse(resp.body)
    end

    def update_product_add_tags(product_name = nil, product_id: nil, tags:)
      product_id ||= begin
        raise ArgumentError, "Either product_name or product_id is required" unless product_name
        lookup_product_id(product_name)
      end
      current  = get("/user/product/#{product_id}")
      existing = Array(current["tags"])
      merged   = existing + (Array(tags) - existing)
      update_product(product_id: product_id, tags: merged)
    end

    def update_sub_product_add_tags(sub_product_id, tags)
      current  = get_sub_product(sub_product_id)
      existing = Array(current["tags"])
      merged   = existing + (Array(tags) - existing)
      update_sub_product(sub_product_id, tags: merged)
    end

    def update_product_set_tag(key_value, product_name = nil, product_id: nil)
      raise ArgumentError, "key_value must be 'key:value' format" unless key_value.include?(":")
      product_id ||= begin
        raise ArgumentError, "Either product_name or product_id is required" unless product_name
        lookup_product_id(product_name)
      end
      current  = get("/user/product/#{product_id}")
      key      = key_value.split(":", 2).first
      existing = (Array(current["tags"])).reject { |t| t.start_with?("#{key}:") }
      update_product(product_id: product_id, tags: existing + [key_value])
    end

    def update_sub_product_set_tag(sub_product_id, key_value)
      raise ArgumentError, "key_value must be 'key:value' format" unless key_value.include?(":")
      current  = get_sub_product(sub_product_id)
      key      = key_value.split(":", 2).first
      existing = (Array(current["tags"])).reject { |t| t.start_with?("#{key}:") }
      update_sub_product(sub_product_id, tags: existing + [key_value])
    end

    # ---------------------------------------------------------------
    # Tickets
    # ---------------------------------------------------------------

    def get_tickets(product: nil, sub_product: nil, assignee: nil,
                    page: 0, size: 100)
      params = { page: page, size: size }

      if product
        params[:product] = product.is_a?(String) ? lookup_product_id(product) : product
      end

      if sub_product
        if sub_product.is_a?(Integer)
          params[:subProduct] = sub_product
        else
          sps     = get_sub_products
          match   = sps.find { |sp| sp["name"] == sub_product }
          raise "No sub-product found with name #{sub_product.inspect}" unless match
          params[:subProduct] = match["id"]
        end
      end

      params[:assignee] = assignee if assignee

      resp = @conn.get("/api/v2/tickets") { |req| req.params = params }
      body = JSON.parse(resp.body)
      data = body.is_a?(Hash) ? (body["data"] || body) : body
      {
        tickets:       data["content"]       || [],
        totalElements: data["totalElements"] || 0,
        totalPages:    data["totalPages"]    || 0,
      }
    end

    # ---------------------------------------------------------------
    # Users
    # ---------------------------------------------------------------

    def get_users
      get("/user/data/users")
    end

    # ---------------------------------------------------------------
    # Assets
    # ---------------------------------------------------------------

    def get_assets(source: nil, limit: nil, filters: nil)
      max_page    = 100
      req_filters = (filters || {}).dup
      req_filters["source"] = [source] if source

      assets = []
      page   = 0
      loop do
        size = limit ? [max_page, limit - assets.length].min : max_page
        resp = @conn.post("/api/v2/assets") do |req|
          req.body = { filters: req_filters, page: page, size: size }.to_json
        end
        data  = JSON.parse(resp.body)
        batch = data["content"] || []
        break if batch.empty?
        assets.concat(batch)
        total = data["totalElements"] || 0
        break if assets.length >= total || (limit && assets.length >= limit)
        page += 1
      end
      assets
    end

    # ---------------------------------------------------------------
    # Security Tools
    # ---------------------------------------------------------------

    def get_tools
      get("/user/tools/appsec-tools/status")
    end

    def get_integration_tools
      get("/user/tools/integration-tools/status")
    end

    def get_feature_flags
      get("/user/feature-flags")
    end

    # ---------------------------------------------------------------
    # Runbooks
    # ---------------------------------------------------------------

    def get_runbooks
      get("/api/runbook")
    end

    def get_runbook(runbook_id)
      get("/api/runbook/#{runbook_id}")
    end

    def export_runbooks(name: nil, output_dir: "runbooks")
      FileUtils.mkdir_p(output_dir)

      summaries = get_runbooks
      summaries = summaries.select { |r| r["label"].to_s.downcase.include?(name.downcase) } if name

      exported = summaries.map do |summary|
        rid    = summary["id"]
        detail = begin; get_runbook(rid); rescue; summary; end

        safe_label = detail["label"].to_s.gsub(/[^\w\-]/, "_")[0, 60]
        File.write(File.join(output_dir, "#{rid}_#{safe_label}.json"),
                   JSON.pretty_generate(detail))
        sleep(0.15)
        detail
      end

      File.write(File.join(output_dir, "all_runbooks.json"), JSON.pretty_generate(exported))
      exported
    end

    # ---------------------------------------------------------------
    # SLA
    # ---------------------------------------------------------------

    def get_sla_tiers
      get("/user/findingSla/tiers")
    end

    def get_sla_stats(filters: nil)
      post("/user/findingSla/sla-stats", filters: filters || {})
    end

    def get_team_sla_stats(filters: nil, agg_fields: nil)
      post("/user/findingSla/team-sla-stats",
           filters: filters || {}, aggFields: agg_fields || ["teamId"])
    end

    def get_mttr_stats(filters: nil)
      post("/api/finding-sla/mean-remediation-stats", filters: filters || {})
    end

    # ---------------------------------------------------------------
    # Tenant Configuration / API Discovery
    # ---------------------------------------------------------------

    def get_tenant_config(config_type)
      get("/api/tenant-config", configType: config_type)
    end

    def get_api_docs
      get("/v3/api-docs")
    end

    private

    # ---------------------------------------------------------------
    # HTTP helpers
    # ---------------------------------------------------------------

    def get(path, params = {})
      resp = @conn.get(path) { |req| req.params = params unless params.empty? }
      JSON.parse(resp.body)
    end

    def post(path, body = {})
      resp = @conn.post(path) { |req| req.body = body.to_json }
      JSON.parse(resp.body)
    end

    # ---------------------------------------------------------------
    # Pagination helpers
    # ---------------------------------------------------------------

    def probe_count(filters, filter_ops)
      body = { filters: filters, filterOperations: filter_ops, page: 0, size: 1 }
      resp = @conn.post("/user/findings/") { |req| req.body = body.to_json }
      JSON.parse(resp.body)["totalElements"] || 0
    end

    def paginated_fetch(filters, filter_ops, page_size)
      url          = "/user/findings/"
      all_findings = []
      page         = 0

      loop do
        body = {
          filters:          filters,
          filterOperations: filter_ops,
          page:             page,
          size:             page_size,
          sortColumn:       "foundOn",
          sortOrder:        "DESC",
        }
        resp    = @conn.post(url) { |req| req.body = body.to_json }
        data    = JSON.parse(resp.body)
        content = data["content"] || []
        total   = data["totalElements"] || 0
        all_findings.concat(content)
        break if content.empty? || all_findings.length >= total
        page += 1
      end

      all_findings
    end

    def chunked_fetch(base_filters, base_filter_ops, start_ms, end_ms, total, page_size)
      num_chunks     = [2, (total / (MAX_RESULTS / 2)) + 1].max
      chunk_duration = (end_ms - start_ms) / num_chunks

      all_findings = []
      seen_ids     = {}

      num_chunks.times do |i|
        chunk_start = start_ms + (i * chunk_duration)
        chunk_end   = i < num_chunks - 1 ? start_ms + ((i + 1) * chunk_duration) : end_ms

        chunk_filters = base_filters.reject { |k, _| k == "foundOn" }.merge(
          "foundOn" => [chunk_start.to_s, chunk_end.to_s]
        )
        chunk_ops = base_filter_ops.reject { |k, _| k == "foundOn" }.merge("foundOn" => "BETWEEN")

        chunk_total = probe_count(chunk_filters, chunk_ops)

        sub = if chunk_total > MAX_RESULTS
          chunked_fetch(chunk_filters, chunk_ops, chunk_start, chunk_end, chunk_total, page_size)
        else
          paginated_fetch(chunk_filters, chunk_ops, page_size)
        end

        sub.each do |f|
          fid = f["id"]
          unless seen_ids[fid]
            seen_ids[fid] = true
            all_findings << f
          end
        end
      end

      all_findings
    end

    # ---------------------------------------------------------------
    # Name → ID resolution
    # ---------------------------------------------------------------

    def lookup_product_id(product_name)
      resp    = get("/user/product/elastic/paged", pageNumber: 0, pageSize: 100, search: product_name)
      matches = (resp["content"] || []).select { |p| p["name"] == product_name }
      raise "No product found with name #{product_name.inspect}" if matches.empty?
      if matches.length > 1
        ids = matches.map { |m| m["id"] }
        raise "Multiple products named #{product_name.inspect}: #{ids}. Pass product_id explicitly."
      end
      matches.first["id"].to_i
    end
  end
end
