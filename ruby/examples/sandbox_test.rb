#!/usr/bin/env ruby
# Smoke test of the ArmorCode Ruby SDK against a live tenant.
# Exercises read-only methods and reports pass/fail per call.

$LOAD_PATH.unshift(File.join(__dir__, "..", "lib"))
require "armorcode"

env_path = ENV.fetch("AC_ENV", "/Users/Julian.Wayte/Documents/claude/JulianSandbox/env")
ac = Armorcode::Client.from_env(env_path)

passed = 0
failed = 0

def section(title)
  puts "\n=== #{title} ==="
end

def check(label)
  result = yield
  detail =
    case result
    when Array then "#{result.length} items"
    when Hash  then "#{result.keys.length} keys"
    else result.inspect[0, 60]
    end
  puts "  PASS  #{label} -> #{detail}"
  [true, result]
rescue => e
  puts "  FAIL  #{label} -> #{e.class}: #{e.message[0, 120]}"
  [false, nil]
end

results = []

section "Findings"
results << check("get_findings(Critical/High, 14d)") do
  $findings = ac.get_findings(severities: %w[Critical High], days_back: 14)
end
results << check("list_repos") { ac.list_repos(findings: $findings || []) }
results << check("get_finding_stats") { ac.get_finding_stats }

section "Repositories"
results << check("get_repos") { ac.get_repos(size: 10) }
results << check("get_repo_filters") { ac.get_repo_filters }

section "Teams"
results << check("get_teams") { ac.get_teams }
results << check("get_team_stats(Production)") { ac.get_team_stats }

section "Products / Sub-Products"
results << check("get_products") { ac.get_products(size: 10) }
results << check("get_sub_products") { ac.get_sub_products }

section "Users / Tools"
results << check("get_users") { ac.get_users }
results << check("get_tools") { ac.get_tools }
results << check("get_integration_tools") { ac.get_integration_tools }

section "SLA"
results << check("get_sla_tiers") { ac.get_sla_tiers }
results << check("get_sla_stats") { ac.get_sla_stats }

section "Runbooks"
results << check("get_runbooks") { ac.get_runbooks }

section "Tenant Config"
results << check("get_tenant_config(ASSET_SCORE)") { ac.get_tenant_config("ASSET_SCORE") }

passed = results.count { |ok, _| ok }
failed = results.count { |ok, _| !ok }
puts "\n=== SUMMARY: #{passed} passed, #{failed} failed (#{results.length} total) ==="
exit(failed.zero? ? 0 : 1)
