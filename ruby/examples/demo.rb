#!/usr/bin/env ruby
# Quick demo of the ArmorCode Ruby SDK — run this to verify your setup.

$LOAD_PATH.unshift(File.join(__dir__, "..", "lib"))
require "armorcode"

env_path = ENV.fetch("AC_ENV", File.join(__dir__, "..", "..", "env"))
ac = Armorcode::Client.from_env(env_path)

# Pull all Critical + High findings from the last 14 days
findings = ac.get_findings(severities: ["Critical", "High"], days_back: 14)
puts "Findings: #{findings.length}"

# List repos with finding counts
puts "\nRepos:"
ac.list_repos(findings: findings).each do |repo, count|
  puts "  #{repo}: #{count}"
end

# Get findings for the top repo
unless findings.empty?
  top_repo = ac.list_repos(findings: findings).first.first
  repo_findings = ac.get_findings_by_repo(top_repo)
  puts "\nTop repo '#{top_repo}': #{repo_findings.length} findings"
end

# List teams
teams = ac.get_teams
puts "\nTeams: #{teams.length}"
teams.first(5).each { |t| puts "  #{t["name"]} (id: #{t["id"]})" }
puts "  ... and #{teams.length - 5} more" if teams.length > 5

# List products
products = ac.get_products
total_products = products["totalElements"] || 0
puts "\nProducts: #{total_products}"
(products["content"] || []).first(5).each { |p| puts "  #{p["name"]} (id: #{p["id"]})" }
puts "  ... and #{total_products - 5} more" if total_products > 5

# List sub-products
sub_products = ac.get_sub_products
puts "\nSub-Products: #{sub_products.length}"
sub_products.first(5).each { |sp| puts "  #{sp["name"]} (id: #{sp["id"]})" }
puts "  ... and #{sub_products.length - 5} more" if sub_products.length > 5

# List runbooks
runbooks = ac.get_runbooks
puts "\nRunbooks: #{runbooks.length}"
runbooks.first(5).each do |rb|
  status = rb["enabled"] ? "enabled" : "disabled"
  puts "  #{rb["label"]} (#{status}, #{rb["executionCount"] || 0} runs)"
end
puts "  ... and #{runbooks.length - 5} more" if runbooks.length > 5
