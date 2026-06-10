require_relative "armorcode/version"
require_relative "armorcode/client"

module Armorcode
  # Convenience: Armorcode::Client.from_env is the primary entry point.
  #
  #   require "armorcode"
  #
  #   ac = Armorcode::Client.from_env("env")
  #   findings = ac.get_findings(severities: ["Critical", "High"], statuses: ["OPEN"])
end
