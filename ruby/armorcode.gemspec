require_relative "lib/armorcode/version"

Gem::Specification.new do |spec|
  spec.name    = "armorcode"
  spec.version = Armorcode::VERSION
  spec.authors = ["ArmorCode"]
  spec.summary = "Ruby SDK for the ArmorCode REST API"

  spec.required_ruby_version = ">= 2.7"

  spec.files = Dir["lib/**/*.rb"]

  spec.add_dependency "faraday", "~> 2.0"
  spec.add_dependency "faraday-retry", "~> 2.0"
end
