# frozen_string_literal: true

Gem::Specification.new do |s|
  s.name          = "antech_kdf"
  s.version       = "0.1.0"
  s.summary       = "Antech KDF — thin language wrappers over the canonical Rust FFI"
  s.authors       = ["Udinmo, Inc."]
  s.email         = ["antech-kdf@udinmo.com"]
  s.homepage      = "https://github.com/udinmoInc/antech-kdf"
  s.license       = "MIT"
  s.files         = Dir["lib/**/*.rb", "README.md"]
  s.require_paths = ["lib"]
  s.required_ruby_version = ">= 3.0"
  s.add_dependency "ffi", "~> 1.15"
end
