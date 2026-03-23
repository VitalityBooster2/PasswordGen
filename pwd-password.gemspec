Gem::Specification.new do |spec|
  spec.name = "pwd-password"
  spec.version = "0.1.0"
  spec.authors = ["Cursor Agent"]
  spec.email = ["noreply@example.com"]

  spec.summary = "Password generator and strength checker (with CLI and encrypted store)"
  spec.description = "Generates passwords with chosen character sets, estimates strength (weak/medium/strong) and approximate brute-force time, and optionally stores generated passwords in an encrypted file."
  spec.homepage = "https://example.com"
  spec.license = "MIT"

  spec.required_ruby_version = ">= 3.1"

  spec.files =
    Dir.glob("{lib,bin}/**/*", File::FNM_DOTMATCH).reject { |f| f.end_with?("/.", "/..") } +
    ["README.md", "LICENSE.txt"]

  spec.bindir = "bin"
  spec.executables = ["pwd"]
  spec.require_paths = ["lib"]
end

