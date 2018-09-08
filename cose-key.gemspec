Gem::Specification.new do |gem|
  gem.name          = 'cose-key'
  gem.version       = File.read('VERSION')
  gem.authors       = ['nov matake']
  gem.email         = ['nov@matake.jp']
  gem.homepage      = 'https://github.com/nov/cose-key'
  gem.summary       = %q{COSE Key in Ruby}
  gem.description   = %q{COSE Key (RSA & EC) in Ruby}
  gem.license       = 'MIT'
  gem.files         = `git ls-files`.split("\n")
  gem.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  gem.require_paths = ['lib']
  gem.required_ruby_version = '>= 2.3'
  gem.add_runtime_dependency 'activesupport'
  gem.add_runtime_dependency 'cbor'
  gem.add_development_dependency 'rake', '~> 10.0'
  gem.add_development_dependency 'simplecov'
  gem.add_development_dependency 'rspec'
  gem.add_development_dependency 'rspec-its'
end