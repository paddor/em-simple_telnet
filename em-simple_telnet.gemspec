# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'em-simple_telnet/version'


Gem::Specification.new do |s|
  s.name        = 'em-simple_telnet'
  s.version     = SimpleTelnet::VERSION
  s.authors     = ["Patrik Wenger"]
  s.email       = ["paddor@gmail.com"]

  s.summary     = "Simple telnet client on EventMachine"
  s.description = "This library provides a very simple way to connect to " +
    "telnet servers using EventMachine in a seemingly synchronous manner."
  s.homepage    = "http://github.com/paddor/em-simple_telnet"
  s.license     = "ISC"

  s.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  s.require_paths = ["lib"]

  s.add_development_dependency "bundler", "~> 1.11"
  s.add_development_dependency "rake", "~> 10.0"
  s.add_development_dependency "minitest", "~> 5.0"
  s.add_dependency('eventmachine', '>= 1.0.0')
end
