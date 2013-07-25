#! /Users/paddor/.rvm/rubies/default

Gem::Specification.new do |s|
  s.name        = 'em-simple_telnet'
  s.version     = '0.0.11'
  s.date        = '2013-07-24'
  s.summary     = "Simple telnet client on EventMachine"
  s.description = "This library provides a very simple way to connect to " +
    "telnet servers using EventMachine in a seemingly synchronous manner."
  s.authors     = ["Patrik Wenger"]
  s.email       = ["paddor@gmail.com"]
  s.homepage    = "http://github.com/paddor/em-simple_telnet"
  s.files       = ["lib/em-simple_telnet.rb"]
  s.extra_rdoc_files = ['README.rdoc']
  s.add_dependency('eventmachine', '>= 1.0.0')
  s.has_rdoc = true
  s.license     = "BSD"
end
