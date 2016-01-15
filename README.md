# SimpleTelnet

Provides telnet client functionality.

This class was once derived from the
[Net::Telnet](http://ruby-doc.org/stdlib-2.0.0/libdoc/net/telnet/rdoc/Net/Telnet.html)
class in Ruby's standard library.  It uses EventMachine, adds some
functionality around logging and other useful features that came up useful back
when I was using this code productively.

It was developed with simplicity in mind. It tries to hide the complexity of
asynchronous programming using Fibers.


Here's the [API documentation](http://www.rubydoc.info/gems/em-simple_telnet)
of the current release.

## News

With the coming up release I plan to modernize this repository a bit. That
means porting it to a standard `bundle gem`-like structure, and improve
documentation and make it more YARD compatible, which is used on
[rubydoc.info](http://www.rubydoc.info/github/paddor/em-simple_telnet/master).

I plan to add specs as soon as I've released a related gem called
_em-telnet_server_ (see below).

## Overview

This section has been copied and slightly modified from Net::Telnet's documentation.

The telnet protocol allows a client to login remotely to a user account on a
server and execute commands via a shell.  The equivalent is done by creating a
SimpleTelnet::Connection instance with the `:host` option set to your host
along with a block which defines the task to be done on the host. The
established connection (login already performed by `#login`) is passed to the
block. In the block, you'd normally make one or more calls to `#cmd`. After the
block returns, the connection is automatically closed.

This class can also be used to connect to non-telnet services, such as SMTP
or HTTP.  In this case, you normally want to provide the `:port`
option to specify the port to connect to, and set the `:telnet_mode`
option to `false` to prevent the client from attempting to interpret telnet
command sequences.  Generally, `#login` will not work with other protocols,
and you have to handle authentication yourself.

## Differences to Net::Telnet

* based on EventMachine and `Fiber`s
* uses lowercase Symbols (like `:host`) for options (instead of `"Host")
* provides per connection logging for:
  * general activity (see `#logger`)
  * output log (see the option `:output_log` and `#output_log`)
  * commands sent (see the option `:command_log` and `#command_log`)
  * debug logging (if `logger.debug?`)
    * prints recently received data in a more human-friendly 0.5s interval, as
      opposed to single characters (because EventMachine is fast)
* no hexdump log
* can handle extremely big outputs by deferring checking for the prompt in the
  output in case it's getting huge
* the `:connect_timeout` which specifies the timeout for establishing new
  connections
* the `:wait_time` option which is useful for commands that result in multiple
  prompts
  - it specifies the time to wait for more data to arrive after what looks like
    a prompt
* `#last_command` sent
* `#last_prompt` last prompt matched
* `#logged_in` time when login succeeded
* `#last_data_sent_at` time when last data was sent
* `SimpleTelnet::TimeoutError` exceptions know the causing command and on which
  host it happened (`#hostname`, `#command`)

## Examples

If you're starting from scratch and simply want to access a single host via
telnet, do something like this:

```ruby
opts = {
  host: "localhost",
  username: "user",
  password: "secret",
}

EM::P::SimpleTelnet.new(opts) do |host|
  # At this point, we're already logged in.

  host.cmd("touch /my/file")

  # get some output
  puts host.cmd("ls -la")

  host.timeout(30) do
    # custom timeout for this block
    host.cmd "slow command"
  end
end
```

If you already have an EventMachine reactor running, you can use SimpleTelnet
inside it, like here:

```ruby
EventMachine.run do

  opts = {
    host: "localhost",
    username: "user",
    password: "secret",
    output_log: "output.log", # log output to file
    command_log: "command.log", # log commands to file
  }

  EM::P::SimpleTelnet.new(opts) do |host|
    # already logged in
    puts host.cmd("ls -la")
  end
end
```

By the way, `SimpleTelnet::Connection` and
`EventMachine::Protocols::SimpleTelnet` are the same.

# Related Projects

I'm planning to release
[_em-massive_telnet_](https://github.com/paddor/em-massive_telnet) for
massively parallel telnet connections (from client to server) and
[_em-telnet_server_](https://github.com/paddor/em-telnet_server) which can be
used to build your own telnet server based on EventMachine.

I've written the code for these two gems years ago, but I'll need to carefully
extract it so any sensitive information is stripped off.

## References

There is a large number of RFCs relevant to the Telnet protocol.
RFCs 854-861 define the base protocol.  For a complete listing
of relevant RFCs, see
http://www.omnifarious.org/~hopper/technical/telnet-rfc.html
