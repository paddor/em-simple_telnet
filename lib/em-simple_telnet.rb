require 'em-simple_telnet/version'
require "fiber"
require 'timeout' # for Timeout::Error
require "socket" # for SocketError
require "eventmachine"
require "logger"

##
# Provides the facility to connect to telnet servers using EventMachine. The
# asynchronity is hidden so you can use this library just like Net::Telnet in
# a seemingly synchronous manner. See README for an example.
#
# @example Standalone
#   opts = {
#     host: "localhost",
#     username: "user",
#     password: "secret",
#   }
#   
#   EM::P::SimpleTelnet.new(opts) do |host|
#     # At this point, we're already logged in.
#   
#     host.cmd("touch /my/file")
#   
#     # get some output
#     puts host.cmd("ls -la")
#   
#     host.timeout(30) do
#       # custom timeout for this block
#       host.cmd "slow command"
#     end
#   end
#
# @example Inside an existing EventMachine loop
#   EventMachine.run do
#   
#     opts = {
#       host: "localhost",
#       username: "user",
#       password: "secret",
#       output_log: "output.log", # log output to file
#       command_log: "command.log", # log commands to file
#     }
#   
#     EM::P::SimpleTelnet.new(opts) do |host|
#       # already logged in
#       puts host.cmd("ls -la")
#     end
#   end
#
class SimpleTelnet::Connection < EventMachine::Connection

  # :stopdoc:
  IAC   = 255.chr # "\377" # "\xff" # interpret as command
  DONT  = 254.chr # "\376" # "\xfe" # you are not to use option
  DO    = 253.chr # "\375" # "\xfd" # please, you use option
  WONT  = 252.chr # "\374" # "\xfc" # I won't use option
  WILL  = 251.chr # "\373" # "\xfb" # I will use option
  SB    = 250.chr # "\372" # "\xfa" # interpret as subnegotiation
  GA    = 249.chr # "\371" # "\xf9" # you may reverse the line
  EL    = 248.chr # "\370" # "\xf8" # erase the current line
  EC    = 247.chr # "\367" # "\xf7" # erase the current character
  AYT   = 246.chr # "\366" # "\xf6" # are you there
  AO    = 245.chr # "\365" # "\xf5" # abort output--but let prog finish
  IP    = 244.chr # "\364" # "\xf4" # interrupt process--permanently
  BREAK = 243.chr # "\363" # "\xf3" # break
  DM    = 242.chr # "\362" # "\xf2" # data mark--for connect. cleaning
  NOP   = 241.chr # "\361" # "\xf1" # nop
  SE    = 240.chr # "\360" # "\xf0" # end sub negotiation
  EOR   = 239.chr # "\357" # "\xef" # end of record (transparent mode)
  ABORT = 238.chr # "\356" # "\xee" # Abort process
  SUSP  = 237.chr # "\355" # "\xed" # Suspend process
  EOF   = 236.chr # "\354" # "\xec" # End of file
  SYNCH = 242.chr # "\362" # "\xf2" # for telfunc calls

  OPT_BINARY         =   0.chr # "\000" # "\x00" # Binary Transmission
  OPT_ECHO           =   1.chr # "\001" # "\x01" # Echo
  OPT_RCP            =   2.chr # "\002" # "\x02" # Reconnection
  OPT_SGA            =   3.chr # "\003" # "\x03" # Suppress Go Ahead
  OPT_NAMS           =   4.chr # "\004" # "\x04" # Approx Message Size Negotiation
  OPT_STATUS         =   5.chr # "\005" # "\x05" # Status
  OPT_TM             =   6.chr # "\006" # "\x06" # Timing Mark
  OPT_RCTE           =   7.chr # "\a"   # "\x07" # Remote Controlled Trans and Echo
  OPT_NAOL           =   8.chr # "\010" # "\x08" # Output Line Width
  OPT_NAOP           =   9.chr # "\t"   # "\x09" # Output Page Size
  OPT_NAOCRD         =  10.chr # "\n"   # "\x0a" # Output Carriage-Return Disposition
  OPT_NAOHTS         =  11.chr # "\v"   # "\x0b" # Output Horizontal Tab Stops
  OPT_NAOHTD         =  12.chr # "\f"   # "\x0c" # Output Horizontal Tab Disposition
  OPT_NAOFFD         =  13.chr # "\r"   # "\x0d" # Output Formfeed Disposition
  OPT_NAOVTS         =  14.chr # "\016" # "\x0e" # Output Vertical Tabstops
  OPT_NAOVTD         =  15.chr # "\017" # "\x0f" # Output Vertical Tab Disposition
  OPT_NAOLFD         =  16.chr # "\020" # "\x10" # Output Linefeed Disposition
  OPT_XASCII         =  17.chr # "\021" # "\x11" # Extended ASCII
  OPT_LOGOUT         =  18.chr # "\022" # "\x12" # Logout
  OPT_BM             =  19.chr # "\023" # "\x13" # Byte Macro
  OPT_DET            =  20.chr # "\024" # "\x14" # Data Entry Terminal
  OPT_SUPDUP         =  21.chr # "\025" # "\x15" # SUPDUP
  OPT_SUPDUPOUTPUT   =  22.chr # "\026" # "\x16" # SUPDUP Output
  OPT_SNDLOC         =  23.chr # "\027" # "\x17" # Send Location
  OPT_TTYPE          =  24.chr # "\030" # "\x18" # Terminal Type
  OPT_EOR            =  25.chr # "\031" # "\x19" # End of Record
  OPT_TUID           =  26.chr # "\032" # "\x1a" # TACACS User Identification
  OPT_OUTMRK         =  27.chr # "\e"   # "\x1b" # Output Marking
  OPT_TTYLOC         =  28.chr # "\034" # "\x1c" # Terminal Location Number
  OPT_3270REGIME     =  29.chr # "\035" # "\x1d" # Telnet 3270 Regime
  OPT_X3PAD          =  30.chr # "\036" # "\x1e" # X.3 PAD
  OPT_NAWS           =  31.chr # "\037" # "\x1f" # Negotiate About Window Size
  OPT_TSPEED         =  32.chr # " "    # "\x20" # Terminal Speed
  OPT_LFLOW          =  33.chr # "!"    # "\x21" # Remote Flow Control
  OPT_LINEMODE       =  34.chr # "\""   # "\x22" # Linemode
  OPT_XDISPLOC       =  35.chr # "#"    # "\x23" # X Display Location
  OPT_OLD_ENVIRON    =  36.chr # "$"    # "\x24" # Environment Option
  OPT_AUTHENTICATION =  37.chr # "%"    # "\x25" # Authentication Option
  OPT_ENCRYPT        =  38.chr # "&"    # "\x26" # Encryption Option
  OPT_NEW_ENVIRON    =  39.chr # "'"    # "\x27" # New Environment Option
  OPT_EXOPL          = 255.chr # "\377" # "\xff" # Extended-Options-List

  NULL = "\000"
  CR   = "\015"
  LF   = "\012"
  EOL  = CR + LF
  # :startdoc:

  # raised when establishing the TCP connection fails
  class ConnectionFailed < SocketError; end

  # raised when the login procedure fails
  class LoginFailed < Timeout::Error; end

  ##
  # Extens Timeout::Error by the attributes _hostname_ and _command_ so one
  # knows where the exception comes from and why.
  #
  class TimeoutError < Timeout::Error
    # hostname this timeout comes from
    attr_accessor :hostname

    # command that caused this timeout
    attr_accessor :command
  end

  # @return [Hash] default options for new connections (used for merging)
  # @see #initialize
  # @see .connect
  DEFAULT_OPTIONS = {
    host: "localhost",
    port: 23,
    prompt: %r{[$%#>] \z}n,
    connect_timeout: 3,
    timeout: 10,
    wait_time: 0,
    bin_mode: false,
    telnet_mode: true,
    output_log: nil,
    command_log: nil,
    login_prompt: %r{[Ll]ogin[: ]*\z}n,
    password_prompt: %r{[Pp]ass(?:word|phrase)[: ]*\z}n,
    username: nil,
    password: nil,

    # telnet protocol stuff
    SGA: false,
    BINARY: false,
  }.freeze

  # @deprecated
  DefaultOptions = DEFAULT_OPTIONS

  # @return [Proc] used to stop EventMachine when everything has completed
  STOP_WHEN_DONE = lambda do
    # stop when everything is done
    if self.connection_count.zero? and EventMachine.defers_finished?
      EventMachine.stop
    else
      EventMachine.next_tick(&STOP_WHEN_DONE)
    end
  end

  # @deprecated
  StopWhenEMDone = STOP_WHEN_DONE

  # @return [Integer] number of active connections
  @@_telnet_connection_count = 0

  # @return [Fiber] the root fiber
  RootFiber = Fiber.current

  # SimpleTelnet.logger
  @logger = Logger.new($stderr)
  @logger.progname = "SimpleTelnet"
  @logger.level = Logger::INFO
  @logger.level = Logger::DEBUG if $DEBUG

  class << self
    # @return [Logger, #debug, #debug?, #info, #warn, ...] the logger instance
    #   for SimpleTelnet
    def logger() @logger end

    # Recognizes whether this call was issued by the user program or by
    # EventMachine. If the call was not issued by EventMachine, merges the
    # options provided with the {DEFAULT_OPTIONS} and creates a Fiber (not
    # started yet).  Inside the Fiber SimpleTelnet.connect would be called.
    #
    # If EventMachine's reactor is already running, just starts the Fiber.
    #
    # If it's not running yet, starts a new EventMachine reactor and starts the
    # Fiber. It'll stop automatically when everything has completed
    # (connections and deferred tasks).
    #
    # @return [SimpleTelnet::Connection] the (closed) connection
    #
    def new *args, &blk
      # call super if first argument is a connection signature of
      # EventMachine
      return super(*args, &blk) if args.first.is_a? Integer

      # This method was probably called with a Hash of connection options.

      # create new fiber to connect and execute block
      opts = args[0] || {}
      connection = nil
      fiber = Fiber.new do | callback |
        connection = connect(opts, &blk)
        callback.call if callback
      end

      if EventMachine.reactor_running? and Fiber.current == RootFiber
        logger.debug "EventMachine reactor had been started " +
          "independently. Won't stop it automatically."
        fiber.resume

      elsif EventMachine.reactor_running?
        # NOTE: Seems like the EventMachine reactor is already running, but we're
        # not in the root Fiber. That means we're probably in the process of
        # establishing a nested connection (from inside a Fiber created by SimpleTelnet).

        # Transfer control to the "inner" Fiber and stop the current one.
        # The block will be called after connect() returned to transfer control
        # back to the "outer" Fiber.
        outer_fiber = Fiber.current
        fiber.transfer ->{ outer_fiber.transfer }

      else
        # start EventMachine and stop it when connection is done
        EventMachine.run do
          fiber.resume
          EventMachine.next_tick(&STOP_WHEN_DONE)
        end
      end
      return connection
    end

    # Establishes connection to the host.
    #
    # Merges {DEFAULT_OPTIONS} with _opts_. Tells EventMachine to establish
    # the connection to the desired host and port using
    # {SimpleTelnet::Connection}, and logs into the host using {#login}.
    #
    # Passes the connection to the block provided. It also ensures that the
    # connection is closed using {#close} after the block returns, unless it's
    # already {#closed?}. The connection is then returned.
    #
    # @option opts [String] :host the hostname to connect to
    # @option opts [Integer] :port the TCP port to connect to
    # @yieldparam connection [SimpleTelnet::Connection] the logged in
    #   connection
    # @return [SimpleTelnet::Connection]
    def connect(opts)
      opts = DEFAULT_OPTIONS.merge opts

      params = [
        # for EventMachine.connect
        opts[:host],
        opts[:port],
        self,

        # pass the *merged* options to SimpleTelnet#initialize
        opts
      ]

      begin
        # start establishing the connection
        connection = EventMachine.connect(*params)

        # will be resumed by #connection_completed or #unbind
        connection.pause_and_wait_for_result

        # login
        connection.__send__(:login)

        begin
          yield connection
        ensure
          # Use #close so a subclass can execute some kind of logout command
          # before the connection is closed.
          connection.close unless connection.closed?
        end
      ensure
        # close the connection in any case
        if connection
          connection.close_connection_after_writing

          # give some time to send the remaining data, which should be nothing
          EventMachine.add_timer(2) { connection.close_connection }
        end
      end

      return connection
    end

    # @return [Integer] number of active connections
    def connection_count
      @@_telnet_connection_count
    end
  end

  # Initializes the current instance. _opts_ is a Hash of options. The default
  # values are in the constant {DEFAULT_OPTIONS}.
  #
  # @option opts [String] :host ("localhost")
  #   the hostname or IP address of the host to connect to.
  #
  # @option opts [Integer] :port (23)
  #   the TCP port to connect to
  #
  # @option opts [Boolean] :bin_mode (false)
  #   if +false+, newline substitution is performed.  Outgoing LF is converted
  #   to CRLF, and incoming CRLF is converted to LF.  If +true+, this
  #   substitution is not performed.  This value can also be set using
  #   {#bin_mode=}.  The outgoing conversion only applies to the {#puts} and
  #   {#print} methods, not the {#write} method.  The precise nature of the
  #   newline conversion is also affected by the telnet options SGA and BIN.
  #
  # @option opts [String, nil] :output_log (nil)
  #   the name of the file to write connection status messages and all
  #   received traffic to.  In the case of a proper Telnet session, this will
  #   include the client input as echoed by the host; otherwise, it only
  #   includes server responses.  Output is appended verbatim to this file.
  #   By default, no output log is kept.
  #
  # @option opts [String, nil] :command_log (nil)
  #   the name of the file to write the commands executed in this Telnet
  #   session.  Commands are appended to this file.  By default, no command
  #   log is kept.
  #
  # @option opts [Regexp, String] :prompt (%r{[$%#>] \z}n)
  #   a regular expression matching the host's command-line prompt sequence.
  #   This is needed to determine the end of a command's output.
  #
  # @option opts [Regexp, String] :login_prompt (%r{[Ll]ogin[: ]*\z}n)
  #   a regular expression (or String, see {#waitfor}) used to wait for the
  #   login prompt.
  #
  # @option opts [Regexp, String] :password_prompt
  #   (%r{[Pp]ass(?:word|phrase)[: ]*\z}n)
  #   a regular expression (or String, see {#waitfor}) used to wait for the
  #   password prompt.
  #
  # @option opts [String, nil] :username (nil)
  #   the String that is sent to the telnet server after seeing the login
  #   prompt. +nil+ means there's no need to log in.
  #
  # @option opts [String, nil] :password (nil)
  #   the String that is sent to the telnet server after seeing the password
  #   prompt. +nil+ means there's no need for a password.
  #
  # @option opts [Boolean] :telnet_mode (true)
  #   In telnet mode, traffic received
  #   from the host is parsed for special command sequences, and these
  #   sequences are escaped in outgoing traffic sent using {#puts} or {#print}
  #   (but not {#write}).  If you are connecting to a non-telnet service (such
  #   as SMTP or POP), this should be set to +false+ to prevent undesired data
  #   corruption.  This value can also be set by the {#telnet_mode=} method.
  #
  # @option opts [Integer] :timeout (10)
  #   the number of seconds to wait before timing out while
  #   waiting for the prompt (in {#waitfor}).  Exceeding this timeout causes a
  #   TimeoutError to be raised.  You can disable the timeout by setting
  #   this value to +nil+.
  #
  # @option opts [Integer] :connect_timeout (3)
  #   the number of seconds to wait before timing out the initial attempt to
  #   connect. You can disable the timeout during login by setting this value
  #   to +nil+.
  #
  # @option opts [Integer, Float] :wait_time (0)
  #   the number of seconds to wait after seeing what looks like a prompt
  #   (that is, received data that matches the :prompt option value) to let
  #   more data arrive.  If more data does arrive during that time, it is
  #   assumed that the previous prompt was in fact not the final prompt.  This
  #   can avoid false matches, but it can also lead to missing real prompts
  #   (if, for instance, a background process writes to the terminal soon
  #   after the prompt is displayed).  The default of zero means not to wait
  #   for more data after seeing what looks like a prompt.
  #
  # The options are actually merged in {.connect}.
  #
  def initialize(opts)
    @options = opts
    @last_command = nil

    @logged_in = nil
    @connection_state = :connecting
    f = Fiber.current
    @fiber_resumer = ->(result = nil){ f.resume(result) }
    @input_buffer = ""
    @input_rest = ""
    @wait_time_timer = nil
    @check_input_buffer_timer = nil
    @recently_received_data = ""
    @logger = opts[:logger] || EventMachine::Protocols::SimpleTelnet.logger

    setup_logging
  end

  # @return [String] Last command that was executed in this telnet session
  attr_reader :last_command

  # @return [Logger] connection specific logger used to log output
  attr_reader :output_logger

  # @return [Logger] connection specific logger used to log commands
  attr_reader :command_logger

  # @return [Hash] used telnet options Hash
  attr_reader :options

  # @deprecated
  # Same as {#options}.
  # @return [Hash]
  def telnet_options
    @options
  end

  # @return [Proc] the callback executed again and again to resume this
  #   connection's Fiber
  attr_accessor :fiber_resumer

  # @return [Logger, #debug, #debug?, #info, ...] logger for connection
  #   activity (messages from SimpleTelnet)
  attr_accessor :logger

  # @deprecated use {#fiber_resumer} instead
  def connection_state_callback
    fiber_resumer
  end

  # @return [String] last prompt matched
  attr_reader :last_prompt

  # @return [Time] when the last data was sent
  attr_reader :last_data_sent_at

  # @return [Boolean] whether telnet mode is enabled or not
  def telnet_mode?
    @options[:telnet_mode]
  end

  # Turn telnet command interpretation on or off for this connection.  It
  # should be on for true telnet sessions, off if used to connect to a
  # non-telnet service such as SMTP.
  #
  # @param bool [Boolean] whether to use telnet mode for this connection
  def telnet_mode=(bool)
    @options[:telnet_mode] = bool
  end

  # @return [Boolean] current bin mode option of this connection
  def bin_mode?
    @options[:bin_mode]
  end

  # Turn newline conversion on or off for this connection.
  # @param bool [Boolean] whether to use bin mode (no newline conversion) for
  #   this connection
  def bin_mode=(bool)
    @options[:bin_mode] = bool
  end

  # Set the activity timeout to _seconds_ for this connection.  To disable it,
  # set it to +0+ or +nil+. If no data is received (or sent) for that amount
  # of time, the connection will be closed.
  # @param seconds [Integer] the new timeout in seconds
  def timeout=(seconds)
    @options[:timeout] = seconds
    set_comm_inactivity_timeout( seconds )
  end

  # If a block is given, sets the timeout to _seconds_ and executes the block
  # and restores the previous timeout.  This is useful when you want to
  # temporarily change the timeout for some commands.
  #
  # If no block is given, the current timeout is returned.
  #
  # @example
  #   current_timeout = host.timeout
  #
  #    host.timeout(200) do
  #      host.cmd "command 1"
  #      host.cmd "command 2"
  #    end
  #
  # @return [Integer] the current timeout, if no block given
  # @return [Object] the block's value, if it was given
  # @see #timeout=
  def timeout(seconds = nil)
    return @options[:timeout] unless block_given?

    before = @options[:timeout]
    self.timeout = seconds
    yield
  ensure
    self.timeout = before
  end

  # @return [Time] when the login succeeded for this connection
  attr_reader :logged_in

  # @return [Boolean] whether the login already succeeded for this connection
  def logged_in?
    @logged_in ? true : false
  end

  # @return [Boolean] whether the connection is closed.
  def closed?
    @connection_state == :closed
  end

  # Called by EventMachine when data is received.
  #
  # The data is processed using {#preprocess}, which processes telnet
  # sequences and strips them away. The resulting "payload" is
  # logged and handed over to {#process_payload}.
  #
  # @param data [String] newly received raw data, including telnet sequences
  # @return [void]
  def receive_data(data)
    @recently_received_data << data if log_recently_received_data?
    if @options[:telnet_mode]
      c = @input_rest + data
      se_pos = c.rindex(/#{IAC}#{SE}/no) || 0
      sb_pos = c.rindex(/#{IAC}#{SB}/no) || 0
      if se_pos < sb_pos
        buf = preprocess(c[0 ... sb_pos])
        @input_rest = c[sb_pos .. -1]

      elsif pt_pos = c.rindex(
        /#{IAC}[^#{IAC}#{AO}#{AYT}#{DM}#{IP}#{NOP}]?\z/no) ||
        c.rindex(/\r\z/no)

        buf = preprocess(c[0 ... pt_pos])
        @input_rest = c[pt_pos .. -1]

      else
        buf = preprocess(c)
        @input_rest.clear
      end
    else
      # Not Telnetmode.
      #
      # We cannot use #preprocess on this data, because that
      # method makes some Telnetmode-specific assumptions.
      buf = @input_rest + data
      @input_rest.clear
      unless @options[:bin_mode]
        buf.chop! if buf =~ /\r\z/no
        buf.gsub!(/#{EOL}/no, "\n")
      end
    end

    # in case only telnet sequences were received
    return if buf.empty?

    @output_logger << buf if @output_logger
    process_payload(buf)
  end

  # Appends _buf_ to the <tt>@input_buffer</tt>.
  # Then cancels the <tt>@wait_time_timer</tt> and
  # <tt>@check_input_buffer_timer</tt> if they're set.
  #
  # Does some performance optimizations in case the input buffer is becoming
  # huge and finally calls {#check_input_buffer}.
  #
  # @param buf [String] received data with telnet sequences stripped away
  # @return [void]
  def process_payload(buf)
    # append output from server to input buffer and log it
    @input_buffer << buf

    case @connection_state
    when :waiting_for_prompt

      # cancel the timer for wait_time value because we received more data
      if @wait_time_timer
        @wait_time_timer.cancel
        @wait_time_timer = nil
      end

      # we ensure there's no timer running for checking the input buffer
      if @check_input_buffer_timer
        @check_input_buffer_timer.cancel
        @check_input_buffer_timer = nil
      end

      if @input_buffer.size >= 100_000
        ##
        # if the input buffer is really big
        #

        # We postpone checking the input buffer by one second because the regular
        # expression matches can get quite slow.
        #
        # So as long as data is being received (continuously), the input buffer
        # is not checked. It's only checked one second after the whole output
        # has been received.
        @check_input_buffer_timer = EventMachine::Timer.new(1) do
          @check_input_buffer_timer = nil
          check_input_buffer
        end
      else
        ##
        # as long as the input buffer is small
        #

        # check the input buffer now
        check_input_buffer
      end
    when :listening
      @fiber_resumer.(buf)
    when :connected, :sleeping
      logger.debug "#{node}: Discarding data that was received " +
        "while not waiting " +
        "for data (state = #{@connection_state.inspect}): #{buf.inspect}"
    else
      raise "Don't know what to do with received data while being in " +
        "connection state #{@connection_state.inspect}"
    end
  end

  # Checks the input buffer (<tt>@input_buffer</tt>) for the prompt we're
  # waiting for. Calls <tt>@fiber_resumer</tt> with the output if the
  # prompt has been found.
  #
  # If <tt>@options[:wait_time]</tt> is set, it will wait this amount
  # of seconds after seeing what looks like the prompt before calling
  # @fiber_resumer.  This way, more data can be received
  # until the real prompt is received. This is useful for commands that result
  # in multiple prompts.
  #
  # @return [void]
  def check_input_buffer
    return unless md = @input_buffer.match(@options[:prompt])

    if s = @options[:wait_time] and s > 0
      # resume Fiber after s seconds
      @wait_time_timer = EventMachine::Timer.new(s) { process_match_data(md) }
    else
      # resume Fiber now
      process_match_data(md)
    end
  end

  # Remembers md as the <tt>@last_prompt</tt> and resumes the fiber, passing
  # it the whole output received up to and including the match data.
  # @param md [MatchData]
  # @return [void]
  def process_match_data(md)
    @last_prompt = md.to_s # remember the prompt matched
    output = md.pre_match + @last_prompt
    @input_buffer = md.post_match
    @fiber_resumer.(output)
  end

  # Read data from the host until a certain sequence is matched.
  #
  # @param prompt [Regexp, String] If it's not a Regexp, it's converted to
  #   a Regexp (all special characters escaped) assuming it's a String.
  # @option opts [Integer] :timeout the timeout while waiting for new data to
  #   arrive
  # @option opts [Integer] :wait_time time to wait after receiving what looks
  #   like a prompt
  # @return [String] output including prompt
  # @raise [Errno::ENOTCONN] if connection is closed
  def waitfor(prompt = nil, opts = {})
    if closed?
      raise Errno::ENOTCONN,
        "Can't wait for anything when connection is already closed!"
    end
    options_were = @options
    timeout_was = self.timeout if opts.key?(:timeout)
    opts[:prompt] = prompt if prompt
    @options = @options.merge opts

    # convert String prompt into a Regexp
    unless @options[:prompt].is_a? Regexp
      regex = Regexp.new(Regexp.quote(@options[:prompt]))
      @options[:prompt] = regex
    end

    # set custom inactivity timeout, if wanted
    self.timeout = @options[:timeout] if opts.key?(:timeout)

    # so #unbind knows we were waiting for a prompt (in case that inactivity
    # timeout fires)
    self.connection_state = :waiting_for_prompt

    pause_and_wait_for_result
  ensure
    @options = options_were
    self.timeout = timeout_was if opts.key?(:timeout)

    # NOTE: #unbind could have been called in the meantime
    self.connection_state = :connected if !closed?
  end

  # Pauses the current Fiber. When resumed, returns the value passed. If the
  # value passed is an Exeption, it's raised.
  # @return [String] value passed to Fiber#resume (output received)
  # @raise [Exception] exception that has been passed to Fiber#resume
  def pause_and_wait_for_result
    result = nil
    while result.nil?
      result = Fiber.yield
    end

    raise result if result.is_a? Exception
    return result
  end

  # Identifier for this connection. Like an IP address or hostname. In this
  # case, it's <tt>@options[:host]</tt>.
  # @return [String]
  def node
    @options[:host]
  end

  # Listen for anything that's received from the node. Each received chunk
  # will be yielded to the block passed. To make it stop listening, the block
  # should return or raise something.
  #
  # @option opts [Integer] :timeout (90) temporary {#timeout} to use
  # @yieldparam output [String] the newly output received
  # @return [void]
  def listen(opts = {}, &blk)
    self.connection_state = :listening
    timeout(opts.fetch(:timeout, 90)) do
      yield pause_and_wait_for_result while true
    end
  ensure
    self.connection_state = :connected if !closed?
  end

  # Passes argument to {#send_data}.
  # @param s [String] raw data to send
  def write(s)
    send_data(s)
  end

  # Tells EventMachine to send raw data to the telnet server. This also
  # updates {#last_data_sent_at} and logs recently received data, if wanted.
  # @param s [String] what to send
  # @raise [Errno::ENOTCONN] if the connection is closed
  def send_data(s)
    raise Errno::ENOTCONN,
      "Can't send data: Connection is already closed." if closed?
    @last_data_sent_at = Time.now
    log_recently_received_data
    logger.debug "#{node}: Sending #{s.inspect}"
    super
  end

  ##
  # Sends a string to the host.
  #
  # This does _not_ automatically append a newline to the string.  Embedded
  # newlines may be converted and telnet command sequences escaped depending
  # upon the values of {#telnet_mode}, {#bin_mode}, and telnet options set by the
  # host.
  #
  # @param string [String] what to send
  # @return [void]
  def print(string)
    string = string.gsub(/#{IAC}/no, IAC + IAC) if telnet_mode?

    unless bin_mode?
      string = if @options[:BINARY] and @options[:SGA]
        # IAC WILL SGA IAC DO BIN send EOL --> CR
        string.gsub(/\n/n, CR)

      elsif @options[:SGA]
        # IAC WILL SGA send EOL --> CR+NULL
        string.gsub(/\n/n, CR + NULL)

      else
        # NONE send EOL --> CR+LF
        string.gsub(/\n/n, EOL)
      end
    end

    send_data string
  end

  ##
  # Sends a string to the host, along with an appended newline if there isn't
  # one already.
  #
  # @param string [String] what to send
  # @return [void]
  def puts(string)
    string += "\n" unless string.end_with? "\n"
    print string
  end

  # Sends a command to the host and returns its output.
  #
  # More exactly, the following things are done:
  #
  # * stores the command (see {#last_command})
  # * logs it (see {#command_logger})
  # * sends a string to the host ({#print} or {#puts})
  # * reads in all received data (using {#waitfor})
  #
  # @example Normal usage
  #   output = host.cmd "ls -la"
  #
  # @example Custom Prompt
  #   host.cmd "delete user john", prompt: /Are you sure?/
  #   host.cmd "yes"
  #
  # @note The returned output includes the prompt and in most cases the
  # host's echo of the command sent.
  #
  # @param command [String] the command to execute
  # @option opts [Boolean] :hide (false) whether to hide the command from the
  #   command log ({#command_logger}). If so, it is logged as <tt>"<hidden
  #   command>"</tt> instead of the command itself. This is useful for
  #   passwords, so they don't get logged to the command log.
  # @option opts [Boolean] :raw_command (false) whether to send a raw command
  #   using {#print}, as opposed to using {#puts}
  # @option opts [Regexp, String] :prompt (nil) prompt to look for after this
  #   command's output (instead of the one set in <tt>options[:prompt]</tt>)
  # @return [String] the command's output, including prompt
  def cmd(command, opts = {})
    @last_command = command = command.to_s

    # log the command
    if @command_logger
      @command_logger.info(opts[:hide] ? "<hidden command>" : command)
    end

    # send the command
    opts[:raw_command] ? print(command) : puts(command)

    # wait for the output
    waitfor(opts[:prompt], opts)
  end

  # Login to the host with a given username and password.
  #
  # @example
  #   host.login username: "myuser", password: "mypass"
  #
  # This method looks for the login and password prompt (see implementation)
  # from the host to determine when to send the username and password.  If the
  # login sequence does not follow this pattern (for instance, you are
  # connecting to a service other than telnet), you will need to handle login
  # yourself.
  #
  # @note Don't forget to set <tt>@logged_in</tt> after the login succeeds if
  #   you override this method!
  #
  # @option opts [String, nil] :username (options[:username]) the username to
  #   use to log in, if login is needed
  # @option opts [String, nil] :password (options[:password] the password to
  #   use to log in, if a password is needed
  # @return [String] all data received during the login process
  def login opts={}
    opts = @options.merge opts

    # don't log in if username is not set
    if opts[:username].nil?
      @logged_in = Time.now
      return
    end

    begin
      output = waitfor opts[:login_prompt]

      if opts[:password]
        # login with username and password
        output << cmd(opts[:username], prompt: opts[:password_prompt])
        output << cmd(opts[:password], hide: true)
      else
        # login with username only
        output << cmd(opts[:username])
      end
    rescue Timeout::Error
      raise LoginFailed, "Timed out while expecting some kind of prompt."
    end

    @logged_in = Time.now
    output
  end

  # Called by EventMachine when the connection is being established (not after
  # the connection is established! see {#connection_completed}).  This occurs
  # directly after the call to {#initialize}.
  #
  # Sets the +pending_connect_timeout+ to
  # <tt>options[:connect_timeout]</tt> seconds. This is the duration
  # after which a TCP connection in the connecting state will fail (abort and
  # run {#unbind}). Increases <tt>@@_telnet_connection_count</tt> by one after
  # that.
  #
  # Sets also the +comm_inactivity_timeout+ to
  # <tt>options[:timeout]</tt> seconds. This is the duration after
  # which a TCP connection is automatically closed if no data was sent or
  # received.
  #
  # @return [void]
  #
  def post_init
    self.pending_connect_timeout = @options[:connect_timeout]
    self.comm_inactivity_timeout = @options[:timeout]
    @@_telnet_connection_count += 1
  end

  # Called by EventMachine after this connection has been closed.
  #
  # Decreases <tt>@@_telnet_connection_count</tt> by one and calls {#close_logs}.
  #
  # If we were in the connection state <tt>:waiting_for_prompt</tt>, this will
  # cause a TimeoutError to be raised.
  #
  # If we were in the process of connecting, this will cause
  # {ConnectionFailed} to be raised.

  # Finally, the connection state is set to +:closed+.
  #
  # @return [void]
  #
  def unbind(reason)
    prev_conn_state = @connection_state
    self.connection_state = :closed
    logger.debug "#{node}: Unbind reason: " + reason.inspect
    @@_telnet_connection_count -= 1
    close_logs

    # if we were connecting or waiting for a prompt, return an exception to
    # #waitfor
    case prev_conn_state
    when :waiting_for_prompt, :listening
      # NOTE: reason should be Errno::ETIMEDOUT in these cases.
      error = TimeoutError.new

      # set hostname and command
      if hostname = @options[:host]
        error.hostname = hostname
      end
      error.command = @last_command if @last_command

      @fiber_resumer.(error)
    when :sleeping, :connected

    when :connecting
      @fiber_resumer.(ConnectionFailed.new)
    else
      logger.error "#{node}: bad connection state #{prev_conn_state.inspect} " +
        "while unbinding"
    end
  end

  # Called by EventMachine after the connection is successfully established.
  #
  # If the debug level in {#logger} is active, this will cause received data
  # to be logged periodically.
  #
  # @return [void]
  def connection_completed
    self.connection_state = :connected
    @fiber_resumer.(:connection_completed)

    # log received data in a more readable way
    if logger.debug?
      EventMachine.add_periodic_timer(0.5) { log_recently_received_data }
    end
  end

  ##
  # Redefine this method to execute some logout command like +exit+ or
  # +logout+ before the connection is closed. Don't forget: The command will
  # probably not return a prompt, so use {#puts}, which doesn't wait for a
  # prompt.
  #
  def close
  end

  ##
  # Close output and command logs if they're set.

  #
  def close_logs
    # NOTE: IOError is rescued because they could already be closed.
    # {#closed?} can't be used, because the method is not implemented by
    # Logger, for example.

    begin
      @output_logger.close
    rescue IOError
      # already closed
    end if @options[:output_log]

    begin
      @command_logger.close
    rescue IOError
      # already closed
    end if @options[:command_log]
  end

  private

  # Prints recently received data (@recently_received_data) if
  # {#log_recently_received_data?} says so and there is recently received data
  # in the buffer. Clears the buffer afterwards.
  #
  # The goal is to log data in a more readable way, by periodically log what
  # has recently been received, as opposed to each single character in case of
  # a slowly answering telnet server.
  #
  # @return [void]
  def log_recently_received_data
    return if @recently_received_data.empty? || !log_recently_received_data?
    logger.debug "#{node}: Received: #{@recently_received_data.inspect}"
    @recently_received_data.clear
  end

  # @return [Boolean] if recently received data should be logged or not
  def log_recently_received_data?
    logger.debug?
  end

  # Sets a new connection state.
  # @param new_state [Symbol]
  # @raise [Errno::ENOTCONN] if current (old) state is +:closed+, because that
  #   can't be changed.
  def connection_state=(new_state)
    if closed?
      raise Errno::ENOTCONN,
        "Can't change connection state: Connection is already closed."
    end
    @connection_state = new_state
  end

  # Sets up output and command logging. This depends on
  # <tt>options[:output_log]</tt> and <tt>options[:command_log]</tt>.
  #
  # @return [void]
  def setup_logging
    @output_logger = @command_logger = nil

    if file = @options[:output_log]
      @output_logger = Logger.new(file)
      @output_logger.info "# Starting telnet output log at #{Time.now}\n"
    end

    if file = @options[:command_log]
      @command_logger = Logger.new(file)
    end
  end

  # Preprocess received data from the host.
  #
  # Performs newline conversion and detects telnet command sequences.
  # Called automatically by {#receive_data}.
  #
  # @param string [String] the raw string including telnet sequences
  # @return [String] resulting data, hereby called "payload"
  def preprocess string
    # combine CR+NULL into CR
    string = string.gsub(/#{CR}#{NULL}/no, CR) if telnet_mode?

    # combine EOL into "\n"
    string = string.gsub(/#{EOL}/no, LF) unless bin_mode?

    # remove NULL
    string = string.gsub(/#{NULL}/no, '') unless bin_mode?

    string.gsub(/#{IAC}(
                 [#{IAC}#{AO}#{AYT}#{DM}#{IP}#{NOP}]|
                 [#{DO}#{DONT}#{WILL}#{WONT}]
                   [#{OPT_BINARY}-#{OPT_NEW_ENVIRON}#{OPT_EXOPL}]|
                 #{SB}[^#{IAC}]*#{IAC}#{SE}
               )/xno) do
      if    IAC == $1  # handle escaped IAC characters
        IAC
      elsif AYT == $1  # respond to "IAC AYT" (are you there)
        send_data("nobody here but us pigeons" + EOL)
        ''
      elsif DO[0] == $1[0]  # respond to "IAC DO x"
        if OPT_BINARY[0] == $1[1]
          @options[:BINARY] = true
          send_data(IAC + WILL + OPT_BINARY)
        else
          send_data(IAC + WONT + $1[1..1])
        end
        ''
      elsif DONT[0] == $1[0]  # respond to "IAC DON'T x" with "IAC WON'T x"
        send_data(IAC + WONT + $1[1..1])
        ''
      elsif WILL[0] == $1[0]  # respond to "IAC WILL x"
        if    OPT_BINARY[0] == $1[1]
          send_data(IAC + DO + OPT_BINARY)
        elsif OPT_ECHO[0] == $1[1]
          send_data(IAC + DO + OPT_ECHO)
        elsif OPT_SGA[0]  == $1[1]
          @options[:SGA] = true
          send_data(IAC + DO + OPT_SGA)
        else
          send_data(IAC + DONT + $1[1..1])
        end
        ''
      elsif WONT[0] == $1[0]  # respond to "IAC WON'T x"
        if    OPT_ECHO[0] == $1[1]
          send_data(IAC + DONT + OPT_ECHO)
        elsif OPT_SGA[0]  == $1[1]
          @options[:SGA] = false
          send_data(IAC + DONT + OPT_SGA)
        else
          send_data(IAC + DONT + $1[1..1])
        end
        ''
      else
        ''
      end
    end # string.gsub
  end
end

# backwards compatibility
EventMachine::Protocols::SimpleTelnet = SimpleTelnet::Connection
