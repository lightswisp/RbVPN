require 'rb_tuntap'
require 'socket'
require 'openssl'
require 'logger'
require 'ipaddress'
require 'gtk3'

class VPNClient
  def initialize(config, status)
    @status = status
    @dev_main_interface = config['interface']
    @max_buffer = config['max_buffer']
    @dev_main_interface_default_route = `ip route show default`.strip.split[2]
    @dev_name = config['tun_interface']
    @vpn_server_ip = config['ip']
    @vpn_server_port = config['port']
    @sni_host = config['sni_host']
    @login = config['login']
    @password = config['password']
    @connected = false
    @tun = nil
  end

  def is_connected?
    @connected
  end

  def setup_tun(dev_addr, dev_netmask)
    @status.add_status "Status: Opening tun device as #{@dev_name}"
    tun = RbTunTap::TunDevice.new(@dev_name)
    tun.open(true)

    @status.add_status "Status: Assigning ip #{dev_addr} to device"
    tun.addr    = dev_addr
    tun.netmask = dev_netmask
    tun.up

    @status.add_status "Status: set #{@dev_name} up"
    tun
  end

  def restore_routes
    `ip route del #{@vpn_server_ip}`
    `ip route add default via #{@dev_main_interface_default_route} dev #{@dev_main_interface}`
  end

  def setup_routes(dev_addr)
    @status.add_status 'Status: Setting up routes'
    `ip route add #{@vpn_server_ip} via #{@dev_main_interface_default_route} dev #{@dev_main_interface}`
    `ip route del default`
    `ip route add default via #{dev_addr} dev #{@dev_name}`
    @status.add_status "Status: Default via #{dev_addr} dev #{@dev_name}"
  end

  def client_authorize(connection)
    connection.puts("#{@login}:#{@password}") # login and password
    begin 
      return false if connection.eof?
      return true
	rescue
      return false
    end
  end

  def lease_address(connection)
    addr = connection.gets.chomp
    dev_addr, dev_netmask, public_ip = addr.split('/')
    @status.add_status "Status: Got #{addr} from the VPN server"
    [dev_addr, dev_netmask, public_ip]
  end

  def setup_connection
    begin
      socket = TCPSocket.new(@vpn_server_ip, @vpn_server_port)
      return nil unless socket

      ssl_context = OpenSSL::SSL::SSLContext.new
      ssl_context.min_version = OpenSSL::SSL::TLS1_3_VERSION
      ssl = OpenSSL::SSL::SSLSocket.new(socket, ssl_context)
      ssl.hostname = @sni_host
      ssl.sync_close = true
      ssl.connect
      @status.add_status "Status: Current TLS/SSL version: #{ssl.ssl_version}"
    rescue StandardError => e
      @status.add_status "Status: Can't establish connection with VPN server!\n#{e}"
      return nil
    end
    ssl
  end

  def connect
    connection = setup_connection
    if connection.nil?
      @status.add_status "Status: Can't establish connection with VPN server!"
      return
    end
    authorized = client_authorize(connection)
    if !authorized
      @status.add_status 'Status: Unauthorized, check your credentials!'
      return
    end

    dev_addr, dev_netmask, public_ip = lease_address(connection)
    @tun = setup_tun(dev_addr, dev_netmask)
    setup_routes(dev_addr)
    @connected = true
    @status.add_status "Status: Connected\nPublic IP: #{public_ip}"

    begin
      Thread.new do
        loop do
          Thread.exit if !@connected || @tun.closed?
          fds = IO.select([@tun.to_io, connection])
          if fds[0].member?(@tun.to_io)
            buf = @tun.to_io.sysread(@max_buffer)
            connection.print(buf)
          elsif fds[0].member?(connection)
            buf = connection.readpartial(@max_buffer)
            @tun.to_io.syswrite(buf)
          end
        end
      end
    rescue StandardError => e
      @status.add_status "Status: Error has occured!\n#{e}"
      disconnect
    end
  end

  def disconnect
    @connected = false
    @status.add_status "Status: Bringing down #{@dev_name}"
    sleep 1
    if @tun.opened?
      @tun.down
      @tun.close
    end
    restore_routes if @tun.closed?
    @status.add_status 'Status: Disconnected'
  end
end
