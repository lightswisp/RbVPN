require "rb_tuntap"
require "socket"
require "openssl"
require "logger"
require "ipaddress"
require "gtk3"

class VPNClient

	attr_accessor :status, :dev_main_interface, :max_buffer, :dev_main_interface_default_route, :dev_name, :vpn_server_ip, :vpn_server_port, :sni_host, :login, :password, :connected, :tun
	
	def initialize(config, status)
		self.status = status
		self.dev_main_interface = config["interface"]
		self.max_buffer = config["max_buffer"]
		self.dev_main_interface_default_route = `ip route show default`.strip.split[2]
		self.dev_name = config["tun_interface"]
		self.vpn_server_ip = config["ip"]
		self.vpn_server_port = config["port"]
		self.sni_host = config["sni_host"]
		self.login = config["login"]
		self.password = config["password"]
		self.connected = false
		self.tun = nil
	end

	def setup_tun(dev_addr, dev_netmask)
		self.status.add_status "Status: Opening tun device as #{self.dev_name}"
		tun = RbTunTap::TunDevice.new(self.dev_name)
		tun.open(true)
		
		self.status.add_status "Status: Assigning ip #{dev_addr} to device"
		tun.addr    = dev_addr
		tun.netmask = dev_netmask
		tun.up

		self.status.add_status "Status: set #{self.dev_name} up"
		return tun
	end


	def restore_routes()
		`ip route del #{self.vpn_server_ip}`
		`ip route add default via #{self.dev_main_interface_default_route} dev #{self.dev_main_interface}`
	end

	def setup_routes(dev_addr)
		self.status.add_status "Status: Setting up routes"
		`ip route add #{self.vpn_server_ip} via #{self.dev_main_interface_default_route} dev #{self.dev_main_interface}`
		`ip route del default`
		`ip route add default via #{dev_addr} dev #{self.dev_name}`
		self.status.add_status "Status: Default via #{dev_addr} dev #{self.dev_name}"
	end

	def client_authorize(connection)
		connection.puts("#{self.login}:#{self.password}") # login and password
		return false if connection.eof?
		return true
	end
	
	def lease_address(connection)
		addr = connection.gets.chomp
		dev_addr, dev_netmask, public_ip = addr.split("/")
		self.status.add_status "Status: Got #{addr} from the VPN server"
		return [dev_addr, dev_netmask, public_ip]
	end

	def setup_connection()
		begin
			socket = TCPSocket.new(self.vpn_server_ip, self.vpn_server_port)
			return nil if !socket
			sslContext = OpenSSL::SSL::SSLContext.new
			sslContext.min_version = OpenSSL::SSL::TLS1_3_VERSION
			ssl = OpenSSL::SSL::SSLSocket.new(socket, sslContext)
			ssl.hostname = self.sni_host
			ssl.sync_close = true
			ssl.connect
			self.status.add_status "Status: Current TLS/SSL version: #{ssl.ssl_version}"
		rescue => e
			self.status.add_status "Status: Can't establish connection with VPN server!\n#{e}"
			return nil
		end
		return ssl
	end
	
	def connect()
		connection = setup_connection()
		if connection.nil?
			self.status.add_status "Status: Can't establish connection with VPN server!"
			return 
		end
		authorized = client_authorize(connection)
		if !authorized
			self.status.add_status "Status: Unauthorized, check your credentials!"
			return
		end
		
		dev_addr, dev_netmask, public_ip = lease_address(connection)
		self.tun = setup_tun(dev_addr, dev_netmask) 
		setup_routes(dev_addr)
		self.connected = true
		self.status.add_status "Status: Connected\nPublic IP: #{public_ip}"

		begin
		Thread.new do
				loop do
					if !self.connected
						Thread.exit 
					end
					fds = IO.select([self.tun.to_io, connection])
					if fds[0].member?(self.tun.to_io)
						buf = self.tun.to_io.sysread(self.max_buffer)
						connection.print(buf)
					elsif fds[0].member?(connection)
						buf = connection.readpartial(self.max_buffer)
						self.tun.to_io.syswrite(buf)
					end
				end
		end
		rescue => e
			self.status.add_status "Status: Error has occured!\n#{e}"
			disconnect()
		end

	end

	def disconnect()
		self.connected = false
		sleep 1
		self.status.add_status "Status: Bringing down #{dev_name}"
		if self.tun.opened?
			self.tun.down
			self.tun.close
		end
		restore_routes() if self.tun.closed?
		self.status.add_status "Status: Disconnected"
	end
end





