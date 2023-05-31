#!/usr/bin/ruby

require "rb_tuntap"
require "packetgen"
require "socket"
require "openssl"
require "logger"

if Process.uid != 0
	puts "Please run the client as a root user!"
	exit 130
end

LOG = Logger.new(STDOUT)
DEV_MAIN_INTERFACE = PacketGen.default_iface #wlan0
DEV_MAIN_INTERFACE_DEFAULT_ROUTE = `ip route show default`.strip.split[2] #172.16.8.1
DEV_NAME = 'tun0'
DEV_ADDR = '192.168.0.2'
DEV_NETMASK = '255.255.255.0'
VPN_SERVER_IP = '167.99.236.107'
VPN_SERVER_PORT = 9578
SNI_HOST = "example.com"
MAX_BUFFER = 1024 * 640

def setup_tun()
	LOG.info("** Opening tun device as #{DEV_NAME}")
	tun = RbTunTap::TunDevice.new(DEV_NAME) # DEV_NAME = 'tun0'
	tun.open(true)

	trap "SIGINT" do
		close_tun(tun)
	end

	LOG.info("** Assigning ip #{DEV_ADDR} to device")
	tun.addr    = DEV_ADDR
	tun.netmask = DEV_NETMASK
	tun.up

	LOG.info("** set #{DEV_NAME} up")
	LOG.info("** Done!")
	return tun
end

def close_tun(tun)
		puts("** Bringing down and closing device")
		tun.down
		tun.close
		`ip route del #{VPN_SERVER_IP}`
		`ip route add default via #{DEV_MAIN_INTERFACE_DEFAULT_ROUTE} dev wlan0`
		puts("** Done!")
		exit 130
end

def setup_routes()
	LOG.info("** Setting up routes")
	`ip route add #{VPN_SERVER_IP} via #{DEV_MAIN_INTERFACE_DEFAULT_ROUTE} dev #{DEV_MAIN_INTERFACE}`
	`ip route del default`
	`ip route add default via #{DEV_ADDR} dev #{DEV_NAME}`
	LOG.info("** #{DEV_ADDR}/#{DEV_NETMASK} dev #{DEV_NAME}")
	LOG.info("** Done!")
end

def setup_connection()
	begin
		socket = TCPSocket.new(VPN_SERVER_IP, VPN_SERVER_PORT)
		return nil if !socket
		sslContext = OpenSSL::SSL::SSLContext.new
		sslContext.min_version = OpenSSL::SSL::TLS1_3_VERSION
		ssl = OpenSSL::SSL::SSLSocket.new(socket, sslContext)
		ssl.hostname = SNI_HOST
		ssl.sync_close = true
		ssl.connect 
	rescue => e
		LOG.info("Can't establish connection with VPN server! #{e}")
		return nil
	end
	return ssl
end



tun = setup_tun()
setup_routes()
connection = setup_connection()
close_tun(tun) if connection.nil?

begin
	loop do
		fds = IO.select([tun.to_io, connection])
		if fds[0].member?(tun.to_io)
			buf = tun.to_io.sysread(MAX_BUFFER)
			connection.print(buf)
		elsif fds[0].member?(connection)
			buf = connection.readpartial(MAX_BUFFER)
			tun.to_io.syswrite(buf)
		end
	end
rescue
	close_tun(tun)
end



