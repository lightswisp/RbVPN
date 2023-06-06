require "socket"
require "openssl"
require "rb_tuntap"
require "thread"
require "logger"
require "timeout"
require "json"
require "ipaddress"
require "optparse"
require "net/http"

if Process.uid != 0
        puts "** Please run the client as a root user!"
        exit 130
end

LOG = Logger.new(STDOUT)
ARGV << '-h' if ARGV.empty?
OPTIONS = {}
PARSER = OptionParser.new do |opts|
        opts.banner = "RbVPN Tunnel Server\n\n" + "Usage: ruby server.rb [OPTIONS]"
                opts.on("-v", "--verbose", "Run verbosely") do |v|
                OPTIONS[:verbose] = v
        end

        opts.on("-h", "--help", "Prints help") do
                puts opts
                exit
        end

        opts.on("-c", "--config CONFIG", "Config file (json format), example: ruby server.rb --config config.json") do |config|
                OPTIONS[:config] = config
        end
        
end.parse!

if !OPTIONS[:config] || !File.exist?(OPTIONS[:config])
        LOG.info "** Config file not found!"
        exit 130
end

PUBLIC_IP = Net::HTTP.get URI "https://api.ipify.org"
CONFIG = JSON.parse(File.read(OPTIONS[:config]))
CERTIFICATE = CONFIG["certificate"]
PRIVATE_KEY = CONFIG["private_key"]
PORT = CONFIG["port"]
MAX_BUFFER = CONFIG["max_buffer"]
DEV_MAIN_INTERFACE = CONFIG["interface"]
DEV_NAME = CONFIG["tun_interface"]
NETWORK = IPAddress(CONFIG["network"])
DEV_NETMASK = NETWORK.netmask
DEV_ADDR = NETWORK.first.to_s

LEASED_ADDRESSES = {} # All clients are gonna be here

STATUS = {
        :UNAUTHORIZED => "STATUS_UA",
        :AUTHORIZED   => "STATUS_OK"
}

SSL = {
         :SSLVerifyClient=>OpenSSL::SSL::VERIFY_PEER,                             
         :SSLVerifyDepth=>5,                            
         :SSLTimeout=>10,                                  
         :SSLVer=>OpenSSL::SSL::TLS1_3_VERSION 
}

sslContext  = OpenSSL::SSL::SSLContext.new()
sslContext.cert             = OpenSSL::X509::Certificate.new(File.open(CERTIFICATE))
sslContext.key              = OpenSSL::PKey::RSA.new(File.open(PRIVATE_KEY))
sslContext.verify_mode      = SSL[:SSLVerifyClient]
sslContext.verify_depth     = SSL[:SSLVerifyDepth]
sslContext.timeout          = SSL[:SSLTimeout]
sslContext.min_version      = SSL[:SSLVer] # *IMPORTANT* TLS_1.3 

def close_tun(tun)
        tun.down
        tun.close
        puts("** #{DEV_NAME} device is closed") if OPTIONS[:verbose]
        exit 130
end

def setup_forwarding()
        `echo 1 > /proc/sys/net/ipv4/ip_forward`
        `iptables -t nat -A POSTROUTING -o #{DEV_MAIN_INTERFACE} -j MASQUERADE`
        `iptables -A FORWARD -i #{DEV_NAME} -j ACCEPT`
end

def setup_tun()
        tun = RbTunTap::TunDevice.new(DEV_NAME) # DEV_NAME = 'tun0'
        tun.open(true)

        trap "SIGINT" do
                close_tun(tun)
        end

        tun.addr = DEV_ADDR
        tun.netmask = DEV_NETMASK
        tun.up
        LOG.info("** #{DEV_NAME} device is up") if OPTIONS[:verbose]
        return tun
end

socket = TCPServer.new(PORT)
LOG.debug("** Listening on #{PORT}")

def lease_address(client, client_address)
        free_addresses = NETWORK.to_a[2...-1].reject { |x| LEASED_ADDRESSES.include?(x.to_s) }
        random_address = free_addresses.sample.to_s
        LEASED_ADDRESSES.merge!(random_address => client_address)
        client.puts(random_address + "/" + DEV_NETMASK + "/" + PUBLIC_IP) # the address is sent in the form of (address/netmask), example -> 192.168.0.10/255.255.255.0
        LOG.info("** Address #{random_address} is now leased by #{client_address}") if OPTIONS[:verbose]
end

def free_address(client_address)
        LEASED_ADDRESSES.delete_if{|k,v| v == client_address}
        LOG.info("** Deleted #{client_address} record.") if OPTIONS[:verbose]
end

def handle_authentication(client)
        credentials = client.gets
        login, password = credentials.split(":").map(&:chomp) # the credentials are received in the form of (login:password)
        return true if login == CONFIG["login"] && password == CONFIG["password"] 
        return false
end

def handle_connection(client, tun)
                loop do
                        fds = IO.select([tun.to_io, client])
                        if fds[0].member?(tun.to_io)
                                buf = tun.to_io.sysread(MAX_BUFFER)
                                client.print(buf)
                        elsif fds[0].member?(client)
                                buf = client.readpartial(MAX_BUFFER)
                                tun.to_io.syswrite(buf)
                        end
                end

end

tun = setup_tun() # setup the tun interface 
setup_forwarding() # setup the NAT and forwarding

loop do
        Thread.new(socket.accept) do |connection|
                begin
                        connection_address = connection.peeraddr[3]
                        LOG.info("** New client is connected => #{connection_address}") if OPTIONS[:verbose]
                        tls   = OpenSSL::SSL::SSLSocket.new(connection, sslContext)
                        tls_connection = nil
                        Timeout.timeout(10) do
                                tls_connection = tls.accept # timeout for the tls accept
                        end
                        if tls_connection
                                authorized = handle_authentication(tls_connection) # handle the auth stuff
                                if authorized
                                        lease_address(tls_connection, connection_address) # we act like a DHCP server by leasing addresses to the clients 
                                        handle_connection(tls_connection, tun) # just do the tunneling stuff
                                else
                                        connection.close if connection # close the connection in case the credentials are wrong
                                end
                        end
                rescue Timeout::Error
                        if connection && tls.state == "PINIT"
                                connection.close if connection# close the connection if no ssl handshake was made (state -> PINIT and the TCP connection is still alive)
                        end
                rescue => e
                        LOG.info("** Fatal error, closing the connection... #{e}") if OPTIONS[:verbose]
                        free_address(connection_address) # free up the lease space
                        connection.close if connection# close the connection in case of the disconnect
                        
                end
        end
end
