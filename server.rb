require "packetgen"
require "socket"
require "openssl"
require "rb_tuntap"
require "thread"
require "logger"

if Process.uid != 0
        puts "Please run the client as a root user!"
        exit 130
end

LOG = Logger.new(STDOUT)
PORT = 9578
MAX_BUFFER = 1024 * 640
DEV_MAIN_INTERFACE = PacketGen.default_iface
DEV_NAME = "tun0"
DEV_ADDR = "192.168.0.1"
DEV_NETMASK = "255.255.255.0"

SSL = {
         :SSLClientCA=>nil,
         :SSLExtraChainCert=>nil,                         
         :SSLCACertificateFile=>nil,                      
         :SSLCACertificatePath=>nil,                      
         :SSLCertificateStore=>nil,                       
         :SSLTmpDhCallback=>nil,                          
         :SSLVerifyClient=>OpenSSL::SSL::VERIFY_PEER,                             
         :SSLVerifyDepth=>5,                            
         :SSLVerifyCallback=>nil,
         :SSLTimeout=>10,                                
         :SSLOPTIONS=>nil,                                
         :SSLCiphers=>nil,                                
         :SSLStartImmediately=>true,                      
         :SSLCertName=>nil,   
         :SSLVer=>OpenSSL::SSL::TLS1_3_VERSION 
}

sslContext  = OpenSSL::SSL::SSLContext.new()
sslContext.cert             = OpenSSL::X509::Certificate.new(File.open("cert.pem"))
sslContext.key              = OpenSSL::PKey::RSA.new(File.open("key.pem"))
sslContext.verify_mode      = SSL[:SSLVerifyClient]
sslContext.verify_depth     = SSL[:SSLVerifyDepth]
sslContext.timeout          = SSL[:SSLTimeout]
sslContext.min_version      = SSL[:SSLVer] # *IMPORTANT* TLS_1.3 

def close_tun(tun)
        tun.down
        tun.close
        puts("** #{DEV_NAME} device is closed")
        exit 130
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
        LOG.info("** #{DEV_NAME} device is up")
        `echo 1 > /proc/sys/net/ipv4/ip_forward`
        `iptables -t nat -A POSTROUTING -o #{DEV_MAIN_INTERFACE} -j MASQUERADE`
        `iptables -A FORWARD -i #{DEV_NAME} -j ACCEPT`
        return tun
end

socket = TCPServer.new(PORT)
sslServer = OpenSSL::SSL::SSLServer.new(socket, sslContext)

LOG.debug("** Listening on #{PORT}")


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

tun = setup_tun()

loop do
        Thread.new(sslServer.accept) do |client|
                begin
                        LOG.info("** New client is connected")
                        handle_connection(client, tun)
                rescue => e
                        puts "[ERR] Unexpected disconnect, closing the connection... #{e}"
                        client.close if client
                end
        end
end
