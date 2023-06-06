
# Ruby VPN Client and Server

This is a self made VPN protocol written in ruby.

It uses tun/tap driver to capture all traffic and tunnel it via secured tunnel.

I used GTK3 for the GUI and rb_tuntap for tun/tap interface manipulation. And a bit of iptables rules for NAT. 


## Demo

![](https://github.com/lightswisp/RbVPN/blob/main/gif/main.gif?raw=true)


## Dependencies

- Ruby
- bundler (gem)
- ruby-dev
- build-essential

## Installation

### Server

Don't forget to create your config file! 

For the cert.pem and key.pem run: ```openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 ```
- Config Example
```
{
        "certificate": "cert.pem",
        "private_key": "key.pem",
        "network": "192.168.0.0/24",
        "interface": "eth0",
        "tun_interface": "tun0",
        "max_buffer": 655360,
        "port": 9578,
        "login": "ryuk",
        "password": "123456789"
}
```
- Installation
```bash
sudo apt update && sudo apt install -y ruby ruby-dev build-essential
git clone https://github.com/lightswisp/RbVPN.git
cd RbVPN
sudo bundle install
cd bin/
./server -c config.json -v
```

### Client
- Config Example
```
{
        "interface": "wlan0",
        "tun_interface": "tun0",
        "max_buffer": 655360,
        "ip": "167.99.236.107",
        "sni_host": "example.com",
        "port": 9578,
        "login": "ryuk",
        "password": "123456789"
}
```
- Installation
```bash
sudo apt update && sudo apt install -y ruby ruby-dev build-essential
git clone https://github.com/lightswisp/RbVPN.git
cd RbVPN
sudo bundle install
cd bin/
./client
```
    
