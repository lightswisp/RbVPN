
# Ruby VPN Client and Server

This is a self made VPN protocol written in ruby.

It uses tun/tap driver to capture all traffic and tunnel it via secured tunnel.

I used GTK3 for the GUI and rb_tuntap for tun/tap interface manipulation. And a bit of iptables rules for NAT. 

Configs must be stored in json format only! Example configs are already present inside the src/client and src/server


## Demo

![](https://github.com/lightswisp/RbVPN/blob/main/gif/main.gif?raw=true)


## Dependencies

- Ruby
- bundler (gem)
## Installation

### Server

```bash
git clone https://github.com/lightswisp/RbVPN.git
cd RbVPN
bundle install
cd src/server
ruby server.rb config.json
```

### Client

```bash
git clone https://github.com/lightswisp/RbVPN.git
cd RbVPN
bundle install
cd src/client
ruby client.rb
```
    
