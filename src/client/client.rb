#!/usr/bin/ruby

if Process.uid != 0
  puts '** Please run the client as a root user!'
  exit 130
end

require 'gtk3'
require 'json'
require 'net/http'
require_relative 'utils/vpn'
require_relative 'utils/status'

REQUIRED_KEYS = %w[dns_servers interface tun_interface max_buffer ip sni_host port login password]

client = nil
config_json = nil
public_ip = Net::HTTP.get URI 'https://api.ipify.org'

builder_file = "#{__dir__}/ui/main.ui"
builder = Gtk::Builder.new(file: builder_file)

status = builder.get_object('status')
spinner = builder.get_object('spinner')
window = builder.get_object('window')
switch = builder.get_object('switch')
file = builder.get_object('file')

status_manager = StatusManager.new(status)
status_manager.add_status("Status: Not-connected\nPublic IP: #{public_ip}")
status_manager.start

window.signal_connect('destroy') do
  client.disconnect if client && client.is_connected?
  Gtk.main_quit
end

trap 'SIGINT' do
  client.disconnect if client && client.is_connected?
  Gtk.main_quit
  exit 130
end

switch.signal_connect('state-set') do |_widget, state|
  if state
    spinner.active = true
    if config_json
      config_diff = REQUIRED_KEYS - config_json.keys
      if config_diff.empty?
        client ||= VPNClient.new(config_json, status_manager) # Client init
        client.connect # client connect
        puts 'On'
      else
        status_manager.add_status "Status: Error! Missing config parameters:\n" + config_diff.join("\n")
        puts 'missing parameters!'
      end

    else
      status_manager.add_status 'Status: Error! Select config file first'
      puts 'Select config'
    end
  else
    client.disconnect if client && client.is_connected?
    spinner.active = false
    puts 'Off'
  end
end

file.signal_connect('file-set') do
  config = file.filename
  begin
    config_json = JSON.parse(File.read(config))
  rescue StandardError => e
    puts e
    status_manager.add_status 'Status: Error! config must be JSON format'
  end
end

window.show_all
Gtk.main
