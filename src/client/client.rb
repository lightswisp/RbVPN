#!/usr/bin/ruby

if Process.uid != 0
	puts "** Please run the client as a root user!"
	exit 130
end

require "gtk3"
require "json"
require "net/http"
require_relative "vpn"
require_relative "status"

client = nil
config_json = nil
public_ip = Net::HTTP.get URI "https://api.ipify.org"

builder_file = "#{File.expand_path(File.dirname(__FILE__))}/main.ui"
builder = Gtk::Builder.new(:file => builder_file)

status = builder.get_object("status")
spinner= builder.get_object("spinner")
window = builder.get_object("window")
switch = builder.get_object("switch")
file = builder.get_object("file")

status_manager = StatusManager.new(status)
status_manager.add_status("Status: Not-connected\nPublic IP: #{public_ip}")
status_manager.start



window.signal_connect("destroy") do 
	client.disconnect() if client
	Gtk.main_quit 
end
trap "SIGINT" do
	client.disconnect() if client
	Gtk.main_quit 
end

switch.signal_connect("state-set") do |widget, state|
	if state
	spinner.active = true
		if config_json
			
			client = VPNClient.new(config_json, status_manager) # Client init
			client.connect # client connect
			puts "On"
			
		else
			status_manager.add_status "Status: Error! Select config file first"
			puts "CFG"
		end
	else
		client.disconnect if client
		spinner.active = false
		puts "Off"
	end
end

file.signal_connect("file-set") do 
	config = file.filename
	begin
		config_json = JSON.parse(File.read(config))
	rescue => e
		puts e
		status_manager.add_status "Status: Error! config must be JSON format"
	end
end

window.show_all
Gtk.main

