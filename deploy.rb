#!/usr/bin/env ruby

require 'sshkit'
require 'sshkit/dsl'
require 'resolv'
require 'fileutils'
require 'yaml'
require 'sinatra'
require 'os'

include FileUtils
include SSHKit::DSL

SSHKit::Backend::Netssh.configure do |ssh|
  ssh.ssh_options = {
    known_hosts: SSHKit::Backend::Netssh::KnownHosts.new,
    auth_methods: ['publickey'],
    forward_agent: false,
    timeout: 10,
    keys: ['~/.ssh/id_rsa'],
  }
end

CERTS_DIR = File.join(File.dirname(__FILE__), 'certs')
CONFIG_YML = File.join(File.dirname(__FILE__), 'config.yml')
OCSERV_DEB = File.join(File.dirname(__FILE__), 'deb', 'ocserv_0.11.8-1ubuntu1_amd64.deb')

class Server
  def initialize(session, config={})
    @session = session
    @config = config
    @domain = config['domain']
    ip = Resolv.getaddress(@domain)
    @pub_ip = ip
    @ip = (config['local_ip'].nil? or config['local_ip'].strip.empty?) ? ip : config['local_ip']
    @enable_udp = config['enable_udp'] || false
    @port = config['port'] || 443
    @org = config['cert_org'] || 'ProjectO'
  end
  
  def check_os
    if @session.test('[ -e /etc/lsb-release ]')
      lsb = @session.capture('cat /etc/lsb-release').lines.map{|l| l.strip.split('=')}.to_h
      release = lsb['DISTRIB_RELEASE']
      major, minor = release.split('.').map(&:to_i)
      return if major >= 16
    end
    raise 'This script is only compatible with Ubuntu 16.04 and up.'
  end
 
  def install_server
    destination = "/tmp/#{File.basename(OCSERV_DEB)}"
    @session.upload!(OCSERV_DEB, destination)
    @session.execute("gdebi --n #{destination}")
    udp_config = @enable_udp ? "udp-port = #{@port}" : ""
    oc_config =<<END
auth = "certificate"
listen-host = #{@pub_ip}
tcp-port = #{@port}
#{udp_config}
run-as-user = nobody
run-as-group = daemon
socket-file = /var/run/ocserv-socket
server-cert = /etc/ssl/private/openconnect-server-cert.pem
server-key = /etc/ssl/private/openconnect-server-key.pem
ca-cert = /etc/ssl/private/openconnect-ca-cert.pem
isolate-workers = true
max-clients = 0
max-same-clients = 0
server-stats-reset-time = 604800
keepalive = 32400
dpd = 90
mobile-dpd = 1800
switch-to-tcp-timeout = 25
try-mtu-discovery = true
mtu = 1360
cert-user-oid = 2.5.4.3
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT:-VERS-SSL3.0"
auth-timeout = 240
min-reauth-time = 300
max-ban-score = 80
ban-reset-time = 1200
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-occtl = true
pid-file = /var/run/ocserv.pid
device = vpns
predictable-ips = true
ipv4-network = 192.168.199.0
ipv4-netmask = 255.255.255.0
dns = 8.8.8.8
dns = 8.8.4.4
ping-leases = false
no-route = 192.168.0.0/255.255.0.0
no-route = 172.16.0.0/255.240.0.0
no-route = 10.0.0.0/255.0.0.0
cisco-client-compat = true
dtls-legacy = true
END
    ocserv_conf = '/etc/ocserv/ocserv.conf'
    @session.upload!(StringIO.new(oc_config), ocserv_conf)
    @session.execute('systemctl daemon-reload')
    @session.execute('systemctl enable ocserv.service')
  end
  
  def cert(name)
    File.join(CERTS_DIR, name)
  end
  
  def upload_certs
    destination_dir = '/etc/ssl/private'
    @session.execute("mkdir -p #{destination_dir}")
    @session.upload!(cert('ca-cert.pem'), File.join(destination_dir, 'openconnect-ca-cert.pem'))
    @session.upload!(cert('server-cert.pem'), File.join(destination_dir, 'openconnect-server-cert.pem'))
    @session.upload!(cert('server-key.pem'), File.join(destination_dir, 'openconnect-server-key.pem'))
  end
  
  def common_setup
    @session.execute('apt-get update')
    @session.execute('DEBIAN_FRONTEND=noninteractive apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y upgrade')
    @session.execute('apt-get -y install gdebi-core')
    @session.execute('apt-get -y install linux-image-4.15.0-29-generic') unless bbr_compatible?
  end
  
  def setup_sysctl
    sysctl_conf = '/etc/sysctl.conf'
    content = <<END
net.ipv6.conf.all.accept_ra = 2
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.ip_forward = 1 
END
    @session.upload!(StringIO.new(content), sysctl_conf)
  end
  
  def default_iface
    @session.capture('ip route | grep default').split(/\s+/)[4]
  end
  
  def setup_firewall
    firewall_rules = '/etc/iptables.firewall.rules'
    iface = default_iface
    content = <<END
*nat

-A POSTROUTING -s 192.168.199.0/24 -o #{iface} -j SNAT --to-source #{@ip}

COMMIT

*filter

-A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
-A FORWARD -i vpns+ -o #{iface} -j ACCEPT
-A FORWARD -j DROP

-A INPUT -p icmp -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
-A INPUT -p tcp --dport #{@port} -j ACCEPT
-A INPUT -p udp --dport #{@port} -j ACCEPT
-A INPUT -p tcp --dport 53 -j ACCEPT
-A INPUT -p udp --dport 53 -j ACCEPT
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -j DROP

COMMIT
END
    @session.upload!(StringIO.new(content), firewall_rules)
    script = '/etc/network/if-pre-up.d/firewall'
    content = <<END
#!/bin/sh
/sbin/iptables-restore < /etc/iptables.firewall.rules
exit 0
END
    @session.upload!(StringIO.new(content), script)
    @session.execute("chmod +x #{script}")
  end
  
  def bbr_compatible?
    current = @session.capture('uname -r').strip.split('.').map(&:to_i)
    (current[0] < 4 or (current[0] == 4 and current[1] <9)) ? false : true
  end
  
  def deploy
    check_os
    common_setup
    install_server
    upload_certs
    setup_sysctl
    setup_firewall
  end
  
  def reboot
    begin
      @session.execute('reboot;exit')  
    rescue StandardError => e
    end
  end
end

class Deployer
  def initialize
    path = CONFIG_YML
    raise 'config.yml does not exists.' unless File.exists?(path)
    @config = YAML.load(File.open(path).read)
    @domain = @config['domain']
    @org = @config['cert_org'] || 'ProjectO'
  end
  
  def generate_certs
    certtool = OS.mac? ? `which gnutls-certtool`.strip : `which certtool`.strip
    raise 'You need gnutls to create certificates.\nPlease install gnutls or gnutls-bin via your favorite package manager.' if certtool == ""
    
    cd CERTS_DIR do
      ca_key = 'ca-key.pem'
      unless File.exists?(ca_key)
        system("#{certtool} --generate-privkey --outfile #{ca_key}")
      end
      
      ca_cert = 'ca-cert.pem'
      unless File.exists?(ca_cert)
        ca_tmpl = 'ca.tmpl'
        File.open(ca_tmpl, 'w+') do |f|
          f.write "cn = \"#{@org}\"\norganization = \"#{@org}\"\nserial = 1\nexpiration_days = #{ 365 * @config['cert_lifespan'].to_i }\nca\nsigning_key\ncert_signing_key\ncrl_signing_key\n"
        end
        system("#{certtool} --generate-self-signed --load-privkey #{ca_key} --template #{ca_tmpl} --outfile #{ca_cert}")
      end
      
      server_key = 'server-key.pem'
      unless File.exists?(server_key)
        system("#{certtool} --generate-privkey --outfile #{server_key}")
      end
      
      # Always generate server cert
      server_cert = 'server-cert.pem'
      server_tmpl = 'server.tmpl'
      File.open(server_tmpl, 'w+') do |f|
        f.write "cn = \"#{@domain}\"\norganization = \"#{@org}\"\nexpiration_days = #{ 365 * @config['cert_lifespan'].to_i }\nsigning_key\nencryption_key\ntls_www_server\n"
      end
      system("#{certtool} --generate-certificate --load-privkey #{server_key} --load-ca-certificate #{ca_cert} --load-ca-privkey #{ca_key} --template #{server_tmpl} --outfile #{server_cert}")
      
      user_key = 'user-key.pem'
      unless File.exists?(user_key)
        system("#{certtool} --generate-privkey --outfile #{user_key}")
      end
      
      user_cert = 'user-cert.pem'
      unless File.exists?(user_cert)
        user_tmpl = 'user.tmpl'
        File.open(user_tmpl, 'w+') do |f|
          f.write "cn = \"#{@org}\"\norganization = \"#{@org}\"\nexpiration_days = #{ 365 * @config['user_cert_lifespan'].to_i }\nsigning_key\ntls_www_client\n"
        end
        system("#{certtool} --generate-certificate --load-privkey #{user_key} --load-ca-certificate #{ca_cert} --load-ca-privkey #{ca_key} --template #{user_tmpl} --outfile #{user_cert}")
        system("#{certtool} --to-p12 --load-privkey #{user_key} --pkcs-cipher 3des-pkcs12 --load-certificate #{user_cert} --p12-name #{@org} --password #{@config['user_cert_password']} --outfile user.p12 --outder")
      end
    end
  end

  def os_check
    if OS.mac?
      if `which gnutls-certtool`.empty?
        puts "Please run `brew install gnutls` first."
        exit(1)
      end
    elsif OS.linux? or OS.cygwin?
      if `which certtool`.empty?
        puts "Please install `gnutls-bin` or `gnutls-cli` first."
        exit(1)
      end
    else
      puts "Your OS is not supported."
      exit(1)
    end
  end
  
  def run
    os_check
    generate_certs
    config = @config
    on "root@#{@domain}" do
      server = Server.new(self, config)
      begin
        server.deploy
      rescue StandardError => e
        puts e.message
        exit(1)
      else
        server.reboot
      end
    end
  end
end

Deployer.new.run

configure do
  set :bind, '0.0.0.0'
end

get '/user.p12' do
  send_file File.join(CERTS_DIR, 'user.p12')
end

