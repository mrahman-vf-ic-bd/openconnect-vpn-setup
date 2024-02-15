# Openconnect VPN setup in cento OS 7.6

Let's setup all the packages first: 

Update the installation to get update package
```
sudo yum update -y
```
Add Extra Packages for Enterprise Linux (EPEL) Repository:
OpenConnect package is availabe in EPEL repository.

```
yum install epel-release -y
```

Certbot installation
Install certbot for obtaining the Lets Encrypt signed certificate
```
yum install certbot -y
```
OpeConnect Installation
Install the OpenConnect Server package
```
yum install ocserv -y
```

Firewall Setup
Open firewall ports and enable NAT (Masquerade)
```
firewall-cmd --permanent --zone=public --add-port=443/udp # Make sure zone public is activated
firewall-cmd --permanent --zone=public --add-port=443/tcp
firewall-cmd --zone=public --permanent --add-masquerade # enable NAT
firewall-cmd --reload
```
This machine will work like a router so we need enable the IP forwarding
```
echo "net.ipv4.ip_forward = 1" | sudo tee /etc/sysctl.d/70-custom.conf
echo "net.core.default_qdisc=fq" | sudo tee -a /etc/sysctl.d/70-custom.conf
echo "net.ipv4.tcp_congestion_control=bbr" | sudo tee -a /etc/sysctl.d/70-custom.conf
sysctl -p /etc/sysctl.d/70-custom.conf
```
Explanation:
- `net.core.default_qdisc=fq`  sets the default queuing discipline for network devices to FQ (Fair Queueing), which can help improve network performance.
- `net.ipv4.tcp_congestion_control=bbr` sets the TCP congestion control algorithm to BBR (Bottleneck Bandwidth and RTT) which is designed to improve network performance and congestion avoidance.
- `sysctl -p /etc/sysctl.d/70-custom.conf`  This command reloads the sysctl settings from the file `/etc/sysctl.d/70-custom.conf`. This makes the changes made to the sysctl configuration file effective without needing to reboot the system.

SSL Certificate:
Make sure your URL is resolvable. Afterwards, get signed certificates
```
certbot certonly --standalone --preferred-challenges http --agree-tos --email support@mail.com -d vpn.exmaple.com
```

Backup Original Configuration
Backup the default configuration which can be used in case we want to strat over
```
cp /etc/ocserv/ocserv.conf /etc/ocserv/ocserv.conf.bak
```
Edit Server Configuration
Add your configuration. See the comments in the configuration file which have been modified
```
cat > /etc/ocserv/ocserv.conf <<'EOF'
auth = "plain[passwd=/etc/ocserv/ocpasswd]" #### Using the credentials from this file
tcp-port = 443
udp-port = 443
run-as-user = ocserv
run-as-group = ocserv
socket-file = ocserv.sock
chroot-dir = /var/lib/ocserv
server-cert = /etc/letsencrypt/live/vpn.induslevel.com/fullchain.pem ### Update the path to certificate file obtained from LetsEncrypt
server-key = /etc/letsencrypt/live/vpn.induslevel.com/privkey.pem  ### Update the path to private key file obtained from LetsEncrypt
ca-cert = /etc/ocserv/ssl/ca-cert.pem
isolate-workers = true
max-clients = 16
max-same-clients = 2
rate-limit-ms = 100
server-stats-reset-time = 604800
keepalive = 32400
dpd = 90
mobile-dpd = 1800
switch-to-tcp-timeout = 25
try-mtu-discovery = true #################### Enabled this option for traffic optimization
cert-user-oid = 0.9.2342.19200300.100.1.1
tls-priorities = "NORMAL:%SERVER_PRECEDENCE"
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
log-level = 1
device = vpns
predictable-ips = true
default-domain = vpn.example.com ########### Update the domain URL
ipv4-network = 192.168.250.0/24 ##### This is used to lease IP when a client connected to VPN for NATting. Use the subnet that is not being used in your existing network
dns = 1.1.1.3 ############## Using CloudFlare DNS for families to block Malware or Adult Content
ping-leases = false #### ipv4-network related when ipv4-network has same subnet a your server LAN then use true
route=192.168.1.0/24 ### this route will be pushed back to client. When your browse any IP in this range will use this VPN server
cisco-client-compat = true
dtls-legacy = true
cisco-svc-client-compat = false
client-bypass-protocol = false
camouflage = false
camouflage_secret = "mysecretkey"
camouflage_realm = "Restricted Content"
included-http-headers = Strict-Transport-Security: max-age=31536000 ; includeSubDomains
included-http-headers = X-Frame-Options: deny
included-http-headers = X-Content-Type-Options: nosniff
included-http-headers = Content-Security-Policy: default-src 'none'
included-http-headers = X-Permitted-Cross-Domain-Policies: none
included-http-headers = Referrer-Policy: no-referrer
included-http-headers = Clear-Site-Data: "cache","cookies","storage"
included-http-headers = Cross-Origin-Embedder-Policy: require-corp
included-http-headers = Cross-Origin-Opener-Policy: same-origin
included-http-headers = Cross-Origin-Resource-Policy: same-origin
included-http-headers = X-XSS-Protection: 0
included-http-headers = Pragma: no-cache
included-http-headers = Cache-control: no-store, no-cache
EOF
```

Start Service
start the service
```
systemctl start ocserv
```
Enable on Boot
Enable the service to start at boot time
```
systemctl enable ocserv
```
Service Status
Check status of the service
```
systemctl status ocserv
```

User Creation
create User. You will be asked for the password
```
ocpasswd -c /etc/ocserv/ocpasswd vpnuser
```

VPN Client Application

Install Cisco AnyConnect Application on your mobile

- [iOS](https://apps.apple.com/us/app/cisco-secure-client/id1135064690?platform=iphone)
- [Android](https://play.google.com/store/apps/details?id=com.cisco.anyconnect.vpn.android.avf&pcampaignid=web_share)
- [Windows](https://olemiss.edu/helpdesk/vpn/windows.html)
