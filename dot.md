````markdown
# Security & Networking Labs – Clean Notes

---

## PORT FORWARDING

---

### Basics

- → When a request comes from **WAN (NAT IP)**  
- → Router/firewall checks **PREROUTING** chain first  
- → PREROUTING allows us to change the **destination IP**  
- → This is called **DNAT (Destination NAT)**  

---

### 2) Port Forwarding to Client 1 (Port 80)

**Client 1:**

- → Webserver running on `192.168.20.5:80`  
  (Shown in PDF page 1)

**Requirement:**

- → Base machine (host PC) opens:  
  `http://<firewall-NAT-IP>:80`  
- → It should reach **Client 1’s webserver**.

**Add DNAT rule in PREROUTING:**

```bash
sudo iptables -t nat -A PREROUTING -i ens160 -p tcp --dport 80 \
  -j DNAT --to-destination 192.168.20.5:80
````

**Check PREROUTING table:**

```bash
sudo iptables -t nat -L
```

**Test:**

* → Open browser on base machine
* → Type: `<NAT IP>:80`
* → You should see **Client 1 webpage**

---

### 3) Why Do We Need a Second Port for Client 2?

* Port **80** is already used by **Client 1**.
* If we want **Client 2** to also have a webserver:

  * → We must use a **different port** on WAN side
  * → Choose port **81** for Client 2
    (As mentioned on page 1 bottom)

---

### 4) Port Forwarding to Client 2 (Port 81 → 80)

**Client 2 webserver:**

* `192.168.20.10:80`

**Add rule:**

```bash
sudo iptables -t nat -A PREROUTING -p tcp -i ens160 --dport 81 \
  -j DNAT --to-destination 192.168.20.10:80
```

**Test:**

* → Open base machine browser
* → Type: `<NAT IP>:81`
* → This should display **Client 2’s webserver**.

---

### 5) Final Result

* **Client 1 website:**

  * → `http://<NAT IP>:80`
  * (forwarded to `192.168.20.5:80`)

* **Client 2 website:**

  * → `http://<NAT IP>:81`
  * (forwarded to `192.168.20.10:80`)

Both webservers can run at the same time because they use **different external ports**.

---

## SQUID PROXY

---

### Squid Proxy Basics (from PDF page 1)

* Squid proxy works on port: **3128**
* Squid firewall → works up to **Application Layer**
  (Shown in diagram on page 1)

**ACL Types supported:**

* → `src` = source IP
* → `dst` = destination IP
* → `srcdomain` = source domain
* → `dstdomain` = destination domain
* → `url_regex` = URL content
* → `time` = time-based blocking

**Basic ACL format:**

```text
acl <name> <type> <value>
```

**Examples:**

```text
acl client1 src 192.168.20.5
acl mynet src 192.168.20.0/24
```

**Apply ACL:**

```text
acl microsoft dstdomain microsoft.com
http_access deny microsoft client1
```

---

### 2) Important Squid Rule Order (from PDF page 2)

* NOTE:

  * → Squid works **ONLY for HTTP/Web traffic**

**Rule order:**

* Allow rules must be written **FIRST**
* Block rules **AFTER** allow rules

You can:

* → Allow few → Block remaining
* → Block few → Allow remaining

---

### 3) Install Squid Proxy

```bash
sudo dnf install squid -y     # or yum/apt as applicable
```

**Add INPUT rule for squid:**

```bash
sudo iptables -I INPUT 1 -s 192.168.20.0/24 -p tcp --dport 3128 -j ACCEPT
```

**Squid cache directory:**

* Location → `/var/spool/squid`

**Open squid config:**

```bash
sudo nano /etc/squid/squid.conf
```

---

### 4) Edit Squid Config (from PDF page 3)

* Uncomment **disk cache** line.
* Uncomment the directory line shown inside config.

**Squid cache structure:**

* → `var/spool/squid`
* → 16 directories × each having 256 subdirs

**Set visible hostname:**

```text
visible_hostname proxy.boss.error
```

**Start squid:**

```bash
sudo systemctl start squid
sudo systemctl enable squid
```

**Check folders:**

```bash
ls /var/spool/squid
```

* → You will see multiple directories (as shown on page 3)

---

### 5) Configure Client for Proxy (page 3)

**Client1:**

```bash
sudo nmtui
```

* → Remove default gateway
* → Remove DNS entries

**Browser Settings:**

* → Search “proxy” → Manual Proxy
* → HTTP proxy = Firewall machine IP
* → Port = **3128**
* → Enable checkbox
* → OK

---

### 6) Adding Rules in Squid (page 4)

Open config:

```bash
sudo vi /etc/squid/squid.conf
```

**Add ACLs (from PDF highlighted section):**

```text
acl mynet src 192.168.20.0/24
acl client1 src 192.168.20.5
acl client2 src 192.168.20.10
acl google dstdomain .google.com
acl microsoft dstdomain .microsoft.com
acl redhat dstdomain .redhat.com
```

**Allow specific websites:**

```text
http_access allow google mynet
http_access allow microsoft client1
http_access allow redhat client2
```

**Block everything else:**

```text
http_access deny mynet
```

---

### 7) Reload vs Restart (Important)

* **Reload:**

  ```bash
  sudo systemctl reload squid.service
  ```

  * → apply changes without stopping service

* **Restart:**

  * → stops and starts squid (not recommended)

---

### 8) Testing Result (from PDF images)

If allowed sites:

* → `google.com`, `microsoft.com`, `redhat.com`
  will open normally (see screenshots page 4)

If blocked:

* → user gets **“proxy server is refusing connections”**
  shown on last page.

---

## FAIL2BAN – DETAILED NOTEPAD VERSION

---

### Why Fail2ban is Used (PDF explanation)

* → Client1 tries SSH on firewall
* → Enters wrong password repeatedly
* → Possible brute-force / dictionary attack

Fail2ban works like this:

* → If wrong password entered **3 times** → **ban for 10 minutes**
* → After 10 minutes, if he tries again → ban increases (ex: 20 min)
* → Helps block attackers automatically

---

### 2) Install Fail2ban

```bash
sudo dnf update -y
sudo dnf install epel-release -y
sudo dnf update -y
sudo dnf install fail2ban -y
```

---

### 3) Create Fail2ban Local Config Files

Copy main config:

```bash
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

Create SSH-specific jail rule:

```bash
sudo vim /etc/fail2ban/jail.d/sshd.local
```

Add:

```ini
[sshd]
enabled = true
findtime = 3600
maxretry = 3
bantime = 10m
```

Explanation:

* → `findtime = 1 hour` (time window to count failures)
* → `maxretry = 3` wrong passwords allowed
* → `bantime = 10 minutes`

---

### 4) Start Fail2ban Service

```bash
sudo systemctl start fail2ban
sudo systemctl enable fail2ban
```

Fail2ban is now active and protecting SSH.

---

### 5) Test Fail2ban

From another client (ex: Client2):

* → Try to SSH into Firewall
* → Enter wrong password 3 times

Fail2ban will:

* → Immediately block client IP
* → Ban lasts 10 minutes

---

### 6) Check Fail2ban Status

**List all jails:**

```bash
sudo fail2ban-client status
```

**See specific jail:**

```bash
sudo fail2ban-client status sshd
```

---

### 7) Default Ban Time (from PDF)

* Default `bantime = 10 minutes`

---

### 8) How to Unban an IP (Very Important)

```bash
sudo fail2ban-client set sshd unbanip 192.168.20.5
```

After unban:

* → Client can attempt SSH again

---

## DMZ NETWORK SETUP – DETAILED STEPS

---

### Understanding DMZ (from page 1 image)

* **DMZ = “Demilitarized Zone”**

  * → Area between WAN (internet) and LAN
  * → Public-facing servers (web, ftp) stay in DMZ
  * → Internal LAN servers stay protected behind firewall

Diagram on PDF page 1 shows:

* → WAN → Firewall → DMZ → LAN

---

### 2) Create DMZ Network in VMware

**Step 1:**

* VMware → Edit → Virtual Network Editor → Change Settings → Yes

**Step 2:**

* Add Network → `vmnet2` → OK → Apply → OK
* → Set this network to `192.168.50.0` network

This `vmnet2` is your **DMZ network**.

---

### 3) Configure VM Adapters (from page 2 images)

**Firewall VM:**

* → Add Adapter → Custom → `vmnet2` (DMZ interface)

**Client 1 (LAN):**

* → Adapter: `vmnet1` or host-only (`192.168.20.x` network)

**Client 2 (DMZ):**

* → Adapter: `vmnet2` (`192.168.50.x` network)

Overall setup (page 2 diagram):

* Firewall:

  * → `ens160` = external network (NAT)
  * → `ens192` = LAN (`192.168.20.0/24`)
  * → `ens256` = DMZ (`192.168.50.0/24`)

---

### 4) Assign IP Addresses Using nmtui

**On Client 1 (LAN):**

```bash
sudo nmtui
```

* → IPv4 Manual
* → Address: `192.168.20.10/24`
* → Gateway: `192.168.20.5`
* → DNS: `192.168.72.20`

Check:

```bash
ip -br a
```

**On Client 2 (DMZ):**

```bash
sudo nmtui
```

* → IPv4 Manual
* → Address: `192.168.50.10/24`
* → Gateway: `192.168.50.5`
* → DNS: `192.168.72.20`

**Firewall interface IPs (page 4):**

* → `ens160` → external
* → `ens192` → `192.168.20.5`
* → `ens256` → `192.168.50.5`

---

### 5) iptables Rules on Firewall

#### 5.1 NAT Masquerading (Internet Access)

**For Client 1 (LAN `192.168.20.0/24`):**

```bash
sudo iptables -t nat -A POSTROUTING -o ens160 -s 192.168.20.0/24 -j MASQUERADE
```

**For Client 2 (DMZ `192.168.50.0/24`):**

```bash
sudo iptables -t nat -A POSTROUTING -o ens160 -s 192.168.50.0/24 -j MASQUERADE
```

---

#### 5.2 DNS Allow Rules for Both Clients

**For LAN:**

```bash
sudo iptables -I FORWARD 1 -s 192.168.20.0/24 -d 192.168.72.20 -p udp --dport 53 -j ACCEPT
sudo iptables -I FORWARD 2 -d 192.168.20.0/24 -s 192.168.72.20 -p udp --sport 53 -j ACCEPT
```

**For DMZ:**

```bash
sudo iptables -I FORWARD 1 -s 192.168.50.0/24 -d 192.168.72.20 -p udp --dport 53 -j ACCEPT
sudo iptables -I FORWARD 2 -d 192.168.50.0/24 -s 192.168.72.20 -p udp --sport 53 -j ACCEPT
```

---

#### 5.3 Allow DMZ Client to Access HTTPS Websites

```bash
sudo iptables -I FORWARD 3 -s 192.168.50.0/24 -p tcp --dport 443 \
  -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

sudo iptables -I FORWARD 4 -d 192.168.50.0/24 -p tcp --sport 443 \
  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

Result → DMZ client can access browser now.

---

### 6) Port Forwarding (DNAT) from WAN → DMZ Web Server

**Scenario:**

* → DMZ web server at `192.168.50.10` should be reachable from WAN.

**Add rules:**

Forward HTTP traffic:

```bash
sudo iptables -t nat -A PREROUTING -i ens160 -p tcp --dport 80 \
  -j DNAT --to-destination 192.168.50.10:80
```

Allow traffic towards DMZ:

```bash
sudo iptables -I FORWARD 1 -d 192.168.50.10 -p tcp --dport 80 \
  -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
```

Allow traffic coming back:

```bash
sudo iptables -I FORWARD 2 -s 192.168.50.10 -p tcp --sport 80 \
  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```

Now:

* → Your base machine can open the website using firewall WAN IP.

---

### 7) SSH from LAN to DMZ

**On Firewall:**

Allow LAN → DMZ SSH:

```bash
sudo iptables -I FORWARD 1 -s 192.168.20.10 -d 192.168.50.10 -p tcp --dport 22 -j ACCEPT
sudo iptables -I FORWARD 2 -d 192.168.20.10 -s 192.168.50.10 -p tcp --sport 22 -j ACCEPT
```

**On DMZ Client (Client 2):**

```bash
sudo firewall-cmd --add-service=ssh --permanent
sudo firewall-cmd --reload
```

**On LAN Client (Client 1):**

```bash
ssh 192.168.50.10
# or
ssh boss@192.168.50.10
```

---

### 8) Useful Commands

List forwarding rules:

```bash
sudo iptables -L FORWARD -n --line-numbers
```

Check interfaces:

```bash
ip -br a
```

Restart network:

```bash
sudo systemctl restart NetworkManager
```

---

## SURICATA ON PFSENSE (DETAILED STEPS)

---

### Install Suricata

Go to:

* System → Package Manager → Available Packages → Search **"suricata"** → Install

Wait for installation to finish.

---

### 2) Basic Suricata Global Settings

Go to:

* Services → Suricata → Global Settings

Enable:

* → "Enable Global Logging" (or similar depending on version)
* → Blacklist
* → ET/Open or ETOpen/FIDO ruleset

Set update frequency:

* → 6 hours

Click **Save**.

Go to:

* **Updates** tab → Click **Update**
* Wait for all rule sets to download.

---

### 3) Important System Tuning (Very Important)

Go to:

* System → Advanced → Networking

Enable the first 3 checkboxes:

* → Hardware Checksum Offloading
* → Hardware TCP Segmentation Offloading
* → Hardware Large Receive Offloading

Scroll → **Save**

Reboot pfSense:

* System → Reboot

---

### 4) Add Suricata to WAN Interface

Go to:

* Services → Suricata → Interfaces → **Add**

Add interface:

* → Interface: **WAN**
* Save

Select newly added WAN:

* Services → Suricata → Interfaces → **WAN**

Below section:

* → WAN Rule Category → Choose **"Custom Rules"** (if shown)

Now add a custom rule.

---

### 5) Add Custom Alert Rules

Go to:

* Services → Suricata → Interfaces → WAN → Scroll to **"Custom Rules"** section → Edit

Add rule:

```text
alert icmp any any -> 8.8.8.8 any (msg:"ping to google bhai"; sid:10000001; rev:0001;)
```

Example FTP rule:

```text
alert tcp any any -> any 21 (msg:"FTP marala hana yala"; sid:2222222; rev:1;)
```

Save changes.

---

### 6) Test Alert Generation

On client:

```bash
ping 8.8.8.8
# or test FTP:
ftp 192.168.x.x
```

Then on pfSense:

* Services → Suricata → Logs → **Alerts** Tab

→ You should see alerts listed.
If alerts appear → Suricata ALERT mode is working.

---

### 7) Enable Blocking Mode (IPS Mode)

To turn Suricata from **ALERT → BLOCK**:

Go to:

* Services → Suricata → Interfaces → WAN → Edit

Scroll down:

* Find: **"Block Offenders"** or **"IPS Mode"**
* → Check ✔ (Enable Blocking)

Scroll → **Save**

Now Suricata will drop/block packets that match rules.

---

### 8) Test Blocking

From client, try:

```bash
ftp <ftp-server-ip>
# or
ping 8.8.8.8
```

Then check in pfSense:

* Services → Suricata → Logs → **Blocks** Tab

→ Block entry should appear.
This confirms Suricata IPS is working.

---

## PFSENSE FIREWALL – DETAILED STEPS

---

### Download & Install pfSense

Download ISO:

* [https://www.pfsense.org/download/](https://www.pfsense.org/download/)

Setup VM:

* → Use **3 network adapters**

  1. NAT
  2. Host-only
  3. Host-only
* → During installation always select NAT interface for **WAN**

Start installation normally.

---

### 2) After Installation

Default login:

* Username: `admin`
* Password: `pfsense`

Open browser on host:

* → Type: `https://<your-pfsense-LAN-IP>`

Go through Setup Wizard:

* System → Setup Wizard → Next
* → Primary DNS = `8.8.8.8`
* → Secondary DNS = `8.8.4.4`
* → Next → Next → Reload → Finish
* → Click **"Update"**

---

### 3) Configure Client IP Addresses

* **Client 1** → `192.168.20.20`
* **Client 2** → `192.168.20.30`

On each client:

* → Network settings → Assign manual IP
* → Gateway = pfSense LAN IP
* → DNS = pfSense LAN IP or `8.8.8.8`

Test:

```bash
ping 192.168.20.132   # pfSense LAN IP
```

---

### 4) Firewall Rule: Block Ping from Client to DNS Server

**Requirement:**

* Block ping from clients → DNS server `192.168.72.20`

Steps:

* pfSense GUI → Firewall → Rules → LAN → Add (up arrow icon)

Edit rule:

* Action → **Block**
* Interface → **LAN**
* Source → Any
* Destination → `192.168.72.20`
* Enable Log → ✔

Save → Apply Changes

**IMPORTANT:**

* Rule must be at **TOP**

  * → Drag rule ↑ to the top
  * → Save → Apply

Check on client:

```bash
ping 192.168.72.20
```

* → It should fail.

---

### 5) Install Squid (Web Proxy)

Dashboard:

* System → Package Manager → Available Packages
* → Search: `squid`
* → Install squid

Configure Squid:

* Services → Squid Proxy Server → General

  * → Enable Squid Proxy ✔
  * → Proxy Interface(s) → LAN + Loopback
  * → Logging Settings → check first box

Local Cache (next tab):

* → Hard Disk Cache Size = `1024`
* Save.

On client browser:

* → Configure Manual Proxy
* IP = pfSense LAN IP
* Port = default squid port (**3128**)

---

### 6) Install SquidGuard (Web Filter)

Dashboard:

* System → Package Manager → Available Packages
* → Search: `squidguard`
* → Install

Download blacklist:

* Google → search: **pfsense blacklist index of**
* Use link:

  * `https://dsi.ut-capitole.fr/blacklists/download/`

Configure:

* Services → SquidGuard Proxy Filter
* General Settings → scroll down

  * → Check "Blacklist"
  * → Paste blacklist URL
  * → Save

Go to **Blacklist** header:

* → Paste URL again
* → Click **Download**

Enable SquidGuard:

* General Settings → Enable ✔
* Save → Apply

---

### 7) Create Target Category & ACL Rules

#### Case 1: Sales Department

* Allow: shopping, social media
* Block: all other websites

Create user:

* Services → Squid Proxy Server → Users → Create

  * Add username + password → Save

Create allowlist:

* Services → SquidGuard Proxy Filter → Target Categories → Add

  * Name: `sales-whitelist`
  * Add domains → Save

Group ACL:

* Services → SquidGuard → Group ACL → Add

  * Name: `sales`
  * Client Source → `192.168.20.30`
  * Target Rules → **Click +** under `sales-whitelist` → **Allow**
  * Default Access → **Deny**
  * Enable Logging → check
  * Save → Apply

Check on client browser.

---

#### Case 2: Accounts Department

* Allow: bank sites + `gov.in`
* Block: everything else

Target Category:

* Target Categories → Add

  * Name: `bankingAndGov`
  * Regular Expression: `bank|gov.in`
  * Save

Group ACL:

* Group ACL → Add

  * Select `bankingAndGov` under Target Rules → **Allow**
  * Default Access → **Deny**
  * Save → Apply

Check on client.

---

#### Case 3: Development Department

* Allow: Microsoft, Redhat, Oracle, Docker, IBM
* Block: everything else

Target Category:

* Target Categories → Add

  * Name: `devsites`
  * Domain List:

    * `microsoft.com`
    * `redhat.com`
    * `oracle.com`
    * `docker.com`
    * `ibm.com`
  * Save

Group ACL:

* Group ACL → Add

  * Allow `devsites`
  * Default: **Deny**
  * Save → Apply

Check on client.

---

#### Case 4: Other Users

* Allow: google, wikipedia, news
* Block all other sites

Target Category:

* Name: `basic-sites`
* Regex: `google|wikipedia|news`
* Save

Group ACL:

* Allow `basic-sites`
* Default: **Deny**
* Save → Apply

Check on client.

---

#### Case 5: Allow google, bing, cdac for All Users

Target Category:

* Name: `allow-basic`
* Domains:

  * `google.com`
  * `bing.com`
  * `cdac.in`
* Save

Group ACL:

* Allow `allow-basic`
* Default: **Deny**
* Save → Apply

Test on client.

---

### 8) Block Access to pfSense Admin Page for One Client

pfSense:

* Firewall → Rules → LAN → Add

Rule:

* Action → **Block**
* Source → client IP (example `192.168.20.20`)
* Destination → pfSense LAN IP (example `192.168.20.132`)
* Port → Any

Save → Apply

Test:

* On client → Try to open pfSense IP
* It should be blocked.

---

### 9) Block Free FTP Servers

Block these IPs:

* `194.108.117.16`
* `85.188.1.133`
* `207.210.46.249`

pfSense:

* Firewall → Rules → LAN → Add

  * Action → **Block**
  * Destination → FTP IP
  * Port → 21
  * Save → Apply

Repeat for all IPs.

Test from client:

```bash
ftp 194.108.117.16
```

* → Should NOT allow login.

---

## SNORT 2.9 INSTALLATION

---

### Install Required Packages

```bash
sudo dnf update -y
sudo dnf install -y epel-release
sudo yum config-manager --set-enabled crb
sudo yum update -y

sudo dnf install -y gcc gcc-c++ libnetfilter_queue-devel git flex bison \
  zlib zlib-devel pcre pcre-devel libdnet libdnet-devel libnghttp2 wget xz-devel

cd   # go to home directory
```

---

### 2) Download and Install Snort Package

```bash
wget https://www.snort.org/downloads/snort/snort-2.9.20-1.f35.x86_64.rpm
sudo yum localinstall snort-2.9.20-1.f35.x86_64.rpm -y
```

Create library link:

```bash
sudo ln -s /usr/lib64/libdnet.so.1.0.1 /usr/lib64/libdnet.1
```

---

### 3) Verify Snort Installation

```bash
sudo snort -V
```

---

### 4) Configure Snort

Open config:

```bash
sudo vi /etc/snort/snort.conf
```

**Edit the following lines:**

Set HOME_NET:

```text
ipvar HOME_NET network-add/24
```

Set EXTERNAL_NET:

```text
ipvar EXTERNAL_NET !$HOME_NET
```

Set rule paths:

```text
var RULE_PATH /etc/snort/rules
var SO_RULE_PATH /etc/snort/rules/so_rules
var PREPROC_RULE_PATH /etc/snort/rules/preproc_rules

var WHITE_LIST_PATH /etc/snort/rules
var BLACK_LIST_PATH /etc/snort/rules
```

Enable logging:

```text
output unified2: filename snort.log, limit 128
```

At the end of file add:

```text
include $RULE_PATH/local.rules
```

Save and exit.

---

### 5) Create Rule Directories & Files

```bash
sudo touch /etc/snort/rules/white_list.rules
sudo touch /etc/snort/rules/black_list.rules
sudo touch /etc/snort/rules/local.rules

sudo mkdir /usr/local/lib/snort_dynamicrules
sudo chown -R snort:snort /usr/local/lib/snort_dynamicrules
```

---

### 6) Test Snort Configuration

```bash
sudo snort -T -c /etc/snort/snort.conf
```

If output ends with:

* `Snort successfully validated the configuration!`
  → Snort is installed correctly.

---

### 7) Create Test Rule

```bash
sudo vi /etc/snort/rules/local.rules
```

Add:

```text
alert icmp $HOME_NET any -> $EXTERNAL_NET any (msg:"Ping from LAN"; sid:1000001; rev:001;)
```

Save.

---

### 8) Run Snort in Console Mode

```bash
sudo snort -A console -i ens160 -c /etc/snort/snort.conf -q
```

Open another terminal:

```bash
ping 8.8.8.8
```

Stop ping (`CTRL+C`).

Check Snort console for alerts.
Stop Snort (`CTRL+C`).

---

### 9) Create Snort systemd Service

```bash
sudo vi /etc/systemd/system/snort.service
```

Paste:

```ini
[Unit]
Description=Snort 2.9 IDS/IPS
After=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/sbin/snort -A fast -D -q -c /etc/snort/snort.conf -i ens160
ExecStop=/bin/kill -SIGINT $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Reload services:

```bash
sudo systemctl daemon-reload
```

Start Snort:

```bash
sudo systemctl start snort
sudo systemctl status snort
```

Enable service:

```bash
sudo systemctl enable snort
```

---

### 10) Important Note

Snort may require SELinux disabled:

```bash
sudo setenforce 0
```

---

## GEOIP BLOCKING (xtables-addons)

---

### Ubuntu – Install & Configure GeoIP Blocker

1.1) Update system:

```bash
sudo apt update -y
```

1.2) Disable UFW:

```bash
sudo systemctl stop ufw
sudo systemctl disable ufw
sudo systemctl mask ufw
```

1.3) Install dependencies:

```bash
sudo apt install gcc make automake pkg-config libxtables-dev linux-headers-generic unzip -y
sudo apt install libnet-cidr-lite-perl libnet-cidr-perl libtext-csv-xs-perl -y
```

1.4) Download xtables-addons:

```bash
cd /tmp
wget -c https://inai.de/files/xtables-addons/xtables-addons-3.27.tar.xz
tar -xvf xtables-addons-3.27.tar.xz
cd xtables-addons-3.27
```

1.5) Edit Kbuild (enable only GeoIP):

```bash
vi extensions/Kbuild
```

* Put `#` for all except `geoip`.

1.6) Compile & install module:

```bash
sudo ./configure
sudo make
sudo make install
```

1.7) Check SecureBoot:

```bash
sudo mokutil --sb-state
```

1.8) Load module:

```bash
sudo depmod -a
sudo modprobe xt_geoip
```

1.9) Prepare GeoIP directory:

```bash
sudo mkdir /usr/share/xt_geoip
cd /usr/share/xt_geoip/
```

1.10) Download MaxMind GeoLite2 country DB:

```bash
sudo wget -q -O GeoLite2-Country-CSV.zip "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=<your-maxmind-license>&suffix=zip"
sudo unzip GeoLite2-Country-CSV.zip
sudo cp GeoLite2-Country-CSV*/GeoLite2-Country-Blocks-IPv4.csv /usr/share/xt_geoip/
```

1.11) Download DB-IP free country data (optional):

```bash
sudo wget -O dbip-country-lite.csv.gz "https://download.db-ip.com/free/dbip-country-lite-$(date +'%Y-%m').csv.gz"
sudo gunzip dbip-country-lite.csv.gz
```

1.12) Build GeoIP DB:

```bash
sudo /tmp/xtables-addons-3.27/geoip/xt_geoip_build -D /usr/share/xt_geoip/ GeoLite2-Country-Blocks-IPv4.csv
```

---

### 2) RHEL / CentOS / Rocky – Install & Configure GeoIP Blocker

2.1) Enable EPEL:

```bash
sudo yum install epel-release -y
```

2.2) Update system:

```bash
sudo yum update -y
```

2.3) Install dependencies:

```bash
sudo yum install gcc gcc-c++ kernel-modules kernel-core kernel-headers kernel-devel \
  perl-Net-CIDR-Lite perl-Text-CSV_XS elfutils-libelf-devel wget unzip tar mokutil -y
```

2.4) Download xtables-addons:

```bash
cd /tmp
wget -c https://inai.de/files/xtables-addons/xtables-addons-3.27.tar.xz
tar -xvf xtables-addons-3.27.tar.xz
cd xtables-addons-3.27
```

2.5) Edit Kbuild:

```bash
vi extensions/Kbuild
```

* Enable only GeoIP.

2.6) Compile and install:

```bash
sudo ./configure
sudo make
sudo make install
```

2.7) Check SecureBoot:

```bash
sudo mokutil --sb-state
```

2.8) Load module:

```bash
sudo modprobe xt_geoip
```

2.9) Create directory:

```bash
sudo mkdir /usr/share/xt_geoip
cd /usr/share/xt_geoip/
```

2.10) Download GeoLite2 DB:

```bash
sudo wget -q -O GeoLite2-Country-CSV.zip "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=<your-maxmind-license>&suffix=zip"
sudo unzip GeoLite2-Country-CSV.zip
sudo cp GeoLite2-Country-CSV*/GeoLite2-Country-Blocks-IPv4.csv /usr/share/xt_geoip/
```

2.11) Download DB-IP lite DB:

```bash
sudo wget -O dbip-country-lite.csv.gz "https://download.db-ip.com/free/dbip-country-lite-$(date +'%Y-%m').csv.gz"
sudo gunzip dbip-country-lite.csv.gz
```

2.12) Build GeoIP DB:

```bash
sudo /tmp/xtables-addons-3.27/geoip/xt_geoip_build -D /usr/share/xt_geoip/ GeoLite2-Country-Blocks-IPv4.csv
```

---

### 3) Add iptables GeoIP Blocking Rule

Example rule:

```bash
iptables -A INPUT -m geoip ! --src-cc IN -p tcp -m multiport \
  --dport 80,110,143,443,465,587,993,995,7071 -j DROP
```

Meaning:

* This blocks traffic from **ALL COUNTRIES except India**.

---

## OSSEC SERVER + CLIENT SETUP

---

### Server Installation

Install required packages:

```bash
sudo yum install zlib-devel pcre2-devel make gcc sqlite-devel openssl-devel \
  libevent-devel systemd-devel automake autoconf epel-release wget tar unzip -y
```

Install Remi repo + PHP:

```bash
sudo yum install -y https://rpms.remirepo.net/enterprise/remi-release-9.rpm
sudo yum module enable php:remi-7.4 -y
sudo yum install -y php php-cli php-common php-fpm
```

Install OSSEC Server (Atomic):

```bash
wget -q -O - https://updates.atomicorp.com/installers/atomic | sh
yum install ossec-hids ossec-hids-server
```

---

### 2) Server Configuration

Edit config:

```bash
nano /var/ossec/etc/ossec.conf
```

Go to line 81 and ensure:

```xml
<frequency>79200</frequency>
<alert_new_files>yes</alert_new_files>
```

Modify directories:

```xml
<directories report_changes="yes" realtime="yes" check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
<directories report_changes="yes" realtime="yes" check_all="yes">/bin,/sbin,/var/www</directories>
```

Save.

Add rule:

```bash
nano /var/ossec/rules/local_rules.xml
```

Add before “rules to ignore”:

```xml
<rule id="554" level="7" overwrite="yes">
  <category>ossec</category>
  <decoded_as>syscheck_new_entry</decoded_as>
  <description>File added to the system.</description>
  <group>syscheck,</group>
</rule>
```

Save.

Start server:

```bash
sudo /var/ossec/bin/ossec-control start
sudo /var/ossec/bin/ossec-control restart
sudo /var/ossec/bin/ossec-control status
```

---

### 3) Install Web Interface

Install httpd:

```bash
dnf install httpd -y
```

Download UI:

```bash
wget https://github.com/ossec/ossec-wui/archive/master.zip
unzip master.zip
sudo mv ossec-wui-master /var/www/html/ossec
cd /var/www/html/ossec
sudo ./setup.sh   # set username + password, web user = apache
```

Start Apache:

```bash
systemctl start httpd
systemctl enable httpd
```

Open firewall:

```bash
firewall-cmd --add-service=http --permanent
firewall-cmd --reload
```

Visit:

* `http://SERVER-IP/ossec`

---

### 4) Agent Installation

Install Atomic repo again:

```bash
wget -q -O - https://updates.atomicorp.com/installers/atomic | sh
```

Install agent:

```bash
yum install ossec-hids ossec-hids-agent
```

Edit agent config:

```bash
nano /var/ossec/etc/ossec.conf
```

Add server IP:

```xml
<server-ip>SERVER-IP-HERE</server-ip>
```

Save.

---

### 5) Link Agent with Server

On Server:

```bash
sudo /var/ossec/bin/manage_agents
```

* Press `A` → Add agent

  * Name = `client1`
  * IP = `CLIENT-IP`
  * ID = `001`
  * Confirm = `y`

* Press `E` → Extract key for agent `001`

  * Copy the key.

On Client:

```bash
sudo /var/ossec/bin/manage_agents
```

* Press `I` → Import key
* Paste the key
* Press `y` → confirm
* Press `Q` → quit

---

### 6) Start Client + Verify

Start agent:

```bash
sudo /var/ossec/bin/ossec-control start
```

Wait 2–3 minutes.

Check OSSEC Web UI:

* `http://SERVER-IP/ossec`

Client should appear under **“Agents”**.

If not, restart server:

```bash
sudo systemctl restart ossec
```

---

### 7) Enable OSSEC as a Service (Optional)

Create file:

```bash
nano /usr/lib/systemd/system/ossec.service
```

Paste:

```ini
[Unit]
Description=OSSEC service

[Service]
Type=forking
ExecStart=/var/ossec/bin/ossec-control start
ExecStop=/var/ossec/bin/ossec-control stop
ExecRestart=/var/ossec/bin/ossec-control restart

[Install]
WantedBy=multi-user.target
```

Install chkconfig:

```bash
yum install chkconfig -y
```

Enable:

```bash
systemctl start ossec
systemctl enable ossec
```

---

### Final Flow Summary

**Server:**

* Install OSSEC server
* Edit `ossec.conf`
* Add rule
* Start server
* Install Web UI (optional)

**Client:**

* Install OSSEC agent
* Add server IP in `ossec.conf`
* On server → add agent + extract key
* On client → import key
* Start agent
* Check in dashboard

---

## REVERSE PROXY: NGINX + 2 APACHE SERVERS (1 SERVER, 2 CLIENT LAB)

---

### Lab Setup – 3 VMs (1 Server + 2 Clients)

* ALL machines in **NAT Network Mode**

* ALL machines → SELinux **disabled** or **permissive**

* **VM1** → Apache Server 1

* **VM2** → Apache Server 2

* **VM3** → Nginx Server (Front-End for clients)

Update all VMs:

```bash
sudo yum update -y
```

---

### APACHE SETUP (Client 1 + Client 2)

#### 2) Install Apache on Client 1 & Client 2

Install:

```bash
sudo yum install httpd -y
# Ubuntu:
sudo apt install apache2 -y
```

Create webpage:

```bash
sudo vi /var/www/html/index.html
```

**Example content for Client 1:**

```html
<h1>Apache Server 1</h1> Served by: <IP-of-Apache-1>
```

**Example content for Client 2:**

```html
<h1>Apache Server 2</h1> Served by: <IP-of-Apache-2>
```

Start Apache:

```bash
sudo systemctl start httpd
sudo systemctl enable httpd
```

Firewall open:

```bash
sudo firewall-cmd --add-service=http
sudo firewall-cmd --add-service=http --permanent
```

---

### NGINX SETUP (Main Server)

#### 3) Install Nginx on Front-End Server

Install:

```bash
sudo yum install nginx -y
```

Start:

```bash
sudo systemctl start nginx
sudo systemctl enable nginx
```

Firewall:

```bash
sudo firewall-cmd --add-service=http
sudo firewall-cmd --add-service=http --permanent
```

---

#### 4) Test Nginx Default Page

On your Windows browser:

* `http://<nginx-server-IP>`

You should see **default Nginx page**.

Now Nginx will be configured as:

* Reverse Proxy → route `/` to Apache1, `/courses` to Apache2
* Load Balancer → distribute to both Apache servers

---

### NGINX as Reverse Proxy

#### 5) Backup Original Config

```bash
sudo cp /etc/nginx/nginx.conf ~
```

---

#### 6) Edit Config File

```bash
sudo vi /etc/nginx/nginx.conf
```

Inside `server { }` comment these lines:

```nginx
#listen [::]:80;
#server_name _;
#root /usr/share/nginx/html;
```

Make sure:

```nginx
include /etc/nginx/default.d/*.conf;
```

Now add:

```nginx
location / {
    proxy_pass http://<Apache-1-IP>/;
    proxy_buffering off;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Port $server_port;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}

location /courses {
    proxy_pass http://<Apache-2-IP>/;
    proxy_buffering off;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Port $server_port;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Restart nginx:

```bash
sudo systemctl restart nginx
```

---

#### 7) Test Reverse Proxy

On Windows browser:

* Test Apache 1:

  * `http://<nginx-IP>/`
  * → Should show **Apache Server 1** page

* Test Apache 2:

  * `http://<nginx-IP>/courses`
  * → Should show **Apache Server 2** page

Reverse Proxy working ✔️

---

### NGINX as Load Balancer

#### 8) Restore Original Config

```bash
sudo cp -f ~/nginx.conf /etc/nginx/
```

---

#### 9) Edit `nginx.conf` for Load Balancing

```bash
sudo vi /etc/nginx/nginx.conf
```

Comment again:

```nginx
#listen [::]:80;
#server_name _;
#root /usr/share/nginx/html;
```

Include line:

```nginx
include /etc/nginx/default.d/*.conf;
```

Add upstream + server block:

```nginx
upstream backend {
    server <Apache-1-IP>;
    server <Apache-2-IP>;
}

server {
    listen 80;
    location / {
        proxy_pass http://backend/;
    }
}
```

---

#### 10) Restart Nginx

```bash
sudo systemctl restart nginx
```

---

#### 11) Test Load Balancer

Open browser:

* `http://<nginx-IP>/`

Results:

* 1st refresh → Apache 1 page
* 2nd refresh → Apache 2 page
* 3rd refresh → Apache 1
* and so on…

Nginx defaults to **Round Robin** load balancing.

---

## OPENVPN SERVER SETUP

---

### Lab Requirements

You need **3 VMs**:

1. **OpenVPN Server**

   * 2 Network Cards:

     * NAT
     * Host-Only
   * Hostname: `openvpnserver`

2. **VPN Client (Remote Client)**

   * 1 Network Card:

     * NAT
   * Hostname: `client1`

3. **LAN Machine**

   * 1 Network Card:

     * Host-Only

Create user `admin` on all machines and give sudo access.

Run on all VMs:

```bash
sudo yum update -y
```

Set correct timezone everywhere.

---

### 2) Disable SELinux

Edit config:

```bash
sudo vi /etc/selinux/config
```

Set:

```text
SELINUX=disabled
```

Apply temporary permissive mode:

```bash
sudo setenforce 0
```

---

### 3) Enable IP Forwarding

Temporary:

```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

Permanent:

```bash
sudo vi /etc/sysctl.conf
```

Add:

```text
net.ipv4.ip_forward = 1
```

---

### 4) Install Required Packages

```bash
sudo dnf install epel-release -y
sudo dnf install openvpn wget tar -y
```

Go to OpenVPN directory:

```bash
cd /etc/openvpn
```

Download EasyRSA:

```bash
sudo wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.6/EasyRSA-unix-v3.0.6.tgz
```

Extract:

```bash
sudo tar xvzf EasyRSA-unix-v3.0.6.tgz
```

Rename:

```bash
sudo mv EasyRSA-v3.0.6 easy-rsa
```

Enter folder:

```bash
cd easy-rsa
```

---

### 5) Create `vars` File

```bash
vi vars
```

Paste:

```bash
set_var EASYRSA "$PWD"
set_var EASYRSA_PKI "$EASYRSA/pki"
set_var EASYRSA_DN "cn_only"
set_var EASYRSA_REQ_COUNTRY "IN"
set_var EASYRSA_REQ_PROVINCE "Maharastra"
set_var EASYRSA_REQ_CITY "Pune"
set_var EASYRSA_REQ_ORG "Demo Labs"
set_var EASYRSA_REQ_EMAIL ""
set_var EASYRSA_REQ_OU "Demo Labs CA"
set_var EASYRSA_KEY_SIZE 2048
set_var EASYRSA_ALGO rsa
set_var EASYRSA_CA_EXPIRE 7500
set_var EASYRSA_CERT_EXPIRE 365
set_var EASYRSA_NS_SUPPORT "no"
set_var EASYRSA_NS_COMMENT "Demo Labs"
set_var EASYRSA_EXT_DIR "$EASYRSA/x509-types"
set_var EASYRSA_SSL_CONF "$EASYRSA/openssl-easyrsa.cnf"
set_var EASYRSA_DIGEST "sha256"
```

---

### 6) Initialize PKI & Build CA

Init PKI:

```bash
sudo ./easyrsa init-pki
```

Build CA:

```bash
sudo ./easyrsa build-ca
```

* Enter password
* Common Name (example): `demo-ca`

---

### 7) Generate Server Certificates

Request:

```bash
sudo ./easyrsa gen-req openvpnserver nopass
```

* Press Enter at hostname.

Sign:

```bash
sudo ./easyrsa sign-req server openvpnserver
```

* Choose: `yes`
* Enter CA password.

Generate DH:

```bash
sudo ./easyrsa gen-dh
```

Copy certs to server directory:

```bash
sudo cp pki/ca.crt /etc/openvpn/server
sudo cp pki/dh.pem /etc/openvpn/server
sudo cp pki/private/openvpnserver.key /etc/openvpn/server
sudo cp pki/issued/openvpnserver.crt /etc/openvpn/server
```

---

### 8) Generate Client Certificates

Request:

```bash
sudo ./easyrsa gen-req client1 nopass
```

* Press Enter.

Sign:

```bash
sudo ./easyrsa sign-req client client1
```

Copy client certs:

```bash
sudo cp pki/ca.crt /etc/openvpn/client
sudo cp pki/issued/client1.crt /etc/openvpn/client
sudo cp pki/private/client1.key /etc/openvpn/client
```

---

### 9) Create `server.conf` File

```bash
sudo vi /etc/openvpn/server/server.conf
```

Paste:

```conf
port 1194
proto udp
dev tun

ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/openvpnserver.crt
key /etc/openvpn/server/openvpnserver.key
dh /etc/openvpn/server/dh.pem

server 10.8.0.0 255.255.255.0

push "route 192.168.237.0 255.255.255.0"

duplicate-cn
cipher AES-256-CBC
tls-version-min 1.2
auth SHA512
auth-nocache

keepalive 20 60
persist-key
persist-tun
compress lz4

daemon
user nobody
group nobody

log-append /var/log/openvpn.log
verb 3
```

---

### 10) Start OpenVPN Server

```bash
sudo systemctl start openvpn-server@server
sudo systemctl status openvpn-server@server
sudo systemctl enable openvpn-server@server
```

---

### 11) Create Client `.ovpn` File

```bash
sudo vi /etc/openvpn/client/client1.ovpn
```

Paste:

```conf
client
dev tun
proto udp
remote vpn-server-ip 1194

ca ca.crt
cert client1.crt
key client1.key

cipher AES-256-CBC
auth SHA512
auth-nocache

tls-version-min 1.2
compress lz4

nobind
persist-key
persist-tun

verb 3
```

---

### 12) Firewall Rules

```bash
sudo firewall-cmd --permanent --add-service=openvpn
sudo firewall-cmd --permanent --zone=trusted --add-service=openvpn
sudo firewall-cmd --permanent --zone=trusted --change-interface=tun0

sudo firewall-cmd --add-masquerade
sudo firewall-cmd --permanent --add-masquerade

sudo firewall-cmd --permanent --direct --passthrough ipv4 -t nat \
  -A POSTROUTING -s 10.8.0.0/24 -o ens160 -j MASQUERADE

sudo firewall-cmd --reload
```

---

### 13) Copy Client Files to Client Machine

```bash
sudo scp /etc/openvpn/client/. admin@vpn-client-ip:/home/admin
```

---

### 14) On Client Machine

Install:

```bash
sudo dnf install epel-release -y
sudo dnf install openvpn -y
```

Disable SELinux:

```bash
sudo setenforce 0
```

Copy files:

```bash
sudo cp /home/admin/ca.crt /etc/openvpn/client
sudo cp /home/admin/client1.crt /etc/openvpn/client
sudo cp /home/admin/client1.key /etc/openvpn/client
```

Edit `.ovpn` and set server IP.

---

### 15) Connect to VPN

Start VPN:

```bash
sudo openvpn --config client1.ovpn
```

Open another terminal:

```bash
ip a
```

Test:

```bash
ping <LAN-IP>
ssh <LAN-IP>
```

Disconnect:

* `Ctrl + C`

---

```
```
