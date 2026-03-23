# Linux 安全強化筆記

連線方式：`docker exec -it sec_challenge bash`

---

## 1. SSH 服務配置安全

設定檔：`/etc/ssh/sshd_config`

```
PermitRootLogin no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
Banner /etc/ssh/banner
```

建立 Banner 檔：

```bash
echo "WARNING: Authorized use only." > /etc/ssh/banner
```

重載：

```bash
kill -HUP $(cat /var/run/sshd.pid)
```

---

## 2. SSH 弱密碼

```bash
echo "admin:Str0ng#Pass2024!" | chpasswd
```

或互動式：

```bash
passwd admin
```

---

## 3. Web 上傳漏洞

編輯 `/var/www/html/upload.php`：
- 白名單副檔名（jpg、jpeg、png、gif）
- 用 `finfo_file()` 驗證 MIME

禁止 uploads 目錄執行 PHP（縱深防禦）：

```bash
echo "php_flag engine off" > /var/www/html/uploads/.htaccess
```

---

## 4. 最小權限原則

```bash
chmod 640 /etc/shadow
chmod 644 /opt/app/config.ini
chmod 755 /var/log
```

重點：
- `/etc/shadow` — 密碼雜湊，不該讓一般使用者讀取
- `/opt/app/config.ini` — 含 API 金鑰，不該讓所有人寫入
- `/var/log` — 日誌目錄，不該讓所有人寫入（防止竄改）

---

## 5. 防火牆配置（iptables）

順序很重要，先放行再 DROP：

```bash
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -P INPUT DROP
```

驗證：

```bash
iptables -L INPUT -n -v
```

---

## 6. Cron 任務安全

```bash
chmod 755 /etc/cron.hourly/backup.sh
chmod 644 /etc/cron.d/backup
```

原理：
- 排程腳本 777 → 任何人可修改 → 植入惡意指令
- 設定檔 666 → 任何人可修改 → 新增排程任務

---

## 7. SUID/SGID 稽核

找出所有 SUID 檔案：

```bash
find / -perm -4000 -type f 2>/dev/null
```

移除不該有 SUID 的檔案：

```bash
chmod u-s /usr/local/bin/vuln_tool
```

保留系統需要的（如 `/usr/bin/passwd`、`/usr/bin/su`），移除異常的。

---

## 8. 系統日誌配置

編輯 `/etc/rsyslog.conf`，找到被註解的 auth 行，取消註解：

```
auth,authpriv.*    /var/log/auth.log
```

若找不到就直接新增。確保認證事件（登入成功/失敗）有被記錄。

---

## 9. 不必要服務移除

找出多餘的服務：

```bash
ss -tlnp
ps aux
```

停止 vsftpd（FTP 使用明文傳輸帳密，不安全）：

```bash
pkill vsftpd
```

驗證：

```bash
pgrep vsftpd      # 應無輸出
ss -tlnp | grep 21 # 應無輸出
```

---

## 10. 密碼策略強化

### PAM 密碼複雜度

編輯 `/etc/pam.d/common-password`，在 `pam_pwquality.so` 那行加入：

```
minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1
```

意義：最少 12 字元，至少各含 1 個大寫、小寫、數字、特殊字元。

### 密碼有效期

編輯 `/etc/login.defs`：

```
PASS_MAX_DAYS   90
```

---

## 11. sysctl 核心安全參數

編輯 `/etc/sysctl.d/99-hardening.conf`：

```
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
kernel.randomize_va_space = 2
net.ipv4.icmp_echo_ignore_broadcasts = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
```

各參數意義：
- `ip_forward = 0` — 不當路由器轉發封包
- `accept_redirects = 0` — 不接受 ICMP 重導向（防 MITM）
- `send_redirects = 0` — 不發送 ICMP 重導向
- `accept_source_route = 0` — 不接受來源路由（防偽造路徑）
- `randomize_va_space = 2` — 完整 ASLR，防記憶體攻擊
- `icmp_echo_ignore_broadcasts = 1` — 忽略廣播 ping（防 Smurf 攻擊）
- `protected_hardlinks = 1` — 防止硬連結攻擊
- `protected_symlinks = 1` — 防止符號連結攻擊

---

## 12. PAM 登入失敗鎖定

編輯 `/etc/security/faillock.conf`：

```
deny = 5
unlock_time = 900
```

意義：連續 5 次失敗鎖定帳號 15 分鐘，防暴力破解。

---

## 13. sudoers NOPASSWD 風險

檢查 `/etc/sudoers.d/` 下的檔案：

```bash
cat /etc/sudoers.d/deploy
# deploy ALL=(ALL) NOPASSWD: ALL  ← 危險！
```

修復：刪除或限縮權限

```bash
rm /etc/sudoers.d/deploy
```

---

## 14. SSH 停用密碼認證

編輯 `/etc/ssh/sshd_config`：

```
PasswordAuthentication no
PubkeyAuthentication yes
```

重載：

```bash
kill -HUP $(cat /var/run/sshd.pid)
```

改用公鑰認證，防止暴力破解密碼。

---

## 15. 空密碼帳號鎖定

找出空密碼帳號：

```bash
awk -F: '($2==""){print $1}' /etc/shadow
```

鎖定帳號：

```bash
passwd -l ghost
passwd -l phantom
```

驗證：

```bash
passwd -S ghost    # 應顯示 L（locked）
```

---

## 16. ACL 存取控制

限制 it 群組執行 find：

```bash
setfacl -m g:it:r-- /usr/bin/find
```

驗證：

```bash
getfacl /usr/bin/find
su -s /bin/bash svcuser -c "find /tmp"  # 應被拒絕
```

---

## 17. sudo 最小授權

建立 `/etc/sudoers.d/webadmin`：

```
webadmin ALL=(ALL) /usr/bin/find
```

設定權限：

```bash
chmod 440 /etc/sudoers.d/webadmin
```

重點：
- 不能用 NOPASSWD（需驗證身份）
- 不能授權 ALL（只限特定指令）

驗證：

```bash
sudo -l -U webadmin
```

---

## 18. 家目錄權限

```bash
chmod 700 /home/*
```

或逐一設定：

```bash
for u in $(ls /home/); do chmod 700 /home/$u; done
```

`700` = rwx------ = 只有擁有者可讀寫執行。

---

## 19. HTTPS 與強制重導向

### 生成自簽憑證

```bash
openssl req -x509 -newkey rsa:2048 \
    -keyout /etc/ssl/private/server.key \
    -out /etc/ssl/certs/server.crt \
    -days 365 -nodes \
    -subj '/CN=localhost'
```

### 啟用 SSL 模組

```bash
a2enmod ssl
```

### 設定 HTTPS VirtualHost

建立 `/etc/apache2/sites-available/default-ssl.conf`：

```apache
<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile    /etc/ssl/certs/server.crt
    SSLCertificateKeyFile /etc/ssl/private/server.key
    DocumentRoot /var/www/html
</VirtualHost>
```

啟用：

```bash
a2ensite default-ssl
```

### HTTP 重導向至 HTTPS

編輯 `/etc/apache2/sites-available/000-default.conf`，在 `<VirtualHost *:80>` 內加入：

```apache
Redirect permanent / https://localhost/
```

重啟：

```bash
service apache2 restart
```

---

## 20. iptables 連接埠轉發（DNAT）

將 9090 轉發到 80：

```bash
iptables -t nat -A PREROUTING -p tcp --dport 9090 -j DNAT --to-destination 127.0.0.1:80
iptables -t nat -A OUTPUT -p tcp --dport 9090 -j DNAT --to-destination 127.0.0.1:80
```

驗證：

```bash
iptables -t nat -L PREROUTING -n -v
```

---

## 21. PHP 安全設定

找到 php.ini 位置：

```bash
php -r "echo php_ini_loaded_file();"
```

修改以下設定：

```ini
expose_php = Off
display_errors = Off
allow_url_include = Off
disable_functions = system,exec,passthru,shell_exec,popen,proc_open
```

重啟 Apache：

```bash
service apache2 restart
```

各設定意義：
- `expose_php = Off` — HTTP header 不洩漏 PHP 版本（X-Powered-By）
- `display_errors = Off` — 不在頁面顯示錯誤細節（防洩漏路徑、SQL 等）
- `allow_url_include = Off` — 禁止遠端檔案引入（防 RFI 攻擊）
- `disable_functions` — 停用可執行系統指令的危險函數（防 RCE）
  - `system` / `exec` / `passthru` / `shell_exec` — 直接執行 OS 指令
  - `popen` / `proc_open` — 開啟程序管道，同樣可執行指令

---

## 22. Apache 目錄列表防護

編輯 `/etc/apache2/apache2.conf`，找到：

```apache
<Directory /var/www/html/data>
    Options Indexes FollowSymLinks
```

改為：

```apache
<Directory /var/www/html/data>
    Options FollowSymLinks
```

或使用 `-Indexes`：

```apache
    Options -Indexes
```

重啟：

```bash
service apache2 restart
```

---

## 23. Nginx 安全配置

設定檔：`/etc/nginx/sites-available/vulnerable`

### 修復 alias 路徑穿越

原始（有漏洞）：

```nginx
location /secret {
    alias /var/www/nginx/;
```

修復（加尾斜線）：

```nginx
location /secret/ {
    alias /var/www/nginx/;
```

原理：`location /secret` 沒有尾斜線時，請求 `/secret../` 會被 alias 拼接成 `/var/www/nginx/../`，造成路徑穿越。

### 停用 autoindex

將所有 `autoindex on;` 改為 `autoindex off;`。

重載：

```bash
nginx -s reload
```
