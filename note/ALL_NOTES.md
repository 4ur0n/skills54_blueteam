# Linux 安全強化完整筆記（23 題）

---

# 題 1 — SSH 服務配置安全

## 設定檔

```
/etc/ssh/sshd_config
```

## 重要參數

| 參數 | 建議值 | 說明 |
|------|--------|------|
| `PermitRootLogin` | no | 禁止 root 直接 SSH 登入 |
| `MaxAuthTries` | 3 | 最多嘗試 3 次密碼 |
| `LoginGraceTime` | 30 | 30 秒內未認證就斷線 |
| `X11Forwarding` | no | 關閉 X11 轉發（減少攻擊面） |
| `Banner` | /etc/ssh/banner | 登入前顯示警告訊息 |
| `PasswordAuthentication` | no | 停用密碼認證，改用金鑰 |
| `PubkeyAuthentication` | yes | 啟用公鑰認證 |
| `PermitEmptyPasswords` | no | 禁止空密碼登入 |
| `ClientAliveInterval` | 300 | 每 300 秒送心跳 |
| `ClientAliveCountMax` | 2 | 2 次沒回應就斷線（=10 分鐘閒置踢出） |
| `Protocol` | 2 | 只用 SSH v2（舊版才需要設） |
| `AllowUsers` | user1 user2 | 白名單，只允許特定帳號登入 |
| `AllowGroups` | sshusers | 白名單，只允許特定群組 |
| `Port` | 2222 | 改預設埠（降低掃描命中率） |

## 重載方式

```bash
kill -HUP $(cat /var/run/sshd.pid)   # 不斷現有連線
systemctl reload sshd
service ssh reload
```

重點：用 `reload` 不是 `restart`，reload 不會踢掉正在連線的人。

## 延伸：公鑰認證設定

### 產生金鑰對（client 端）

```bash
ssh-keygen -t ed25519 -C "user@host"
ssh-keygen -t rsa -b 4096    # RSA
```

### 部署公鑰到 server

```bash
ssh-copy-id user@server
# 或手動
cat ~/.ssh/id_ed25519.pub >> ~/.ssh/authorized_keys
chmod 700 ~/.ssh
chmod 600 ~/.ssh/authorized_keys
```

### 金鑰演算法比較

| 類型 | 安全性 | 速度 | 說明 |
|------|--------|------|------|
| ed25519 | 最高 | 最快 | 首選，256-bit 橢圓曲線 |
| rsa 4096 | 高 | 慢 | 相容性最好 |
| ecdsa | 高 | 快 | 部分情境有爭議（NIST 曲線） |

## 延伸：SSH Tunnel

```bash
ssh -L 8080:localhost:3306 user@server    # 正向代理（本機 8080 → 遠端 3306）
ssh -R 9090:localhost:80 user@server      # 反向代理（遠端 9090 → 本機 80）
ssh -D 1080 user@server                   # SOCKS5 代理
```

## 延伸：SCP / SFTP

```bash
scp file.txt user@server:/tmp/
sftp user@server
```

## 延伸：~/.ssh/config

```
Host myserver
    HostName 192.168.1.100
    User admin
    Port 2222
    IdentityFile ~/.ssh/id_ed25519
```

之後只要 `ssh myserver` 就好。

## 延伸：偵錯

```bash
tail -f /var/log/auth.log     # SSH 登入日誌
ssh -vvv user@server          # client verbose 模式
sshd -t                       # 測試設定檔語法
who                           # 查看目前連線
ss -tlnp | grep 22            # 查看 port
```

## 速解

```bash
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config
sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 30/' /etc/ssh/sshd_config
echo "Banner /etc/ssh/banner" >> /etc/ssh/sshd_config
echo "WARNING: Authorized use only." > /etc/ssh/banner
kill -HUP $(cat /var/run/sshd.pid)
```

## 易錯

1. **改完沒 reload** → 設定不生效
2. **停用密碼認證前沒部署公鑰** → 鎖死自己（競賽環境用 docker exec 救）
3. **sed 改錯行** → 設定檔可能有多個相同參數，以最後一個為準
4. **Banner 檔案不存在** → SSH 不會報錯但不顯示
5. **PermitRootLogin 寫成 PermitRootlogin** → 大小寫敏感

---

# 題 2 — SSH 弱密碼檢測

## 相關檔案

| 檔案 | 說明 | 權限 |
|------|------|------|
| `/etc/passwd` | 帳號資訊（UID、GID、家目錄、shell） | 644 |
| `/etc/shadow` | 密碼雜湊 + 密碼策略 | 640 |
| `/etc/group` | 群組資訊 | 644 |
| `/etc/gshadow` | 群組密碼 | 640 |

## /etc/shadow 格式

```
admin:$6$salt$hash:19000:0:90:7:::
  │      │        │   │  │  │
  │      │        │   │  │  └─ 到期前幾天警告
  │      │        │   │  └──── PASS_MAX_DAYS
  │      │        │   └─────── PASS_MIN_DAYS
  │      │        └──────────── 上次改密碼（天數，1970 起算）
  │      └───────────────────── 密碼雜湊（$6$=SHA-512, $y$=yescrypt）
  └──────────────────────────── 帳號名稱
```

特殊值：
- `!` 或 `!!` → 帳號被鎖定
- 空字串 → 無密碼（危險！）
- `*` → 系統帳號，無法用密碼登入

## 雜湊演算法

| 前綴 | 演算法 | 安全性 |
|------|--------|--------|
| `$1$` | MD5 | 不安全 |
| `$5$` | SHA-256 | 可用 |
| `$6$` | SHA-512 | 推薦 |
| `$y$` | yescrypt | 最新，Debian 12+ 預設 |

## 改密碼

```bash
passwd admin                              # 互動式
echo "admin:Str0ng#Pass2024!" | chpasswd  # 非互動式
echo "admin:Str0ng#Pass2024!" | chpasswd -c SHA512  # 指定演算法
```

## 延伸：帳號管理

```bash
useradd -m -s /bin/bash newuser    # 新增（-m 建立家目錄）
passwd newuser                      # 設密碼
userdel -r olduser                  # 刪除（-r 連家目錄）
```

## 延伸：查看登入紀錄

```bash
last                   # 最近登入紀錄
lastb                  # 登入失敗紀錄
lastlog                # 每個帳號最後登入時間
faillog -a             # 失敗次數統計
```

## 延伸：用 john 批次檢查弱密碼

```bash
unshadow /etc/passwd /etc/shadow > combined.txt
john --wordlist=/usr/share/wordlists/rockyou.txt combined.txt
john --show combined.txt
```

## 速解

```bash
echo "admin:Str0ng#Pass2024!" | chpasswd
```

## 易錯

1. **chpasswd 沒加 `-c`** → 用系統預設雜湊，驗證器可能期望 SHA512
2. **passwd -l 不是刪除密碼** → 是在 hash 前加 `!`，帳號還在
3. **login.defs 不影響現有帳號** → 要用 `chage` 逐一設定
4. **空密碼 ≠ 鎖定** → 空密碼是 shadow 第二欄為空，鎖定是有 `!`
5. **忘記檢查 PermitEmptyPasswords** → SSH 設定也要確認

---

# 題 3 — Web 應用上傳漏洞

## 漏洞原理

上傳沒驗證 → 攻擊者上傳 `.php` → 瀏覽器訪問 → RCE

常見 webshell：

```php
<?php system($_GET['cmd']); ?>
<?php eval($_POST['code']); ?>
```

## 防禦層次

### 第一層：白名單副檔名

```php
$allowed = ['jpg', 'jpeg', 'png', 'gif'];
$ext = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allowed)) die("不允許的檔案類型");
```

### 第二層：MIME 驗證

```php
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime = $finfo->file($_FILES['file']['tmp_name']);
$allowed_mime = ['image/jpeg', 'image/png', 'image/gif'];
if (!in_array($mime, $allowed_mime)) die("MIME 類型不符");
```

為什麼不只看 `$_FILES['file']['type']`？那是 client 傳的，可以偽造。`finfo_file()` 讀檔案內容判斷。

### 第三層：禁止 uploads 執行 PHP

```bash
echo "php_flag engine off" > /var/www/html/uploads/.htaccess
```

或在 Apache 設定：

```apache
<Directory /var/www/html/uploads>
    php_admin_flag engine off
</Directory>
```

### 第四層：重新命名檔案

```php
$newname = bin2hex(random_bytes(16)) . '.' . $ext;
move_uploaded_file($_FILES['file']['tmp_name'], $upload_dir . $newname);
```

## 常見繞過手法

| 手法 | 說明 | 防禦 |
|------|------|------|
| 雙副檔名 | `shell.php.jpg` | 白名單取最後一個副檔名 |
| null byte | `shell.php%00.jpg` | PHP 5.3 以下有效 → 升級 |
| Content-Type 偽造 | 改成 `image/jpeg` | 用 `finfo_file()` |
| `.htaccess` 上傳 | 讓 `.jpg` 當 PHP 執行 | 白名單不含 `.htaccess` |
| 大小寫 | `.PhP`、`.pHP` | `strtolower()` |
| 圖片馬 | 在圖片裡塞 PHP code | 禁止 uploads 執行 PHP |
| `.phar` | PHP Archive | 白名單不含 `.phar` |

## Nginx 環境

Nginx 不認 `.htaccess`，要在 config 裡設：

```nginx
location /uploads/ {
    location ~ \.php$ { return 403; }
}
```

## 延伸：PHP 上傳設定（php.ini）

```ini
file_uploads = On
upload_max_filesize = 2M
post_max_size = 8M
max_file_uploads = 20
```

## 易錯

1. **只擋副檔名沒擋 MIME** → 圖片馬繞過
2. **用黑名單遺漏 `.phtml`/`.phar`** → 永遠用白名單
3. **`.htaccess` 沒生效** → Apache 要設 `AllowOverride All`
4. **uploads 目錄 777** → 改 755
5. **忘記 `strtolower()`** → `.PHP` 繞過

---

# 題 4 — 最小權限原則

## 權限基礎

```
-rwxr-x--- 1 root shadow
 │││ │││ │││
 │││ │││ └┴┴─ others
 │││ └┴┴───── group
 └┴┴──────── owner
```

| 符號 | 數字 | 檔案意義 | 目錄意義 |
|------|------|----------|----------|
| r | 4 | 讀取內容 | 列出檔案（ls） |
| w | 2 | 修改內容 | 新增/刪除檔案 |
| x | 1 | 執行 | 進入目錄（cd） |

組合：`7`=rwx, `6`=rw-, `5`=r-x, `4`=r--, `0`=---

## chmod 用法

```bash
chmod 640 /etc/shadow          # 數字模式
chmod u+x script.sh            # 符號模式：owner 加執行
chmod g-w file.txt             # group 移除寫入
chmod o= file.txt              # others 清空
chmod u=rwx,g=rx,o= dir/      # 等同 750
chmod -R 750 /opt/app/         # 遞迴
```

## chown / chgrp

```bash
chown root:shadow /etc/shadow
chown -R www-data:www-data /var/www/html/
chgrp adm /var/log/syslog
```

## 特殊權限

| 權限 | 數字 | 符號 | 用途 |
|------|------|------|------|
| SUID | 4000 | `u+s` | 執行時以 owner 身份運行 |
| SGID | 2000 | `g+s` | 執行時以 group 身份運行；目錄上 → 新檔案繼承群組 |
| Sticky | 1000 | `o+t` | 目錄上 → 只有 owner 可刪自己的檔案（如 `/tmp`） |

`ls -la` 顯示：SUID=`-rwsr-xr-x`，SGID=`-rwxr-sr-x`，Sticky=`drwxrwxrwt`
大寫 `S`/`T` = 沒有 x 但有特殊位（通常是設定錯誤）

## umask

新檔案/目錄預設權限 = 基礎權限 - umask

| | 基礎 | umask 022 | 結果 |
|---|------|-----------|------|
| 檔案 | 666 | 022 | 644 |
| 目錄 | 777 | 022 | 755 |

```bash
umask              # 查看
umask 027          # 設定（新檔案 640，新目錄 750）
```

## 競賽常見權限

| 檔案 | 權限 | 說明 |
|------|------|------|
| `/etc/shadow` | 640 | 密碼雜湊 |
| `/etc/passwd` | 644 | 帳號資訊 |
| `/opt/app/config.ini` | 640 | 含 API key |
| `/var/log` | 755 | 日誌目錄 |
| `/home/*` | 700 | 家目錄 |
| `/etc/cron.d/*` | 644 | 排程設定 |
| `/etc/cron.hourly/*.sh` | 755 | 排程腳本 |
| `/etc/sudoers.d/*` | 440 | sudoers |

## 延伸：找異常權限

```bash
find / -type f -perm -o+w 2>/dev/null                         # world-writable 檔案
find / -type d -perm -o+w ! -path "/tmp*" 2>/dev/null         # world-writable 目錄
find / -nouser -o -nogroup 2>/dev/null                         # 沒有 owner 的檔案
```

## 速解

```bash
chmod 640 /etc/shadow
chmod 644 /opt/app/config.ini
chmod 755 /var/log
```

## 易錯

1. **777 萬用** → 永遠不該用
2. **`/etc/shadow` 設 644** → 任何人可讀密碼雜湊，可離線破解
3. **目錄忘記 x** → 沒有 x 就不能 cd 進去
4. **遞迴 chmod 把檔案也加 x** → 用 `find -type f` 和 `find -type d` 分開處理
5. **sudoers 權限不是 440** → sudo 會拒絕載入

---

# 題 5 — 防火牆配置（iptables）

## 封包流向

```
封包進來 → PREROUTING → 路由判斷 → INPUT → 本機處理
                                    ↓
                            FORWARD → 轉發
                                    ↓
封包出去 ← POSTROUTING ← OUTPUT ← 本機產生
```

## 語法

```bash
iptables [-t 表] -操作 鏈 [條件] -j 動作
```

### 表

| 表 | 用途 | 鏈 |
|---|------|-----|
| filter | 預設，過濾封包 | INPUT、OUTPUT、FORWARD |
| nat | 位址轉換 | PREROUTING、POSTROUTING、OUTPUT |

### 操作

| 旗標 | 說明 |
|------|------|
| -A | append，加到最後 |
| -I | insert，插到最前 |
| -D | delete，刪除規則 |
| -F | flush，清空全部 |
| -L | list，列出規則 |
| -P | policy，設定預設策略 |

### 動作

| 動作 | 說明 |
|------|------|
| ACCEPT | 放行 |
| DROP | 丟棄（不回應） |
| REJECT | 拒絕（回應錯誤） |
| DNAT | 目標位址轉換 |
| SNAT | 來源位址轉換 |

### 條件

| 旗標 | 說明 |
|------|------|
| -p tcp/udp/icmp | 協定 |
| --dport 22 | 目的埠 |
| --sport 1234 | 來源埠 |
| -s 192.168.1.0/24 | 來源 IP |
| -d 10.0.0.1 | 目的 IP |
| -i lo | 進入介面（INPUT 用） |
| -o eth0 | 出去介面（OUTPUT 用） |
| -m state --state | 連線狀態 |

### 連線狀態

| 狀態 | 說明 |
|------|------|
| NEW | 新連線 |
| ESTABLISHED | 已建立的連線 |
| RELATED | 相關連線（如 FTP 資料通道） |

## 歷屆考法

```bash
# 擋 ping
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# 擋特定 IP
iptables -A INPUT -s 10.0.0.100 -j DROP

# 放行特定網段的 SSH
iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT
```

## 查看 / 管理

```bash
iptables -L -n -v              # 查看 filter
iptables -t nat -L -n -v       # 查看 NAT
iptables -F                    # 清空 filter
iptables -t nat -F             # 清空 NAT
iptables -P INPUT ACCEPT       # 重設預設（解鎖自己）
```

## 速解（順序重要！）

```bash
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -P INPUT DROP
```

## 易錯

1. **先 DROP 再加規則** → 鎖死自己，一定最後才 `-P INPUT DROP`
2. **忘記 ESTABLISHED** → 回應封包被擋，連線斷掉
3. **忘記 loopback** → 本機服務（MySQL、PHP）壞掉
4. **DNAT 只加 PREROUTING** → 外部能連，本機 curl 連不到

---

# 題 6 — Cron 任務安全

## 原理

排程腳本 777 → 任何人可修改 → 植入惡意指令
設定檔 666 → 任何人可修改 → 新增排程任務

## 延伸：crontab 語法

```
分 時 日 月 星期 指令
*  *  *  *  *    /path/to/script.sh

0 3 * * *   /opt/backup.sh      # 每天凌晨 3 點
*/5 * * * * /opt/monitor.sh     # 每 5 分鐘
```

```bash
crontab -l              # 列出排程
crontab -e              # 編輯
crontab -l -u admin     # 看別人的
cat /etc/crontab        # 系統排程
ls /etc/cron.d/         # 額外排程
ls /etc/cron.daily/     # 每日執行
```

## 延伸：限制誰可以用 cron

```
/etc/cron.allow    # 白名單（存在時只有列出的人可用）
/etc/cron.deny     # 黑名單
```

## 速解

```bash
chmod 755 /etc/cron.hourly/backup.sh
chmod 644 /etc/cron.d/backup
```

---

# 題 7 — SUID/SGID 稽核

## 原理

SUID = 執行時以**檔案擁有者**身份運行。不該有 SUID 的程式被設了 → 提權。

## 找出 SUID/SGID 檔案

```bash
find / -perm -4000 -type f 2>/dev/null                           # SUID
find / -perm -2000 -type f 2>/dev/null                           # SGID
find / \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null     # 兩個一起
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null        # 加詳細資訊
```

## 正常的 SUID（保留）

| 路徑 | 用途 |
|------|------|
| `/usr/bin/passwd` | 改密碼（需寫 /etc/shadow） |
| `/usr/bin/su` | 切換使用者 |
| `/usr/bin/sudo` | 提權執行 |
| `/usr/bin/chfn` | 改使用者資訊 |
| `/usr/bin/chsh` | 改預設 shell |
| `/usr/bin/newgrp` | 切換群組 |
| `/usr/bin/gpasswd` | 群組密碼管理 |
| `/usr/bin/mount` | 掛載 |
| `/usr/bin/umount` | 卸載 |
| `/usr/bin/ping` | 發 ICMP |

## 危險的 SUID（移除）— GTFOBins

| 程式 | 提權方式 |
|------|----------|
| `find` | `find . -exec /bin/sh \;` |
| `vim` / `vi` | `:!/bin/sh` |
| `python` | `python -c 'import os; os.system("/bin/sh")'` |
| `bash` | `bash -p` |
| `nmap`（舊版） | `nmap --interactive` → `!sh` |
| `cp` | 覆寫 `/etc/passwd` 或 `/etc/shadow` |
| `less` / `more` | `!/bin/sh` |
| `awk` | `awk 'BEGIN {system("/bin/sh")}'` |
| `env` | `env /bin/sh` |
| `perl` | `perl -e 'exec "/bin/sh"'` |

參考：https://gtfobins.github.io/

## SGID 在目錄上的用法

```bash
mkdir /opt/project
chgrp devteam /opt/project
chmod 2775 /opt/project
# 新檔案自動屬於 devteam 群組
```

## 延伸：Capabilities（SUID 替代方案）

```bash
getcap -r / 2>/dev/null              # 找所有有 capabilities 的檔案
getcap /usr/bin/ping                 # 查看特定檔案
setcap cap_net_raw=ep /usr/bin/ping  # 設定
setcap -r /usr/bin/ping              # 移除
```

| Capability | 用途 |
|------------|------|
| `cap_net_raw` | 發送 raw packet（ping） |
| `cap_net_bind_service` | 綁定 1024 以下的 port |
| `cap_dac_override` | 跳過檔案權限檢查（危險） |
| `cap_setuid` | 切換 UID（等於 SUID，危險） |

## 自動化稽核腳本

```bash
#!/bin/bash
known_suid=(/usr/bin/passwd /usr/bin/su /usr/bin/sudo /usr/bin/chfn
             /usr/bin/chsh /usr/bin/newgrp /usr/bin/gpasswd
             /usr/bin/mount /usr/bin/umount)

echo "=== 異常 SUID 檔案 ==="
while IFS= read -r f; do
    if [[ ! " ${known_suid[*]} " =~ " $f " ]]; then
        ls -la "$f"
    fi
done < <(find / -perm -4000 -type f 2>/dev/null)
```

## 速解

```bash
find / -perm -4000 -type f 2>/dev/null
chmod u-s /usr/local/bin/vuln_tool
```

## 易錯

1. **移除 `/usr/bin/passwd` 的 SUID** → 一般使用者無法改密碼
2. **移除 `/usr/bin/sudo` 的 SUID** → sudo 壞掉
3. **只看 SUID 忘記 SGID** → SGID 也可能被利用
4. **忘記看 capabilities** → `getcap` 也要檢查

---

# 題 8 — 系統日誌配置（rsyslog）

## 重要日誌檔

| 檔案 | 內容 |
|------|------|
| `/var/log/auth.log` | 認證事件（登入、sudo、SSH） |
| `/var/log/syslog` | 系統通用訊息 |
| `/var/log/kern.log` | 核心訊息 |
| `/var/log/apache2/access.log` | Web 存取 |
| `/var/log/apache2/error.log` | Web 錯誤 |
| `/var/log/cron.log` | 排程執行紀錄 |
| `/var/log/wtmp` | 登入登出（二進位，用 `last` 讀） |
| `/var/log/btmp` | 登入失敗（二進位，用 `lastb` 讀） |

## 設定檔

```
/etc/rsyslog.conf           # 主設定
/etc/rsyslog.d/*.conf       # 額外設定
```

## 語法

```
facility.priority    action
```

### facility（來源）

| 值 | 說明 |
|----|------|
| auth, authpriv | 認證相關 |
| kern | 核心 |
| mail | 郵件 |
| cron | 排程 |
| daemon | 背景服務 |
| local0-local7 | 自訂 |
| * | 所有 |

### priority（嚴重度，低→高）

debug → info → notice → warning → err → crit → alert → emerg

### 範例

```bash
auth,authpriv.*    /var/log/auth.log     # 認證事件
kern.*             /var/log/kern.log     # 核心
*.*                @192.168.1.100:514    # 轉發遠端（UDP，單 @）
*.*                @@192.168.1.100:514   # 轉發遠端（TCP，雙 @@）
```

## 延伸：手動寫入日誌

```bash
logger "Test message"
logger -p auth.warning "Suspicious login attempt"
logger -t myapp "Application started"
```

## 延伸：journalctl（systemd）

```bash
journalctl -u sshd                  # 特定服務
journalctl -f                       # 即時追蹤
journalctl --since "1 hour ago"     # 時間範圍
journalctl -p err                   # 只看 error 以上
journalctl _UID=1000                # 特定使用者
```

## 延伸：logrotate

```
/var/log/auth.log {
    weekly          # 每週輪替
    rotate 12       # 保留 12 份
    compress        # gzip 壓縮
    missingok       # 檔案不存在不報錯
    notifempty      # 空檔不輪替
}
```

```bash
logrotate -d /etc/logrotate.conf    # dry run
logrotate -f /etc/logrotate.conf    # 強制執行
```

## 速解

```bash
sed -i 's/^#\(auth,authpriv.*\)/\1/' /etc/rsyslog.conf
grep -q 'auth,authpriv' /etc/rsyslog.conf || \
    echo 'auth,authpriv.*    /var/log/auth.log' >> /etc/rsyslog.conf
service rsyslog restart
```

## 易錯

1. **auth.log 那行被註解** → 取消 `#` 就好
2. **改完沒重啟 rsyslog** → 不生效
3. **日誌檔權限太鬆** → `/var/log/auth.log` 應 640
4. **facility 拼錯** → `authpriv` 不是 `auth_priv`
5. **`@` vs `@@`** → 單 @ 是 UDP，雙 @@ 是 TCP

---

# 題 9 — 不必要服務移除

## 找出運行中的服務

```bash
ss -tlnp       # TCP listening
ss -ulnp       # UDP listening
ps aux          # 所有程序
systemctl list-units --type=service --state=running
```

## 常見不安全服務

| 服務 | port | 風險 | 替代 |
|------|------|------|------|
| FTP (vsftpd) | 21 | 明文傳帳密 | SFTP |
| Telnet | 23 | 明文傳一切 | SSH |
| rsh/rlogin | 513/514 | 無加密無認證 | SSH |
| TFTP | 69 | 無認證 | SFTP |
| finger | 79 | 洩漏使用者資訊 | 移除 |
| SNMP v1/v2 | 161 | community string 明文 | v3 或移除 |
| rpcbind | 111 | NFS/NIS 相關 | 移除 |

## 停止與移除

```bash
pkill vsftpd                    # 臨時停止
systemctl stop vsftpd           # systemd 停止
systemctl disable vsftpd        # 開機不啟動
systemctl mask vsftpd           # 完全遮蔽
apt purge vsftpd                # 連設定檔刪除
```

## 延伸：常見 port

| port | 服務 | port | 服務 |
|------|------|------|------|
| 21 | FTP | 443 | HTTPS |
| 22 | SSH | 445 | SMB |
| 25 | SMTP | 3306 | MySQL |
| 53 | DNS | 5432 | PostgreSQL |
| 80 | HTTP | 6379 | Redis |

## 速解

```bash
ss -tlnp
pkill vsftpd
pgrep vsftpd && echo "還在" || echo "已停"
ss -tlnp | grep :21
```

## 易錯

1. **只 kill 沒 disable** → 重啟後又跑
2. **忘記檢查 UDP** → `ss -ulnp` 也要看
3. **`0.0.0.0` vs `127.0.0.1`** → 前者對外開放

---

# 題 10 — 密碼策略強化（PAM）

## PAM 是什麼

PAM（Pluggable Authentication Modules）= 可插拔認證模組

```
login / sshd / sudo → PAM → 各種模組（密碼檢查、鎖定、MFA…）
```

## 設定檔位置

```
/etc/pam.d/common-auth          # 認證（驗密碼）
/etc/pam.d/common-password      # 改密碼時的規則
/etc/pam.d/common-account       # 帳號狀態檢查
/etc/pam.d/common-session       # 登入/登出
/etc/pam.d/sshd                 # SSH 專用
/etc/pam.d/sudo                 # sudo 專用
```

## PAM 語法

```
type    control    module    [options]
```

### type

| 類型 | 時機 |
|------|------|
| auth | 驗證身份（密碼、MFA） |
| account | 帳號狀態（過期、鎖定） |
| password | 改密碼時（密碼策略） |
| session | 登入/登出前後 |

### control

| 值 | 說明 |
|----|------|
| required | 必須通過，繼續檢查其他（失敗不立即回報） |
| requisite | 必須通過，失敗立即回報 |
| sufficient | 通過就直接成功 |
| optional | 可選 |
| include | 引入另一個檔案 |

## pam_pwquality 參數

編輯 `/etc/pam.d/common-password`：

```
password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1
```

| 參數 | 說明 |
|------|------|
| `minlen=12` | 最少 12 字元 |
| `ucredit=-1` | 至少 1 個大寫 |
| `lcredit=-1` | 至少 1 個小寫 |
| `dcredit=-1` | 至少 1 個數字 |
| `ocredit=-1` | 至少 1 個特殊字元 |
| `retry=3` | 可重試 3 次 |
| `difok=5` | 新舊密碼至少 5 字元不同 |
| `maxrepeat=3` | 同一字元最多連續 3 次 |
| `reject_username` | 密碼不能含帳號名 |
| `enforce_for_root` | root 也要遵守 |

也可以寫在：`/etc/security/pwquality.conf`

## 密碼有效期（/etc/login.defs）

```
PASS_MAX_DAYS   90     # 最長有效天數
PASS_MIN_DAYS   7      # 最短幾天才能改
PASS_WARN_AGE   14     # 到期前幾天警告
PASS_MIN_LEN    12     # 最短長度
```

注意：`login.defs` 只影響**新帳號**，現有帳號用 `chage`：

```bash
chage -M 90 -m 7 -W 14 admin
chage -l admin          # 查看
```

## 延伸：其他 PAM 模組

| 模組 | 用途 |
|------|------|
| `pam_unix.so` | 標準 Unix 密碼認證 |
| `pam_pwquality.so` | 密碼複雜度 |
| `pam_faillock.so` | 登入失敗鎖定 |
| `pam_limits.so` | 資源限制（ulimit） |
| `pam_access.so` | IP/使用者存取控制 |
| `pam_time.so` | 時間存取控制 |
| `pam_wheel.so` | 限制 wheel 群組才可 su |
| `pam_google_authenticator.so` | TOTP 二步驟驗證 |
| `pam_nologin.so` | `/etc/nologin` 存在時禁止非 root |

## 延伸：限制 su 只有 wheel 群組

`/etc/pam.d/su`：

```
auth required pam_wheel.so
```

```bash
usermod -aG wheel admin
```

## 延伸：資源限制（pam_limits）

`/etc/security/limits.conf`：

```
*     hard    nofile    65535
admin soft    nproc     1024
```

## 延伸：IP 存取控制（pam_access）

`/etc/security/access.conf`：

```
+:admin:192.168.1.0/24
-:ALL:ALL
```

## 速解

```bash
sed -i '/pam_pwquality/s/$/ minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' \
    /etc/pam.d/common-password
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
```

## 易錯

1. **pam_pwquality 那行已經有參數** → append 不是覆蓋，小心重複
2. **credit 正負號** → `-1`=至少 1 個，`+1`=最多給 1 分（意義相反！）
3. **策略只在改密碼時檢查** → 不影響現有密碼
4. **PAM 設定搞壞** → 可能連 root 都登不進去，改之前先備份

---

# 題 11 — sysctl 核心安全參數

## 設定檔

```
/etc/sysctl.d/99-hardening.conf
```

## 參數

```bash
net.ipv4.ip_forward = 0                    # 不當路由器轉發封包
net.ipv4.conf.all.accept_redirects = 0     # 不接受 ICMP 重導向（防 MITM）
net.ipv4.conf.all.send_redirects = 0       # 不發送 ICMP 重導向
net.ipv4.conf.all.accept_source_route = 0  # 不接受來源路由（防偽造路徑）
kernel.randomize_va_space = 2              # 完整 ASLR，防記憶體攻擊
net.ipv4.icmp_echo_ignore_broadcasts = 1   # 忽略廣播 ping（防 Smurf）
fs.protected_hardlinks = 1                 # 防硬連結攻擊
fs.protected_symlinks = 1                  # 防符號連結攻擊
```

## 套用

```bash
sysctl -p /etc/sysctl.d/99-hardening.conf    # 載入特定檔案
sysctl --system                               # 載入全部
sysctl -a | grep ip_forward                   # 查看目前值
```

## 延伸：其他有用參數

```bash
net.ipv4.tcp_syncookies = 1                # 防 SYN flood
net.ipv4.conf.all.log_martians = 1         # 記錄異常封包
net.ipv4.conf.default.rp_filter = 1        # 反向路徑過濾
kernel.dmesg_restrict = 1                  # 限制 dmesg 只有 root 可看
kernel.kptr_restrict = 2                   # 隱藏核心指標位址
```

## 易錯

1. **寫完沒 `sysctl -p`** → 不生效
2. **`ip_forward = 0` 影響 Docker** → Docker 需要 ip_forward = 1

---

# 題 12 — PAM 登入失敗鎖定

## 設定檔

```
/etc/security/faillock.conf
```

## 參數

```
deny = 5              # 連續 5 次失敗鎖定
unlock_time = 900     # 鎖定 900 秒（15 分鐘），0 = 永久
fail_interval = 900   # 在 900 秒內計算失敗次數
even_deny_root = no   # root 是否也被鎖定
```

## PAM 設定（/etc/pam.d/common-auth 需要有）

```
auth required pam_faillock.so preauth
auth [default=die] pam_faillock.so authfail
```

## 管理鎖定

```bash
faillock --user admin           # 查看失敗紀錄
faillock --user admin --reset   # 手動解鎖
faillock                        # 查看所有帳號
```

## 舊版系統用 pam_tally2

```bash
pam_tally2 --user admin            # 查看
pam_tally2 --user admin --reset    # 重置
```

## 速解

```bash
cat > /etc/security/faillock.conf << 'EOF'
deny = 5
unlock_time = 900
EOF
```

## 易錯

1. **faillock.conf 不存在** → 自己建立
2. **忘記確認 pam_faillock 有沒有載入** → common-auth 要有

---

# 題 13 — sudoers NOPASSWD 風險

## 問題

```bash
cat /etc/sudoers.d/deploy
# deploy ALL=(ALL) NOPASSWD: ALL  ← 免密碼的完整 root 權限
```

## 延伸：sudoers 語法

```
使用者 主機=(身份) 指令
admin    ALL=(ALL) ALL                  # 需密碼，可執行所有指令
deploy   ALL=(ALL) NOPASSWD: ALL        # 免密碼（危險！）
webadmin ALL=(ALL) /usr/bin/find        # 只能 sudo find
%devteam ALL=(ALL) /usr/bin/docker      # 群組寫法用 %
```

## 速解

```bash
rm /etc/sudoers.d/deploy
```

## 易錯

1. **用 `visudo` 檢查語法** → 改壞 sudoers 會鎖死 sudo
2. **sudoers.d 裡的檔案權限必須 440**

---

# 題 14 — SSH 停用密碼認證

## 設定

編輯 `/etc/ssh/sshd_config`：

```
PasswordAuthentication no
PubkeyAuthentication yes
```

## 速解

```bash
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
kill -HUP $(cat /var/run/sshd.pid)
```

## 易錯

- 停用密碼認證前沒部署公鑰 → 鎖死自己（競賽環境用 docker exec 救）

---

# 題 15 — 空密碼帳號鎖定

## 找出空密碼帳號

```bash
awk -F: '($2==""){print $1}' /etc/shadow
```

## 鎖定

```bash
passwd -l ghost       # 鎖定（hash 前加 !）
passwd -l phantom
```

## 查看狀態

```bash
passwd -S ghost       # L=locked, P=有密碼, NP=無密碼
```

## 其他鎖定方式

```bash
usermod -L ghost                           # 等同 passwd -l
usermod -s /usr/sbin/nologin ghost         # 改 shell
chage -E 0 ghost                           # 設帳號過期
```

## 速解

```bash
awk -F: '($2==""){print $1}' /etc/shadow | while read u; do passwd -l "$u"; done
```

## 易錯

1. **空密碼 ≠ 鎖定** → 空密碼是 shadow 第二欄為空，鎖定是有 `!`
2. **passwd -l 不是刪除帳號** → 只是在 hash 前加 `!`

---

# 題 16 — ACL 存取控制（setfacl）

## 基本語法

```bash
setfacl -m u:username:rwx file       # 給特定使用者權限
setfacl -m g:groupname:rx file       # 給特定群組權限
setfacl -x u:username file           # 移除特定使用者 ACL
setfacl -b file                      # 移除所有 ACL
setfacl -R -m u:username:rx /dir     # 遞迴套用
setfacl -d -m u:username:rx /dir     # 預設 ACL（新檔案繼承）
```

## 查看

```bash
getfacl /usr/bin/find
```

## ACL vs chmod

- chmod：只能設 owner / group / others 三組
- ACL：可以針對**任意**使用者或群組設定不同權限
- `ls -la` 看到 `+` 表示有 ACL：`-rwxr-x---+`

## mask（有效權限上限）

```bash
setfacl -m m::rx file
```

mask 限制所有 ACL 條目的最大權限。即使設了 `u:bob:rwx`，如果 mask 是 `r-x`，bob 實際只有 `r-x`。

## 歷屆考法

```bash
# 53屆：限制 webadmin 執行 ssh
setfacl -m u:webadmin:r-- /usr/bin/ssh

# 54屆：限制 IT 群組執行 find
setfacl -m g:it:r-- /usr/bin/find
```

## 速解

```bash
setfacl -m g:it:r-- /usr/bin/find
getfacl /usr/bin/find
su -s /bin/bash svcuser -c "find /tmp"  # 應被拒絕
```

## 易錯

1. **`r--` 沒有 `x`** → 不能執行程式，正是我們要的
2. **忘記看 mask** → 可能限制了你設的權限

---

# 題 17 — sudo 最小授權

## 建立 sudoers 檔案

```bash
echo 'webadmin ALL=(ALL) /usr/bin/find' > /etc/sudoers.d/webadmin
chmod 440 /etc/sudoers.d/webadmin
```

## 驗證

```bash
sudo -l -U webadmin
```

## 延伸：更細緻的限制

```bash
# 限制參數
webadmin ALL=(ALL) /usr/bin/find /var/log -name *.log

# 多個指令
webadmin ALL=(ALL) /usr/bin/find, /usr/bin/cat

# 指定以誰的身份
webadmin ALL=(ALL:ALL) /usr/bin/find
```

## 易錯

1. **不能用 NOPASSWD**（需驗證身份）
2. **不能授權 ALL**（只限特定指令）
3. **權限不是 440** → sudo 會拒絕載入

---

# 題 18 — 家目錄權限

## 速解

```bash
chmod 700 /home/*
```

`700` = `rwx------` = 只有擁有者可讀寫執行。

## 延伸：useradd 預設

```bash
# /etc/login.defs
UMASK 077

# /etc/adduser.conf（Debian）
DIR_MODE=0700
```

---

# 題 19 — HTTPS 與強制重導向（OpenSSL + Apache）

## 產生自簽憑證

```bash
openssl req -x509 -newkey rsa:2048 \
    -keyout /etc/ssl/private/server.key \
    -out /etc/ssl/certs/server.crt \
    -days 365 -nodes \
    -subj '/CN=localhost'
```

| 參數 | 說明 |
|------|------|
| `-x509` | 產生自簽憑證（不送 CA） |
| `-newkey rsa:2048` | 產生 RSA 2048 bits 新私鑰 |
| `-keyout` | 私鑰存到哪（不能外洩） |
| `-out` | 憑證存到哪（公開的） |
| `-days 365` | 有效期 365 天 |
| `-nodes` | 私鑰不加密（no DES），Apache 不用手動輸密碼 |
| `-subj '/CN=localhost'` | 憑證資訊，CN = Common Name |

## 查看憑證

```bash
openssl x509 -in /etc/ssl/certs/server.crt -text -noout
openssl x509 -in /etc/ssl/certs/server.crt -text -noout | grep "Public-Key"
```

## Apache 設定

```bash
# 1. 啟用 SSL 模組
a2enmod ssl

# 2. HTTPS VirtualHost
cat > /etc/apache2/sites-available/default-ssl.conf << 'EOF'
<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile    /etc/ssl/certs/server.crt
    SSLCertificateKeyFile /etc/ssl/private/server.key
    DocumentRoot /var/www/html
</VirtualHost>
EOF

# 3. 啟用站台
a2ensite default-ssl

# 4. HTTP 重導向至 HTTPS
sed -i '/<VirtualHost \*:80>/a\    Redirect permanent / https://localhost/' \
    /etc/apache2/sites-available/000-default.conf

# 5. 重啟
service apache2 restart
```

## 驗證

```bash
ss -tlnp | grep 443
curl -k https://localhost/
curl -sI http://localhost/ | head -5    # 應回 301
```

## 易錯

1. **忘記 `-nodes`** → 產生憑證時要求輸密碼，Apache 每次重啟也要輸
2. **憑證路徑錯** → `default-ssl.conf` 預設指向 `snakeoil.pem`，要改成你的
3. **忘記 `a2enmod ssl`** → Apache 不認識 SSLEngine
4. **忘記 `a2ensite default-ssl`** → 443 不會聽
5. **Redirect 加錯位置** → 要在 `*:80` 裡面，不是 `*:443`
6. **混用 `-Indexes` 和 `FollowSymLinks`** → `Options` 要嘛都帶符號要嘛都不帶

---

# 題 20 — iptables 連接埠轉發（DNAT）

## 將 9090 轉發到 80

```bash
iptables -t nat -A PREROUTING -p tcp --dport 9090 -j DNAT --to-destination 127.0.0.1:80
iptables -t nat -A OUTPUT -p tcp --dport 9090 -j DNAT --to-destination 127.0.0.1:80
```

## 驗證

```bash
iptables -t nat -L -n -v
curl http://localhost:9090/
```

## 延伸：其他 NAT 用法

```bash
# SNAT（偽裝來源 IP，常用於 NAT 閘道）
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# port forwarding 到另一台機器
iptables -t nat -A PREROUTING -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.100:80
```

## 易錯

- 只加 PREROUTING → 外部能連，本機 curl 連不到（要加 OUTPUT）

---

# 題 21 — PHP 安全設定

## 找 php.ini

```bash
php -r "echo php_ini_loaded_file();"
```

## 修改

```ini
expose_php = Off                # 不洩漏 PHP 版本（X-Powered-By）
display_errors = Off            # 不顯示錯誤細節（防洩漏路徑、SQL）
allow_url_include = Off         # 禁止遠端檔案引入（防 RFI）
disable_functions = system,exec,passthru,shell_exec,popen,proc_open
```

## disable_functions 常見危險函數

| 函數 | 風險 |
|------|------|
| `system()` | 執行 OS 指令 |
| `exec()` | 執行 OS 指令 |
| `passthru()` | 執行 OS 指令（直接輸出） |
| `shell_exec()` | 執行 OS 指令（等同反引號） |
| `popen()` | 開啟程序管道 |
| `proc_open()` | 開啟程序 |
| `eval()` | **無法**用 disable_functions 停用（語言結構） |
| `assert()` | 可以執行程式碼 |

## 延伸：其他 php.ini 安全設定

```ini
open_basedir = /var/www/html/        # 限制 PHP 可存取的路徑
session.cookie_httponly = 1          # cookie 不能被 JS 讀取（防 XSS）
session.cookie_secure = 1           # cookie 只在 HTTPS 傳送
file_uploads = On
upload_max_filesize = 2M
post_max_size = 8M
```

## 速解

```bash
PHP_INI=$(php -r "echo php_ini_loaded_file();")
sed -i 's/^expose_php.*/expose_php = Off/' "$PHP_INI"
sed -i 's/^display_errors.*/display_errors = Off/' "$PHP_INI"
sed -i 's/^allow_url_include.*/allow_url_include = Off/' "$PHP_INI"
sed -i 's/^disable_functions.*/disable_functions = system,exec,passthru,shell_exec,popen,proc_open/' "$PHP_INI"
service apache2 restart
```

## 易錯

1. **改完沒重啟 Apache** → 不生效
2. **`eval()` 不能用 disable_functions 停** → 它是語言結構不是函數

---

# 題 22 — Apache 目錄列表防護

## 問題

`Options Indexes` → 瀏覽目錄結構洩漏檔案清單

## 修復

編輯 `/etc/apache2/apache2.conf`：

```apache
<Directory /var/www/html/data>
    Options -Indexes
</Directory>
```

## 延伸：其他 Apache 安全設定

```apache
# 隱藏版本號
ServerTokens Prod
ServerSignature Off

# 停用不需要的 HTTP 方法
<Directory /var/www/html>
    <LimitExcept GET POST>
        Require all denied
    </LimitExcept>
</Directory>

# 安全 header
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
```

## 速解

```bash
sed -i 's/Options Indexes/Options -Indexes/g' /etc/apache2/apache2.conf
service apache2 restart
```

## 易錯

1. **混用 `+`/`-` 和不帶符號** → `Options` 要嘛都帶符號要嘛都不帶
2. **改錯 Directory 區段** → 確認路徑對

---

# 題 23 — Nginx 安全配置

## 設定檔

```
/etc/nginx/sites-available/vulnerable
```

## 修復 alias 路徑穿越

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

原理：`/secret` 沒尾斜線 → `/secret../etc/passwd` → alias 拼成 `/var/www/nginx/../etc/passwd` → 路徑穿越

## 停用 autoindex

```nginx
autoindex off;    # 把所有 on 改成 off
```

## 延伸：其他 Nginx 安全設定

```nginx
# 隱藏版本號
server_tokens off;

# 限制請求大小
client_max_body_size 10m;

# 安全 header
add_header X-Frame-Options "SAMEORIGIN";
add_header X-Content-Type-Options "nosniff";
add_header X-XSS-Protection "1; mode=block";

# 限制 HTTP 方法
if ($request_method !~ ^(GET|POST|HEAD)$) {
    return 405;
}

# 禁止存取隱藏檔
location ~ /\. {
    deny all;
}
```

## 重載

```bash
nginx -t            # 測試語法
nginx -s reload     # 重載
```

## 速解

```bash
sed -i 's|location /secret {|location /secret/ {|' /etc/nginx/sites-available/vulnerable
sed -i 's/autoindex on/autoindex off/g' /etc/nginx/sites-available/vulnerable
nginx -s reload
```

## 易錯

1. **alias 和 location 尾斜線要匹配** → 兩個都要有 `/`
2. **`nginx -t` 先測語法再 reload** → 語法錯 nginx 會掛掉
