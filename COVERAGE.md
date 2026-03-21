# 歷屆出題範圍 vs 模擬題對照表

## 一、Linux 安全強化

| 主題 | 2022 (52屆) | 2023 (53屆) | 2024 (54屆) | 2025 (55屆) | 出現次數 | 模擬題 | 關鍵指令/檔案 |
|---|---|---|---|---|---|---|---|
| SSH 配置 | — | 安裝 SSH Server | — | SSH 服務測試 | 2 | 1, 14 | `/etc/ssh/sshd_config` |
| 弱密碼/空密碼 | — | — | — | SSH 弱密碼測試 | 1 | 2, 15 | `passwd`、`/etc/shadow` |
| Web 上傳漏洞 | — | — | — | Web 上傳漏洞 | 1 | 3 | `upload.php`、`.htaccess` |
| 檔案權限 chmod | — | — | 家目錄 drwx------ | 權限設置測試 | 2 | 4, 6, 18 | `chmod`、`ls -la` |
| iptables 防火牆 | — | ping 封鎖 | DNAT 轉發 80port | — | 2 | 5, 20 | `iptables` |
| SUID 稽核 | — | — | — | — | 0 | 7 | `find / -perm -4000`、`chmod u-s` |
| rsyslog 日誌 | — | — | — | — | 0 | 8 | `/etc/rsyslog.conf` |
| 移除服務 | — | — | — | — | 0 | 9 | `pkill`、`ss -tlnp` |
| 密碼策略 PAM | — | — | — | — | 0 | 10, 12 | `/etc/pam.d/common-password`、`/etc/login.defs`、`/etc/security/faillock.conf` |
| sysctl 核心參數 | — | — | — | — | 0 | 11 | `/etc/sysctl.d/99-hardening.conf` |
| sudoers | — | sudo 執行 find（需密碼） | sudo 執行 find（需密碼） | — | 2 | 13, 17 | `visudo -f /etc/sudoers.d/xxx`、`chmod 440` |
| setfacl ACL | — | 限制 webadmin 執行 ssh | 限制 IT 群組執行 find | — | 2 | 16 | `setfacl -m g:it:r-- /usr/bin/find` |
| HTTPS 自簽憑證 | — | RSA 2048 + HTTP→HTTPS 重導向 | — | — | 1 | 19 | `openssl req -x509`、`a2enmod ssl` |
| PHP disable_functions | 停用危險函數（system 等） | — | — | — | 1 | 21 | `php.ini`、`disable_functions` |
| Apache 目錄列表 | IndexOf 目錄洩漏 | — | — | — | 1 | 22 | `Options -Indexes` |
| Nginx 安全 | — | — | — | — | 0 | 23 | `alias` path traversal、`autoindex off` |
| MySQL 權限 | 分離管理員/一般帳號 | — | — | — | 1 | 沒有 | `GRANT`、`REVOKE` |
| 登入 IP 顯示關閉 | — | — | 關閉 /etc/issue IP 顯示 | — | 1 | 沒有 | `echo "" > /etc/issue` |
| 新增使用者 | — | 建立帳號 + SSH 登入 | — | — | 1 | 沒有 | `useradd`、`passwd` |

### 高頻考題（優先準備）

- **每年都考**：SSH 配置、檔案權限
- **連續兩年**：iptables、sudoers、setfacl
- **近年新增**：Web 上傳漏洞、弱密碼/空密碼

---

## 二、記憶體鑑識

| 題型 | 2022 | 2023 | 2024 | 2025 | 出現次數 | Volatility 3 指令 |
|---|---|---|---|---|---|---|
| 作業系統 | ✅ | ✅ | ✅ | ✅ | **4/4** | `windows.info`、`windows.registry.printkey` |
| 惡意程序名稱 | ✅ | ✅ | — | ✅ | **3/4** | `windows.pstree`、`windows.malfind` |
| 電腦名稱/使用者 | ✅ | ✅ | — | ✅ | **3/4** | `windows.envars` grep COMPUTERNAME/USERNAME |
| 惡意伺服器 IP:port | ✅ | ✅ | ✅ | ✅ | **4/4** | `windows.netscan` grep ESTABLISHED |
| 特徵碼 sk54{...} | — | ✅ | ✅ | ✅ | **3/4** | `regexscan.RegExScan --pattern "sk54\{"` |
| 惡意程式參數 | ✅ | — | — | — | 1/4 | `windows.cmdline` |
| 執行惡意程式的使用者 | — | — | ✅ | — | 1/4 | `windows.getsids` |
| 惡意程式路徑 | ✅ | — | — | — | 1/4 | `windows.cmdline`、`windows.filescan` |
| 父程序名稱 | — | — | — | ✅ | 1/4 | `windows.pstree` 看 PPID |

---

## 三、封包鑑識

| 題型 | 2022 | 2023 | 2024 | 2025 | 出現次數 | Wireshark filter |
|---|---|---|---|---|---|---|
| 攻擊來源 IP | — | — | — | ✅ | 1/4 | Statistics → Conversations |
| 攻擊目標 Domain | — | — | — | ✅ | 1/4 | `http.host`、`dns.qry.name` |
| 攻擊手法/弱點類型 | — | — | — | ✅ | 1/4 | `http.request.method == "POST"` → Follow Stream |
| 弱點 URL | — | — | — | ✅ | 1/4 | `http.request.uri` |
| 攻擊套件名稱 | — | ✅ | — | — | 1/4 | User-Agent 欄位 |
| 帳號密碼 | — | ✅ | — | — | 1/4 | Follow TCP Stream |
| C2 伺服器 IP | — | — | ✅ | — | 1/4 | 看異常外連非標準 port |
| 駭客利用的漏洞名稱 | — | — | ✅ | — | 1/4 | 分析攻擊 payload |
| 弱點網頁檔案路徑 | — | — | ✅ | — | 1/4 | `http.request.uri` |

---

## 四、硬碟鑑識（不是每年都考）

| 題型 | 2022 | 2023 | 2024 | 出現次數 | 工具 |
|---|---|---|---|---|---|
| 曾登入的使用者 | — | ✅ | — | 1 | `SAM` hive 或 `last` |
| 電腦名稱 | — | ✅ | ✅ | 2 | Registry `SYSTEM` hive |
| 瀏覽器下載的惡意檔案 | — | ✅ | — | 1 | Browser history |
| 網頁伺服器網域名稱 | — | — | ✅ | 1 | Apache/Nginx config |
| 弱點網頁路徑 | — | — | ✅ | 1 | Web log 或 config |
| 漏洞名稱 | — | — | ✅ | 1 | 分析攻擊痕跡 |
| C2 伺服器 IP | — | — | ✅ | 1 | Network artifacts |
| SHA1 計算 | ✅ | — | — | 1 | `sha1sum`、`certutil -hashfile` |

---

## 五、原始碼分析

| 題型 | 2022 | 2023 | 2024 | 2025 | 說明 |
|---|---|---|---|---|---|
| SQL Injection | — | ✅ | — | ✅ | f-string / 字串拼接 SQL |
| Buffer Overflow | — | — | — | ✅ | `gets()`、`strcpy()` 到小 buffer |
| Insecure Deserialization | — | ✅ | — | — | `pickle.loads()` |
| Signature Confusion | — | ✅ | — | — | HMAC/hash 簽章繞過 |
| JWT 弱點 | — | ✅ | — | — | algorithm confusion |
