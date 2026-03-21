# 數位鑑識模擬練習

## 題組一：封包分析（Task_practice.pcapng）

### 背景說明
某公司的資安監控人員在網路設備上側錄到一段可疑流量，請分析 Task_practice.pcapng 並回答以下問題。

### 試題 1（2 分）
請分析出駭客攻擊的**來源 IP 地址**。

### 試題 2（2 分）
請分析出駭客攻擊的**目標網站網域名稱（Domain Name）**。

### 試題 3（3 分）
請分析出駭客使用的**攻擊工具名稱**（可能不止一個）。

### 試題 4（3 分）
請分析出駭客是利用**哪種弱點**取得主機控制權。

### 試題 5（2 分）
承上題，此弱點在**哪個網址（URL）**。

### 試題 6（3 分）
請從封包中找出駭客竊取的**管理者帳號（username）及密碼（password）**。

### 試題 7（3 分）
請分析出駭客上傳的 **WebShell 檔案名稱及路徑**。

### 試題 8（3 分）
請找出駭客所使用的 **C2（Command and Control）中繼站 IP 地址及連接埠（port）**。

### 試題 9（2 分）
請找出 C2 中繼站的**網域名稱（Domain Name）**。

### 試題 10（4 分）
請找出駭客於攻擊中留下的**特徵碼（格式：sk54{...}）**。

---

## 題組二：記憶體分析

### 推薦練習資源

因為 mem 檔無法從零生成（需要從真實系統擷取），以下是推薦的練習用記憶體映像：

#### 1. MemLabs（GitHub 免費）
- https://github.com/stuxnet999/MemLabs
- Lab1~Lab6，難度遞增
- 每個 lab 都有 flag 要找

#### 2. CyberDefenders（免費註冊）
- https://cyberdefenders.org
- 搜尋 "memory forensics" 或 "volatility"
- 推薦：
  - **Seized** — 基礎記憶體分析
  - **DumpMe** — Windows 記憶體分析
  - **RedLine** — 惡意程式分析

#### 3. Volatility Foundation 官方範例
- https://github.com/volatilityfoundation/volatility3
- wiki 裡有測試用的 memory sample

### 記憶體分析必背指令（歷屆必考）

```bash
# 1. 作業系統（每年必考）
vol3 -f Task01.mem windows.info
vol3 -f Task01.mem windows.registry.printkey --key "Microsoft\Windows NT\CurrentVersion"

# 2. 惡意程序名稱/PID（每年必考）
vol3 -f Task01.mem windows.pslist
vol3 -f Task01.mem windows.pstree
vol3 -f Task01.mem windows.malfind
vol3 -f Task01.mem windows.cmdline

# 3. 電腦名稱/使用者（每年必考）
vol3 -f Task01.mem windows.envars | grep -iE "COMPUTERNAME|USERNAME"
vol3 -f Task01.mem windows.registry.printkey --key "ControlSet001\Control\ComputerName\ComputerName"

# 4. 惡意伺服器 IP:port（每年必考）
vol3 -f Task01.mem windows.netscan
vol3 -f Task01.mem windows.netstat

# 5. 特徵碼 sk54{...}（近3年必考）
# 方法一：YARA
cat > /tmp/flag.yar << 'EOF'
rule find_flag {
    strings:
        $flag = "sk54{" ascii wide
    condition:
        $flag
}
EOF
vol3 -f Task01.mem windows.vadyarascan --yara-file /tmp/flag.yar

# 方法二：strings
strings Task01.mem | grep "sk54{"

# 6. 惡意程式的使用者（2024 考過）
vol3 -f Task01.mem windows.getsids

# 7. 惡意程式路徑/映像檔（2022 考過）
vol3 -f Task01.mem windows.filescan | grep -i "exe\|dll\|tmp"

# 8. 程式參數（2022 考過）
vol3 -f Task01.mem windows.cmdline
```

---

## 封包分析答案

<details>
<summary>點擊展開答案（練習完再看）</summary>

| 題 | 答案 |
|---|------|
| 1 | 攻擊來源 IP: `10.99.88.77` |
| 2 | 目標 Domain: `corp-internal.local` |
| 3 | 攻擊工具: `sqlmap/1.8.2`、`Nikto/2.1.6`（看 User-Agent） |
| 4 | 弱點類型: SQL Injection |
| 5 | 弱點 URL: `/login.php` |
| 6 | 帳號密碼: `admin` / `P@ssw0rd!2025` |
| 7 | WebShell: `/uploads/help.php` |
| 8 | C2 IP:port: `185.199.33.44:4444` |
| 9 | C2 Domain: `update-service.evil.net` |
| 10 | FLAG: `sk54{p4ck3t_f0r3ns1cs_m4st3r_2025}` |

### 解題 Filter 參考

```
# 試題 1：Statistics → Conversations → 看發送最多封包的 IP
# 試題 2：http.host 或 dns.qry.name
# 試題 3：http.request → 看 User-Agent
# 試題 4-5：http.request.method == "POST" → Follow TCP Stream
# 試題 6：Follow TCP Stream 看 UNION SELECT 回傳的資料
# 試題 7：http.request.uri contains "upload" 或 http.request.uri contains ".php?cmd"
# 試題 8-9：dns.qry.name contains "evil" 或 tcp.port == 4444
# 試題 10：Follow TCP Stream 找 sk54{
```

</details>
