# iptables 筆記

## 封包流向

```
封包進來 → PREROUTING → 路由判斷 → INPUT → 本機處理
                                     ↓
                             FORWARD → 轉發
                                     ↓
封包出去 ← POSTROUTING ← OUTPUT ← 本機產生
```

競賽重點：**INPUT**（防火牆）和 **NAT**（轉發）

---

## 語法

```bash
iptables [-t 表] -操作 鏈 [條件] -j 動作
```

### 表（-t）

| 表 | 用途 | 包含的鏈 |
|---|------|---------|
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

### 動作（-j）

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

---

## 題 5 — 防火牆（順序重要！）

```bash
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -P INPUT DROP
```

## 題 20 — DNAT 轉發

```bash
iptables -t nat -A PREROUTING -p tcp --dport 9090 -j DNAT --to-destination 127.0.0.1:80
iptables -t nat -A OUTPUT -p tcp --dport 9090 -j DNAT --to-destination 127.0.0.1:80
```

---

## 歷屆考法

```bash
# 擋 ping
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# 擋特定 IP
iptables -A INPUT -s 10.0.0.100 -j DROP

# 放行特定網段的 SSH
iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 22 -j ACCEPT
```

---

## 查看 / 管理

```bash
iptables -L -n -v              # 查看 filter
iptables -t nat -L -n -v       # 查看 NAT
iptables -F                    # 清空 filter
iptables -t nat -F             # 清空 NAT
iptables -P INPUT ACCEPT       # 重設預設（解鎖自己）
```

---

## 易錯重點

1. **先 DROP 再加規則** → 鎖死自己，一定最後才 `-P INPUT DROP`
2. **忘記 ESTABLISHED** → 回應封包被擋，連線斷掉
3. **忘記 loopback** → 本機服務（MySQL、PHP）壞掉
4. **DNAT 只加 PREROUTING** → 外部能連，本機 curl 連不到
