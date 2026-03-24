# Windows Server / AD 安全強化題單

> 歷屆考過 + 預測可能出的題目，依優先度排序

---

## 一、歷屆確定考過的（必練）

### 1. 密碼策略（每年都考）

`gpedit.msc` → 電腦設定 → Windows 設定 → 安全性設定 → 帳戶原則 → 密碼原則

| 項目 | 53屆設定 | 建議值 |
|------|----------|--------|
| 密碼必須符合複雜性需求 | 已啟用 | 已啟用 |
| 密碼最長使用期限 | 90 天 | 60-90 天 |
| 密碼最短使用期限 | 0 天 | 1 天 |
| 強制密碼歷程記錄 | 5 組 | 5-24 組 |
| 密碼最小長度 | 8 字元 | 8-16 字元 |
| 使用可還原加密來存放密碼 | 停用 | 停用 |

```powershell
# 查看目前密碼策略
net accounts
# 或
secedit /export /cfg C:\secpol.cfg
```

### 2. 帳戶鎖定原則（每年都考）

`gpedit.msc` → 帳戶原則 → 帳戶鎖定原則

| 項目 | 53屆設定 | 建議值 |
|------|----------|--------|
| 帳戶鎖定閾值 | 3 次 | 3-5 次 |
| 帳戶鎖定時間 | 60 分鐘 | 30-60 分鐘 |
| 重設帳戶鎖定計數器 | 60 分鐘 | 30-60 分鐘 |

### 3. 安全性選項（53屆考過）

`gpedit.msc` → 本機原則 → 安全性選項

| 項目 | 53屆設定 | 說明 |
|------|----------|------|
| 互動式登入：不要求 CTRL+ALT+DEL | 停用 | 強制安全登入序列 |
| 互動式登入：不要顯示上次使用者名稱 | 停用 | 不洩漏帳號名 |
| 互動式登入：到期前提示變更密碼 | 10 天 | 預先警告 |

### 4. SMB2 安全（53屆、54屆考過）

nmap 掃描發現 "Message signing enabled but not required" → 需修復

```powershell
# 啟用 SMB signing（強制簽名）
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

# 或用群組原則
# gpedit.msc → 本機原則 → 安全性選項
# Microsoft 網路伺服器：數位簽章通訊（自動）→ 已啟用
# Microsoft 網路用戶端：數位簽章通訊（自動）→ 已啟用

# 停用 SMBv1（已知不安全）
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# 驗證
Get-SmbServerConfiguration | Select EnableSMB1Protocol, RequireSecuritySignature
```

### 5. 稽核策略（52屆、55屆考過）

`gpedit.msc` → 本機原則 → 稽核原則

| 項目 | 建議值 |
|------|--------|
| 稽核帳戶登入事件 | 成功、失敗 |
| 稽核帳戶管理 | 成功、失敗 |
| 稽核登入事件 | 成功、失敗 |
| 稽核物件存取 | 成功、失敗 |
| 稽核原則變更 | 成功、失敗 |
| 稽核特殊權限使用 | 成功、失敗 |
| 稽核系統事件 | 成功、失敗 |

```powershell
# 一次全開
auditpol /set /category:* /success:enable /failure:enable

# 查看目前設定
auditpol /get /category:*

# 查看特定事件（52屆考的）
# 事件 4688 = 程序建立
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} | Measure-Object

# 查看登入失敗事件（事件 4625）
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} |
    Where-Object { $_.TimeCreated -ge '2025-03-28' } | Measure-Object
```

### 6. Windows 防火牆（55屆考過）

```powershell
# 啟用所有設定檔的防火牆
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# 預設拒絕入站
Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow

# 允許特定 IP 網段
New-NetFirewallRule -DisplayName "Allow LAN" -Direction Inbound `
    -RemoteAddress 192.168.10.0/24 -Action Allow

# 允許 RDP
New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound `
    -Protocol TCP -LocalPort 3389 -Action Allow

# 擋特定 port
New-NetFirewallRule -DisplayName "Block Telnet" -Direction Inbound `
    -Protocol TCP -LocalPort 23 -Action Block

# 查看規則
Get-NetFirewallRule | Where-Object {$_.Enabled -eq 'True'} |
    Select DisplayName, Direction, Action

# netsh 指令（傳統方式）
netsh advfirewall set allprofiles state on
netsh advfirewall firewall add rule name="Block Telnet" dir=in protocol=tcp localport=23 action=block
netsh advfirewall show allprofiles
```

### 7. Windows Installer 原則（53屆考過）

`gpedit.msc` → 電腦設定 → 系統管理範本 → Windows 元件 → Windows Installer

| 項目 | 設定 |
|------|------|
| 禁止移除更新 | 已啟用 |

### 8. 權限配置（55屆考過）

```powershell
# 查看資料夾權限
icacls C:\path\to\folder

# 設定權限（移除 Everyone）
icacls C:\sensitive /remove Everyone
icacls C:\sensitive /grant Administrators:F
icacls C:\sensitive /grant "Domain Admins":F

# 移除繼承
icacls C:\sensitive /inheritance:r

# 使用者權限指派
# gpedit.msc → 本機原則 → 使用者權限指派
# 從網路存取這台電腦 → 只留必要群組
# 拒絕從網路存取這台電腦 → 加入 Guest
```

---

## 二、高機率會考的（強烈建議練）

### 9. 遠端桌面安全（54屆考過「遠端連線服務安全強化」）

```powershell
# 啟用 NLA（網路等級驗證）
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name UserAuthentication -Value 1

# 設定加密層級為 High
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name MinEncryptionLevel -Value 3

# 限制誰可以 RDP
# gpedit.msc → 使用者權限指派 → 允許透過遠端桌面服務登入
# 只留 Remote Desktop Users 群組

# 限制空白密碼
# gpedit.msc → 安全性選項 → 帳戶：限制使用空白密碼的本機帳戶僅能從主控台登入 → 已啟用

# 設定閒置斷線時間
# gpedit.msc → 電腦設定 → 系統管理範本 → Windows 元件 → 遠端桌面服務 → 工作階段時間限制
# 設定中斷工作階段的時間限制 → 已啟用，30 分鐘
```

### 10. 事件記錄檔設定（54屆考過「稽核日誌安全強化」）

```powershell
# 設定事件記錄檔大小
wevtutil sl Security /ms:209715200       # 200MB
wevtutil sl Application /ms:104857600    # 100MB
wevtutil sl System /ms:104857600         # 100MB

# 設定不覆寫（滿了就封存）
wevtutil sl Security /rt:false /ab:true

# 或用群組原則
# gpedit.msc → 電腦設定 → 系統管理範本 → Windows 元件 → 事件記錄服務
# 安全性 → 指定記錄檔大小上限 → 已啟用 → 200000 KB
# 安全性 → 記錄檔滿時的行為 → 封存記錄檔但不覆寫事件

# 限制事件記錄檔存取
# 預設只有 Administrators 和 Event Log Readers 群組可讀 Security log
```

### 11. AD 帳號管理

```powershell
# 停用 Guest 帳號
Disable-LocalUser -Name Guest
# 或 AD 環境
Disable-ADAccount -Identity Guest

# 重新命名 Administrator
Rename-LocalUser -Name Administrator -NewName SecAdmin
# gpedit.msc → 安全性選項 → 帳戶：重新命名系統管理員帳戶

# 查看所有使用者
Get-LocalUser
# AD
Get-ADUser -Filter * | Select Name, Enabled

# 查看 Administrators 群組成員
Get-LocalGroupMember -Group "Administrators"
# AD
Get-ADGroupMember -Identity "Domain Admins"

# 移除不該在 admin 群組的帳號
Remove-LocalGroupMember -Group "Administrators" -Member "baduser"
Remove-ADGroupMember -Identity "Domain Admins" -Members "baduser"

# 建立新使用者
New-ADUser -Name "newadmin" -AccountPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) `
    -Enabled $true -ChangePasswordAtLogon $true
```

### 12. Windows Defender

```powershell
# 確認 Defender 啟用
Get-MpComputerStatus | Select AntivirusEnabled, RealTimeProtectionEnabled

# 啟用即時保護
Set-MpPreference -DisableRealtimeMonitoring $false

# 更新定義檔
Update-MpSignature

# 檢查排除項目（攻擊者可能加了 C:\ 全排除）
Get-MpPreference | Select ExclusionPath, ExclusionExtension, ExclusionProcess

# 移除可疑排除
Remove-MpPreference -ExclusionPath "C:\"

# 全系統掃描
Start-MpScan -ScanType FullScan
```

### 13. 服務管理

```powershell
# 查看運行中的服務
Get-Service | Where-Object {$_.Status -eq 'Running'} | Select Name, DisplayName

# 停用不安全服務
Stop-Service -Name "RemoteRegistry" -Force
Set-Service -Name "RemoteRegistry" -StartupType Disabled

# 常見應停用的服務
$dangerousServices = @(
    "RemoteRegistry",       # 遠端登錄存取
    "TlntSvr",             # Telnet
    "FTPSVC",              # FTP
    "SNMP",                # SNMP
    "SSDPSRV",             # SSDP Discovery
    "upnphost",            # UPnP
    "WMSvc",               # Web Management Service（不需要時）
    "Browser"              # Computer Browser
)
foreach ($svc in $dangerousServices) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled
    }
}
```

---

## 三、中等機率（建議了解操作方式）

### 14. UAC（使用者帳戶控制）

```powershell
# 確認 UAC 啟用
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System |
    Select EnableLUA, ConsentPromptBehaviorAdmin

# 啟用 UAC
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System `
    -Name EnableLUA -Value 1

# 設定 Admin 需同意提示（不是自動提升）
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System `
    -Name ConsentPromptBehaviorAdmin -Value 2
```

### 15. 排程任務稽核

```powershell
# 列出所有排程任務
Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} |
    Select TaskName, TaskPath, State

# 找可疑的排程（非 Microsoft 的）
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\Microsoft\*'} |
    Select TaskName, TaskPath

# 停用可疑排程
Disable-ScheduledTask -TaskName "SuspiciousTask"

# 刪除
Unregister-ScheduledTask -TaskName "SuspiciousTask" -Confirm:$false
```

### 16. 共享資料夾安全

```powershell
# 查看所有共享
Get-SmbShare

# 移除不需要的共享
Remove-SmbShare -Name "BadShare" -Force

# 檢查共享權限
Get-SmbShareAccess -Name "ShareName"

# 設定共享權限
Grant-SmbShareAccess -Name "ShareName" -AccountName "Domain Users" -AccessRight Read -Force
Revoke-SmbShareAccess -Name "ShareName" -AccountName "Everyone" -Force

# 隱藏管理共享（C$, ADMIN$）
# 通常不建議停用，但要確認存取權限
```

### 17. IIS 安全（如果有裝）

```powershell
# 移除不需要的 HTTP 方法
# 在 IIS Manager → Request Filtering → HTTP Verbs → Deny: PUT, DELETE, TRACE

# 移除版本資訊
# web.config:
# <httpRuntime enableVersionHeader="false" />
# <customHeaders><remove name="X-Powered-By" /></customHeaders>

# 停用目錄瀏覽
Set-WebConfigurationProperty -Filter system.webServer/directoryBrowse `
    -Name enabled -Value false -PSPath "IIS:\Sites\Default Web Site"

# 啟用 HTTPS
# 類似 Apache 的做法，需要憑證 + binding
```

### 18. DNS 安全（AD 環境常見）

```powershell
# 停用 DNS 區域轉送（防洩漏所有 DNS 紀錄）
# DNS Manager → Zone → Properties → Zone Transfers → 不允許

# 或 PowerShell
Set-DnsServerPrimaryZone -Name "domain.local" -SecureSecondaries NoTransfer

# 啟用 DNS 記錄
Set-DnsServerDiagnostics -All $true
```

### 19. LDAP 安全（AD 環境）

```powershell
# 強制 LDAP 簽名
# gpedit.msc → 本機原則 → 安全性選項
# 網域控制站：LDAP 伺服器簽署需求 → 需要簽署

# 或登錄檔
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" `
    -Name "LDAPServerIntegrity" -Value 2

# 停用 LDAP 匿名綁定
# 預設 AD 不允許，但要確認
```

### 20. 網路驗證等級（54屆考過）

```powershell
# 設定 LAN Manager 驗證等級
# gpedit.msc → 安全性選項 → 網路安全性：LAN Manager 驗證等級
# 設定為：僅傳送 NTLMv2 回應。拒絕 LM & NTLM

# 登錄檔
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -Value 5
```

---

## 四、低機率但值得了解的

### 21. BitLocker

```powershell
# 啟用 BitLocker
Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 `
    -RecoveryPasswordProtector

# 查看狀態
Get-BitLockerVolume
```

### 22. PowerShell 執行原則

```powershell
# 查看
Get-ExecutionPolicy -List

# 設定（限制未簽名腳本）
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine

# 啟用 PowerShell 腳本日誌
# gpedit.msc → 系統管理範本 → Windows 元件 → Windows PowerShell
# 開啟 PowerShell 指令碼區塊記錄 → 已啟用
# 開啟模組記錄 → 已啟用
```

### 23. WSUS / Windows Update

```powershell
# 檢查更新
Get-WindowsUpdate                              # 需要 PSWindowsUpdate 模組
Install-WindowsUpdate -AcceptAll -AutoReboot   # 安裝全部

# 群組原則設定自動更新
# gpedit.msc → 電腦設定 → 系統管理範本 → Windows 元件 → Windows Update
# 設定自動更新 → 已啟用 → 自動下載並排程安裝
```

### 24. 登錄檔安全

```powershell
# 停用自動執行（防 USB 攻擊）
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -Name NoDriveTypeAutoRun -Value 255

# 停用 LM hash 儲存
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name NoLMHash -Value 1

# 啟用安全登入（CTRL+ALT+DEL）
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name DisableCAD -Value 0
```

### 25. 憑證管理

```powershell
# 查看已儲存的憑證
cmdkey /list

# 刪除可疑憑證
cmdkey /delete:targetname

# 清除已快取的 Kerberos tickets
klist purge
```

---

## 五、工具速查

| 工具 | 用途 |
|------|------|
| `gpedit.msc` | 群組原則編輯器（最常用） |
| `secpol.msc` | 本機安全性原則 |
| `lusrmgr.msc` | 本機使用者和群組 |
| `compmgmt.msc` | 電腦管理 |
| `eventvwr.msc` | 事件檢視器 |
| `services.msc` | 服務管理 |
| `wf.msc` | Windows 防火牆（進階） |
| `diskmgmt.msc` | 磁碟管理 |
| `fsmgmt.msc` | 共享資料夾管理 |
| `taskschd.msc` | 排程任務 |
| `dsa.msc` | AD 使用者和電腦 |
| `gpmc.msc` | 群組原則管理（AD） |
| `dnsmgmt.msc` | DNS 管理 |
| `auditpol` | 稽核原則命令列 |
| `secedit` | 安全設定命令列 |
| `netsh` | 網路/防火牆命令列 |
| `icacls` | 檔案權限命令列 |

---

## 六、PowerShell 速查

```powershell
# 匯出目前安全性設定（可備份比對）
secedit /export /cfg C:\before.cfg

# 比對修改前後
Compare-Object (Get-Content C:\before.cfg) (Get-Content C:\after.cfg)

# 查看所有本機使用者
Get-LocalUser | Select Name, Enabled, PasswordLastSet

# 查看所有群組及成員
Get-LocalGroup | ForEach-Object {
    Write-Host "`n$($_.Name):" -ForegroundColor Cyan
    Get-LocalGroupMember -Group $_.Name | Select Name, ObjectClass
}

# 查看已安裝的功能
Get-WindowsFeature | Where-Object {$_.Installed} | Select Name    # Server
Get-WindowsOptionalFeature -Online | Where-Object {$_.State -eq 'Enabled'}  # Desktop

# 查看 listening ports
Get-NetTCPConnection -State Listen | Select LocalAddress, LocalPort, OwningProcess |
    Sort-Object LocalPort

# 查看啟動項目
Get-CimInstance Win32_StartupCommand | Select Name, Command, Location
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

---

## 七、歷屆 vs 預測對照表

| 主題 | 52 | 53 | 54 | 55 | 預測機率 | 上面編號 |
|------|:--:|:--:|:--:|:--:|:--------:|:--------:|
| 密碼策略 | | ✅ | | ✅ | ★★★★★ | 1 |
| 帳戶鎖定 | | ✅ | | | ★★★★★ | 2 |
| 安全性選項 | | ✅ | | | ★★★★☆ | 3 |
| SMB 安全 | | ✅ | ✅ | | ★★★★☆ | 4 |
| 稽核策略 | ✅ | | | ✅ | ★★★★★ | 5 |
| 防火牆 | | | | ✅ | ★★★★☆ | 6 |
| Windows Installer | | ✅ | | | ★★★☆☆ | 7 |
| 權限配置 | | | | ✅ | ★★★★☆ | 8 |
| 遠端桌面安全 | | | ✅ | | ★★★★☆ | 9 |
| 事件記錄檔 | | | ✅ | | ★★★★☆ | 10 |
| AD 帳號管理 | | | | | ★★★★☆ | 11 |
| Windows Defender | | | | | ★★★☆☆ | 12 |
| 服務管理 | | | | | ★★★☆☆ | 13 |
| UAC | | | | | ★★★☆☆ | 14 |
| 排程任務 | | | | | ★★★☆☆ | 15 |
| 共享資料夾 | | | | | ★★★☆☆ | 16 |
| IIS 安全 | | | | | ★★☆☆☆ | 17 |
| DNS 安全 | | | | | ★★★☆☆ | 18 |
| LDAP 安全 | | | | | ★★★☆☆ | 19 |
| 網路驗證等級 | | | ✅ | | ★★★☆☆ | 20 |
| PowerShell 日誌 | ✅ | | | | ★★★☆☆ | 22 |

### 建議練習順序

**第一輪（必練，歷屆必考）**：1 → 2 → 5 → 6 → 3

**第二輪（高機率）**：4 → 8 → 9 → 10 → 11

**第三輪（補齊）**：12 → 13 → 14 → 15 → 20

**有空再看**：其餘
