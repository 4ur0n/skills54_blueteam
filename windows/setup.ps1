#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Server AD 環境安全錯誤配置腳本 - 藍隊練習用
.DESCRIPTION
    此腳本會故意將 Windows Server AD 環境設為不安全的狀態，
    讓藍隊選手練習找出並修復所有安全性問題。
    涵蓋 WINDOWS_TOPICS.md 中列出的所有 25 個主題。
.NOTES
    作者：藍隊練習用
    用途：僅供比賽練習環境使用，切勿在正式環境執行！
#>

# ============================================================
# 前置檢查：確認以系統管理員身分執行
# ============================================================
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "請以系統管理員身分執行此腳本！(Run as Administrator)"
    exit 1
}

Write-Host "============================================================" -ForegroundColor Red
Write-Host "  Windows Server AD 安全錯誤配置腳本 - 藍隊練習環境" -ForegroundColor Red
Write-Host "  警告：此腳本會故意建立不安全的系統設定！" -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Red
Write-Host ""

# ============================================================
# 備份：匯出目前安全性設定作為還原基準
# ============================================================
Write-Host "[備份] 匯出目前安全性設定到 C:\backup_security.cfg ..." -ForegroundColor Cyan
try {
    secedit /export /cfg C:\backup_security.cfg /quiet
    Write-Host "[備份] 完成！還原指令：secedit /configure /db reset.sdb /cfg C:\backup_security.cfg /areas SECURITYPOLICY" -ForegroundColor Green
} catch {
    Write-Warning "[備份] 匯出安全性設定失敗：$($_.Exception.Message)"
}

# ============================================================
# 建立暫存安全性範本檔案（供 secedit 匯入）
# ============================================================
$secTemplate = @"
[Unicode]
Unicode=yes
[System Access]
; === 題目 1：密碼策略 - 設為不安全 ===
; 密碼最小長度設為 4（應為 8 以上）
MinimumPasswordLength = 4
; 停用密碼複雜性需求（應啟用）
PasswordComplexity = 0
; 密碼最長使用期限設為 0（永不過期，應為 60-90 天）
MaximumPasswordAge = 0
; 密碼最短使用期限設為 0
MinimumPasswordAge = 0
; 強制密碼歷程記錄設為 0（不記錄舊密碼，應至少 5 組）
PasswordHistorySize = 0
; 使用可還原加密存放密碼（明文儲存，極度危險）
ClearTextPassword = 1

; === 題目 2：帳戶鎖定原則 - 停用鎖定 ===
; 帳戶鎖定閾值設為 0（不鎖定，應為 3-5 次）
LockoutBadCount = 0

; === 題目 3：安全性選項 - 不安全設定 ===
; 不要求 CTRL+ALT+DEL（應停用此選項，即要求按 CTRL+ALT+DEL）
EnableGuestAccount = 1

[Registry Values]
; === 題目 3 續：安全性選項 - 不安全的登錄檔設定 ===
; 不要求 CTRL+ALT+DEL（啟用=不要求，應設為 0=停用=要求）
MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD=4,1
; 顯示上次登入的使用者名稱（0=顯示，應設為 1=不顯示）
MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName=4,0
; 密碼到期前提示天數設為 0（不提醒，應為 10-14 天）
MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\PasswordExpiryWarning=4,0
; 允許不需登入即可關機（1=允許，應為 0）
MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon=4,1
; 限制空白密碼帳戶僅從主控台登入（0=不限制，應為 1）
MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse=4,0

; === 題目 4：SMB 安全 - 停用簽章 ===
; Microsoft 網路伺服器：數位簽章通訊（自動）- 停用（應啟用）
MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,0
; Microsoft 網路伺服器：數位簽章通訊（如果用戶端同意）- 停用
MACHINE\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,0
; Microsoft 網路用戶端：數位簽章通訊（自動）- 停用（應啟用）
MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,0
; Microsoft 網路用戶端：數位簽章通訊（如果伺服器同意）- 停用
MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnableSecuritySignature=4,0

; === 題目 19：LDAP 安全 - 不要求簽署 ===
; LDAP 伺服器簽署需求設為 0（無，應為 2=需要簽署）
MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=4,0
; LDAP 用戶端簽署需求設為 0（無，應為 2=需要簽署）
MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,0

; === 題目 20：網路驗證等級 - 設為最不安全 ===
; LAN Manager 驗證等級設為 0（傳送 LM & NTLM 回應，應為 5=僅 NTLMv2，拒絕 LM & NTLM）
MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel=4,0

; === 題目 14：UAC - 停用 ===
; 停用 UAC（0=停用，應為 1=啟用）
MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,0
; UAC 提示行為：不提示（0=不提示，應為 2=同意提示）
MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,0
; UAC：安全桌面上提示（0=停用）
MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=4,0

[Privilege Rights]
; === 題目 8：使用者權限指派 - 設為不安全 ===
; 從網路存取這台電腦：加入 Everyone 和 Guest（應只有 Administrators 和 Authenticated Users）
SeNetworkLogonRight = *S-1-1-0,*S-1-5-32-546
; 允許本機登入：加入 Everyone（應只有 Administrators）
SeInteractiveLogonRight = *S-1-1-0,*S-1-5-32-544
; 不拒絕 Guest 從網路存取（應拒絕 Guest）
; 清空拒絕列表
SeDenyNetworkLogonRight =
SeDenyInteractiveLogonRight =
SeDenyRemoteInteractiveLogonRight =
"@

# ============================================================
# 題目 1-3, 4(部分), 8, 14, 19, 20：套用安全性範本
# ============================================================
Write-Host ""
Write-Host "[題目 1] 密碼策略 - 設為不安全（最小長度 4、無複雜性、永不過期、無歷程記錄）..." -ForegroundColor Yellow
Write-Host "[題目 2] 帳戶鎖定原則 - 停用鎖定（閾值 0）..." -ForegroundColor Yellow
Write-Host "[題目 3] 安全性選項 - 不安全設定（不要求 CTRL+ALT+DEL、顯示上次使用者名稱等）..." -ForegroundColor Yellow
Write-Host "[題目 4] SMB 安全 - 停用數位簽章..." -ForegroundColor Yellow
Write-Host "[題目 8] 權限配置 - 不安全的使用者權限指派..." -ForegroundColor Yellow
Write-Host "[題目 14] UAC - 停用使用者帳戶控制..." -ForegroundColor Yellow
Write-Host "[題目 19] LDAP 安全 - 停用簽署需求..." -ForegroundColor Yellow
Write-Host "[題目 20] 網路驗證等級 - 設為傳送 LM & NTLM（最不安全）..." -ForegroundColor Yellow

try {
    $templatePath = "C:\insecure_template.inf"
    $secTemplate | Out-File -FilePath $templatePath -Encoding Unicode -Force
    # 使用 secedit 匯入不安全的安全性範本
    secedit /configure /db C:\insecure.sdb /cfg $templatePath /areas SECURITYPOLICY /quiet
    Write-Host "[secedit] 安全性範本套用完成" -ForegroundColor Green
} catch {
    Write-Warning "[secedit] 安全性範本套用失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 4：SMB 安全 - 啟用 SMBv1（不安全，應停用）
# ============================================================
Write-Host ""
Write-Host "[題目 4] SMB 安全 - 啟用 SMBv1（不安全，應停用）..." -ForegroundColor Yellow
try {
    # 啟用 SMBv1 協定（容易遭受 EternalBlue 等攻擊）
    Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force -ErrorAction SilentlyContinue
    # 停用 SMB 簽章需求
    Set-SmbServerConfiguration -RequireSecuritySignature $false -Force -ErrorAction SilentlyContinue
    Set-SmbServerConfiguration -EnableSecuritySignature $false -Force -ErrorAction SilentlyContinue
    # 嘗試安裝 SMBv1 功能（Windows Server）
    Install-WindowsFeature FS-SMB1 -ErrorAction SilentlyContinue | Out-Null
    Write-Host "[題目 4] SMBv1 已啟用、簽章已停用" -ForegroundColor Green
} catch {
    Write-Warning "[題目 4] SMB 設定部分失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 5：稽核策略 - 停用所有稽核（應全部啟用成功+失敗）
# ============================================================
Write-Host ""
Write-Host "[題目 5] 稽核策略 - 停用所有稽核..." -ForegroundColor Yellow
try {
    # 使用 auditpol 停用所有稽核類別
    auditpol /clear /y | Out-Null
    # 逐一確認停用每個類別
    $categories = @(
        "Account Logon",
        "Account Management",
        "Detailed Tracking",
        "DS Access",
        "Logon/Logoff",
        "Object Access",
        "Policy Change",
        "Privilege Use",
        "System"
    )
    foreach ($cat in $categories) {
        auditpol /set /category:"$cat" /success:disable /failure:disable 2>$null | Out-Null
    }
    Write-Host "[題目 5] 所有稽核策略已停用" -ForegroundColor Green
} catch {
    Write-Warning "[題目 5] 稽核策略停用失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 6：防火牆 - 關閉所有設定檔
# ============================================================
Write-Host ""
Write-Host "[題目 6] 防火牆 - 關閉所有設定檔（網域、私人、公用）..." -ForegroundColor Yellow
try {
    # 使用 netsh 關閉所有防火牆設定檔
    netsh advfirewall set allprofiles state off | Out-Null
    # 也可以用 PowerShell cmdlet
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False -ErrorAction SilentlyContinue
    Write-Host "[題目 6] 所有防火牆設定檔已關閉" -ForegroundColor Green
} catch {
    Write-Warning "[題目 6] 防火牆設定失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 7：Windows Installer - 允許移除更新（應禁止）
# ============================================================
Write-Host ""
Write-Host "[題目 7] Windows Installer - 允許移除更新（應禁止）..." -ForegroundColor Yellow
try {
    # 設定群組原則：禁止移除更新 = 停用（即允許移除更新）
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer"
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    # DisablePatchUninstall = 0 表示允許移除更新（應為 1=禁止）
    Set-ItemProperty -Path $regPath -Name "DisablePatchUninstall" -Value 0 -Type DWord -Force
    Write-Host "[題目 7] Windows Installer 已允許移除更新" -ForegroundColor Green
} catch {
    Write-Warning "[題目 7] Windows Installer 設定失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 8：權限配置 - 建立測試資料夾並設定不安全權限
# ============================================================
Write-Host ""
Write-Host "[題目 8] 權限配置 - 建立 C:\SensitiveData 並設定 Everyone 完全控制..." -ForegroundColor Yellow
try {
    # 建立測試資料夾
    if (-not (Test-Path "C:\SensitiveData")) {
        New-Item -Path "C:\SensitiveData" -ItemType Directory -Force | Out-Null
    }
    # 建立一些假的敏感檔案
    "機密資料 - 員工薪資清單" | Out-File -FilePath "C:\SensitiveData\salary_list.txt" -Encoding UTF8 -Force
    "帳號密碼清單`nAdmin: P@ssw0rd`nUser1: 123456" | Out-File -FilePath "C:\SensitiveData\passwords.txt" -Encoding UTF8 -Force
    "公司機密文件" | Out-File -FilePath "C:\SensitiveData\confidential.docx" -Encoding UTF8 -Force

    # 設定 Everyone 完全控制（極度不安全，應移除 Everyone 並只給特定群組）
    $acl = Get-Acl "C:\SensitiveData"
    $everyoneRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $acl.AddAccessRule($everyoneRule)
    Set-Acl -Path "C:\SensitiveData" -AclObject $acl
    Write-Host "[題目 8] C:\SensitiveData 已建立，Everyone 擁有完全控制" -ForegroundColor Green
} catch {
    Write-Warning "[題目 8] 權限配置失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 9：遠端桌面安全 - 設為不安全
# ============================================================
Write-Host ""
Write-Host "[題目 9] 遠端桌面安全 - 停用 NLA、允許空白密碼、無加密、無閒置逾時..." -ForegroundColor Yellow
try {
    # 啟用遠端桌面
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Type DWord -Force
    # 停用 NLA（網路等級驗證，應啟用）
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0 -Type DWord -Force
    # 設定最低安全層級（0=原生 RDP，應為 2=SSL）
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 0 -Type DWord -Force
    # 設定最低加密等級（1=低，應為 3=高）
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Value 1 -Type DWord -Force

    # 群組原則：停用 NLA 要求
    $rdpPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
    if (-not (Test-Path $rdpPolicyPath)) {
        New-Item -Path $rdpPolicyPath -Force | Out-Null
    }
    # 不要求 NLA（應啟用）
    Set-ItemProperty -Path $rdpPolicyPath -Name "UserAuthentication" -Value 0 -Type DWord -Force
    # 加密等級設為低（應為高）
    Set-ItemProperty -Path $rdpPolicyPath -Name "MinEncryptionLevel" -Value 1 -Type DWord -Force
    # 安全層級設為 RDP（應為 SSL）
    Set-ItemProperty -Path $rdpPolicyPath -Name "SecurityLayer" -Value 0 -Type DWord -Force
    # 閒置逾時設為 0（不斷線，應為 30 分鐘=1800000 毫秒）
    Set-ItemProperty -Path $rdpPolicyPath -Name "MaxIdleTime" -Value 0 -Type DWord -Force
    # 中斷連線逾時設為 0（不斷線，應設定時限）
    Set-ItemProperty -Path $rdpPolicyPath -Name "MaxDisconnectionTime" -Value 0 -Type DWord -Force

    Write-Host "[題目 9] 遠端桌面已設為不安全（無 NLA、低加密、無閒置逾時）" -ForegroundColor Green
} catch {
    Write-Warning "[題目 9] 遠端桌面設定失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 10：事件記錄檔 - 設為不安全的小容量並覆寫
# ============================================================
Write-Host ""
Write-Host "[題目 10] 事件記錄檔 - 設為 1MB 並覆寫事件..." -ForegroundColor Yellow
try {
    # 設定各記錄檔最大大小為 1MB（1024 KB，應為 200MB 以上）
    # 並設定為覆寫事件（應為封存不覆寫）
    $logNames = @("Application", "Security", "System")
    foreach ($logName in $logNames) {
        # 透過登錄檔設定（直接有效）
        $logRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$logName"
        # MaxSize 單位為 bytes（1MB = 1048576）
        Set-ItemProperty -Path $logRegPath -Name "MaxSize" -Value 1048576 -Type DWord -Force
        # Retention = 0 表示覆寫事件（應設為 -1 = 不覆寫）
        Set-ItemProperty -Path $logRegPath -Name "Retention" -Value 0 -Type DWord -Force
    }

    # 也透過 wevtutil 設定
    foreach ($logName in $logNames) {
        wevtutil sl $logName /ms:1048576 2>$null | Out-Null
        wevtutil sl $logName /rt:false 2>$null | Out-Null
    }

    # 群組原則方式設定
    $eventLogPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog"
    foreach ($logName in $logNames) {
        $policyPath = "$eventLogPolicyPath\$logName"
        if (-not (Test-Path $policyPath)) {
            New-Item -Path $policyPath -Force | Out-Null
        }
        # 最大大小 1024 KB（應為 204800 KB）
        Set-ItemProperty -Path $policyPath -Name "MaxSize" -Value 1024 -Type DWord -Force
        # 覆寫事件（0=覆寫，應設為保留）
        Set-ItemProperty -Path $policyPath -Name "Retention" -Value "0" -Type String -Force
    }

    Write-Host "[題目 10] 事件記錄檔已設為 1MB 並覆寫事件" -ForegroundColor Green
} catch {
    Write-Warning "[題目 10] 事件記錄檔設定失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 11：AD 帳號管理 - 建立不安全帳號
# ============================================================
Write-Host ""
Write-Host "[題目 11] AD 帳號管理 - 建立未授權帳號、啟用 Guest、保留預設 Administrator 名稱..." -ForegroundColor Yellow
try {
    # 檢查是否為 AD 環境
    $adAvailable = $false
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $adAvailable = $true
    } catch {
        Write-Host "  [資訊] 非 AD 環境或 AD 模組未安裝，使用本機帳號管理" -ForegroundColor Gray
    }

    if ($adAvailable) {
        $domain = (Get-ADDomain).DistinguishedName

        # 建立可疑使用者 baduser（不應存在的帳號）
        try {
            New-ADUser -Name "baduser" -SamAccountName "baduser" -UserPrincipalName "baduser@$((Get-ADDomain).DNSRoot)" `
                -AccountPassword (ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force) `
                -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true `
                -Description "Backdoor account" -ErrorAction Stop
            Write-Host "  [題目 11] AD 使用者 baduser 已建立" -ForegroundColor Green
        } catch {
            Write-Warning "  [題目 11] baduser 建立失敗（可能已存在）：$($_.Exception.Message)"
        }

        # 建立 testadmin 並加入 Domain Admins（不應有未授權的管理員）
        try {
            New-ADUser -Name "testadmin" -SamAccountName "testadmin" -UserPrincipalName "testadmin@$((Get-ADDomain).DNSRoot)" `
                -AccountPassword (ConvertTo-SecureString "Admin123!" -AsPlainText -Force) `
                -Enabled $true -PasswordNeverExpires $true `
                -Description "Unauthorized admin" -ErrorAction Stop
            Add-ADGroupMember -Identity "Domain Admins" -Members "testadmin" -ErrorAction Stop
            Write-Host "  [題目 11] AD 使用者 testadmin 已建立並加入 Domain Admins" -ForegroundColor Green
        } catch {
            Write-Warning "  [題目 11] testadmin 建立失敗（可能已存在）：$($_.Exception.Message)"
        }

        # 啟用 Guest 帳號（應停用）
        try {
            Enable-ADAccount -Identity "Guest" -ErrorAction Stop
            Write-Host "  [題目 11] Guest 帳號已啟用" -ForegroundColor Green
        } catch {
            Write-Warning "  [題目 11] Guest 帳號啟用失敗：$($_.Exception.Message)"
        }

        # 確保 Administrator 帳號保留預設名稱（應重新命名）
        Write-Host "  [題目 11] Administrator 帳號保留預設名稱（應重新命名）" -ForegroundColor Green

    } else {
        # 非 AD 環境：使用 net user 建立本機帳號
        net user baduser "P@ssw0rd123" /add /comment:"Backdoor account" 2>$null | Out-Null
        net user baduser /passwordchg:no 2>$null | Out-Null
        Write-Host "  [題目 11] 本機使用者 baduser 已建立" -ForegroundColor Green

        net user testadmin "Admin123!" /add /comment:"Unauthorized admin" 2>$null | Out-Null
        net localgroup Administrators testadmin /add 2>$null | Out-Null
        Write-Host "  [題目 11] 本機使用者 testadmin 已建立並加入 Administrators" -ForegroundColor Green

        # 啟用 Guest 帳號
        net user Guest /active:yes 2>$null | Out-Null
        Write-Host "  [題目 11] Guest 帳號已啟用" -ForegroundColor Green
    }
} catch {
    Write-Warning "[題目 11] AD 帳號管理設定失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 12：Windows Defender - 新增排除項目、停用即時保護
# ============================================================
Write-Host ""
Write-Host "[題目 12] Windows Defender - 新增 C:\ 排除、停用即時保護..." -ForegroundColor Yellow
try {
    # 新增 C:\ 為排除路徑（攻擊者常用手法，等於完全停用 Defender）
    Add-MpPreference -ExclusionPath "C:\" -ErrorAction SilentlyContinue
    # 新增常見攻擊工具路徑排除
    Add-MpPreference -ExclusionPath "C:\Users\Public" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath "C:\Temp" -ErrorAction SilentlyContinue

    # 停用即時保護（需要先停用竄改防護，此處嘗試透過登錄檔）
    $defenderPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    if (-not (Test-Path $defenderPolicyPath)) {
        New-Item -Path $defenderPolicyPath -Force | Out-Null
    }
    # 停用 Windows Defender（1=停用）
    Set-ItemProperty -Path $defenderPolicyPath -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force

    $rtpPath = "$defenderPolicyPath\Real-Time Protection"
    if (-not (Test-Path $rtpPath)) {
        New-Item -Path $rtpPath -Force | Out-Null
    }
    # 停用即時保護（1=停用，應為 0=啟用）
    Set-ItemProperty -Path $rtpPath -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force
    # 停用行為監控
    Set-ItemProperty -Path $rtpPath -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -Force
    # 停用掃描已下載檔案
    Set-ItemProperty -Path $rtpPath -Name "DisableIOAVProtection" -Value 1 -Type DWord -Force

    # 嘗試直接停用即時保護（可能因竄改防護而失敗）
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue

    Write-Host "[題目 12] Windows Defender 排除已新增（C:\），即時保護已嘗試停用" -ForegroundColor Green
} catch {
    Write-Warning "[題目 12] Windows Defender 設定失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 13：服務管理 - 啟用危險服務
# ============================================================
Write-Host ""
Write-Host "[題目 13] 服務管理 - 啟用危險服務（Remote Registry、Telnet 等）..." -ForegroundColor Yellow
try {
    # 需要啟用的不安全服務清單
    $dangerousServices = @(
        @{Name="RemoteRegistry"; DisplayName="Remote Registry（遠端登錄檔存取）"},
        @{Name="TlntSvr"; DisplayName="Telnet（明文遠端連線）"},
        @{Name="SSDPSRV"; DisplayName="SSDP Discovery（UPnP 裝置發現）"},
        @{Name="upnphost"; DisplayName="UPnP Device Host（UPnP 服務）"},
        @{Name="Browser"; DisplayName="Computer Browser（廣播網路資源）"},
        @{Name="Spooler"; DisplayName="Print Spooler（PrintNightmare 漏洞）"},
        @{Name="SNMP"; DisplayName="SNMP Service（社群字串明文）"},
        @{Name="FTPSVC"; DisplayName="FTP Publishing Service（FTP 明文傳輸）"}
    )

    foreach ($svc in $dangerousServices) {
        try {
            $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
            if ($service) {
                Set-Service -Name $svc.Name -StartupType Automatic -ErrorAction SilentlyContinue
                Start-Service -Name $svc.Name -ErrorAction SilentlyContinue
                Write-Host "  [題目 13] $($svc.DisplayName) 已設為自動啟動" -ForegroundColor Green
            } else {
                Write-Host "  [題目 13] $($svc.DisplayName) 服務不存在（未安裝）" -ForegroundColor Gray
            }
        } catch {
            Write-Host "  [題目 13] $($svc.DisplayName) 設定失敗" -ForegroundColor Gray
        }
    }
} catch {
    Write-Warning "[題目 13] 服務管理設定失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 14：UAC - 停用（已在 secedit 範本中處理，這裡做額外確認）
# ============================================================
Write-Host ""
Write-Host "[題目 14] UAC - 確認停用使用者帳戶控制..." -ForegroundColor Yellow
try {
    $uacPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    # EnableLUA = 0 停用 UAC（應為 1）
    Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 0 -Type DWord -Force
    # ConsentPromptBehaviorAdmin = 0 不提示（應為 2 或 5）
    Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 0 -Type DWord -Force
    # PromptOnSecureDesktop = 0 不在安全桌面提示
    Set-ItemProperty -Path $uacPath -Name "PromptOnSecureDesktop" -Value 0 -Type DWord -Force
    # FilterAdministratorToken = 0 不過濾管理員 token
    Set-ItemProperty -Path $uacPath -Name "FilterAdministratorToken" -Value 0 -Type DWord -Force
    Write-Host "[題目 14] UAC 已完全停用" -ForegroundColor Green
} catch {
    Write-Warning "[題目 14] UAC 設定失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 15：排程任務 - 建立可疑排程任務
# ============================================================
Write-Host ""
Write-Host "[題目 15] 排程任務 - 建立可疑排程任務..." -ForegroundColor Yellow
try {
    # 建立可疑排程任務 1：每 5 分鐘執行 Base64 編碼的 PowerShell（模擬後門）
    $encodedCmd = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output "beacon"; Start-Sleep -Seconds 1'))
    $action1 = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -enc $encodedCmd"
    $trigger1 = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 5) -Once -At (Get-Date)
    $principal1 = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    Register-ScheduledTask -TaskName "SystemUpdateService" -Action $action1 -Trigger $trigger1 -Principal $principal1 `
        -Description "System Update Service" -Force | Out-Null
    Write-Host "  [題目 15] 可疑排程任務 'SystemUpdateService' 已建立（每 5 分鐘執行 Base64 PowerShell）" -ForegroundColor Green

    # 建立可疑排程任務 2：開機時從 Public 資料夾執行程式
    $action2 = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c C:\Users\Public\update.bat"
    $trigger2 = New-ScheduledTaskTrigger -AtStartup
    $principal2 = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    Register-ScheduledTask -TaskName "WindowsHealthCheck" -Action $action2 -Trigger $trigger2 -Principal $principal2 `
        -Description "Windows Health Check Service" -Force | Out-Null
    # 建立假的 bat 檔案
    "echo Backdoor running > C:\Users\Public\health.log" | Out-File -FilePath "C:\Users\Public\update.bat" -Encoding ASCII -Force
    Write-Host "  [題目 15] 可疑排程任務 'WindowsHealthCheck' 已建立（開機執行 Public\update.bat）" -ForegroundColor Green
} catch {
    Write-Warning "[題目 15] 排程任務建立失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 16：共享資料夾 - 建立開放共享
# ============================================================
Write-Host ""
Write-Host "[題目 16] 共享資料夾 - 建立 Everyone 完全控制的共享..." -ForegroundColor Yellow
try {
    # 建立共享資料夾
    $sharePath = "C:\OpenShare"
    if (-not (Test-Path $sharePath)) {
        New-Item -Path $sharePath -ItemType Directory -Force | Out-Null
    }
    "這是一個開放的共享資料夾" | Out-File -FilePath "$sharePath\readme.txt" -Encoding UTF8 -Force
    "機密資料不應放在公開共享中" | Out-File -FilePath "$sharePath\secret.txt" -Encoding UTF8 -Force

    # 移除現有共享（如果存在）
    Remove-SmbShare -Name "OpenShare" -Force -ErrorAction SilentlyContinue

    # 建立共享，Everyone 完全控制（極度不安全，應移除 Everyone 權限）
    New-SmbShare -Name "OpenShare" -Path $sharePath -FullAccess "Everyone" `
        -Description "Open file share" -ErrorAction Stop | Out-Null

    # NTFS 權限也設為 Everyone 完全控制
    $acl = Get-Acl $sharePath
    $everyoneRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $acl.AddAccessRule($everyoneRule)
    Set-Acl -Path $sharePath -AclObject $acl

    Write-Host "[題目 16] 共享 'OpenShare' 已建立（Everyone 完全控制）" -ForegroundColor Green
} catch {
    Write-Warning "[題目 16] 共享資料夾建立失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 17：IIS 安全 - 啟用目錄瀏覽（若已安裝 IIS）
# ============================================================
Write-Host ""
Write-Host "[題目 17] IIS 安全 - 啟用目錄瀏覽（若已安裝）..." -ForegroundColor Yellow
try {
    # 檢查 IIS 是否已安裝
    $iisInstalled = Get-WindowsFeature -Name Web-Server -ErrorAction SilentlyContinue
    if ($iisInstalled -and $iisInstalled.Installed) {
        Import-Module WebAdministration -ErrorAction SilentlyContinue

        # 啟用目錄瀏覽（應停用，避免洩露目錄結構）
        Set-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -PSPath "IIS:\Sites\Default Web Site" `
            -Name enabled -Value $true -ErrorAction SilentlyContinue

        # 也可以用 appcmd
        & "$env:windir\system32\inetsrv\appcmd.exe" set config "Default Web Site" /section:directoryBrowse /enabled:true 2>$null | Out-Null

        Write-Host "[題目 17] IIS 目錄瀏覽已啟用" -ForegroundColor Green
    } else {
        Write-Host "[題目 17] IIS 未安裝，跳過" -ForegroundColor Gray
    }
} catch {
    Write-Warning "[題目 17] IIS 設定失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 18：DNS 安全 - 允許區域轉送（若已安裝 DNS）
# ============================================================
Write-Host ""
Write-Host "[題目 18] DNS 安全 - 允許區域轉送給任何伺服器..." -ForegroundColor Yellow
try {
    # 檢查 DNS 伺服器角色是否安裝
    $dnsInstalled = Get-WindowsFeature -Name DNS -ErrorAction SilentlyContinue
    if ($dnsInstalled -and $dnsInstalled.Installed) {
        Import-Module DnsServer -ErrorAction SilentlyContinue

        # 取得所有 DNS 區域
        $zones = Get-DnsServerZone -ErrorAction SilentlyContinue | Where-Object { $_.IsReverseLookupZone -eq $false -and $_.ZoneType -eq 'Primary' }
        foreach ($zone in $zones) {
            # 允許區域轉送給任何伺服器（應停用或僅允許特定伺服器）
            Set-DnsServerPrimaryZone -Name $zone.ZoneName -SecureSecondaries NoTransfer -ErrorAction SilentlyContinue
            # 重新設定為允許任何伺服器轉送
            Set-DnsServerPrimaryZone -Name $zone.ZoneName -SecureSecondaries TransferAnyServer -ErrorAction SilentlyContinue
            Write-Host "  [題目 18] DNS 區域 '$($zone.ZoneName)' 已允許區域轉送給任何伺服器" -ForegroundColor Green
        }

        # 透過登錄檔確保區域轉送開啟
        # 也可以直接設定 DNS 伺服器層級
    } else {
        Write-Host "[題目 18] DNS 伺服器未安裝，跳過" -ForegroundColor Gray
    }
} catch {
    Write-Warning "[題目 18] DNS 設定失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 19：LDAP 安全 - 停用簽署需求（已在 secedit 範本中部分處理）
# ============================================================
Write-Host ""
Write-Host "[題目 19] LDAP 安全 - 停用 LDAP 簽署需求..." -ForegroundColor Yellow
try {
    # LDAP 伺服器簽署需求：0=無（應為 2=需要簽署）
    $ntdsPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    if (Test-Path $ntdsPath) {
        Set-ItemProperty -Path $ntdsPath -Name "LDAPServerIntegrity" -Value 0 -Type DWord -Force
        Write-Host "  [題目 19] LDAP 伺服器簽署需求已停用" -ForegroundColor Green
    }
    # LDAP 用戶端簽署需求：0=無
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LdapClientIntegrity" -Value 0 -Type DWord -Force
    Write-Host "  [題目 19] LDAP 用戶端簽署需求已停用" -ForegroundColor Green
} catch {
    Write-Warning "[題目 19] LDAP 設定失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 20：網路驗證等級 - 設為最不安全（已在 secedit 範本中處理）
# ============================================================
Write-Host ""
Write-Host "[題目 20] 網路驗證等級 - 設為傳送 LM & NTLM 回應（最不安全）..." -ForegroundColor Yellow
try {
    # LmCompatibilityLevel = 0（傳送 LM & NTLM 回應）
    # 應為 5（僅傳送 NTLMv2 回應，拒絕 LM & NTLM）
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -Value 0 -Type DWord -Force
    Write-Host "[題目 20] LAN Manager 驗證等級已設為 0（傳送 LM & NTLM）" -ForegroundColor Green
} catch {
    Write-Warning "[題目 20] 網路驗證設定失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 21：BitLocker - 跳過（無法輕易錯誤配置）
# ============================================================
Write-Host ""
Write-Host "[題目 21] BitLocker - 跳過（無法在腳本中輕易錯誤配置）" -ForegroundColor Gray

# ============================================================
# 題目 22：PowerShell 日誌 - 停用指令碼區塊記錄和模組記錄
# ============================================================
Write-Host ""
Write-Host "[題目 22] PowerShell 日誌 - 停用指令碼區塊記錄和模組記錄..." -ForegroundColor Yellow
try {
    # 停用 PowerShell 指令碼區塊記錄（應啟用）
    $psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $psLogPath)) {
        New-Item -Path $psLogPath -Force | Out-Null
    }
    # EnableScriptBlockLogging = 0 停用（應為 1）
    Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 0 -Type DWord -Force

    # 停用 PowerShell 模組記錄（應啟用）
    $psModLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
    if (-not (Test-Path $psModLogPath)) {
        New-Item -Path $psModLogPath -Force | Out-Null
    }
    # EnableModuleLogging = 0 停用（應為 1，且模組名稱設為 *）
    Set-ItemProperty -Path $psModLogPath -Name "EnableModuleLogging" -Value 0 -Type DWord -Force

    # 停用 PowerShell 轉譯記錄（應啟用）
    $psTransPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    if (-not (Test-Path $psTransPath)) {
        New-Item -Path $psTransPath -Force | Out-Null
    }
    Set-ItemProperty -Path $psTransPath -Name "EnableTranscripting" -Value 0 -Type DWord -Force

    Write-Host "[題目 22] PowerShell 所有日誌記錄已停用" -ForegroundColor Green
} catch {
    Write-Warning "[題目 22] PowerShell 日誌設定失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 23：Windows Update - 停用自動更新
# ============================================================
Write-Host ""
Write-Host "[題目 23] Windows Update - 停用自動更新..." -ForegroundColor Yellow
try {
    # 群組原則：停用自動更新
    $wuPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    if (-not (Test-Path $wuPolicyPath)) {
        New-Item -Path $wuPolicyPath -Force | Out-Null
    }
    # NoAutoUpdate = 1 停用自動更新（應為 0，並設定 AUOptions=4 自動下載安裝）
    Set-ItemProperty -Path $wuPolicyPath -Name "NoAutoUpdate" -Value 1 -Type DWord -Force
    # AUOptions = 1 表示不自動更新（應為 4=自動下載並排程安裝）
    Set-ItemProperty -Path $wuPolicyPath -Name "AUOptions" -Value 1 -Type DWord -Force

    # 停用 Windows Update 服務（極度不安全）
    Set-Service -Name wuauserv -StartupType Disabled -ErrorAction SilentlyContinue
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue

    Write-Host "[題目 23] Windows Update 自動更新已停用，wuauserv 服務已停用" -ForegroundColor Green
} catch {
    Write-Warning "[題目 23] Windows Update 設定失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 24：登錄檔安全 - 啟用自動執行、啟用 LM hash 儲存、停用 CTRL+ALT+DEL
# ============================================================
Write-Host ""
Write-Host "[題目 24] 登錄檔安全 - 啟用自動執行、啟用 LM hash 儲存..." -ForegroundColor Yellow
try {
    # 啟用自動執行（AutoRun）- 應停用以防 USB 攻擊
    $explorerPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    if (-not (Test-Path $explorerPolicyPath)) {
        New-Item -Path $explorerPolicyPath -Force | Out-Null
    }
    # NoDriveTypeAutoRun = 0 啟用自動執行（應為 255=全部停用）
    Set-ItemProperty -Path $explorerPolicyPath -Name "NoDriveTypeAutoRun" -Value 0 -Type DWord -Force
    # 同時移除 AutoPlay 的停用設定
    Set-ItemProperty -Path $explorerPolicyPath -Name "NoAutorun" -Value 0 -Type DWord -Force

    # 啟用 LM hash 儲存（極度不安全，LM hash 容易被破解）
    # NoLMHash = 0 表示儲存 LM hash（應為 1=不儲存）
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Value 0 -Type DWord -Force

    # 停用 CTRL+ALT+DEL 要求（已在 secedit 和題目 3 處理，這裡做額外確認）
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableCAD" -Value 1 -Type DWord -Force

    # 停用安全開機（Secure Boot）相關警告
    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    # AutoAdminLogon = 1 啟用自動登入（不安全）
    Set-ItemProperty -Path $winlogonPath -Name "AutoAdminLogon" -Value "1" -Type String -Force

    Write-Host "[題目 24] 自動執行已啟用、LM hash 儲存已啟用、CTRL+ALT+DEL 已停用" -ForegroundColor Green
} catch {
    Write-Warning "[題目 24] 登錄檔設定失敗：$($_.Exception.Message)"
}

# ============================================================
# 題目 25：憑證管理 - 跳過（無法輕易錯誤配置）
# ============================================================
Write-Host ""
Write-Host "[題目 25] 憑證管理 - 跳過（無法在腳本中輕易錯誤配置）" -ForegroundColor Gray

# ============================================================
# 額外：安全性選項補充設定（題目 3 的額外登錄檔加強）
# ============================================================
Write-Host ""
Write-Host "[補充] 安全性選項 - 額外不安全設定..." -ForegroundColor Yellow
try {
    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"

    # 允許 SAM 帳戶的匿名列舉（應禁止）
    Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymousSAM" -Value 0 -Type DWord -Force
    # 允許 SAM 帳戶和共用的匿名列舉（應禁止）
    Set-ItemProperty -Path $lsaPath -Name "RestrictAnonymous" -Value 0 -Type DWord -Force
    # 允許匿名 SID/名稱轉譯
    Set-ItemProperty -Path $lsaPath -Name "TurnOffAnonymousBlock" -Value 1 -Type DWord -Force

    # 網路存取：讓 Everyone 權限套用到匿名使用者（不安全）
    Set-ItemProperty -Path $lsaPath -Name "EveryoneIncludesAnonymous" -Value 1 -Type DWord -Force

    Write-Host "[補充] 匿名存取限制已移除" -ForegroundColor Green
} catch {
    Write-Warning "[補充] 安全性選項補充設定失敗：$($_.Exception.Message)"
}

# ============================================================
# 強制更新群組原則
# ============================================================
Write-Host ""
Write-Host "[最終步驟] 強制更新群組原則（gpupdate /force）..." -ForegroundColor Cyan
try {
    gpupdate /force 2>$null | Out-Null
    Write-Host "[最終步驟] 群組原則已更新" -ForegroundColor Green
} catch {
    Write-Warning "[最終步驟] gpupdate 失敗：$($_.Exception.Message)"
}

# ============================================================
# 完成：顯示摘要
# ============================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Red
Write-Host "  所有錯誤配置已完成！" -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Red
Write-Host ""
Write-Host "已建立的錯誤配置摘要：" -ForegroundColor White
Write-Host ""
Write-Host "  一、歷屆必考（題目 1-8）：" -ForegroundColor Cyan
Write-Host "    [1] 密碼策略 - 最小長度 4、無複雜性、永不過期、無歷程記錄" -ForegroundColor White
Write-Host "    [2] 帳戶鎖定 - 閾值 0（不鎖定）" -ForegroundColor White
Write-Host "    [3] 安全性選項 - 不要求 CTRL+ALT+DEL、顯示上次使用者、無密碼過期警告" -ForegroundColor White
Write-Host "    [4] SMB 安全 - 停用簽章、啟用 SMBv1" -ForegroundColor White
Write-Host "    [5] 稽核策略 - 停用所有稽核" -ForegroundColor White
Write-Host "    [6] 防火牆 - 關閉所有設定檔" -ForegroundColor White
Write-Host "    [7] Windows Installer - 允許移除更新" -ForegroundColor White
Write-Host "    [8] 權限配置 - C:\SensitiveData Everyone 完全控制、不安全使用者權限指派" -ForegroundColor White
Write-Host ""
Write-Host "  二、高機率（題目 9-13）：" -ForegroundColor Cyan
Write-Host "    [9]  遠端桌面 - 停用 NLA、低加密、無閒置逾時" -ForegroundColor White
Write-Host "    [10] 事件記錄檔 - 1MB、覆寫事件" -ForegroundColor White
Write-Host "    [11] AD 帳號 - baduser、testadmin(Domain Admins)、Guest 啟用" -ForegroundColor White
Write-Host "    [12] Windows Defender - C:\ 排除、停用即時保護" -ForegroundColor White
Write-Host "    [13] 服務管理 - Remote Registry 等危險服務已啟用" -ForegroundColor White
Write-Host ""
Write-Host "  三、中等機率（題目 14-20）：" -ForegroundColor Cyan
Write-Host "    [14] UAC - 完全停用" -ForegroundColor White
Write-Host "    [15] 排程任務 - SystemUpdateService、WindowsHealthCheck（可疑任務）" -ForegroundColor White
Write-Host "    [16] 共享資料夾 - OpenShare Everyone 完全控制" -ForegroundColor White
Write-Host "    [17] IIS - 啟用目錄瀏覽（若已安裝）" -ForegroundColor White
Write-Host "    [18] DNS - 允許區域轉送（若已安裝）" -ForegroundColor White
Write-Host "    [19] LDAP - 停用簽署需求" -ForegroundColor White
Write-Host "    [20] 網路驗證 - LM & NTLM（最不安全等級）" -ForegroundColor White
Write-Host ""
Write-Host "  四、低機率（題目 21-25）：" -ForegroundColor Cyan
Write-Host "    [21] BitLocker - 跳過" -ForegroundColor Gray
Write-Host "    [22] PowerShell - 停用指令碼區塊記錄和模組記錄" -ForegroundColor White
Write-Host "    [23] Windows Update - 停用自動更新" -ForegroundColor White
Write-Host "    [24] 登錄檔 - 啟用自動執行、啟用 LM hash 儲存" -ForegroundColor White
Write-Host "    [25] 憑證管理 - 跳過" -ForegroundColor Gray
Write-Host ""
Write-Host "  建立的測試帳號：" -ForegroundColor Cyan
Write-Host "    baduser / P@ssw0rd123（後門帳號）" -ForegroundColor White
Write-Host "    testadmin / Admin123!（未授權管理員，已加入 Domain Admins）" -ForegroundColor White
Write-Host ""
Write-Host "  建立的測試資料夾/檔案：" -ForegroundColor Cyan
Write-Host "    C:\SensitiveData\（Everyone 完全控制）" -ForegroundColor White
Write-Host "    C:\OpenShare\（共享，Everyone 完全控制）" -ForegroundColor White
Write-Host "    C:\Users\Public\update.bat（可疑排程任務執行檔）" -ForegroundColor White
Write-Host ""
Write-Host "  備份檔案：" -ForegroundColor Cyan
Write-Host "    C:\backup_security.cfg（原始安全性設定，可用於還原）" -ForegroundColor White
Write-Host ""
Write-Host "  注意：部分設定（如 UAC）需要重新開機才會完全生效。" -ForegroundColor Yellow
Write-Host "  建議執行後重新開機一次：Restart-Computer -Force" -ForegroundColor Yellow
Write-Host ""
Write-Host "============================================================" -ForegroundColor Red
Write-Host "  現在請藍隊選手找出並修復所有安全性問題！" -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Red
