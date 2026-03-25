######################################################################
# UTF-8 BOM is included in the file encoding.
######################################################################
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows AD Security Hardening Platform - Cyberpunk GUI
.DESCRIPTION
    A WPF-based security hardening training platform with matrix rain animation,
    23 challenge topics covering AD security hardening checks.
    All functions use global: scope so WPF event handlers can find them.
.NOTES
    Must run as Administrator on a Windows Server with AD DS role.
    Run setup.ps1 first to create intentionally insecure defaults.
#>

# -- Encoding & Assembly ------------------------------------------------
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms

# ======================================================================
# SECTION 1 - DATA MODEL: Challenge Definitions
# ======================================================================

$script:Challenges = @(
    # -- Category 1: historical must-know --
    @{ Id=1;  Title="密碼策略";         Category="歷屆必考"; Color="#ff6600"; Checks=@("MinimumPasswordLength >= 8","PasswordComplexity = 1","MaximumPasswordAge <= 90","PasswordHistorySize >= 5","MinimumPasswordAge >= 2","登入 Banner 訊息已設定 (LegalNoticeCaption)") }
    @{ Id=2;  Title="帳戶鎖定原則";     Category="歷屆必考"; Color="#ff6600"; Checks=@("LockoutBadCount 3-5","ResetLockoutCount >= 30","LockoutDuration >= 30") }
    @{ Id=3;  Title="安全性選項";       Category="歷屆必考"; Color="#ff6600"; Checks=@("DisableCAD = 0","DontDisplayLastUserName = 1","PasswordExpiryWarning >= 7","關機: 不允許未登入關機","不允許 SAM 匿名列舉") }
    @{ Id=4;  Title="SMB 安全";         Category="歷屆必考"; Color="#ff6600"; Checks=@("伺服器端強制簽章 RequireSecuritySignature","用戶端強制簽章 EnableSecuritySignature","SMBv1 已停用","GPO 伺服器簽章原則","GPO 用戶端簽章原則","SMB 加密已啟用 (EncryptData)") }
    @{ Id=5;  Title="稽核策略";         Category="歷屆必考"; Color="#ff6600"; Checks=@("Account Logon Audit","Logon/Logoff Audit","Object Access Audit","Policy Change Audit","System Audit") }
    @{ Id=6;  Title="Windows 防火牆";   Category="歷屆必考"; Color="#ff6600"; Checks=@("Domain 設定檔已啟用且記錄已開啟","Domain 預設拒絕輸入","Private 設定檔已啟用且記錄已開啟","Private 預設拒絕輸入","Public 設定檔已啟用且記錄已開啟","Public 預設拒絕輸入") }
    @{ Id=7;  Title="Windows Installer"; Category="歷屆必考"; Color="#ff6600"; Checks=@("DisablePatchUninstall = 1") }
    @{ Id=8;  Title="權限配置";         Category="歷屆必考"; Color="#ff6600"; Checks=@("C:\\SensitiveData 資料夾存在","無 Everyone:FullControl","擁有者為 Administrators") }

    # -- Category 2: high probability --
    @{ Id=9;  Title="遠端桌面安全";     Category="高機率"; Color="#00d4ff"; Checks=@("NLA 網路等級驗證已啟用","安全層級 >= SSL (SecurityLayer >= 2)","加密層級 = 高 (MinEncryptionLevel >= 3)","限制空白密碼遠端登入","閒置逾時已設定 (MaxIdleTime)","加密等級已透過 GPO 設定") }
    @{ Id=10; Title="事件記錄檔";       Category="高機率"; Color="#00d4ff"; Checks=@("Security Log >= 200 MB","Application Log >= 100 MB","System Log >= 100 MB","保留原則已設定為不覆寫") }
    @{ Id=11; Title="AD 帳號管理";      Category="高機率"; Color="#00d4ff"; Checks=@("Guest Account Disabled","No Extra Domain Admins","Administrator Renamed") }
    # Windows Defender 已移除（Server 2022 無此功能）
    @{ Id=13; Title="服務管理";         Category="高機率"; Color="#00d4ff"; Checks=@("RemoteRegistry Stopped","Telnet Stopped","Other Risky Services","Print Spooler 已停用","Windows Remote Management 已停用") }

    # -- Category 3: medium probability --
    @{ Id=14; Title="UAC";              Category="中等機率"; Color="#a855f7"; Checks=@("EnableLUA = 1","ConsentPromptBehaviorAdmin = 2","FilterAdministratorToken = 1") }
    @{ Id=15; Title="排程任務";         Category="中等機率"; Color="#a855f7"; Checks=@("No Suspicious Tasks") }
    @{ Id=16; Title="共享資料夾";       Category="中等機率"; Color="#a855f7"; Checks=@("無 Everyone:FullControl 共享","無多餘的自訂共享","已停用管理共享 (AutoShareServer)") }
    @{ Id=17; Title="IIS 安全";         Category="中等機率"; Color="#a855f7"; Checks=@("IIS 角色已安裝","目錄瀏覽已停用") }
    @{ Id=18; Title="DNS 安全";         Category="中等機率"; Color="#a855f7"; Checks=@("DNS 角色已安裝","Zone Transfer Disabled","已停用遞迴查詢 (Recursion)") }
    @{ Id=19; Title="LDAP 安全";        Category="中等機率"; Color="#a855f7"; Checks=@("LDAPServerIntegrity >= 2") }
    @{ Id=20; Title="網路驗證等級";     Category="中等機率"; Color="#a855f7"; Checks=@("LmCompatibilityLevel >= 3") }

    # -- Category 4: low probability --
    @{ Id=22; Title="PowerShell 日誌";  Category="低機率"; Color="#666666"; Checks=@("EnableScriptBlockLogging = 1") }
    @{ Id=23; Title="Windows Update";   Category="低機率"; Color="#666666"; Checks=@("wuauserv 服務執行中","已設定自動更新 (GPO AUOptions = 4)","WSUS 或自動更新排程已設定") }
    @{ Id=24; Title="登錄檔安全";       Category="低機率"; Color="#666666"; Checks=@("NoDriveTypeAutoRun = 255","NoLMHash = 1","DisableCAD = 0","已啟用 NtfsDisable8dot3NameCreation") }
)

# Runtime state per challenge
$script:ChallengeState = @{}
foreach ($c in $script:Challenges) {
    $script:ChallengeState[$c.Id] = @{
        Status       = "Pending"
        CheckResults = @{}
        PassedCount  = 0
        TotalCount   = $c.Checks.Count
    }
}

# -- Secedit cache ------------------------------------------------------
$script:SeceditCache      = $null
$script:SeceditCacheTime  = [datetime]::MinValue
$script:SeceditTempFile   = "$env:TEMP\secedit_export_$PID.inf"

# ======================================================================
# SECTION 2 - HELPER FUNCTIONS (global: scope for WPF event access)
# ======================================================================

function global:Get-SeceditData {
    $now = Get-Date
    if ($script:SeceditCache -and ($now - $script:SeceditCacheTime).TotalSeconds -lt 5) {
        return $script:SeceditCache
    }
    try {
        secedit /export /cfg $script:SeceditTempFile /quiet 2>$null | Out-Null
        $script:SeceditCache     = Get-Content $script:SeceditTempFile -ErrorAction Stop
        $script:SeceditCacheTime = $now
    } catch {
        $script:SeceditCache = @()
    }
    return $script:SeceditCache
}

function global:Get-SeceditValue {
    param([string]$Key)
    $data = Get-SeceditData
    foreach ($line in $data) {
        if ($line -match "^\s*$Key\s*=\s*(.+)$") {
            return $Matches[1].Trim()
        }
    }
    return $null
}

function global:Get-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $val.$Name
    } catch { return $null }
}

# ======================================================================
# SECTION 3 - VERIFY FUNCTION (global: scope for WPF event access)
# ======================================================================

function global:Verify-Challenge {
    param([int]$Id)
    $results = @{}
    try {
        switch ($Id) {
            # --- 1. password policy ---
            1 {
                $v = Get-SeceditValue "MinimumPasswordLength"
                $results["MinimumPasswordLength >= 8"] = ($null -ne $v -and [int]$v -ge 8)

                $v = Get-SeceditValue "PasswordComplexity"
                $results["PasswordComplexity = 1"] = ($null -ne $v -and [int]$v -eq 1)

                $v = Get-SeceditValue "MaximumPasswordAge"
                $results["MaximumPasswordAge <= 90"] = ($null -ne $v -and [int]$v -le 90 -and [int]$v -gt 0)

                $v = Get-SeceditValue "PasswordHistorySize"
                $results["PasswordHistorySize >= 5"] = ($null -ne $v -and [int]$v -ge 5)

                $v = Get-SeceditValue "MinimumPasswordAge"
                $results["MinimumPasswordAge >= 2"] = ($null -ne $v -and [int]$v -ge 2)

                $v = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LegalNoticeCaption"
                $results["登入 Banner 訊息已設定 (LegalNoticeCaption)"] = ($null -ne $v -and $v.ToString().Trim() -ne "")
            }

            # --- 2. account lockout ---
            2 {
                $v = Get-SeceditValue "LockoutBadCount"
                $results["LockoutBadCount 3-5"] = ($null -ne $v -and [int]$v -ge 3 -and [int]$v -le 5)

                $v = Get-SeceditValue "ResetLockoutCount"
                $results["ResetLockoutCount >= 30"] = ($null -ne $v -and [int]$v -ge 30)

                $v = Get-SeceditValue "LockoutDuration"
                $results["LockoutDuration >= 30"] = ($null -ne $v -and [int]$v -ge 30)
            }

            # --- 3. security options ---
            3 {
                $v = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD"
                $results["DisableCAD = 0"] = ($null -ne $v -and [int]$v -eq 0)

                $v = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName"
                $results["DontDisplayLastUserName = 1"] = ($null -ne $v -and [int]$v -eq 1)

                $v = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "PasswordExpiryWarning"
                if ($null -eq $v) { $v = 5 }
                $results["PasswordExpiryWarning >= 7"] = ([int]$v -ge 7)

                $v = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ShutdownWithoutLogon"
                $results["關機: 不允許未登入關機"] = ($null -ne $v -and [int]$v -eq 0)

                $v = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "RestrictAnonymousSAM"
                $results["不允許 SAM 匿名列舉"] = ($null -ne $v -and [int]$v -eq 1)
            }

            # --- 4. SMB security (stricter: check GPO signing via secedit) ---
            4 {
                try {
                    $smb = Get-SmbServerConfiguration -ErrorAction Stop
                    $results["伺服器端強制簽章 RequireSecuritySignature"] = ($smb.RequireSecuritySignature -eq $true)
                    $results["用戶端強制簽章 EnableSecuritySignature"] = ($smb.EnableSecuritySignature -eq $true)
                    $results["SMBv1 已停用"] = ($smb.EnableSMB1Protocol -eq $false)
                    $results["SMB 加密已啟用 (EncryptData)"] = ($smb.EncryptData -eq $true)
                } catch {
                    $results["伺服器端強制簽章 RequireSecuritySignature"] = $null
                    $results["用戶端強制簽章 EnableSecuritySignature"] = $null
                    $results["SMBv1 已停用"] = $null
                    $results["SMB 加密已啟用 (EncryptData)"] = $null
                }
                # GPO server signing
                $v1 = Get-SeceditValue "MACHINE\\System\\CurrentControlSet\\Services\\LanManServer\\Parameters\\RequireSecuritySignature"
                $results["GPO 伺服器簽章原則"] = ($null -ne $v1 -and $v1 -match "4,1")
                # GPO client signing
                $v2 = Get-SeceditValue "MACHINE\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters\\RequireSecuritySignature"
                $results["GPO 用戶端簽章原則"] = ($null -ne $v2 -and $v2 -match "4,1")
            }

            # --- 5. audit policy ---
            5 {
                try {
                    $audit = auditpol /get /category:* 2>&1 | Out-String
                    $cats = @{
                        "Account Logon Audit"  = "Account Logon|帳戶登入"
                        "Logon/Logoff Audit"   = "Logon/Logoff|登入/登出"
                        "Object Access Audit"  = "Object Access|物件存取"
                        "Policy Change Audit"  = "Policy Change|原則變更"
                        "System Audit"         = "System|系統"
                    }
                    foreach ($k in $cats.Keys) {
                        $pattern = $cats[$k]
                        $found = $false
                        foreach ($line in ($audit -split "`n")) {
                            if ($line -match $pattern -and $line -match "Success and Failure") {
                                $found = $true; break
                            }
                        }
                        $results[$k] = $found
                    }
                } catch {
                    foreach ($k in @("Account Logon Audit","Logon/Logoff Audit","Object Access Audit","Policy Change Audit","System Audit")) {
                        $results[$k] = $null
                    }
                }
            }

            # --- 6. firewall (stricter: also check DefaultInboundAction = Block AND logging enabled) ---
            6 {
                try {
                    $profiles = Get-NetFirewallProfile -ErrorAction Stop
                    foreach ($p in @("Domain","Private","Public")) {
                        $prof = $profiles | Where-Object { $_.Name -eq $p }
                        $results["$p 設定檔已啟用且記錄已開啟"] = ($prof -and $prof.Enabled -eq $true -and $prof.LogBlocked -eq $true)
                        $results["$p 預設拒絕輸入"] = ($prof -and $prof.DefaultInboundAction -eq "Block")
                    }
                } catch {
                    foreach ($p in @("Domain","Private","Public")) {
                        $results["$p 設定檔已啟用且記錄已開啟"] = $null
                        $results["$p 預設拒絕輸入"] = $null
                    }
                }
            }

            # --- 7. Windows Installer ---
            7 {
                $v = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "DisablePatchUninstall"
                $results["DisablePatchUninstall = 1"] = ($null -ne $v -and [int]$v -eq 1)
            }

            # --- 8. permissions ---
            8 {
                $exists = Test-Path "C:\SensitiveData"
                $results["C:\\SensitiveData 資料夾存在"] = $exists
                if ($exists) {
                    try {
                        $acl = Get-Acl "C:\SensitiveData" -ErrorAction Stop
                        $bad = $acl.Access | Where-Object {
                            $_.IdentityReference -match "Everyone|所有人" -and
                            $_.FileSystemRights -match "FullControl"
                        }
                        $results["無 Everyone:FullControl"] = ($null -eq $bad -or $bad.Count -eq 0)
                        $results["擁有者為 Administrators"] = ($acl.Owner -match "Administrators|BUILTIN\\Administrators")
                    } catch {
                        $results["無 Everyone:FullControl"] = $false
                        $results["擁有者為 Administrators"] = $false
                    }
                } else {
                    $results["無 Everyone:FullControl"] = $false
                    $results["擁有者為 Administrators"] = $false
                }
            }

            # --- 9. RDP security (stricter: SecurityLayer >= 2 AND MinEncryptionLevel >= 3) ---
            9 {
                $v = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication"
                $results["NLA 網路等級驗證已啟用"] = ($null -ne $v -and [int]$v -eq 1)

                $sec = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "SecurityLayer"
                $results["安全層級 >= SSL (SecurityLayer >= 2)"] = ($null -ne $sec -and [int]$sec -ge 2)

                $enc = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "MinEncryptionLevel"
                $results["加密層級 = 高 (MinEncryptionLevel >= 3)"] = ($null -ne $enc -and [int]$enc -ge 3)

                $blank = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "LimitBlankPasswordUse"
                $results["限制空白密碼遠端登入"] = ($null -eq $blank -or [int]$blank -eq 1)

                $idle = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MaxIdleTime"
                $results["閒置逾時已設定 (MaxIdleTime)"] = ($null -ne $idle -and [int]$idle -gt 0)

                $gpoEnc = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "MinEncryptionLevel"
                $results["加密等級已透過 GPO 設定"] = ($null -ne $gpoEnc -and [int]$gpoEnc -ge 3)
            }

            # --- 10. event log (stricter: check 3 logs + retention) ---
            10 {
                foreach ($logEntry in @(
                    @{ Name="Security"; Label="Security Log >= 200 MB"; Min=209715200 },
                    @{ Name="Application"; Label="Application Log >= 100 MB"; Min=104857600 },
                    @{ Name="System"; Label="System Log >= 100 MB"; Min=104857600 }
                )) {
                    try {
                        $info = wevtutil gl $logEntry.Name 2>&1 | Out-String
                        if ($info -match "maxSize:\s*(\d+)") {
                            $bytes = [long]$Matches[1]
                            $results[$logEntry.Label] = ($bytes -ge $logEntry.Min)
                        } else {
                            $results[$logEntry.Label] = $false
                        }
                    } catch {
                        $results[$logEntry.Label] = $false
                    }
                }
                # Retention: Security log must have retention=true (DoNotOverwrite)
                try {
                    $secInfo = wevtutil gl Security 2>&1 | Out-String
                    $results["保留原則已設定為不覆寫"] = ($secInfo -match "retention:\s*true")
                } catch {
                    $results["保留原則已設定為不覆寫"] = $false
                }
            }

            # --- 11. AD account management ---
            11 {
                try {
                    Import-Module ActiveDirectory -ErrorAction Stop
                    $guest = Get-ADUser -Identity "Guest" -Properties Enabled -ErrorAction Stop
                    $results["Guest Account Disabled"] = ($guest.Enabled -eq $false)
                } catch {
                    $results["Guest Account Disabled"] = $null
                }
                try {
                    Import-Module ActiveDirectory -ErrorAction Stop
                    $admins = Get-ADGroupMember "Domain Admins" -ErrorAction Stop
                    $results["No Extra Domain Admins"] = ($admins.Count -le 1)
                } catch {
                    $results["No Extra Domain Admins"] = $null
                }
                try {
                    Import-Module ActiveDirectory -ErrorAction Stop
                    $admin = Get-ADUser -Filter {SID -like "*-500"} -ErrorAction Stop
                    $results["Administrator Renamed"] = ($admin.SamAccountName -ne "Administrator")
                } catch {
                    $results["Administrator Renamed"] = $null
                }
            }

            # --- 12. Windows Defender (已移除，Server 2022 無此功能) ---
            12 {
                $results["此題已停用"] = $null
            }

            # --- 13. service management ---
            13 {
                foreach ($svc in @(
                    @{Name="RemoteRegistry"; Key="RemoteRegistry Stopped"},
                    @{Name="TlntSvr";       Key="Telnet Stopped"}
                )) {
                    try {
                        $s = Get-Service -Name $svc.Name -ErrorAction Stop
                        $results[$svc.Key] = ($s.Status -eq "Stopped" -and $s.StartType -eq "Disabled")
                    } catch {
                        $results[$svc.Key] = $true   # service not present = OK
                    }
                }
                $risky = @("SNMPTRAP","SSDPSRV","upnphost")
                $allGood = $true
                foreach ($r in $risky) {
                    try {
                        $s = Get-Service -Name $r -ErrorAction Stop
                        if ($s.Status -ne "Stopped") { $allGood = $false }
                    } catch { }
                }
                $results["Other Risky Services"] = $allGood

                # Print Spooler - running by default, known PrintNightmare vulnerability
                try {
                    $s = Get-Service -Name "Spooler" -ErrorAction Stop
                    $results["Print Spooler 已停用"] = ($s.Status -eq "Stopped" -and $s.StartType -eq "Disabled")
                } catch {
                    $results["Print Spooler 已停用"] = $true
                }

                # WinRM - running by default on Server
                try {
                    $s = Get-Service -Name "WinRM" -ErrorAction Stop
                    $results["Windows Remote Management 已停用"] = ($s.Status -eq "Stopped" -and $s.StartType -eq "Disabled")
                } catch {
                    $results["Windows Remote Management 已停用"] = $true
                }
            }

            # --- 14. UAC (stricter: also check ConsentPromptBehaviorAdmin = 2) ---
            14 {
                $v = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
                $results["EnableLUA = 1"] = ($null -ne $v -and [int]$v -eq 1)

                $v2 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin"
                $results["ConsentPromptBehaviorAdmin = 2"] = ($null -ne $v2 -and [int]$v2 -eq 2)

                $v3 = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "FilterAdministratorToken"
                $results["FilterAdministratorToken = 1"] = ($null -ne $v3 -and [int]$v3 -eq 1)
            }

            # --- 15. scheduled tasks ---
            15 {
                try {
                    $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object {
                        $_.TaskPath -notmatch "\\Microsoft\\" -and
                        $_.State -ne "Disabled"
                    }
                    $results["No Suspicious Tasks"] = ($null -eq $tasks -or $tasks.Count -eq 0)
                } catch {
                    $results["No Suspicious Tasks"] = $null
                }
            }

            # --- 16. shared folders (stricter: check for bad perms AND extra shares) ---
            16 {
                try {
                    $shares = Get-SmbShare -ErrorAction Stop | Where-Object {
                        $_.Name -notmatch '^\w\$' -and $_.Name -ne "IPC`$" -and $_.Name -ne "ADMIN`$"
                    }
                    # Check 1: no Everyone:FullControl
                    $bad = $false
                    foreach ($sh in $shares) {
                        try {
                            $access = Get-SmbShareAccess -Name $sh.Name -ErrorAction Stop
                            if ($access | Where-Object { $_.AccountName -match "Everyone|所有人" -and $_.AccessRight -eq "Full" }) {
                                $bad = $true; break
                            }
                        } catch { $bad = $true; break }
                    }
                    $results["無 Everyone:FullControl 共享"] = (-not $bad)
                    # Check 2: no extra custom shares (setup.ps1 creates OpenShare etc.)
                    $customShares = $shares | Where-Object { $_.Name -notmatch '^(NETLOGON|SYSVOL|print\$)$' }
                    $results["無多餘的自訂共享"] = ($null -eq $customShares -or @($customShares).Count -eq 0)
                } catch {
                    $results["無 Everyone:FullControl 共享"] = $false
                    $results["無多餘的自訂共享"] = $false
                }
                # Check 3: administrative shares disabled (AutoShareServer not set by default)
                $v = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "AutoShareServer"
                $results["已停用管理共享 (AutoShareServer)"] = ($null -ne $v -and [int]$v -eq 0)
            }

            # --- 17. IIS security (check if installed first) ---
            17 {
                $iisInstalled = $false
                try {
                    $iisFeat = Get-WindowsFeature -Name Web-Server -ErrorAction Stop
                    $iisInstalled = ($iisFeat.InstallState -eq "Installed")
                } catch { }
                $results["IIS 角色已安裝"] = $iisInstalled
                if ($iisInstalled) {
                    try {
                        Import-Module WebAdministration -ErrorAction Stop
                        $browse = Get-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -PSPath "IIS:\Sites\Default Web Site" -Name enabled -ErrorAction Stop
                        $results["目錄瀏覽已停用"] = ($browse.Value -eq $false)
                    } catch {
                        $results["目錄瀏覽已停用"] = $false
                    }
                } else {
                    $results["目錄瀏覽已停用"] = $false
                }
            }

            # --- 18. DNS security (stricter: fail if DNS not installed) ---
            18 {
                $dnsInstalled = $false
                try {
                    $dnsFeature = Get-WindowsFeature -Name DNS -ErrorAction Stop
                    $dnsInstalled = ($dnsFeature.InstallState -eq "Installed")
                } catch {
                    try {
                        Get-DnsServerZone -ErrorAction Stop | Out-Null
                        $dnsInstalled = $true
                    } catch {
                        $dnsInstalled = $false
                    }
                }

                $results["DNS 角色已安裝"] = $dnsInstalled
                if (-not $dnsInstalled) {
                    $results["Zone Transfer Disabled"] = $false
                    $results["已停用遞迴查詢 (Recursion)"] = $false
                } else {
                    try {
                        $zones = Get-DnsServerZone -ErrorAction Stop | Where-Object {
                            $_.IsReverseLookupZone -eq $false -and $_.ZoneType -ne "Forwarder"
                        }
                        $allGood = $true
                        foreach ($z in $zones) {
                            $zt = Get-DnsServerZone -Name $z.ZoneName -ErrorAction Stop
                            if ($zt.SecureSecondaries -ne "NoTransfer" -and $zt.SecureSecondaries -ne 3) {
                                $allGood = $false; break
                            }
                        }
                        $results["Zone Transfer Disabled"] = $allGood
                    } catch {
                        $results["Zone Transfer Disabled"] = $null
                    }
                    # Recursion should be disabled on authoritative DNS (enabled by default)
                    try {
                        $rec = Get-DnsServerRecursion -ErrorAction Stop
                        $results["已停用遞迴查詢 (Recursion)"] = ($rec.Enable -eq $false)
                    } catch {
                        $results["已停用遞迴查詢 (Recursion)"] = $null
                    }
                }
            }

            # --- 19. LDAP security (stricter: key must exist, default is NOT secure) ---
            19 {
                $v = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LDAPServerIntegrity"
                if ($null -eq $v) {
                    # Try alternative path
                    $v = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Services\ldap" "LDAPServerIntegrity"
                }
                # If key doesn't exist at all, FAIL (default is not secure)
                if ($null -eq $v) {
                    $results["LDAPServerIntegrity >= 2"] = $false
                } else {
                    $results["LDAPServerIntegrity >= 2"] = ([int]$v -ge 2)
                }
            }

            # --- 20. network authentication level ---
            20 {
                $v = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
                $results["LmCompatibilityLevel >= 3"] = ($null -ne $v -and [int]$v -ge 3)
            }

            # --- 22. PowerShell logging ---
            22 {
                $v = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
                $results["EnableScriptBlockLogging = 1"] = ($null -ne $v -and [int]$v -eq 1)
            }

            # --- 23. Windows Update (stricter: service running + GPO auto update configured) ---
            23 {
                $svcOk = $false
                try {
                    $s = Get-Service -Name wuauserv -ErrorAction Stop
                    $svcOk = ($s.Status -eq "Running")
                } catch {
                    $svcOk = $false
                }
                $results["wuauserv 服務執行中"] = $svcOk

                # AUOptions=4 means "Auto download and schedule install" (must be explicitly set)
                $auOpt = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions"
                $results["已設定自動更新 (GPO AUOptions = 4)"] = ($null -ne $auOpt -and [int]$auOpt -eq 4)

                # ScheduledInstallDay must be explicitly set (not present by default)
                $sched = Get-RegValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay"
                $results["WSUS 或自動更新排程已設定"] = ($null -ne $sched)
            }

            # --- 24. registry security ---
            24 {
                $v = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun"
                $results["NoDriveTypeAutoRun = 255"] = ($null -ne $v -and [int]$v -eq 255)

                $v = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoLMHash"
                $results["NoLMHash = 1"] = ($null -ne $v -and [int]$v -eq 1)

                $v = Get-RegValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD"
                $results["DisableCAD = 0"] = ($null -ne $v -and [int]$v -eq 0)

                # NtfsDisable8dot3NameCreation: default is 2 (volume-dependent), require 1 (disabled)
                $v = Get-RegValue "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" "NtfsDisable8dot3NameCreation"
                $results["已啟用 NtfsDisable8dot3NameCreation"] = ($null -ne $v -and [int]$v -eq 1)
            }

            default { $results["Unknown Challenge"] = $null }
        }
    } catch {
        $ch = $script:Challenges | Where-Object { $_.Id -eq $Id }
        if ($ch) {
            foreach ($ck in $ch.Checks) { $results[$ck] = $null }
        }
    }

    # Update state
    $state = $script:ChallengeState[$Id]
    $state.CheckResults = $results
    $passed = @($results.Values | Where-Object { $_ -eq $true }).Count
    $total  = $results.Count
    $warns  = @($results.Values | Where-Object { $_ -eq $null }).Count
    $state.PassedCount = $passed
    $state.TotalCount  = $total

    if ($warns -eq $total) {
        $state.Status = "Warning"
    } elseif ($passed -eq $total) {
        $state.Status = "Passed"
    } else {
        $state.Status = "Failed"
    }

    return $results
}

# ======================================================================
# SECTION 4 - XAML GUI DEFINITION
# ======================================================================

$xaml = @'
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Windows AD Security Hardening Platform"
    Width="1200" Height="800"
    WindowStartupLocation="CenterScreen"
    Background="#0a0a0a"
    ResizeMode="CanResizeWithGrip"
    FontFamily="Consolas">

    <Window.Resources>
        <!-- Glow button style -->
        <Style x:Key="GlowButton" TargetType="Button">
            <Setter Property="Background" Value="#1a1a2e"/>
            <Setter Property="Foreground" Value="#00ff41"/>
            <Setter Property="BorderBrush" Value="#00ff41"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="16,8"/>
            <Setter Property="FontFamily" Value="Consolas"/>
            <Setter Property="FontSize" Value="13"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="bd"
                                Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="4"
                                Padding="{TemplateBinding Padding}">
                            <Border.Effect>
                                <DropShadowEffect Color="#00ff41" BlurRadius="0" ShadowDepth="0" Opacity="0"/>
                            </Border.Effect>
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="#0f3d0f"/>
                                <Setter TargetName="bd" Property="Effect">
                                    <Setter.Value>
                                        <DropShadowEffect Color="#00ff41" BlurRadius="15" ShadowDepth="0" Opacity="0.7"/>
                                    </Setter.Value>
                                </Setter>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="#00ff41"/>
                                <Setter Property="Foreground" Value="#0a0a0a"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Cyan accent button -->
        <Style x:Key="CyanButton" TargetType="Button" BasedOn="{StaticResource GlowButton}">
            <Setter Property="Foreground" Value="#00d4ff"/>
            <Setter Property="BorderBrush" Value="#00d4ff"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="bd"
                                Background="#1a1a2e"
                                BorderBrush="#00d4ff"
                                BorderThickness="1"
                                CornerRadius="4"
                                Padding="{TemplateBinding Padding}">
                            <Border.Effect>
                                <DropShadowEffect Color="#00d4ff" BlurRadius="0" ShadowDepth="0" Opacity="0"/>
                            </Border.Effect>
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="#0f2d3d"/>
                                <Setter TargetName="bd" Property="Effect">
                                    <Setter.Value>
                                        <DropShadowEffect Color="#00d4ff" BlurRadius="15" ShadowDepth="0" Opacity="0.7"/>
                                    </Setter.Value>
                                </Setter>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="#00d4ff"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Red button -->
        <Style x:Key="RedButton" TargetType="Button" BasedOn="{StaticResource GlowButton}">
            <Setter Property="Foreground" Value="#ff0040"/>
            <Setter Property="BorderBrush" Value="#ff0040"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="bd"
                                Background="#1a1a2e"
                                BorderBrush="#ff0040"
                                BorderThickness="1"
                                CornerRadius="4"
                                Padding="{TemplateBinding Padding}">
                            <Border.Effect>
                                <DropShadowEffect Color="#ff0040" BlurRadius="0" ShadowDepth="0" Opacity="0"/>
                            </Border.Effect>
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="#3d0f1a"/>
                                <Setter TargetName="bd" Property="Effect">
                                    <Setter.Value>
                                        <DropShadowEffect Color="#ff0040" BlurRadius="15" ShadowDepth="0" Opacity="0.7"/>
                                    </Setter.Value>
                                </Setter>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- ScrollBar style for dark theme -->
        <Style TargetType="ScrollViewer">
            <Setter Property="Background" Value="Transparent"/>
        </Style>
    </Window.Resources>

    <Grid>
        <!-- Layer 0: Matrix Rain Canvas -->
        <Canvas x:Name="MatrixCanvas" ClipToBounds="True" IsHitTestVisible="False"/>

        <!-- Layer 1: Semi-transparent overlay for readability -->
        <Border Background="#0a0a0a" Opacity="0.82" IsHitTestVisible="False"/>

        <!-- Layer 2: Main Content -->
        <DockPanel>

            <!-- TOP BAR -->
            <Border DockPanel.Dock="Top" Background="#0d1117" BorderBrush="#00ff41" BorderThickness="0,0,0,1" Padding="20,12">
                <Border.Effect>
                    <DropShadowEffect Color="#00ff41" BlurRadius="10" ShadowDepth="0" Opacity="0.3"/>
                </Border.Effect>
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="Auto"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>

                    <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center">
                        <TextBlock Text="&#x1F6E1;&#xFE0F;" FontSize="22" VerticalAlignment="Center" Margin="0,0,10,0"/>
                        <TextBlock x:Name="TitleText" Text="WINDOWS AD SECURITY HARDENING" FontSize="18" FontWeight="Bold" Foreground="#00ff41" VerticalAlignment="Center">
                            <TextBlock.Effect>
                                <DropShadowEffect Color="#00ff41" BlurRadius="8" ShadowDepth="0" Opacity="0.6"/>
                            </TextBlock.Effect>
                        </TextBlock>
                    </StackPanel>

                    <StackPanel Grid.Column="1" Orientation="Vertical" Margin="40,0" VerticalAlignment="Center">
                        <ProgressBar x:Name="GlobalProgress" Height="8" Value="0" Maximum="100"
                                     Background="#1a1a2e" Foreground="#00ff41" BorderThickness="0"/>
                        <TextBlock x:Name="ProgressLabel" Text="0 / 23 challenges verified" Foreground="#555555" FontSize="10" Margin="0,4,0,0" HorizontalAlignment="Center"/>
                    </StackPanel>

                    <Border Grid.Column="2" Background="#1a1a2e" BorderBrush="#00ff41" BorderThickness="1" CornerRadius="6" Padding="16,6">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock Text="SCORE: " Foreground="#888888" FontSize="16" VerticalAlignment="Center"/>
                            <TextBlock x:Name="ScoreText" Text="0/0" FontSize="20" FontWeight="Bold" Foreground="#00ff41" VerticalAlignment="Center">
                                <TextBlock.Effect>
                                    <DropShadowEffect Color="#00ff41" BlurRadius="6" ShadowDepth="0" Opacity="0.5"/>
                                </TextBlock.Effect>
                            </TextBlock>
                        </StackPanel>
                    </Border>
                </Grid>
            </Border>

            <!-- BOTTOM BAR -->
            <Border DockPanel.Dock="Bottom" Background="#0d1117" BorderBrush="#00ff41" BorderThickness="0,1,0,0" Padding="20,10">
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="Auto"/>
                        <ColumnDefinition Width="Auto"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>

                    <Button x:Name="VerifyAllBtn" Grid.Column="0" Content="&#x26A1; Verify All" Style="{StaticResource GlowButton}" FontSize="14" Margin="0,0,12,0"/>
                    <Button x:Name="RefreshBtn" Grid.Column="1" Content="&#x1F504; Refresh" Style="{StaticResource CyanButton}" FontSize="14"/>

                    <TextBlock x:Name="StatusText" Grid.Column="3" Text="Ready..." Foreground="#555555" FontSize="12" VerticalAlignment="Center"/>
                </Grid>
            </Border>

            <!-- MAIN CARD AREA -->
            <ScrollViewer VerticalScrollBarVisibility="Auto" Padding="10">
                <WrapPanel x:Name="CardPanel" Orientation="Horizontal" Margin="10" ItemWidth="275" ItemHeight="210"/>
            </ScrollViewer>

        </DockPanel>
    </Grid>
</Window>
'@

# ======================================================================
# SECTION 5 - BUILD WINDOW & BIND NAMED ELEMENTS
# ======================================================================

$reader  = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
$script:Window = [System.Windows.Markup.XamlReader]::Load($reader)

# CRITICAL: Bind ALL named XAML elements to $script: variables using FindName
$script:MatrixCanvas   = $script:Window.FindName("MatrixCanvas")
$script:CardPanel      = $script:Window.FindName("CardPanel")
$script:GlobalProgress = $script:Window.FindName("GlobalProgress")
$script:ProgressLabel  = $script:Window.FindName("ProgressLabel")
$script:ScoreText      = $script:Window.FindName("ScoreText")
$script:VerifyAllBtn   = $script:Window.FindName("VerifyAllBtn")
$script:RefreshBtn     = $script:Window.FindName("RefreshBtn")
$script:StatusText     = $script:Window.FindName("StatusText")

# ======================================================================
# SECTION 6 - MATRIX RAIN ANIMATION
# ======================================================================

$script:MatrixColumns   = @()
$script:MatrixFontSize  = 14
$script:MatrixChars     = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZアイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン"
$script:MatrixRandom    = [System.Random]::new()

function global:Initialize-MatrixColumns {
    $cols = [Math]::Ceiling($script:MatrixCanvas.ActualWidth / $script:MatrixFontSize)
    if ($cols -le 0) { $cols = 80 }
    $script:MatrixColumns = @()
    for ($i = 0; $i -lt $cols; $i++) {
        $script:MatrixColumns += @{
            Y      = $script:MatrixRandom.Next(-40, 0) * $script:MatrixFontSize
            Speed  = $script:MatrixRandom.Next(2, 7)
            Length = $script:MatrixRandom.Next(8, 28)
        }
    }
}

$script:MatrixTimer = [System.Windows.Threading.DispatcherTimer]::new()
$script:MatrixTimer.Interval = [TimeSpan]::FromMilliseconds(50)
$script:MatrixTimer.Add_Tick({
    $canvas = $script:MatrixCanvas
    $canvas.Children.Clear()

    $canvasH = $canvas.ActualHeight
    $canvasW = $canvas.ActualWidth
    if ($canvasH -le 0 -or $canvasW -le 0) { return }

    $fontSize = $script:MatrixFontSize
    $chars    = $script:MatrixChars
    $rnd      = $script:MatrixRandom

    for ($i = 0; $i -lt $script:MatrixColumns.Count; $i++) {
        $col = $script:MatrixColumns[$i]
        $x   = $i * $fontSize

        for ($j = 0; $j -lt $col.Length; $j++) {
            $y = $col.Y - $j * $fontSize
            if ($y -lt -$fontSize -or $y -gt $canvasH) { continue }

            $ch = $chars[$rnd.Next($chars.Length)]
            $tb = [System.Windows.Controls.TextBlock]::new()
            $tb.Text     = [string]$ch
            $tb.FontSize = $fontSize
            $tb.FontFamily = [System.Windows.Media.FontFamily]::new("Consolas")

            if ($j -eq 0) {
                $tb.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Color]::FromArgb(230, 0, 255, 65))
            } else {
                $alpha = [Math]::Max(0, [int](180 * (1 - $j / $col.Length)))
                $green = [Math]::Max(40, [int](255 * (1 - $j / $col.Length)))
                $tb.Foreground = [System.Windows.Media.SolidColorBrush]::new(
                    [System.Windows.Media.Color]::FromArgb($alpha, 0, $green, 20)
                )
            }

            [System.Windows.Controls.Canvas]::SetLeft($tb, $x)
            [System.Windows.Controls.Canvas]::SetTop($tb, $y)
            $canvas.Children.Add($tb) | Out-Null
        }

        $col.Y += $col.Speed
        if (($col.Y - $col.Length * $fontSize) -gt $canvasH) {
            $col.Y     = -$fontSize * $rnd.Next(3, 15)
            $col.Speed = $rnd.Next(2, 7)
            $col.Length = $rnd.Next(8, 28)
        }
    }
})

# Reinitialize on resize
$script:Window.Add_SizeChanged({ Initialize-MatrixColumns })

# ======================================================================
# SECTION 7 - CARD UI UPDATE FUNCTIONS (global: scope)
# ======================================================================

$script:CardControls = @{}

function global:Update-CardUI {
    param([int]$Id)
    $state = $script:ChallengeState[$Id]
    $ctrl  = $script:CardControls[$Id]
    if (-not $ctrl) { return }

    $passed = $state.PassedCount
    $total  = $state.TotalCount

    switch ($state.Status) {
        "Passed" {
            $ctrl.StatusBlock.Text = [char]0x2705 + " Passed"
            $ctrl.StatusBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#00ff41"))
            $ctrl.Badge.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#00ff41"))
            $ctrl.Card.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#00ff41"))
        }
        "Failed" {
            $ctrl.StatusBlock.Text = [char]0x274C + " Failed"
            $ctrl.StatusBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#ff0040"))
            $ctrl.Badge.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#ff0040"))
            $ctrl.Card.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#ff0040"))
        }
        "Warning" {
            $ctrl.StatusBlock.Text = [char]0x26A0 + " Warning"
            $ctrl.StatusBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#ffaa00"))
            $ctrl.Badge.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#ffaa00"))
            $ctrl.Card.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#ffaa00"))
        }
        default {
            $ctrl.StatusBlock.Text = [char]0x23F3 + " Pending"
            $ctrl.StatusBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#888888"))
        }
    }
    $ctrl.ChecksBlock.Text = "$passed/$total checks passed"
    if ($passed -eq $total -and $total -gt 0) {
        $ctrl.ChecksBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#00ff41"))
    } elseif ($passed -gt 0) {
        $ctrl.ChecksBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#ffaa00"))
    } else {
        $ctrl.ChecksBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#555555"))
    }
}

function global:Update-GlobalStats {
    $verified  = 0
    $totalPass = 0
    $totalAll  = 0
    foreach ($c in $script:Challenges) {
        $s = $script:ChallengeState[$c.Id]
        if ($s.Status -ne "Pending") { $verified++ }
        $totalPass += $s.PassedCount
        $totalAll  += $s.TotalCount
    }
    $pct = if ($script:Challenges.Count -gt 0) { [Math]::Round($verified / $script:Challenges.Count * 100) } else { 0 }
    $script:GlobalProgress.Value = $pct
    $script:ProgressLabel.Text   = "$verified / $($script:Challenges.Count) challenges verified"
    $script:ScoreText.Text       = "$totalPass/$totalAll"
}

function global:Show-DetailPopup {
    param([int]$Id)

    $ch    = $script:Challenges | Where-Object { $_.Id -eq $Id }
    $state = $script:ChallengeState[$Id]
    if (-not $ch) { return }

    $popup = [System.Windows.Window]::new()
    $popup.Title = "Challenge #$Id - $($ch.Title)"
    $popup.Width  = 520
    $popup.SizeToContent = "Height"
    $popup.MaxHeight = 600
    $popup.WindowStartupLocation = "CenterOwner"
    $popup.Owner       = $script:Window
    $popup.Background  = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#0d1117"))
    $popup.Foreground  = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Colors]::White)
    $popup.FontFamily  = [System.Windows.Media.FontFamily]::new("Consolas")
    $popup.ResizeMode  = "NoResize"
    $popup.WindowStyle = "None"
    $popup.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#00ff41"))
    $popup.BorderThickness = [System.Windows.Thickness]::new(1)
    $popup.AllowsTransparency = $false

    $mainStack = [System.Windows.Controls.StackPanel]::new()
    $mainStack.Margin = [System.Windows.Thickness]::new(20)

    # Header
    $header = [System.Windows.Controls.TextBlock]::new()
    $header.Text = "[ Challenge #$Id ] $($ch.Title)"
    $header.FontSize = 16
    $header.FontWeight = [System.Windows.FontWeights]::Bold
    $header.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#00ff41"))
    $header.Margin = [System.Windows.Thickness]::new(0,0,0,6)
    $mainStack.Children.Add($header) | Out-Null

    # Category
    $catBlock = [System.Windows.Controls.TextBlock]::new()
    $catBlock.Text = "Category: $($ch.Category)"
    $catBlock.FontSize = 12
    $catBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($ch.Color))
    $catBlock.Margin = [System.Windows.Thickness]::new(0,0,0,14)
    $mainStack.Children.Add($catBlock) | Out-Null

    # Separator
    $sep = [System.Windows.Controls.Border]::new()
    $sep.Height = 1
    $sep.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#1e2a1e"))
    $sep.Margin = [System.Windows.Thickness]::new(0,0,0,14)
    $mainStack.Children.Add($sep) | Out-Null

    # Check results
    if ($state.CheckResults.Count -eq 0) {
        $noData = [System.Windows.Controls.TextBlock]::new()
        $noData.Text = "No verification data. Click 'Verify' first."
        $noData.FontSize = 12
        $noData.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#888888"))
        $noData.Margin = [System.Windows.Thickness]::new(0,0,0,10)
        $mainStack.Children.Add($noData) | Out-Null
    } else {
        foreach ($key in $state.CheckResults.Keys) {
            $val = $state.CheckResults[$key]
            $row = [System.Windows.Controls.StackPanel]::new()
            $row.Orientation = "Horizontal"
            $row.Margin = [System.Windows.Thickness]::new(0,0,0,8)

            $icon = [System.Windows.Controls.TextBlock]::new()
            $icon.FontSize = 14
            $icon.Width = 26
            $nameBlock = [System.Windows.Controls.TextBlock]::new()
            $nameBlock.FontSize = 13
            $nameBlock.VerticalAlignment = "Center"
            $nameBlock.TextWrapping = "Wrap"
            $nameBlock.MaxWidth = 420

            if ($val -eq $true) {
                $icon.Text = [char]0x2705
                $nameBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#00ff41"))
            } elseif ($val -eq $false) {
                $icon.Text = [char]0x274C
                $nameBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#ff0040"))
            } else {
                $icon.Text = [char]0x26A0
                $nameBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#ffaa00"))
            }

            $nameBlock.Text = $key

            $row.Children.Add($icon) | Out-Null
            $row.Children.Add($nameBlock) | Out-Null
            $mainStack.Children.Add($row) | Out-Null
        }
    }

    # Separator
    $sep2 = [System.Windows.Controls.Border]::new()
    $sep2.Height = 1
    $sep2.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#1e2a1e"))
    $sep2.Margin = [System.Windows.Thickness]::new(0,14,0,14)
    $mainStack.Children.Add($sep2) | Out-Null

    # Close button - capture $popup in closure
    $closeBtn = [System.Windows.Controls.Button]::new()
    $closeBtn.Content  = "Close"
    $closeBtn.FontFamily = [System.Windows.Media.FontFamily]::new("Consolas")
    $closeBtn.FontSize = 13
    $closeBtn.Foreground  = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#ff0040"))
    $closeBtn.Background  = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#1a1a2e"))
    $closeBtn.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#ff0040"))
    $closeBtn.BorderThickness = [System.Windows.Thickness]::new(1)
    $closeBtn.Padding  = [System.Windows.Thickness]::new(20,6,20,6)
    $closeBtn.HorizontalAlignment = "Right"
    $closeBtn.Cursor = [System.Windows.Input.Cursors]::Hand
    $popupRef = $popup
    $closeBtn.Add_Click({ $popupRef.Close() }.GetNewClosure())
    $mainStack.Children.Add($closeBtn) | Out-Null

    # Allow dragging
    $mainStack.Add_MouseLeftButtonDown({
        param($s,$e)
        try { $popupRef.DragMove() } catch {}
    }.GetNewClosure())

    $scrollView = [System.Windows.Controls.ScrollViewer]::new()
    $scrollView.VerticalScrollBarVisibility = "Auto"
    $scrollView.Content = $mainStack

    $popup.Content = $scrollView
    $popup.ShowDialog() | Out-Null
}

# ======================================================================
# SECTION 8 - DYNAMIC CARD GENERATION (global: scope)
# ======================================================================

function global:New-ChallengeCard {
    param($Challenge)

    $id    = $Challenge.Id
    $cat   = $Challenge.Category
    $clr   = $Challenge.Color
    $title = $Challenge.Title
    $total = $Challenge.Checks.Count

    # Outer card border
    $card = [System.Windows.Controls.Border]::new()
    $card.Width       = 255
    $card.Height      = 190
    $card.Margin      = [System.Windows.Thickness]::new(8)
    $card.Padding     = [System.Windows.Thickness]::new(14)
    $card.CornerRadius = [System.Windows.CornerRadius]::new(8)
    $card.BorderThickness = [System.Windows.Thickness]::new(1)
    $card.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#1e2a1e"))
    $card.Background  = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#0d1117"))
    $card.Cursor      = [System.Windows.Input.Cursors]::Hand

    # Glow effect (subtle)
    $shadow = [System.Windows.Media.Effects.DropShadowEffect]::new()
    $shadow.Color       = [System.Windows.Media.ColorConverter]::ConvertFromString("#00ff41")
    $shadow.BlurRadius  = 4
    $shadow.ShadowDepth = 0
    $shadow.Opacity     = 0.15
    $card.Effect = $shadow

    # Hover effect
    $card.Add_MouseEnter({
        param($sender, $e)
        $eff = $sender.Effect
        $eff.BlurRadius = 18
        $eff.Opacity    = 0.5
        $sender.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#00ff41"))
    })
    $card.Add_MouseLeave({
        param($sender, $e)
        $eff = $sender.Effect
        $eff.BlurRadius = 4
        $eff.Opacity    = 0.15
        $sender.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#1e2a1e"))
    })

    # Inner layout
    $stack = [System.Windows.Controls.StackPanel]::new()

    # -- Row 1: Badge + Title --
    $headerPanel = [System.Windows.Controls.DockPanel]::new()

    $badge = [System.Windows.Controls.Border]::new()
    $badge.Width  = 30
    $badge.Height = 30
    $badge.CornerRadius = [System.Windows.CornerRadius]::new(15)
    $badge.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#00ff41"))
    $badge.Margin = [System.Windows.Thickness]::new(0,0,10,0)
    $badgeText = [System.Windows.Controls.TextBlock]::new()
    $badgeText.Text = "$id"
    $badgeText.FontSize = 13
    $badgeText.FontWeight = [System.Windows.FontWeights]::Bold
    $badgeText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#0a0a0a"))
    $badgeText.HorizontalAlignment = "Center"
    $badgeText.VerticalAlignment   = "Center"
    $badge.Child = $badgeText
    [System.Windows.Controls.DockPanel]::SetDock($badge, "Left")
    $headerPanel.Children.Add($badge) | Out-Null

    $titleBlock = [System.Windows.Controls.TextBlock]::new()
    $titleBlock.Text = $title
    $titleBlock.FontSize = 14
    $titleBlock.FontWeight = [System.Windows.FontWeights]::Bold
    $titleBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.Colors]::White)
    $titleBlock.VerticalAlignment = "Center"
    $titleBlock.TextTrimming = "CharacterEllipsis"
    $headerPanel.Children.Add($titleBlock) | Out-Null

    $stack.Children.Add($headerPanel) | Out-Null

    # -- Row 2: Category tag --
    $tagBorder = [System.Windows.Controls.Border]::new()
    $tagBorder.Background   = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($clr + "33"))
    $tagBorder.BorderBrush  = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($clr))
    $tagBorder.BorderThickness = [System.Windows.Thickness]::new(1)
    $tagBorder.CornerRadius = [System.Windows.CornerRadius]::new(4)
    $tagBorder.Padding      = [System.Windows.Thickness]::new(8,2,8,2)
    $tagBorder.Margin       = [System.Windows.Thickness]::new(0,8,0,0)
    $tagBorder.HorizontalAlignment = "Left"
    $tagText = [System.Windows.Controls.TextBlock]::new()
    $tagText.Text = $cat
    $tagText.FontSize = 11
    $tagText.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($clr))
    $tagBorder.Child = $tagText
    $stack.Children.Add($tagBorder) | Out-Null

    # -- Row 3: Status --
    $statusBlock = [System.Windows.Controls.TextBlock]::new()
    $statusBlock.Text = [char]0x23F3 + " Pending"
    $statusBlock.FontSize = 13
    $statusBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#888888"))
    $statusBlock.Margin = [System.Windows.Thickness]::new(0,8,0,0)
    $stack.Children.Add($statusBlock) | Out-Null

    # -- Row 4: Sub-checks count --
    $checksBlock = [System.Windows.Controls.TextBlock]::new()
    $checksBlock.Text = "0/$total checks"
    $checksBlock.FontSize = 11
    $checksBlock.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#555555"))
    $checksBlock.Margin = [System.Windows.Thickness]::new(0,4,0,0)
    $stack.Children.Add($checksBlock) | Out-Null

    # -- Row 5: Buttons --
    $btnPanel = [System.Windows.Controls.StackPanel]::new()
    $btnPanel.Orientation = "Horizontal"
    $btnPanel.Margin      = [System.Windows.Thickness]::new(0,10,0,0)

    # Verify button - capture $id in closure properly
    $verifyBtn = [System.Windows.Controls.Button]::new()
    $verifyBtn.Content = "Verify"
    $verifyBtn.FontFamily = [System.Windows.Media.FontFamily]::new("Consolas")
    $verifyBtn.FontSize = 12
    $verifyBtn.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#00ff41"))
    $verifyBtn.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#1a1a2e"))
    $verifyBtn.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#00ff41"))
    $verifyBtn.BorderThickness = [System.Windows.Thickness]::new(1)
    $verifyBtn.Padding    = [System.Windows.Thickness]::new(14,4,14,4)
    $verifyBtn.Cursor     = [System.Windows.Input.Cursors]::Hand
    $verifyBtn.Tag        = $id

    # CRITICAL: Use captured $id variable and call global: functions
    $capturedId = $id
    $verifyBtn.Add_Click({
        param($sender, $e)
        $e.Handled = $true
        $cid = $capturedId
        $script:StatusText.Text = "Verifying challenge #$cid ..."
        $script:Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background, [Action]{})
        Verify-Challenge -Id $cid | Out-Null
        Update-CardUI -Id $cid
        Update-GlobalStats
        $script:StatusText.Text = "Last verified: #$cid $(Get-Date -Format 'HH:mm:ss')"
    }.GetNewClosure())
    $btnPanel.Children.Add($verifyBtn) | Out-Null

    # Details button
    $detailBtn = [System.Windows.Controls.Button]::new()
    $detailBtn.Content = "Details"
    $detailBtn.FontFamily = [System.Windows.Media.FontFamily]::new("Consolas")
    $detailBtn.FontSize = 12
    $detailBtn.Foreground = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#00d4ff"))
    $detailBtn.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#1a1a2e"))
    $detailBtn.BorderBrush = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString("#00d4ff"))
    $detailBtn.BorderThickness = [System.Windows.Thickness]::new(1)
    $detailBtn.Padding    = [System.Windows.Thickness]::new(14,4,14,4)
    $detailBtn.Margin     = [System.Windows.Thickness]::new(8,0,0,0)
    $detailBtn.Cursor     = [System.Windows.Input.Cursors]::Hand
    $detailBtn.Tag        = $id

    $detailBtn.Add_Click({
        param($sender, $e)
        $e.Handled = $true
        Show-DetailPopup -Id $capturedId
    }.GetNewClosure())
    $btnPanel.Children.Add($detailBtn) | Out-Null

    $stack.Children.Add($btnPanel) | Out-Null
    $card.Child = $stack

    # Store references for later UI updates
    $script:CardControls[$id] = @{
        Card        = $card
        StatusBlock = $statusBlock
        ChecksBlock = $checksBlock
        Badge       = $badge
    }

    return $card
}

# ======================================================================
# SECTION 9 - POPULATE CARDS & WIRE EVENTS
# ======================================================================

foreach ($ch in $script:Challenges) {
    $card = New-ChallengeCard -Challenge $ch
    $script:CardPanel.Children.Add($card) | Out-Null
}

# -- Verify All Button ---------------------------------------------------
$script:VerifyAllBtn.Add_Click({
    $script:VerifyAllBtn.IsEnabled = $false
    $script:StatusText.Text = "Running all verifications..."
    $script:Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background, [Action]{})

    $count = 0
    foreach ($ch in $script:Challenges) {
        $count++
        $script:StatusText.Text = "Verifying [$count/$($script:Challenges.Count)] $($ch.Title)..."
        $script:Window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background, [Action]{})

        Verify-Challenge -Id $ch.Id | Out-Null
        Update-CardUI -Id $ch.Id
        Update-GlobalStats
    }

    $script:StatusText.Text = "All verified at $(Get-Date -Format 'HH:mm:ss')"
    $script:VerifyAllBtn.IsEnabled = $true
})

# -- Refresh Button -------------------------------------------------------
$script:RefreshBtn.Add_Click({
    foreach ($c in $script:Challenges) {
        $script:ChallengeState[$c.Id] = @{
            Status       = "Pending"
            CheckResults = @{}
            PassedCount  = 0
            TotalCount   = $c.Checks.Count
        }
        Update-CardUI -Id $c.Id
    }
    Update-GlobalStats
    $script:SeceditCache = $null
    $script:StatusText.Text = "Reset - Ready..."
})

# ======================================================================
# SECTION 10 - LAUNCH
# ======================================================================

$script:Window.Add_ContentRendered({
    Initialize-MatrixColumns
    $script:MatrixTimer.Start()
})

$script:Window.Add_Closed({
    $script:MatrixTimer.Stop()
    if (Test-Path $script:SeceditTempFile) {
        Remove-Item $script:SeceditTempFile -Force -ErrorAction SilentlyContinue
    }
})

# Show the window
$script:Window.ShowDialog() | Out-Null
