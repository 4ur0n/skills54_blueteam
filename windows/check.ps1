#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows AD 安全強化模擬測驗 - 自動計分腳本
.DESCRIPTION
    檢查 Windows Server / AD 環境的安全設定是否正確配置。
    涵蓋密碼策略、帳戶鎖定、安全性選項、SMB、稽核、防火牆、
    遠端桌面、事件記錄、AD 帳號、Defender、服務、UAC、排程任務、
    共享、IIS、DNS、LDAP、網路驗證、PowerShell 日誌、Windows Update、登錄檔安全等。
.NOTES
    必須以系統管理員身分執行
    適用於 Windows Server 2016/2019/2022（含 AD DS 角色）
#>

# ============================
# 初始設定
# ============================

# 設定編碼以正確顯示中文和特殊符號
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# 嚴格模式：未定義變數不會導致錯誤（因為我們需要容錯）
$ErrorActionPreference = 'SilentlyContinue'

# ── 檢查是否以系統管理員身分執行 ──
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "  [!!] 此腳本必須以系統管理員身分執行！" -ForegroundColor Red
    Write-Host "  請右鍵 PowerShell → 以系統管理員身分執行" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# ============================
# 計分用全域變數
# ============================
$script:totalPass  = 0
$script:totalFail  = 0
$script:totalWarn  = 0
$script:totalCheck = 0
$script:catPass    = 0
$script:catTotal   = 0

# ============================
# 輔助函式
# ============================

function Show-Banner {
    <# 顯示標題橫幅 #>
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║       Windows AD 安全強化模擬測驗 - 計分板              ║" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║  檢查日期：$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')                        ║" -ForegroundColor Cyan
    Write-Host "  ║  電腦名稱：$($env:COMPUTERNAME.PadRight(40))║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Show-CategoryHeader {
    <# 顯示分類標題 #>
    param([string]$Title)
    Write-Host ""
    Write-Host "  ── $Title ──────────────────────────────────────" -ForegroundColor White
    Write-Host ""
    # 重設分類計數
    $script:catPass  = 0
    $script:catTotal = 0
}

function Show-CategoryFooter {
    <# 顯示分類小計 #>
    $color = if ($script:catPass -eq $script:catTotal) { "Green" }
             elseif ($script:catPass -ge ($script:catTotal / 2)) { "Yellow" }
             else { "Red" }
    Write-Host ""
    Write-Host "  小計：$($script:catPass) / $($script:catTotal)" -ForegroundColor $color
    Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor DarkGray
}

function Report-Check {
    <#
    .SYNOPSIS
        報告單項檢查結果
    .PARAMETER Id
        檢查編號（如 "1.1"）
    .PARAMETER Name
        檢查名稱
    .PARAMETER Result
        $true = 通過, $false = 未通過, $null = 無法檢查
    #>
    param(
        [string]$Id,
        [string]$Name,
        [object]$Result
    )

    $script:totalCheck++
    $script:catTotal++

    if ($Result -eq $true) {
        Write-Host "  [✅] $Id $Name" -ForegroundColor Green
        $script:totalPass++
        $script:catPass++
    }
    elseif ($Result -eq $false) {
        Write-Host "  [❌] $Id $Name" -ForegroundColor Red
        $script:totalFail++
    }
    else {
        Write-Host "  [⚠️] $Id $Name （無法檢查）" -ForegroundColor Yellow
        $script:totalWarn++
    }
}

function Get-RegistryValue {
    <# 安全地讀取登錄檔值 #>
    param(
        [string]$Path,
        [string]$Name
    )
    try {
        $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $val.$Name
    }
    catch {
        return $null
    }
}

# ============================
# 匯出 secedit 安全性設定（用來檢查密碼策略等）
# ============================
$seceditFile = "$env:TEMP\secedit_export.inf"
try {
    secedit /export /cfg $seceditFile /quiet 2>$null | Out-Null
    $seceditContent = Get-Content $seceditFile -ErrorAction Stop
}
catch {
    $seceditContent = @()
    Write-Host "  [⚠️] 無法匯出 secedit 安全性設定" -ForegroundColor Yellow
}

function Get-SeceditValue {
    <# 從 secedit 匯出檔中取得設定值 #>
    param([string]$Key)
    foreach ($line in $seceditContent) {
        if ($line -match "^\s*$Key\s*=\s*(.+)$") {
            return $Matches[1].Trim()
        }
    }
    return $null
}

# ============================
# 開始計分
# ============================

Show-Banner

# ============================================================
# 分類一：歷屆必考題（8 大題）
# ============================================================
Show-CategoryHeader "分類一：歷屆必考題"

# ── 1. 密碼策略 ──

# 1.1 密碼最小長度 >= 8
$minPwdLen = Get-SeceditValue "MinimumPasswordLength"
if ($null -ne $minPwdLen) {
    Report-Check "1.1" "密碼最小長度 >= 8（目前：$minPwdLen）" ([int]$minPwdLen -ge 8)
} else {
    Report-Check "1.1" "密碼最小長度 >= 8" $null
}

# 1.2 密碼複雜性需求已啟用
$complexity = Get-SeceditValue "PasswordComplexity"
if ($null -ne $complexity) {
    Report-Check "1.2" "密碼複雜性需求已啟用（目前：$complexity）" ([int]$complexity -eq 1)
} else {
    Report-Check "1.2" "密碼複雜性需求已啟用" $null
}

# 1.3 密碼最長使用期限 <= 90 天
$maxPwdAge = Get-SeceditValue "MaximumPasswordAge"
if ($null -ne $maxPwdAge) {
    Report-Check "1.3" "密碼最長使用期限 <= 90 天（目前：$maxPwdAge 天）" (([int]$maxPwdAge -le 90) -and ([int]$maxPwdAge -gt 0))
} else {
    Report-Check "1.3" "密碼最長使用期限 <= 90 天" $null
}

# 1.4 強制密碼歷程記錄 >= 5 組
$pwdHistory = Get-SeceditValue "PasswordHistorySize"
if ($null -ne $pwdHistory) {
    Report-Check "1.4" "強制密碼歷程記錄 >= 5 組（目前：$pwdHistory）" ([int]$pwdHistory -ge 5)
} else {
    Report-Check "1.4" "強制密碼歷程記錄 >= 5 組" $null
}

# 1.5 停用可還原加密來存放密碼
$reversible = Get-SeceditValue "ClearTextPassword"
if ($null -ne $reversible) {
    Report-Check "1.5" "可還原加密已停用（目前：$reversible）" ([int]$reversible -eq 0)
} else {
    Report-Check "1.5" "可還原加密已停用" $null
}

# ── 2. 帳戶鎖定原則 ──

# 2.1 帳戶鎖定閾值 3-5 次
$lockoutThreshold = Get-SeceditValue "LockoutBadCount"
if ($null -ne $lockoutThreshold) {
    $lt = [int]$lockoutThreshold
    Report-Check "2.1" "帳戶鎖定閾值 3-5 次（目前：$lt）" (($lt -ge 3) -and ($lt -le 5))
} else {
    Report-Check "2.1" "帳戶鎖定閾值 3-5 次" $null
}

# 2.2 帳戶鎖定時間 >= 30 分鐘
$lockoutDuration = Get-SeceditValue "LockoutDuration"
if ($null -ne $lockoutDuration) {
    Report-Check "2.2" "帳戶鎖定時間 >= 30 分鐘（目前：$lockoutDuration 分鐘）" ([int]$lockoutDuration -ge 30)
} else {
    Report-Check "2.2" "帳戶鎖定時間 >= 30 分鐘" $null
}

# 2.3 重設帳戶鎖定計數器 >= 30 分鐘
$resetCounter = Get-SeceditValue "ResetLockoutCount"
if ($null -ne $resetCounter) {
    Report-Check "2.3" "重設鎖定計數器 >= 30 分鐘（目前：$resetCounter 分鐘）" ([int]$resetCounter -ge 30)
} else {
    Report-Check "2.3" "重設鎖定計數器 >= 30 分鐘" $null
}

# ── 3. 安全性選項 ──

# 3.1 互動式登入：要求 CTRL+ALT+DEL（DisableCAD = 0）
$disableCAD = Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD"
if ($null -ne $disableCAD) {
    Report-Check "3.1" "要求 CTRL+ALT+DEL 登入（DisableCAD=0，目前：$disableCAD）" ([int]$disableCAD -eq 0)
} else {
    # 預設未設定視為啟用 CTRL+ALT+DEL
    Report-Check "3.1" "要求 CTRL+ALT+DEL 登入（機碼不存在，預設可能未設定）" $null
}

# 3.2 不顯示上次登入的使用者名稱
$dontDisplayLast = Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName"
if ($null -ne $dontDisplayLast) {
    Report-Check "3.2" "不顯示上次登入的使用者名稱（目前：$dontDisplayLast）" ([int]$dontDisplayLast -eq 1)
} else {
    Report-Check "3.2" "不顯示上次登入的使用者名稱" $null
}

# 3.3 密碼到期前提示 >= 7 天
$pwdExpiryWarn = Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "PasswordExpiryWarning"
if ($null -ne $pwdExpiryWarn) {
    Report-Check "3.3" "密碼到期前提示天數 >= 7（目前：$pwdExpiryWarn 天）" ([int]$pwdExpiryWarn -ge 7)
} else {
    # Windows 預設 5 天，如果沒有設定就視為可能不足
    Report-Check "3.3" "密碼到期前提示天數 >= 7（未設定，預設 5 天）" $false
}

# 3.4 Guest 帳戶停用
$guestEnabled = Get-SeceditValue "EnableGuestAccount"
if ($null -ne $guestEnabled) {
    Report-Check "3.4" "Guest 帳戶已停用（目前：$guestEnabled）" ([int]$guestEnabled -eq 0)
} else {
    # 嘗試用 WMI 檢查
    try {
        $guestAcct = Get-WmiObject Win32_UserAccount -Filter "Name='Guest' AND LocalAccount=True" -ErrorAction Stop
        Report-Check "3.4" "Guest 帳戶已停用" ($guestAcct.Disabled -eq $true)
    } catch {
        Report-Check "3.4" "Guest 帳戶已停用" $null
    }
}

# 3.5 空白密碼限制（限制使用空白密碼的本機帳戶僅能從主控台登入）
$limitBlankPwd = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse"
if ($null -ne $limitBlankPwd) {
    Report-Check "3.5" "空白密碼限制已啟用（目前：$limitBlankPwd）" ([int]$limitBlankPwd -eq 1)
} else {
    Report-Check "3.5" "空白密碼限制已啟用" $null
}

# ── 4. SMB 安全 ──

# 4.1 SMB 簽署（伺服器端要求簽署）
$smbSignReq = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RequireSecuritySignature"
if ($null -ne $smbSignReq) {
    Report-Check "4.1" "SMB 伺服器端要求數位簽署（目前：$smbSignReq）" ([int]$smbSignReq -eq 1)
} else {
    # 嘗試用 SMB cmdlet
    try {
        $smbConfig = Get-SmbServerConfiguration -ErrorAction Stop
        Report-Check "4.1" "SMB 伺服器端要求數位簽署" ($smbConfig.RequireSecuritySignature -eq $true)
    } catch {
        Report-Check "4.1" "SMB 伺服器端要求數位簽署" $null
    }
}

# 4.2 SMBv1 已停用
try {
    $smbConfig2 = Get-SmbServerConfiguration -ErrorAction Stop
    $smb1Disabled = ($smbConfig2.EnableSMB1Protocol -eq $false)
    Report-Check "4.2" "SMBv1 已停用" $smb1Disabled
} catch {
    # 透過登錄檔檢查
    $smb1Reg = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1"
    if ($null -ne $smb1Reg) {
        Report-Check "4.2" "SMBv1 已停用（登錄檔值：$smb1Reg）" ([int]$smb1Reg -eq 0)
    } else {
        # 檢查 Windows Feature
        try {
            $smb1Feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
            Report-Check "4.2" "SMBv1 已停用" ($smb1Feature.State -eq "Disabled")
        } catch {
            Report-Check "4.2" "SMBv1 已停用" $null
        }
    }
}

# ── 5. 稽核策略（所有類別都啟用成功+失敗）──
# 使用 auditpol 取得所有類別
try {
    $auditOutput = auditpol /get /category:* 2>&1
    # 計算「No Auditing」出現次數（不含標題行）
    $noAuditCount = ($auditOutput | Select-String -Pattern "No Auditing").Count
    # 計算「Success and Failure」出現次數
    $successFailCount = ($auditOutput | Select-String -Pattern "Success and Failure").Count
    # 取得所有稽核項目數（排除空行和標題）
    $auditItems = ($auditOutput | Select-String -Pattern "(Success|Failure|No Auditing)").Count

    $allAudited = ($noAuditCount -eq 0) -and ($successFailCount -eq $auditItems) -and ($auditItems -gt 0)
    Report-Check "5.1" "稽核策略：所有類別啟用成功+失敗（無稽核項：$noAuditCount，完整稽核項：$successFailCount/$auditItems）" $allAudited
} catch {
    Report-Check "5.1" "稽核策略：所有類別啟用成功+失敗" $null
}

# ── 6. 防火牆：三個設定檔都啟用 ──
try {
    $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
    $allFwEnabled = $true
    $fwStatus = @()
    foreach ($profile in $fwProfiles) {
        $fwStatus += "$($profile.Name):$($profile.Enabled)"
        if ($profile.Enabled -ne $true) {
            $allFwEnabled = $false
        }
    }
    Report-Check "6.1" "防火牆三個設定檔皆已啟用（$($fwStatus -join ', ')）" $allFwEnabled
} catch {
    # 退回用 netsh
    try {
        $fwOutput = netsh advfirewall show allprofiles state 2>&1
        $fwOff = ($fwOutput | Select-String -Pattern "OFF").Count
        Report-Check "6.1" "防火牆三個設定檔皆已啟用" ($fwOff -eq 0)
    } catch {
        Report-Check "6.1" "防火牆三個設定檔皆已啟用" $null
    }
}

# ── 7. Windows Installer：禁止移除更新 ──
$prohibitUpdRemoval = Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" "DisablePatchUninstall"
if ($null -ne $prohibitUpdRemoval) {
    Report-Check "7.1" "Windows Installer 禁止移除更新已啟用（目前：$prohibitUpdRemoval）" ([int]$prohibitUpdRemoval -eq 1)
} else {
    Report-Check "7.1" "Windows Installer 禁止移除更新已啟用（機碼不存在）" $false
}

# ── 8. 權限配置 ──

# 8.1 C:\SensitiveData 不應有 Everyone 完全控制
if (Test-Path "C:\SensitiveData") {
    try {
        $acl = Get-Acl "C:\SensitiveData" -ErrorAction Stop
        $everyoneFullCtrl = $false
        foreach ($ace in $acl.Access) {
            if (($ace.IdentityReference -match "Everyone|所有人") -and
                ($ace.FileSystemRights -match "FullControl") -and
                ($ace.AccessControlType -eq "Allow")) {
                $everyoneFullCtrl = $true
            }
        }
        Report-Check "8.1" "C:\SensitiveData 無 Everyone 完全控制" (-not $everyoneFullCtrl)
    } catch {
        Report-Check "8.1" "C:\SensitiveData 無 Everyone 完全控制" $null
    }
} else {
    Report-Check "8.1" "C:\SensitiveData 無 Everyone 完全控制（資料夾不存在，跳過）" $null
}

# 8.2 使用者權限指派：Guest 在「拒絕從網路存取這台電腦」中
$denyNetworkAccess = Get-SeceditValue "SeDenyNetworkLogonRight"
if ($null -ne $denyNetworkAccess) {
    # secedit 用 SID 或帳戶名表示，Guest SID = *S-1-5-21-...-501
    $hasGuest = ($denyNetworkAccess -match "Guest" -or $denyNetworkAccess -match "S-1-5-21-[0-9\-]+-501")
    Report-Check "8.2" "Guest 已加入「拒絕從網路存取這台電腦」" $hasGuest
} else {
    Report-Check "8.2" "Guest 已加入「拒絕從網路存取這台電腦」" $null
}

Show-CategoryFooter

# ============================================================
# 分類二：高機率題目（5 大題）
# ============================================================
Show-CategoryHeader "分類二：高機率題目"

# ── 9. 遠端桌面安全 ──

# 9.1 NLA 已啟用（UserAuthentication = 1）
$nla = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" "UserAuthentication"
if ($null -ne $nla) {
    Report-Check "9.1" "遠端桌面 NLA 已啟用（UserAuthentication=1，目前：$nla）" ([int]$nla -eq 1)
} else {
    Report-Check "9.1" "遠端桌面 NLA 已啟用" $null
}

# 9.2 限制空白密碼遠端登入（同 3.5 但獨立計分）
$limitBlankRDP = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse"
if ($null -ne $limitBlankRDP) {
    Report-Check "9.2" "空白密碼限制已啟用（限制遠端登入）" ([int]$limitBlankRDP -eq 1)
} else {
    Report-Check "9.2" "空白密碼限制已啟用（限制遠端登入）" $null
}

# ── 10. 事件記錄檔設定 ──

# 10.1 Security 記錄檔大小 >= 100MB（104857600 bytes）
try {
    $secLog = Get-WinEvent -ListLog "Security" -ErrorAction Stop
    $secLogSize = $secLog.MaximumSizeInBytes
    $secLogSizeMB = [math]::Round($secLogSize / 1MB, 1)
    Report-Check "10.1" "Security 記錄檔 >= 100MB（目前：${secLogSizeMB}MB）" ($secLogSize -ge 104857600)
} catch {
    Report-Check "10.1" "Security 記錄檔 >= 100MB" $null
}

# 10.2 Security 記錄檔保留模式（不覆寫）
try {
    $secLog2 = Get-WinEvent -ListLog "Security" -ErrorAction Stop
    # LogMode: Circular = 覆寫, Retain = 不覆寫, AutoBackup = 自動備份不覆寫
    $retainMode = ($secLog2.LogMode -ne "Circular")
    Report-Check "10.2" "Security 記錄檔不覆寫事件（目前模式：$($secLog2.LogMode)）" $retainMode
} catch {
    Report-Check "10.2" "Security 記錄檔不覆寫事件" $null
}

# ── 11. AD 帳號管理 ──

# 11.1 AD Guest 帳戶已停用
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $adGuest = Get-ADUser -Filter {Name -eq "Guest"} -Properties Enabled -ErrorAction Stop
    if ($adGuest) {
        Report-Check "11.1" "AD Guest 帳戶已停用" ($adGuest.Enabled -eq $false)
    } else {
        Report-Check "11.1" "AD Guest 帳戶已停用（找不到 Guest）" $null
    }
} catch {
    # 非 AD 環境或模組不存在，嘗試本機
    try {
        $localGuest = Get-WmiObject Win32_UserAccount -Filter "Name='Guest' AND LocalAccount=True" -ErrorAction Stop
        Report-Check "11.1" "Guest 帳戶已停用（本機帳戶）" ($localGuest.Disabled -eq $true)
    } catch {
        Report-Check "11.1" "AD Guest 帳戶已停用（AD 模組不可用）" $null
    }
}

# 11.2 Domain Admins 群組無未授權使用者（僅應有 Administrator 或重新命名後的管理員）
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction Stop
    $daMembers = ($domainAdmins | Select-Object -ExpandProperty Name) -join ", "
    $daMemberCount = ($domainAdmins | Measure-Object).Count
    # 一般只應有 1-2 個管理員帳號
    Report-Check "11.2" "Domain Admins 成員數檢查（共 $daMemberCount 位：$daMembers）" ($daMemberCount -le 2)
} catch {
    Report-Check "11.2" "Domain Admins 成員數檢查（AD 模組不可用）" $null
}

# 11.3 Administrator 帳戶已重新命名
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    # SID ending with -500 is the built-in Administrator
    $domainSID = (Get-ADDomain -ErrorAction Stop).DomainSID.Value
    $adminAccount = Get-ADUser -Identity "$domainSID-500" -ErrorAction Stop
    $adminRenamed = ($adminAccount.SamAccountName -ne "Administrator")
    Report-Check "11.3" "Administrator 已重新命名（目前名稱：$($adminAccount.SamAccountName)）" $adminRenamed
} catch {
    # 嘗試本機檢查
    try {
        $localAdmin = Get-WmiObject Win32_UserAccount -Filter "SID LIKE '%-500' AND LocalAccount=True" -ErrorAction Stop
        $localRenamed = ($localAdmin.Name -ne "Administrator")
        Report-Check "11.3" "Administrator 已重新命名（本機，目前名稱：$($localAdmin.Name)）" $localRenamed
    } catch {
        Report-Check "11.3" "Administrator 已重新命名" $null
    }
}

# ── 12. Windows Defender ──

# 12.1 即時保護已開啟
try {
    $mpPref = Get-MpPreference -ErrorAction Stop
    $rtpEnabled = ($mpPref.DisableRealtimeMonitoring -eq $false)
    Report-Check "12.1" "Windows Defender 即時保護已開啟" $rtpEnabled
} catch {
    Report-Check "12.1" "Windows Defender 即時保護已開啟（Defender 不可用）" $null
}

# 12.2 無 C:\ 排除項目
try {
    $mpPref2 = Get-MpPreference -ErrorAction Stop
    $exclusionPaths = $mpPref2.ExclusionPath
    $hasCDriveExcl = $false
    if ($exclusionPaths) {
        foreach ($path in $exclusionPaths) {
            if ($path -match "^C:\\?$") {
                $hasCDriveExcl = $true
            }
        }
    }
    $exclDisplay = if ($exclusionPaths) { ($exclusionPaths -join ", ") } else { "無" }
    Report-Check "12.2" "無 C:\ 磁碟排除（目前排除：$exclDisplay）" (-not $hasCDriveExcl)
} catch {
    Report-Check "12.2" "無 C:\ 磁碟排除（Defender 不可用）" $null
}

# ── 13. 服務管理 ──

# 13.1 Remote Registry 已停止且停用
try {
    $remRegSvc = Get-Service -Name "RemoteRegistry" -ErrorAction Stop
    $remRegStopped = ($remRegSvc.Status -eq "Stopped")
    $remRegDisabled = ($remRegSvc.StartType -eq "Disabled")
    Report-Check "13.1" "Remote Registry 已停止且停用（狀態：$($remRegSvc.Status)，啟動類型：$($remRegSvc.StartType)）" ($remRegStopped -and $remRegDisabled)
} catch {
    Report-Check "13.1" "Remote Registry 已停止且停用（服務不存在）" $null
}

# 13.2 其他危險服務檢查（Telnet, FTP, SNMP 等）
$dangerousServices = @(
    @{ Name = "TlntSvr";    Display = "Telnet" },
    @{ Name = "FTPSVC";     Display = "FTP Publishing" },
    @{ Name = "SNMP";       Display = "SNMP" },
    @{ Name = "SSDPSRV";    Display = "SSDP Discovery" },
    @{ Name = "upnphost";   Display = "UPnP Device Host" },
    @{ Name = "Browser";    Display = "Computer Browser" }
)
$dangerSvcRunning = @()
foreach ($svc in $dangerousServices) {
    try {
        $service = Get-Service -Name $svc.Name -ErrorAction Stop
        if ($service.Status -eq "Running") {
            $dangerSvcRunning += $svc.Display
        }
    } catch {
        # 服務不存在，忽略
    }
}
if ($dangerSvcRunning.Count -gt 0) {
    Report-Check "13.2" "危險服務皆已停用（仍在運行：$($dangerSvcRunning -join ', ')）" $false
} else {
    Report-Check "13.2" "危險服務皆已停用" $true
}

Show-CategoryFooter

# ============================================================
# 分類三：中等機率題目（7 大題）
# ============================================================
Show-CategoryHeader "分類三：中等機率題目"

# ── 14. UAC ──

# 14.1 UAC 已啟用（EnableLUA = 1）
$enableLUA = Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
if ($null -ne $enableLUA) {
    Report-Check "14.1" "UAC 已啟用（EnableLUA=1，目前：$enableLUA）" ([int]$enableLUA -eq 1)
} else {
    Report-Check "14.1" "UAC 已啟用" $null
}

# 14.2 UAC 管理員同意提示（ConsentPromptBehaviorAdmin：1 或 2 表示提示）
$consentPrompt = Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin"
if ($null -ne $consentPrompt) {
    # 0 = 不提示自動提升, 1 = 在安全桌面上提示認證, 2 = 在安全桌面上提示同意
    # 3 = 提示認證, 4 = 提示同意, 5 = 非 Windows 二進位提示同意（預設）
    $consentOk = ([int]$consentPrompt -ge 1 -and [int]$consentPrompt -le 4)
    Report-Check "14.2" "UAC 管理員同意提示已設定（目前：$consentPrompt）" $consentOk
} else {
    Report-Check "14.2" "UAC 管理員同意提示已設定" $null
}

# ── 15. 排程任務：無可疑非 Microsoft 任務 ──
try {
    # 取得 Task Scheduler Library 根目錄的任務（排除 Microsoft 子資料夾）
    $rootTasks = Get-ScheduledTask -ErrorAction Stop | Where-Object {
        $_.TaskPath -eq "\" -and
        $_.TaskName -notmatch "^(Microsoft|User_Feed|CreateExplorerShellUnelevatedTask)"
    }
    $suspiciousTasks = @()
    foreach ($task in $rootTasks) {
        # 檢查是否由 Microsoft 建立
        if ($task.Author -notmatch "Microsoft" -and $task.TaskName -notmatch "^(GoogleUpdate|MicrosoftEdge|OneDrive)") {
            $suspiciousTasks += $task.TaskName
        }
    }
    if ($suspiciousTasks.Count -gt 0) {
        Report-Check "15.1" "無可疑排程任務（發現：$($suspiciousTasks -join ', ')）" $false
    } else {
        Report-Check "15.1" "無可疑排程任務（根目錄無非 Microsoft 任務）" $true
    }
} catch {
    Report-Check "15.1" "無可疑排程任務" $null
}

# ── 16. 共享資料夾：無 Everyone:FullControl 共享 ──
try {
    $shares = Get-SmbShare -ErrorAction Stop | Where-Object {
        # 排除系統預設管理共享
        $_.Name -notmatch '^(ADMIN\$|C\$|D\$|E\$|IPC\$|NETLOGON|SYSVOL|print\$)$'
    }
    $badShares = @()
    foreach ($share in $shares) {
        try {
            $shareAccess = Get-SmbShareAccess -Name $share.Name -ErrorAction Stop
            foreach ($ace in $shareAccess) {
                if (($ace.AccountName -match "Everyone|所有人") -and
                    ($ace.AccessRight -eq "Full") -and
                    ($ace.AccessControlType -eq "Allow")) {
                    $badShares += $share.Name
                }
            }
        } catch {
            # 無法取得權限，跳過
        }
    }
    if ($badShares.Count -gt 0) {
        Report-Check "16.1" "無 Everyone:FullControl 共享（違規：$($badShares -join ', ')）" $false
    } else {
        Report-Check "16.1" "無 Everyone:FullControl 共享" $true
    }
} catch {
    Report-Check "16.1" "無 Everyone:FullControl 共享" $null
}

# ── 17. IIS：目錄瀏覽已停用 ──
try {
    # 檢查 IIS 是否已安裝
    $iisService = Get-Service -Name "W3SVC" -ErrorAction Stop
    if ($iisService) {
        Import-Module WebAdministration -ErrorAction Stop
        $dirBrowsing = Get-WebConfigurationProperty -Filter /system.webServer/directoryBrowse -PSPath "IIS:\Sites\Default Web Site" -Name enabled -ErrorAction Stop
        Report-Check "17.1" "IIS 目錄瀏覽已停用（目前：$($dirBrowsing.Value)）" ($dirBrowsing.Value -eq $false)
    }
} catch {
    # IIS 未安裝或無法檢查
    Report-Check "17.1" "IIS 目錄瀏覽已停用（IIS 未安裝或無法檢查）" $null
}

# ── 18. DNS：區域轉送已停用或限制 ──
try {
    # 檢查 DNS 服務是否存在
    $dnsService = Get-Service -Name "DNS" -ErrorAction Stop
    if ($dnsService.Status -eq "Running") {
        Import-Module DnsServer -ErrorAction Stop
        $zones = Get-DnsServerZone -ErrorAction Stop | Where-Object { $_.IsAutoCreated -eq $false -and $_.ZoneType -eq "Primary" }
        $unsafeZones = @()
        foreach ($zone in $zones) {
            $zoneTransfer = Get-DnsServerZone -Name $zone.ZoneName -ErrorAction Stop
            # SecureSecondaries: 0 = 傳送到任何伺服器, 1 = 只傳送到名稱伺服器, 2 = 只傳送到指定的, 3 = 不允許
            if ($zoneTransfer.SecureSecondaries -eq 0) {
                $unsafeZones += $zone.ZoneName
            }
        }
        if ($unsafeZones.Count -gt 0) {
            Report-Check "18.1" "DNS 區域轉送已限制（不安全的區域：$($unsafeZones -join ', ')）" $false
        } else {
            Report-Check "18.1" "DNS 區域轉送已限制或停用" $true
        }
    } else {
        Report-Check "18.1" "DNS 區域轉送已限制（DNS 服務未運行）" $null
    }
} catch {
    Report-Check "18.1" "DNS 區域轉送已限制（DNS 服務不存在）" $null
}

# ── 19. LDAP：伺服器簽署要求 ──
$ldapSignReq = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LDAPServerIntegrity"
if ($null -ne $ldapSignReq) {
    # 0 = 無, 1 = 需要簽署（如果用戶端支援）, 2 = 需要簽署
    Report-Check "19.1" "LDAP 伺服器簽署已要求（目前：$ldapSignReq，需要 >= 2）" ([int]$ldapSignReq -ge 2)
} else {
    # 嘗試另一個路徑
    $ldapSignReq2 = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Services\ldap" "LdapServerIntegrity"
    if ($null -ne $ldapSignReq2) {
        Report-Check "19.1" "LDAP 伺服器簽署已要求（目前：$ldapSignReq2）" ([int]$ldapSignReq2 -ge 2)
    } else {
        Report-Check "19.1" "LDAP 伺服器簽署已要求（機碼不存在）" $false
    }
}

# ── 20. 網路驗證等級：LmCompatibilityLevel >= 3 ──
$lmCompat = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
if ($null -ne $lmCompat) {
    # 0-1 = LM+NTLM, 2 = NTLMv2 if negotiated, 3 = NTLMv2 only, 4 = refuse LM, 5 = refuse LM&NTLM
    Report-Check "20.1" "LAN Manager 驗證等級 >= 3（目前：$lmCompat）" ([int]$lmCompat -ge 3)
} else {
    Report-Check "20.1" "LAN Manager 驗證等級 >= 3（未設定，預設較低）" $false
}

Show-CategoryFooter

# ============================================================
# 分類四：低機率題目（3 大題）
# ============================================================
Show-CategoryHeader "分類四：低機率題目"

# ── 22. PowerShell 日誌 ──

# 22.1 Script Block Logging 已啟用
$scriptBlockLog = Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
if ($null -ne $scriptBlockLog) {
    Report-Check "22.1" "PowerShell Script Block Logging 已啟用（目前：$scriptBlockLog）" ([int]$scriptBlockLog -eq 1)
} else {
    Report-Check "22.1" "PowerShell Script Block Logging 已啟用（未設定）" $false
}

# 22.2 Module Logging 已啟用
$moduleLog = Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" "EnableModuleLogging"
if ($null -ne $moduleLog) {
    Report-Check "22.2" "PowerShell Module Logging 已啟用（目前：$moduleLog）" ([int]$moduleLog -eq 1)
} else {
    Report-Check "22.2" "PowerShell Module Logging 已啟用（未設定）" $false
}

# ── 23. Windows Update ──

# 23.1 自動更新已啟用
$autoUpdate = Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate"
$auOptions   = Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions"
if ($null -ne $autoUpdate) {
    # NoAutoUpdate = 0 表示啟用自動更新
    Report-Check "23.1" "Windows 自動更新已啟用（NoAutoUpdate=$autoUpdate）" ([int]$autoUpdate -eq 0)
} elseif ($null -ne $auOptions) {
    # AUOptions: 4 = 自動下載並排程安裝
    Report-Check "23.1" "Windows 自動更新已啟用（AUOptions=$auOptions）" ([int]$auOptions -eq 4)
} else {
    # 如果兩者都沒設定，可能使用 Windows Update 服務的預設
    try {
        $wuService = Get-Service -Name "wuauserv" -ErrorAction Stop
        $wuEnabled = ($wuService.StartType -ne "Disabled")
        Report-Check "23.1" "Windows Update 服務已啟用（啟動類型：$($wuService.StartType)）" $wuEnabled
    } catch {
        Report-Check "23.1" "Windows 自動更新已啟用" $null
    }
}

# ── 24. 登錄檔安全 ──

# 24.1 停用自動執行（NoDriveTypeAutoRun = 255）
$noAutoRun = Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoDriveTypeAutoRun"
if ($null -ne $noAutoRun) {
    Report-Check "24.1" "自動執行已停用（NoDriveTypeAutoRun=$noAutoRun，需要 255）" ([int]$noAutoRun -eq 255)
} else {
    Report-Check "24.1" "自動執行已停用（機碼不存在）" $false
}

# 24.2 LM Hash 儲存已停用（NoLMHash = 1）
$noLMHash = Get-RegistryValue "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoLMHash"
if ($null -ne $noLMHash) {
    Report-Check "24.2" "LM Hash 儲存已停用（NoLMHash=$noLMHash）" ([int]$noLMHash -eq 1)
} else {
    Report-Check "24.2" "LM Hash 儲存已停用（機碼不存在）" $false
}

# 24.3 CTRL+ALT+DEL 登入（再次確認登錄檔層級）
$disableCAD2 = Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD"
if ($null -ne $disableCAD2) {
    Report-Check "24.3" "登錄檔層級 CTRL+ALT+DEL 已啟用（DisableCAD=$disableCAD2）" ([int]$disableCAD2 -eq 0)
} else {
    Report-Check "24.3" "登錄檔層級 CTRL+ALT+DEL 已啟用（機碼不存在）" $null
}

Show-CategoryFooter

# ============================
# 總分
# ============================
Write-Host ""
Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan
$grandTotal = $script:totalPass + $script:totalFail + $script:totalWarn
$pct = if ($grandTotal -gt 0) { [math]::Round(($script:totalPass / $grandTotal) * 100, 1) } else { 0 }
$scoreColor = if ($pct -ge 80) { "Green" } elseif ($pct -ge 50) { "Yellow" } else { "Red" }

Write-Host "  總分：$($script:totalPass) / $grandTotal （$pct%）" -ForegroundColor $scoreColor
Write-Host ""
Write-Host "    ✅ 通過：$($script:totalPass)    ❌ 未通過：$($script:totalFail)    ⚠️ 無法檢查：$($script:totalWarn)" -ForegroundColor White
Write-Host "  ══════════════════════════════════════════════════════════" -ForegroundColor Cyan

# 評語
Write-Host ""
if ($pct -ge 90) {
    Write-Host "  🏆 優秀！系統安全配置非常完善！" -ForegroundColor Green
} elseif ($pct -ge 70) {
    Write-Host "  👍 不錯！但仍有改善空間，請檢查未通過的項目。" -ForegroundColor Yellow
} elseif ($pct -ge 50) {
    Write-Host "  ⚠️ 及格邊緣，許多安全設定尚未完成，請加強！" -ForegroundColor Yellow
} else {
    Write-Host "  🚨 需要大幅改善！請參考 WINDOWS_TOPICS.md 逐項修復。" -ForegroundColor Red
}
Write-Host ""

# 清理暫存檔
if (Test-Path $seceditFile) {
    Remove-Item $seceditFile -Force -ErrorAction SilentlyContinue
}
# secedit 也會產生一個 .sdb 檔案
$seceditDB = "$env:TEMP\secedit_export.sdb"
if (Test-Path $seceditDB) {
    Remove-Item $seceditDB -Force -ErrorAction SilentlyContinue
}
