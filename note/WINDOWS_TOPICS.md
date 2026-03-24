# Windows Server / AD 安全強化題單

> 歷屆考過 + 預測可能出的題目，依優先度排序
> 以 GUI 操作為主，PowerShell 僅供驗證
> 比賽環境：Windows Server（AD 角色），基於 Windows 10 核心

---

## 零、Server Manager 總覽

Windows Server 開機自動啟動，也可以從工作列或 `Win+R` → `ServerManager` 開啟。

### 介面說明

```
┌─────────────────────────────────────────────────────┐
│  Server Manager                                      │
│  ┌──────────┐  ┌──────────────────────────────────┐ │
│  │ Dashboard │  │  歡迎頁面 / 角色總覽             │ │
│  │ Local Srv │  │  顯示已安裝的角色、警告、事件    │ │
│  │ All Srvrs │  │                                  │ │
│  │ AD DS     │  │                                  │ │
│  │ DNS       │  │                                  │ │
│  │ File Svcs │  │                                  │ │
│  │ IIS       │  │                                  │ │
│  └──────────┘  └──────────────────────────────────┘ │
│  [Manage ▼]  [Tools ▼]  [View ▼]                    │
└─────────────────────────────────────────────────────┘
```

### 常用操作

**安裝/移除角色和功能**：
1. 右上角 **Manage** → **Add Roles and Features**（或 Remove）
2. 選 **Role-based or feature-based installation** → 下一步
3. 選擇要裝的角色（AD DS、DNS、DHCP、Web Server IIS 等）
4. 下一步到底 → Install

**從 Tools 選單開啟管理工具**：

| Tools 選單項目 | 等同指令 | 用途 |
|----------------|----------|------|
| Active Directory Users and Computers | `dsa.msc` | AD 帳號管理 |
| Group Policy Management | `gpmc.msc` | GPO 管理 |
| DNS | `dnsmgmt.msc` | DNS 設定 |
| DHCP | `dhcpmgmt.msc` | DHCP 設定 |
| Windows Defender Firewall with Advanced Security | `wf.msc` | 防火牆 |
| Event Viewer | `eventvwr.msc` | 事件檢視器 |
| Services | `services.msc` | 服務管理 |
| Computer Management | `compmgmt.msc` | 綜合管理 |
| Task Scheduler | `taskschd.msc` | 排程任務 |

**Local Server（快速概覽）**：
1. 左邊點 **Local Server**
2. 可以一眼看到：
   - Computer name（電腦名稱）
   - Domain（網域）
   - Windows Firewall（點可直接開啟設定）
   - Remote Desktop（點可直接開啟/關閉）
   - IE Enhanced Security Configuration（建議關閉方便操作）
   - NIC Teaming、IPv4/IPv6 位址等

### AD 環境的 GPO 管理（gpmc.msc）

**開啟**：Server Manager → Tools → **Group Policy Management**

或 `Win+R` → `gpmc.msc`

```
群組原則管理
├── Forest: domain.local
│   ├── Domains
│   │   └── domain.local
│   │       ├── Default Domain Policy      ← 影響整個網域
│   │       ├── Domain Controllers
│   │       │   └── Default Domain Controllers Policy
│   │       └── 其他 OU...
│   └── Sites
└── Group Policy Objects
    ├── Default Domain Policy
    └── Default Domain Controllers Policy
```

**編輯 GPO**：
1. 右鍵 **Default Domain Policy** → **Edit**（開啟群組原則管理編輯器）
2. 裡面的結構跟 `gpedit.msc` 一樣，但設定會套用到**整個網域**

**gpedit.msc vs gpmc.msc 差異**：

| | gpedit.msc | gpmc.msc |
|---|------------|----------|
| 影響範圍 | 只有本機 | 整個網域/OU |
| 適用環境 | 單機/工作群組 | AD 環境 |
| 開啟方式 | `Win+R` → `gpedit.msc` | Server Manager → Tools |

> **比賽重點**：AD 環境通常用 `gpmc.msc` 編輯 Default Domain Policy，這樣設定會套用到所有加入網域的電腦。但如果題目只要求改本機，用 `gpedit.msc` 就好。

**強制套用 GPO**：
1. `Win+R` → `cmd`
2. 輸入 `gpupdate /force`
3. 等它跑完（電腦原則 + 使用者原則都更新）

---

## 一、歷屆確定考過的（必練）

### 1. 密碼策略（每年都考）

**方法一：本機（gpedit.msc）**

1. `Win+R` → `gpedit.msc`
2. 左邊展開：電腦設定 → Windows 設定 → 安全性設定 → 帳戶原則 → **密碼原則**
3. 右邊會列出所有項目，逐一雙擊修改：

| 項目 | 雙擊後設定 | 說明 |
|------|------------|------|
| 密碼必須符合複雜性需求 | 已啟用 | 大小寫+數字+特殊字元 |
| 密碼最長使用期限 | 90 天 | 強制定期換密碼 |
| 密碼最短使用期限 | 0 天（或 1 天） | 防止馬上換回舊密碼 |
| 強制密碼歷程記錄 | 5 組 | 不能重複用最近 5 組密碼 |
| 密碼最小長度 | 8-16 字元 | 依題目要求 |
| 使用可還原加密來存放密碼 | 停用 | 明文儲存密碼，絕對不開 |

**方法二：AD 環境（gpmc.msc）**

1. Server Manager → Tools → **Group Policy Management**
2. 展開 Forest → Domains → domain.local
3. 右鍵 **Default Domain Policy** → **Edit**
4. 路徑同上：電腦設定 → Windows 設定 → 安全性設定 → 帳戶原則 → 密碼原則
5. 修改完 → 關閉 → 開 cmd → `gpupdate /force`

**驗證**：`Win+R` → `cmd` → `net accounts`

---

### 2. 帳戶鎖定原則（每年都考）

**路徑**（gpedit 或 gpmc 編輯器內）：帳戶原則 → **帳戶鎖定原則**

| 項目 | 雙擊後設定 | 說明 |
|------|------------|------|
| 帳戶鎖定閾值 | 3 次 | 連續 3 次錯誤就鎖 |
| 帳戶鎖定時間 | 60 分鐘 | 鎖定持續時間 |
| 重設帳戶鎖定計數器 | 60 分鐘 | 幾分鐘後重新計算 |

**操作順序**：
1. 先雙擊「**帳戶鎖定閾值**」→ 設定 **3 次無效的登入嘗試** → 確定
2. 系統會自動跳出建議，把鎖定時間和重設計數器都設成 30 分鐘 → 先確定
3. 再分別雙擊「帳戶鎖定時間」和「重設計數器」改成 **60 分鐘**

> 注意：一定要先設「閾值」，其他兩個才能設定。直接改後兩個會顯示灰色。

---

### 3. 安全性選項（53屆考過）

**路徑**：gpedit/gpmc 編輯器 → 本機原則 → **安全性選項**

這個清單很長，往下捲找「**互動式登入**」開頭的：

| 項目 | 雙擊後設定 | 說明 |
|------|------------|------|
| 互動式登入：不要求 CTRL+ALT+DEL | **停用** | 停用這個選項 = 要求按 CTRL+ALT+DEL |
| 互動式登入：不要顯示上次登入的使用者名稱 | **已啟用** | 啟用 = 不顯示上次帳號 |
| 互動式登入：到期前提示使用者變更密碼 | **10 天** | 密碼快過期時提醒 |

繼續找其他重要的安全性選項：

| 項目 | 設定 | 說明 |
|------|------|------|
| 帳戶：重新命名系統管理員帳戶 | 改成其他名稱 | 防止猜到 admin 帳號 |
| 帳戶：重新命名來賓帳戶 | 改成其他名稱 | 同上 |
| 帳戶：Guest 帳戶狀態 | **停用** | 禁止匿名登入 |
| 帳戶：限制使用空白密碼的本機帳戶僅能從主控台登入 | **已啟用** | 空密碼不能遠端登入 |
| 網路存取：不允許 SAM 帳戶的匿名列舉 | **已啟用** | 防止匿名列舉帳號 |
| 網路存取：不允許 SAM 帳戶和共用的匿名列舉 | **已啟用** | 同上（更嚴格） |
| 關機：允許不需登入即可關機 | **停用** | 防止未登入就關機 |

> 注意名稱裡的「不要求」「不要顯示」「不允許」是雙重否定，小心搞反！
> 口訣：「不要求 CTRL+ALT+DEL」設成「停用」= 你必須按 CTRL+ALT+DEL

---

### 4. SMB2 安全（53屆、54屆考過）

**步驟一：啟用 SMB signing**

1. `gpedit.msc` → 本機原則 → 安全性選項
2. 找到 **Microsoft 網路** 開頭的，共有 4 個相關的：

| 項目 | 設定 |
|------|------|
| Microsoft 網路伺服器：數位簽章通訊（自動） | **已啟用** |
| Microsoft 網路伺服器：數位簽章通訊（如果用戶端同意） | **已啟用** |
| Microsoft 網路用戶端：數位簽章通訊（自動） | **已啟用** |
| Microsoft 網路用戶端：數位簽章通訊（如果伺服器同意） | **已啟用** |

**步驟二：停用 SMBv1**

方法一（Server Manager）：
1. 開啟 **Server Manager**
2. 右上角 **Manage** → **Remove Roles and Features**
3. 下一步到 **Features**
4. 找到 **SMB 1.0/CIFS File Sharing Support** → **取消勾選**
5. 下一步 → Remove

方法二（控制台）：
1. `Win+R` → `appwiz.cpl`
2. 左邊「**開啟或關閉 Windows 功能**」
3. 找到 **SMB 1.0/CIFS File Sharing Support** → **取消勾選** → 確定

**驗證**：開 PowerShell →
```
Get-SmbServerConfiguration | Select EnableSMB1Protocol, RequireSecuritySignature
```
應顯示 `EnableSMB1Protocol: False`、`RequireSecuritySignature: True`

---

### 5. 稽核策略（52屆、55屆考過）

**方法一：基本稽核（gpedit）**

1. `gpedit.msc` → 本機原則 → **稽核原則**
2. 每個項目都雙擊，勾選 **成功** 和 **失敗**：

| 項目 | 成功 | 失敗 |
|------|:----:|:----:|
| 稽核帳戶登入事件 | ☑ | ☑ |
| 稽核帳戶管理 | ☑ | ☑ |
| 稽核登入事件 | ☑ | ☑ |
| 稽核物件存取 | ☑ | ☑ |
| 稽核原則變更 | ☑ | ☑ |
| 稽核特殊權限使用 | ☑ | ☑ |
| 稽核系統事件 | ☑ | ☑ |
| 稽核目錄服務存取 | ☑ | ☑ |
| 稽核程序追蹤 | ☑ | ☑ |

**方法二：進階稽核原則（更細緻）**

1. `gpedit.msc` → 安全性設定 → **進階稽核原則設定** → **系統稽核原則**
2. 這裡有更細的分類（帳戶登入、帳戶管理、詳細追蹤等）
3. 每個子項目都雙擊 → 勾選設定以下稽核事件 → **成功** + **失敗**

**查看稽核事件（事件檢視器）**：

1. Server Manager → Tools → **Event Viewer**
   或 `Win+R` → `eventvwr.msc`
2. 左邊展開 **Windows 記錄** → 點 **安全性**
3. 中間列出所有安全性事件
4. 右邊「**篩選目前的記錄**」→ 事件識別碼欄位輸入 ID

**篩選特定事件**：
1. 右邊點「**篩選目前的記錄**」
2. 「事件識別碼」欄位輸入（如 `4688`）
3. 可以設定時間範圍（如「過去 24 小時」）
4. 確定 → 只顯示符合條件的事件

**常見事件 ID**：

| 事件 ID | 意義 | 52屆考過 |
|---------|------|:--------:|
| 4624 | 登入成功 | |
| 4625 | 登入失敗 | ✅ |
| 4634 | 登出 | |
| 4648 | 使用明確認證登入 | |
| 4672 | 特殊權限指派 | |
| 4688 | 新程序建立 | ✅ |
| 4689 | 程序結束 | |
| 4720 | 建立使用者帳戶 | |
| 4722 | 啟用使用者帳戶 | |
| 4724 | 重設密碼 | |
| 4726 | 刪除使用者帳戶 | |
| 4732 | 成員加入安全性群組 | |
| 4740 | 帳戶鎖定 | |
| 4768 | Kerberos TGT 要求 | |
| 4769 | Kerberos 服務票證要求 | |

**52屆考法**：用 PowerShell 計算特定事件 ID 的出現次數：
1. 開 PowerShell
2. 事件 4688 次數：
```
(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688}).Count
```
3. 特定日期的登入失敗次數：
```
(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime='2025-03-28'; EndTime='2025-03-29'}).Count
```

---

### 6. Windows 防火牆（55屆考過）

**方法一：Server Manager**

1. Server Manager → Tools → **Windows Defender Firewall with Advanced Security**

**方法二：直接開啟**

1. `Win+R` → `wf.msc`

**方法三：從 Local Server**

1. Server Manager → 左邊 **Local Server**
2. 找到 **Windows Defender Firewall** → 點旁邊的連結直接開啟

**步驟一：確認防火牆已啟用**

1. 左邊點「**具有進階安全性的 Windows Defender 防火牆**」（最上層）
2. 中間「概觀」會顯示三個設定檔的狀態
3. 如果有「關閉」的 → 點中間的「**Windows Defender 防火牆內容**」
4. 三個分頁（**網域**、**私人**、**公用**）→ 防火牆狀態都改成「**開啟**」

**步驟二：設定預設行為**

同一個「防火牆內容」視窗：
- 每個分頁的：
  - 輸入連線：**封鎖**
  - 輸出連線：**允許**
- 點「確定」

**步驟三：新增允許規則**

1. 左邊點「**輸入規則**」
2. 右邊點「**新增規則**」
3. 規則類型選擇：

**允許特定 port**：
1. 選「**連接埠**」→ 下一步
2. **TCP** → 特定本機連接埠：`3389`（RDP）→ 下一步
3. 「**允許連線**」→ 下一步
4. 套用設定檔全勾（網域、私人、公用）→ 下一步
5. 名稱：`Allow RDP` → 完成

**允許特定 IP 範圍**：
1. 選「**自訂**」→ 下一步
2. 通訊協定和連接埠：依需求設定 → 下一步
3. **範圍**頁面 → 遠端 IP 位址 → 「**這些 IP 位址**」
4. 「**新增**」→ 輸入 `192.168.10.0/24` → 確定 → 下一步
5. 「**允許連線**」→ 下一步 → 完成

**封鎖特定 port**：
1. 同上但在動作選「**封鎖連線**」

**管理現有規則**：
- 雙擊規則 → 可修改所有設定
- 「**一般**」分頁：啟用/停用、允許/封鎖
- 「**通訊協定及連接埠**」分頁：port 設定
- 「**範圍**」分頁：IP 限制
- 「**進階**」分頁：套用哪些設定檔（網域/私人/公用）
- 右鍵規則 → **停用規則** / **刪除**

---

### 7. Windows Installer 原則（53屆考過）

1. `Win+R` → `gpedit.msc`
2. 電腦設定 → 系統管理範本 → Windows 元件 → **Windows Installer**
3. 右邊找到「**禁止移除更新**」→ 雙擊 → **已啟用** → 確定

---

### 8. 權限配置（55屆考過）

**檔案/資料夾權限（GUI）**：

1. 檔案總管中，對目標資料夾**右鍵** → **內容**
2. 點「**安全性**」分頁
3. 看目前有哪些使用者/群組及其權限

**修改權限**：
1. 點「**編輯**」
2. 要新增使用者 → 點「**新增**」→ 輸入帳號名稱 → 「檢查名稱」確認 → 確定
3. 要移除使用者 → 選取 → 「**移除**」
4. 選取使用者後，下方勾選**允許**或**拒絕**：
   - 完全控制
   - 修改
   - 讀取和執行
   - 列出資料夾內容
   - 讀取
   - 寫入

**進階權限**：
1. 安全性分頁 → 點「**進階**」
2. 「**停用繼承**」→ 選「將繼承的權限轉換為此物件上的明確權限」
   （這樣可以自由修改，不受上層影響）
3. 「**變更**」→ 可以改擁有者
4. 「**新增**」→ 可以設定更細緻的權限（如「僅套用到此資料夾」）

**使用者權限指派**：

1. `gpedit.msc` → 本機原則 → **使用者權限指派**
2. 常見設定：

| 項目 | 建議操作 |
|------|----------|
| 從網路存取這台電腦 | 雙擊 → 只留 Administrators、Authenticated Users |
| 拒絕從網路存取這台電腦 | 雙擊 → 「新增使用者或群組」→ 加入 **Guest** |
| 允許本機登入 | 只留 Administrators |
| 拒絕本機登入 | 加入 Guest |
| 允許透過遠端桌面服務登入 | 只留 Administrators、Remote Desktop Users |
| 拒絕透過遠端桌面服務登入 | 加入 Guest |

---

## 二、高機率會考的（強烈建議練）

### 9. 遠端桌面安全（54屆考過「遠端連線服務安全強化」）

**快速開啟（Server Manager）**：
1. Server Manager → 左邊 **Local Server**
2. 找到 **Remote Desktop** → 點旁邊的「Disabled」或「Enabled」

**啟用 + NLA**：
1. 系統內容 → **遠端**分頁
2. 勾選「**允許遠端連線到此電腦**」
3. 勾選「**僅允許執行含有網路等級驗證的遠端桌面的電腦連線**」（NLA）
4. 點「**選取使用者**」→ 確認只有需要的帳號

**限制空白密碼**：

`gpedit.msc` → 本機原則 → 安全性選項 →
「帳戶：限制使用空白密碼的本機帳戶僅能從主控台登入」→ **已啟用**

**設定加密層級**：

1. `gpedit.msc` → 電腦設定 → 系統管理範本 → Windows 元件
2. → 遠端桌面服務 → 遠端桌面工作階段主機 → **安全性**
3. 「設定用戶端連線加密等級」→ **已啟用** → 下拉選「**高**」
4. 「需要使用網路層級驗證的遠端連線使用者驗證」→ **已啟用**

**設定閒置斷線**：

1. 同上路徑 → 遠端桌面服務 → 遠端桌面工作階段主機 → **工作階段時間限制**
2. 「設定使用中但閒置的遠端桌面服務工作階段的時間限制」→ **已啟用** → **30 分鐘**
3. 「設定已中斷連線工作階段的時間限制」→ **已啟用** → **30 分鐘**

---

### 10. 事件記錄檔設定（54屆考過「稽核日誌安全強化」）

**方法一：事件檢視器（GUI 最直覺）**

1. Server Manager → Tools → **Event Viewer**
   或 `Win+R` → `eventvwr.msc`
2. 左邊展開 **Windows 記錄**
3. 逐一對 **Application**、**Security**、**System** 右鍵 → **內容**
4. 設定：
   - 記錄檔大小上限：**204800** KB（≈200MB）
   - 勾選「**記錄檔已滿時封存記錄，不要覆寫事件**」
   或選「不要覆寫事件（手動清除記錄）」
5. 確定

**方法二：群組原則**

1. `gpedit.msc` → 電腦設定 → 系統管理範本 → Windows 元件 → **事件記錄服務**
2. 分別點進 **Application**、**Security**、**System**：

| 項目 | 設定 |
|------|------|
| 指定記錄檔大小上限 | 已啟用 → **204800** KB |
| 記錄檔滿時的行為 | 封存記錄檔但**不覆寫**事件 |

**方法三：限制記錄檔存取權限**

1. 檔案總管到 `C:\Windows\System32\winevt\Logs\`
2. 對 `Security.evtx` 右鍵 → 內容 → 安全性
3. 確認只有 **Administrators** 和 **SYSTEM** 有存取權
4. 移除其他不需要的使用者

---

### 11. AD 帳號管理

**開啟 AD 使用者和電腦**：

Server Manager → Tools → **Active Directory Users and Computers**
或 `Win+R` → `dsa.msc`

**停用 Guest 帳號**：
1. 展開網域 → 點 **Users**
2. 找到 **Guest** → 右鍵 → **停用帳戶**
3. 帳號圖示會出現向下箭頭 ↓

**停用/刪除可疑帳號**：
1. 在 Users 裡逐一檢查
2. 右鍵可疑帳號 → **停用帳戶** 或 **刪除**

**重新命名 Administrator**：
1. 右鍵 **Administrator** → **重新命名** → 輸入新名稱
2. 或用 gpedit：安全性選項 → 「帳戶：重新命名系統管理員帳戶」

**查看/管理群組成員**：
1. 展開網域 → 點 **Users** 或 **Builtin**
2. 雙擊 **Domain Admins**
3. 「**成員**」分頁
4. 檢查是否有不該在的帳號 → 選取 → 「**移除**」

**建立新使用者**：
1. 右鍵 **Users** → **新增** → **使用者**
2. 填入：
   - 名字、姓氏
   - 使用者登入名稱（如 `newadmin`）
3. 下一步 → 設定密碼
4. 勾選「**使用者必須在下次登入時變更密碼**」
5. 完成

**將使用者加入群組**：
1. 右鍵使用者 → **新增至群組**
2. 輸入群組名稱（如 `Remote Desktop Users`）→ 檢查名稱 → 確定

**建立 OU（組織單位）**：
1. 右鍵網域 → **新增** → **組織單位**
2. 輸入名稱 → 確定
3. 可以把使用者拖曳到 OU 裡，方便套用不同的 GPO

**本機使用者管理（非 AD）**：

`Win+R` → `lusrmgr.msc`
- 左邊「**使用者**」→ 右鍵帳號 → **內容** → 勾選「帳戶已停用」
- 左邊「**群組**」→ 雙擊群組 → **新增/移除**成員

---

### 12. Windows Defender

**開啟**：

方法一：開始 → 搜尋「**Windows 安全性**」
方法二：Server Manager → Tools → **Windows Defender Firewall**（這是防火牆，Defender 要從設定開）
方法三：開始 → 設定 → 更新與安全性 → **Windows 安全性**

**確認即時保護**：
1. Windows 安全性 → **病毒與威脅防護**
2. 點「**管理設定**」（病毒與威脅防護設定下方）
3. 確認以下都是**開啟**：
   - 即時保護
   - 雲端提供的保護
   - 自動提交樣本
   - 竄改防護

**檢查排除項目**（重要！攻擊者常加 `C:\` 全排除）：
1. 管理設定 → 往下捲到「**排除項目**」
2. 點「**新增或移除排除**」
3. 如果看到 `C:\` 或任何可疑路徑 → 點該排除 → **移除**

**更新定義檔**：
1. 病毒與威脅防護 → 往下找「**保護更新**」
2. 點「**檢查更新**」

**執行掃描**：
1. 病毒與威脅防護 → 「**掃描選項**」
2. 選「**完整掃描**」→ 立即掃描

**Windows Defender 在 Server 上可能需要額外安裝**：
1. Server Manager → Manage → Add Roles and Features
2. Features → **Windows Defender 功能** → 勾選 → Install

---

### 13. 服務管理

**開啟**：

Server Manager → Tools → **Services**
或 `Win+R` → `services.msc`

**停用不安全服務**：
1. 找到服務名稱（可以點「名稱」排序）
2. 雙擊該服務
3. 「**啟動類型**」改為「**已停用**」
4. 點「**停止**」按鈕
5. 確定

**常見應停用的服務**：

| 顯示名稱 | 服務名稱 | 風險 |
|----------|----------|------|
| Remote Registry | RemoteRegistry | 遠端存取登錄檔 |
| Telnet | TlntSvr | 明文遠端連線 |
| FTP Publishing Service | FTPSVC | FTP 明文傳輸 |
| SNMP Service | SNMP | 社群字串明文 |
| SSDP Discovery | SSDPSRV | UPnP 裝置發現 |
| UPnP Device Host | upnphost | UPnP 服務 |
| Computer Browser | Browser | 廣播網路資源 |
| Print Spooler | Spooler | PrintNightmare 漏洞（不需要列印時關閉） |
| Xbox 相關服務 | Xbl* | 遊戲相關，Server 不需要 |

**不要停用的服務**：

| 服務 | 原因 |
|------|------|
| Windows Defender Firewall (mpssvc) | 防火牆 |
| Windows Event Log | 事件記錄 |
| Windows Update (wuauserv) | 系統更新 |
| Windows Defender | 防毒 |
| DNS Server | AD 需要 |
| Active Directory Domain Services | AD 核心 |
| Kerberos Key Distribution Center | AD 認證 |
| Group Policy Client | GPO 套用 |

---

## 三、中等機率（建議了解操作方式）

### 14. UAC（使用者帳戶控制）

**開啟**：
1. 開始 → 搜尋「**UAC**」→ 點「變更使用者帳戶控制設定」
2. 或：控制台 → 使用者帳戶 → **變更使用者帳戶控制設定**

**介面**：一個滑桿，4 個等級

| 等級 | 說明 | 建議 |
|------|------|------|
| 最高（一律通知） | 任何變更都會提示 | 最安全 |
| 第二格（預設） | 程式變更時通知 | 建議 |
| 第三格 | 程式變更時通知但不暗化桌面 | 不建議 |
| 最低（不通知） | 完全關閉 UAC | 危險！ |

→ 拉到**最高**或**第二格** → 確定

---

### 15. 排程任務稽核

**開啟**：

Server Manager → Tools → **Task Scheduler**
或 `Win+R` → `taskschd.msc`

**檢查步驟**：
1. 左邊點「**工作排程器程式庫**」
2. 中間列出所有排程任務
3. 逐一檢查，特別注意不是 Microsoft 內建的
4. 點選任務 → 下方可以看到：
   - 「**觸發程序**」分頁：什麼時候執行
   - 「**動作**」分頁：執行什麼程式 ← 重點看這個
   - 「**歷程記錄**」分頁：過去執行紀錄

**可疑任務特徵**：
- 名稱隨機（如 `a1b2c3`、`update_service`）
- 動作是 `powershell.exe -enc ...`（Base64 編碼指令）
- 動作是 `cmd.exe /c ...` + 可疑指令
- 觸發器：每 1-5 分鐘執行一次
- 執行路徑在 `C:\Temp`、`C:\Users\Public`、`%APPDATA%`

**處理方式**：
- 右鍵可疑任務 → **停用**
- 確認可疑後 → 右鍵 → **刪除**

---

### 16. 共享資料夾安全

**開啟**：

Server Manager → Tools → 沒有直接的選項，用以下方式：
`Win+R` → `fsmgmt.msc`
或 `compmgmt.msc` → 左邊展開「共用資料夾」

**檢查步驟**：
1. 點「**共用**」→ 看所有共享的資料夾
2. 注意 `C$`、`ADMIN$`、`IPC$` 是系統預設管理共享（通常不動）
3. 其他自訂共享 → 逐一檢查

**修改共享權限**：
1. 右鍵共享 → **內容**
2. 「**共用權限**」分頁：
   - 選取 **Everyone** → 點「**移除**」
   - 「**新增**」→ 加入特定群組（如 Domain Users）
   - 設定權限：讀取 / 變更 / 完全控制
3. 「**安全性**」分頁（NTFS 權限）：
   - 同樣移除 Everyone、設定適當權限

**停止不需要的共享**：
右鍵共享 → **停止共用** → 確定

> **共用權限 vs NTFS 權限**：兩者取交集。例如共用給「讀取」，NTFS 給「完全控制」，實際權限 = 讀取。

---

### 17. IIS 安全（如果有裝）

**開啟**：

Server Manager → Tools → **Internet Information Services (IIS) Manager**
或 `Win+R` → `inetmgr`

**停用目錄瀏覽**：
1. 左邊展開伺服器 → **Sites** → **Default Web Site**
2. 中間雙擊「**目錄瀏覽**」
3. 右邊「動作」面板 → 「**停用**」

**移除版本資訊**：
1. 選擇站台 → 雙擊「**HTTP 回應標頭**」
2. 找到 **X-Powered-By** → 右鍵 → **移除**

**限制 HTTP 方法**：
1. 選擇站台 → 雙擊「**要求篩選**」
2. 切到「**HTTP 指令動詞**」分頁
3. 右邊「**拒絕指令動詞**」→ 分別加入：`PUT`、`DELETE`、`TRACE`、`OPTIONS`

**設定 HTTPS**：
1. 左邊選擇站台 → 右邊「**繫結**」
2. 「**新增**」→ 類型：**https** → 連接埠：**443**
3. SSL 憑證：選擇已安裝的憑證 → 確定

**強制 HTTPS 重導向**：
1. 先確認安裝了「**URL Rewrite**」模組
2. 選擇站台 → 雙擊「**URL 重寫**」
3. 新增規則 → **空白規則**
4. 條件：`{HTTPS}` = `off`
5. 動作：重新導向 → `https://{HTTP_HOST}{REQUEST_URI}`

---

### 18. DNS 安全（AD 環境常見）

**開啟**：

Server Manager → Tools → **DNS**
或 `Win+R` → `dnsmgmt.msc`

**停用區域轉送**：
1. 左邊展開 DNS 伺服器 → **正向對應區域**
2. 右鍵你的網域區域 → **內容**
3. 點「**區域轉送**」分頁
4. **取消勾選**「允許區域轉送」
5. 或選「**僅允許到下列伺服器**」→ 指定特定 IP → 確定

**啟用安全動態更新**：
1. 區域內容 → 「**一般**」分頁
2. 動態更新：改為「**僅安全**」

**清除過時記錄**：
1. 右鍵 DNS 伺服器 → **內容**
2. 「**進階**」分頁 → 勾選「**啟用自動清除過時記錄**」

---

### 19. LDAP 安全（AD 環境）

**路徑**：`gpedit.msc` → 本機原則 → 安全性選項

找到並雙擊：

| 項目 | 設定 |
|------|------|
| 網域控制站：LDAP 伺服器簽署需求 | **需要簽署** |
| 網路安全性：LDAP 用戶端簽署需求 | **需要簽署** |

**AD 環境建議**：
在 `gpmc.msc` → Default Domain Controllers Policy 裡設定，確保所有 DC 都套用。

---

### 20. 網路驗證等級（54屆考過）

**路徑**：`gpedit.msc` → 本機原則 → 安全性選項

找到：「**網路安全性：LAN Manager 驗證等級**」→ 雙擊

下拉選單選項（由低到高）：
1. 傳送 LM & NTLM 回應
2. 傳送 LM & NTLM - 如果交涉使用 NTLMv2 工作階段安全性
3. 僅傳送 NTLM 回應
4. 僅傳送 NTLMv2 回應
5. 僅傳送 NTLMv2 回應。拒絕 LM
6. **僅傳送 NTLMv2 回應。拒絕 LM & NTLM** ← 選這個（最安全）

> LM 和 NTLM v1 的雜湊很容易被破解，要用 NTLMv2

---

## 四、低機率但值得了解的

### 21. BitLocker

1. 開始 → 搜尋「**管理 BitLocker**」
2. 找到 C: → 「**開啟 BitLocker**」
3. 選擇解除鎖定方式（TPM / 密碼 / USB）
4. 備份修復金鑰（存到檔案 / 列印 / AD）
5. 加密整個磁碟 → 開始加密

> Server 可能需要先從 Server Manager 安裝 BitLocker 功能

### 22. PowerShell 執行原則 & 日誌

**路徑**：`gpedit.msc` → 電腦設定 → 系統管理範本 → Windows 元件 → **Windows PowerShell**

| 項目 | 雙擊後設定 |
|------|------------|
| 開啟 PowerShell 指令碼區塊記錄 | **已啟用** |
| 開啟模組記錄 | **已啟用** → 「顯示」→ 輸入 `*` |
| 開啟 PowerShell 轉譯 | **已啟用**（記錄所有輸入/輸出到檔案） |

### 23. Windows Update

**路徑**：`gpedit.msc` → 電腦設定 → 系統管理範本 → Windows 元件 → **Windows Update**

| 項目 | 設定 |
|------|------|
| 設定自動更新 | 已啟用 → **4 - 自動下載並排程安裝** |
| 不要在「關閉 Windows」對話方塊顯示「安裝更新並關機」 | 停用 |

或直接從：設定 → 更新與安全性 → Windows Update → 檢查更新

### 24. 登錄檔安全

**開啟**：`Win+R` → `regedit`

左邊導覽到路徑，右邊找到或新增值：

**停用自動執行（防 USB 攻擊）**：
1. 導覽到 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer`
2. 右邊右鍵 → 新增 → **DWORD (32位元)** → 名稱 `NoDriveTypeAutoRun` → 值 `255`

**停用 LM hash 儲存**：
1. 導覽到 `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`
2. 右邊右鍵 → 新增 → **DWORD** → 名稱 `NoLMHash` → 值 `1`

> 以上也可以透過 gpedit.msc 安全性選項達成，登錄檔是底層方式

### 25. 憑證管理

1. 控制台 → 使用者帳戶 → **憑證管理員**
   或開始搜尋「**憑證管理員**」
2. 分為「**Web 認證**」和「**Windows 認證**」
3. 展開每個項目 → 檢查是否有不認識的
4. 可疑的 → 「**移除**」

---

## 五、工具速查

### Win+R 開啟

| 指令 | 工具 | 用途 |
|------|------|------|
| `ServerManager` | 伺服器管理員 | **Server 總控台** |
| `gpedit.msc` | 群組原則編輯器 | 密碼、鎖定、稽核、安全性選項（本機） |
| `gpmc.msc` | 群組原則管理 | GPO 管理（AD 環境，影響整個網域） |
| `secpol.msc` | 本機安全性原則 | gpedit 安全性部分的子集 |
| `dsa.msc` | AD 使用者和電腦 | AD 帳號管理 |
| `lusrmgr.msc` | 本機使用者和群組 | 帳號管理（非 AD） |
| `eventvwr.msc` | 事件檢視器 | 查看稽核日誌 |
| `services.msc` | 服務管理 | 停用/啟用服務 |
| `wf.msc` | 進階防火牆 | 防火牆規則 |
| `taskschd.msc` | 工作排程器 | 檢查排程任務 |
| `fsmgmt.msc` | 共享資料夾管理 | 共享權限 |
| `compmgmt.msc` | 電腦管理 | 綜合管理工具 |
| `dnsmgmt.msc` | DNS 管理 | DNS 設定 |
| `dhcpmgmt.msc` | DHCP 管理 | DHCP 設定 |
| `diskmgmt.msc` | 磁碟管理 | 磁碟分割 |
| `inetmgr` | IIS Manager | Web 伺服器 |
| `regedit` | 登錄檔編輯器 | 底層設定 |
| `appwiz.cpl` | 程式和功能 | 新增/移除功能 |
| `ncpa.cpl` | 網路連線 | 網路介面卡設定 |
| `firewall.cpl` | 基本防火牆 | 簡易防火牆設定 |
| `sysdm.cpl` | 系統內容 | 電腦名稱、遠端桌面 |

### 常用 cmd / PowerShell 驗證指令

```powershell
# 密碼策略
net accounts

# 稽核策略
auditpol /get /category:*

# 防火牆狀態
netsh advfirewall show allprofiles

# SMB 狀態
Get-SmbServerConfiguration | Select EnableSMB1Protocol, RequireSecuritySignature

# 查看本機使用者
net user

# 查看群組成員
net localgroup Administrators

# AD 使用者
Get-ADUser -Filter * | Select Name, Enabled

# AD 群組
Get-ADGroupMember -Identity "Domain Admins" | Select Name

# listening ports
netstat -ano | findstr LISTENING

# 啟動項目
wmic startup list brief

# 強制更新 GPO
gpupdate /force

# 匯出安全性設定（比賽前後比對）
secedit /export /cfg C:\before.cfg
```

---

## 六、歷屆 vs 預測對照表

| 主題 | 52 | 53 | 54 | 55 | 預測機率 | 編號 |
|------|:--:|:--:|:--:|:--:|:--------:|:----:|
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

**第一輪（必練）**：1 密碼策略 → 2 帳戶鎖定 → 5 稽核策略 → 6 防火牆 → 3 安全性選項

**第二輪（高機率）**：4 SMB → 8 權限 → 9 遠端桌面 → 10 事件記錄檔 → 11 AD 帳號

**第三輪（補齊）**：12 Defender → 13 服務 → 14 UAC → 15 排程 → 20 網路驗證

**有空再看**：其餘
