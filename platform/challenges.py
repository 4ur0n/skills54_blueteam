"""
Challenge definitions and verifiers — single-container architecture.
All 23 challenges run inside the same container: sec_challenge.
"""
import re
import docker
import paramiko
import requests

CONTAINER = 'sec_challenge'   # single challenge machine

_docker_client = None


def get_docker():
    global _docker_client
    if _docker_client is None:
        _docker_client = docker.from_env()
    return _docker_client


def docker_exec(cmd):
    """Execute a shell command inside the challenge container."""
    container = get_docker().containers.get(CONTAINER)
    exit_code, output = container.exec_run(['sh', '-c', cmd])
    return output.decode('utf-8', errors='replace'), exit_code


# ---------------------------------------------------------------------------
# Challenge definitions
# ---------------------------------------------------------------------------

CHALLENGES = [
    {
        'id': 1,
        'title': 'SSH 服務配置安全',
        'category': '服務加固',
        'difficulty': '簡單',
        'difficulty_color': 'success',
        'description': (
            'SSH 服務的預設配置存在多處安全疑慮，'
            '可能讓攻擊者在未授權的情況下取得系統最高權限。'
            '請審查並強化 SSH 的存取控制設定。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash',
        'hints': [
            '設置 <code>PermitRootLogin no</code>',
            '設置 <code>MaxAuthTries 3</code>',
            '設置 <code>X11Forwarding no</code>',
            '設置 <code>LoginGraceTime 30</code>',
            '新增 <code>Banner /etc/ssh/banner</code> 並建立該檔案',
            '重載：<code>kill -HUP $(cat /var/run/sshd.pid)</code>',
        ],
    },
    {
        'id': 2,
        'title': 'SSH 弱密碼檢測',
        'category': '帳號安全',
        'difficulty': '簡單',
        'difficulty_color': 'success',
        'description': (
            '系統中某個帳號的密碼強度不足，'
            '無法抵禦基本的字典攻擊。'
            '請確保所有帳號皆使用符合安全標準的密碼。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash',
        'hints': [
            '<code>passwd admin</code>',
            '或 <code>echo "admin:NewStr0ng#Pass" | chpasswd</code>',
        ],
    },
    {
        'id': 3,
        'title': 'Web 應用上傳漏洞',
        'category': 'Web 安全',
        'difficulty': '中等',
        'difficulty_color': 'warning',
        'description': (
            'Web 應用存在一個高風險的上傳功能缺陷，'
            '攻擊者可藉此在伺服器上執行任意指令。'
            '請修補此漏洞，防止未授權的遠端代碼執行（RCE）。'
        ),
        'container': CONTAINER,
        'access': 'Web UI: http://localhost:8080\nSSH 後編輯 /var/www/html/upload.php',
        'hints': [
            '白名單副檔名：只允許 jpg、jpeg、png、gif',
            '使用 <code>finfo_file()</code> 驗證真實 MIME 類型',
            '在 uploads/ 建立 <code>.htaccess</code>：<code>php_flag engine off</code>',
        ],
    },
    {
        'id': 4,
        'title': '最小權限原則',
        'category': '檔案系統',
        'difficulty': '簡單',
        'difficulty_color': 'success',
        'description': (
            '系統中數個敏感資源的存取權限過於寬鬆，'
            '違反最小權限原則，可能導致機密資料外洩、資料被篡改，'
            '甚至讓攻擊者得以抹除入侵痕跡。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash',
        'hints': [
            '用 <code>ls -l</code> 查看目前的權限，思考哪些檔案不該被「其他人」讀取或寫入',
            '<code>/etc/shadow</code> 儲存密碼雜湊，應該只有 root 和 shadow 群組能讀取',
            '<code>/opt/app/config.ini</code> 含有 API 金鑰，不應讓所有人都能修改',
            '<code>/var/log</code> 是日誌目錄，若任何人都能寫入，攻擊者可竄改或刪除日誌',
        ],
    },
    {
        'id': 5,
        'title': '防火牆配置',
        'category': '網路安全',
        'difficulty': '中等',
        'difficulty_color': 'warning',
        'description': (
            '系統目前對網路流量毫無管制，'
            '所有服務均暴露在外部存取之下。'
            '請建立適當的網路存取控制策略，限縮系統的攻擊面。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash',
        'hints': [
            '依序設定（順序很重要！）：',
            '<code>iptables -A INPUT -i lo -j ACCEPT</code>（放行 loopback）',
            '<code>iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT</code>（放行已建立連線）',
            '<code>iptables -A INPUT -p tcp --dport 22 -j ACCEPT</code>（放行 SSH）',
            '<code>iptables -A INPUT -p tcp --dport 80 -j ACCEPT</code>（放行 HTTP，選用）',
            '<code>iptables -P INPUT DROP</code>（最後才設預設策略為 DROP）',
        ],
    },
    {
        'id': 6,
        'title': 'Cron 任務安全',
        'category': '系統加固',
        'difficulty': '簡單',
        'difficulty_color': 'success',
        'description': (
            '系統的排程任務存在安全漏洞，'
            '低權限使用者可藉此植入惡意指令並等待自動觸發，'
            '進而達到權限提升的目的。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash',
        'hints': [
            '用 <code>ls -la /etc/cron.hourly/</code> 和 <code>ls -la /etc/cron.d/</code> 檢查權限',
            '排程腳本如果任何人都能寫入，低權限使用者就能在裡面塞惡意指令',
            'cron 設定檔（<code>/etc/cron.d/</code> 下的檔案）應該只有 root 能修改',
            '思考：腳本需要「執行」權限，但設定檔只需要「讀取」權限',
        ],
    },
    {
        'id': 7,
        'title': 'SUID/SGID 稽核',
        'category': '權限提升防護',
        'difficulty': '中等',
        'difficulty_color': 'warning',
        'description': (
            '系統中存在非必要且具有特殊執行權限的二進位檔案，'
            '可被攻擊者利用來提升至 root 權限。'
            '請稽核系統中不應存在的高權限可執行檔。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash',
        'hints': [
            '如何找出系統中所有具有 SUID 位元的檔案？試試 <code>find</code> 搭配 <code>-perm</code>',
            '比對清單中哪些是系統預設需要的（如 passwd、su），哪些是不該存在的',
            '移除不必要的 SUID 位元：查詢 <code>chmod</code> 如何操作特殊權限位元',
        ],
    },
    {
        'id': 8,
        'title': '系統日誌配置',
        'category': '日誌監控',
        'difficulty': '中等',
        'difficulty_color': 'warning',
        'description': (
            '系統目前無法記錄關鍵的認證事件，'
            '入侵行為發生後將無從追蹤與溯源。'
            '請確保安全相關的日誌功能正常運作。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash',
        'hints': [
            '取消以下行的註解：<code>auth,authpriv.*  /var/log/auth.log</code>',
            '<code>grep -n auth /etc/rsyslog.conf</code> 找到相關行',
        ],
    },
    {
        'id': 9,
        'title': '不必要服務移除',
        'category': '攻擊面縮減',
        'difficulty': '簡單',
        'difficulty_color': 'success',
        'description': (
            '系統中存在一個不應在此運行的網路服務，'
            '它以明文方式傳輸使用者憑證，且對業務毫無必要。'
            '請識別並移除這個多餘的高風險服務。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash',
        'hints': [
            '<code>pkill vsftpd</code>',
            '確認：<code>pgrep vsftpd</code> 應無輸出',
        ],
    },
    {
        'id': 10,
        'title': '密碼策略強化',
        'category': '帳號安全',
        'difficulty': '中等',
        'difficulty_color': 'warning',
        'description': (
            '系統對使用者密碼毫無品質要求，'
            '且密碼一旦設定便永久有效，不符合基本的帳號安全規範。'
            '請強化全系統的密碼複雜度與生命週期政策。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash',
        'hints': [
            '編輯 <code>/etc/pam.d/common-password</code>，pam_pwquality 行加入：',
            '<code>minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1</code>',
            '編輯 <code>/etc/login.defs</code>：<code>PASS_MAX_DAYS 90</code>',
        ],
    },
    {
        'id': 11,
        'title': 'sysctl 核心安全參數',
        'category': '核心加固',
        'difficulty': '中等',
        'difficulty_color': 'warning',
        'description': (
            '系統的核心安全參數存在多處錯誤配置，'
            '可能讓此機器成為網路攻擊的跳板，'
            '或使記憶體層面的漏洞更易被利用。'
            '請將所有參數調整至符合安全基準的數值。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash',
        'hints': [
            '<code>net.ipv4.ip_forward = 0</code>',
            '<code>net.ipv4.conf.all.accept_redirects = 0</code>',
            '<code>kernel.randomize_va_space = 2</code>',
            '<code>fs.protected_hardlinks = 1</code>',
            '<code>fs.protected_symlinks = 1</code>',
        ],
    },
    {
        'id': 12,
        'title': 'PAM 登入失敗鎖定',
        'category': '帳號安全',
        'difficulty': '中等',
        'difficulty_color': 'warning',
        'description': (
            '系統缺乏對暴力破解攻擊的基本防禦，'
            '攻擊者可對帳號進行無限次登入嘗試而不受任何限制。'
            '請設定適當的失敗登入鎖定機制。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash',
        'hints': [
            '編輯 <code>/etc/security/faillock.conf</code>',
            '<code>deny = 5</code>',
            '<code>unlock_time = 900</code>',
        ],
    },
    {
        'id': 13,
        'title': 'sudoers NOPASSWD 風險',
        'category': '特權管理',
        'difficulty': '簡單',
        'difficulty_color': 'success',
        'description': (
            '系統中某個帳號被授予了過度的特權，'
            '可在完全不需驗證的情況下執行任何管理員操作。'
            '請依循最小權限原則重新審視 sudo 授權配置。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash',
        'hints': [
            'sudo 的額外授權設定通常放在 <code>/etc/sudoers.d/</code> 目錄下',
            '檢查該目錄下所有檔案，找出哪個帳號被授予了過度權限',
            '思考：NOPASSWD 代表什麼？ALL 又代表什麼？這樣的組合有什麼風險？',
            '修復方式：移除危險的授權，或將權限限縮到合理範圍',
        ],
    },
    {
        'id': 14,
        'title': 'SSH 停用密碼認證',
        'category': 'SSH 加固',
        'difficulty': '簡單',
        'difficulty_color': 'success',
        'description': (
            'SSH 目前採用較不安全的認證方式，'
            '使帳號暴露於自動化暴力破解攻擊的風險之下。'
            '請將認證機制升級至更具抵抗力的方式。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash',
        'hints': [
            '編輯 <code>/etc/ssh/sshd_config</code>',
            '<code>PasswordAuthentication no</code>',
            '<code>PubkeyAuthentication yes</code>',
            '重載：<code>kill -HUP $(cat /var/run/sshd.pid)</code>',
        ],
    },
    {
        'id': 15,
        'title': '空密碼帳號鎖定',
        'category': '帳號安全',
        'difficulty': '簡單',
        'difficulty_color': 'success',
        'description': (
            '系統中存在無需任何憑證即可登入的帳號，'
            '任何人都可以直接取得這些帳號的存取權限。'
            '請找出並修復所有存在此問題的帳號。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash',
        'hints': [
            '<code>/etc/shadow</code> 檔案中，密碼欄位為空代表該帳號不需密碼即可登入',
            '找出哪些帳號的密碼欄位是空的（第二個欄位）',
            '修復方式：為這些帳號設定密碼，或將帳號鎖定',
            '可用 <code>passwd -S 帳號名</code> 確認帳號狀態',
        ],
    },
    {
        'id': 16,
        'title': 'ACL 存取控制',
        'category': '權限管理',
        'difficulty': '中等',
        'difficulty_color': 'warning',
        'description': (
            '系統中 <code>it</code> 群組的成員目前可執行 <code>find</code> 指令，'
            '違反職責分離原則。'
            '請透過 ACL 機制限制該群組對此指令的執行權限。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash',
        'hints': [
            'ACL（Access Control List）可以對特定使用者或群組設定比傳統 rwx 更細緻的權限',
            '使用 <code>setfacl</code> 指令來設定 ACL，<code>getfacl</code> 來查看',
            '目標：讓 it 群組的成員只能「讀取」該指令的檔案，但無法「執行」',
            '設定完後，用 <code>su</code> 切換到 it 群組的成員帳號測試是否生效',
        ],
    },
    {
        'id': 17,
        'title': 'sudo 最小授權',
        'category': '特權管理',
        'difficulty': '中等',
        'difficulty_color': 'warning',
        'description': (
            '<code>webadmin</code> 帳號目前沒有任何 sudo 設定，'
            '但業務需要其能以 root 身份執行特定維運指令。'
            '請依最小權限原則，設定需輸入密碼且僅限單一指令的 sudo 規則。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash',
        'hints': [
            'sudoers 的規則格式為：<code>使用者 主機=(身份) 指令</code>',
            '需求：webadmin 必須輸入密碼才能以 root 身份執行「一個特定的維運指令」',
            '規則檔應放在 <code>/etc/sudoers.d/</code> 下，並設定正確的檔案權限',
            '注意：不可使用 NOPASSWD，也不可授權 ALL 指令',
        ],
    },
    {
        'id': 18,
        'title': '家目錄權限',
        'category': '帳號安全',
        'difficulty': '簡單',
        'difficulty_color': 'success',
        'description': (
            '系統中所有使用者的家目錄權限過於開放，'
            '其他使用者可任意瀏覽家目錄內的私人檔案。'
            '請將所有家目錄限制為僅擁有者可存取。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash',
        'hints': [
            '用 <code>ls -la /home/</code> 查看目前每個使用者家目錄的權限',
            '思考：家目錄應該只有擁有者能存取，對應的權限數字是多少？',
            '提示：rwx------ 的八進位表示法',
        ],
    },
    {
        'id': 19,
        'title': 'HTTPS 與強制重導向',
        'category': 'Web 安全',
        'difficulty': '困難',
        'difficulty_color': 'danger',
        'description': (
            'Web 服務目前僅提供 HTTP 明文傳輸，'
            '所有使用者的資料（包含憑證）均以明文在網路上傳遞。'
            '請為 Apache 建立自簽 RSA 2048 憑證並啟用 HTTPS，'
            '同時將所有 HTTP 請求自動重導向至 HTTPS。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash\nHTTPS: https://localhost:8443',
        'hints': [
            'openssl req -x509 -newkey rsa:2048 -keyout /etc/ssl/private/server.key -out /etc/ssl/certs/server.crt -days 365 -nodes',
            'a2enmod ssl && a2ensite default-ssl',
            '在 000-default.conf 加入：<code>Redirect permanent / https://localhost:8443/</code>',
            '重啟：<code>service apache2 restart</code>',
        ],
    },
    {
        'id': 20,
        'title': 'iptables 連接埠轉發',
        'category': '網路安全',
        'difficulty': '困難',
        'difficulty_color': 'danger',
        'description': (
            '需要將進入系統特定連接埠的流量自動轉發至內部服務。'
            '請使用 iptables NAT 表設定 DNAT 規則，'
            '將外部連線到 <code>9090</code> 埠的 TCP 流量轉發至本機的 <code>80</code> 埠。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash',
        'hints': [
            '<code>iptables -t nat -A PREROUTING -p tcp --dport 9090 -j DNAT --to-destination 127.0.0.1:80</code>',
            '<code>iptables -t nat -A OUTPUT -p tcp --dport 9090 -j DNAT --to-destination 127.0.0.1:80</code>',
            '驗證：<code>iptables -t nat -L PREROUTING -n -v</code>',
        ],
    },
    {
        'id': 21,
        'title': 'PHP 安全設定',
        'category': 'Web 安全',
        'difficulty': '中等',
        'difficulty_color': 'warning',
        'description': (
            'PHP 的執行環境設定過於寬鬆，'
            '可能洩漏伺服器版本資訊、內部路徑與錯誤細節，'
            '甚至允許遠端檔案引入（RFI）攻擊，'
            '且未停用可執行系統指令的危險函數。'
            '請強化 php.ini 的安全設定。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash',
        'hints': [
            '設定檔位置：<code>php -r "echo php_ini_loaded_file();"</code>',
            '<code>expose_php = Off</code>（隱藏 PHP 版本）',
            '<code>display_errors = Off</code>（不顯示錯誤細節）',
            '<code>allow_url_include = Off</code>（防止 RFI）',
            '停用危險函數：<code>disable_functions = system,exec,passthru,shell_exec,popen,proc_open</code>',
            '重啟：<code>service apache2 restart</code>',
        ],
    },
    {
        'id': 22,
        'title': 'Apache 目錄列表防護',
        'category': 'Web 安全',
        'difficulty': '簡單',
        'difficulty_color': 'success',
        'description': (
            'Apache 的目錄列表功能（Directory Listing）目前處於開啟狀態，'
            '攻擊者可直接瀏覽伺服器上的檔案清單，'
            '可能洩漏敏感檔案或內部結構。'
            '請停用目錄列表功能。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash\nhttp://localhost:8080/data/',
        'hints': [
            '編輯 <code>/etc/apache2/apache2.conf</code>',
            '找到 <code>&lt;Directory /var/www/html/data&gt;</code> 區塊',
            '將 <code>Options Indexes FollowSymLinks</code> 改為 <code>Options FollowSymLinks</code>',
            '或改為 <code>Options -Indexes</code>',
            '重啟：<code>service apache2 restart</code>',
        ],
    },
    {
        'id': 23,
        'title': 'Nginx 安全配置',
        'category': 'Web 安全',
        'difficulty': '中等',
        'difficulty_color': 'warning',
        'description': (
            'Nginx 伺服器存在不安全的配置，'
            '包含 alias 路徑穿越漏洞（Path Traversal）以及不必要的目錄列表。'
            '攻擊者可利用 alias 錯誤配置讀取伺服器上的任意檔案。'
            '請修復這些安全問題。'
        ),
        'container': CONTAINER,
        'access': 'docker exec -it sec_challenge bash\nNginx: http://localhost:8181',
        'hints': [
            '設定檔：<code>/etc/nginx/sites-enabled/vulnerable</code>',
            'alias 路徑穿越：location 結尾需加 <code>/</code>（如 <code>/secret/</code>）',
            '停用 autoindex：移除或設為 <code>autoindex off;</code>',
            '重載：<code>nginx -s reload</code>',
        ],
    },
]


# ---------------------------------------------------------------------------
# Verifiers  — all use docker_exec() which targets CONTAINER
# ---------------------------------------------------------------------------

def verify_challenge_1(container):
    out, _ = docker_exec('cat /etc/ssh/sshd_config')
    checks = {}

    checks['已禁止特定高權限帳號直接透過 SSH 登入'] = bool(
        re.search(r'^\s*PermitRootLogin\s+no\s*$', out, re.M | re.I)
    )
    m = re.search(r'^\s*MaxAuthTries\s+(\d+)', out, re.M)
    checks['已限制 SSH 認證嘗試次數'] = bool(m and int(m.group(1)) <= 3)

    checks['已關閉不必要的圖形介面轉發功能'] = bool(
        re.search(r'^\s*X11Forwarding\s+no\s*$', out, re.M | re.I)
    )
    m2 = re.search(r'^\s*LoginGraceTime\s+(\d+)', out, re.M)
    checks['已縮短登入等待逾時時間'] = bool(m2 and int(m2.group(1)) <= 60)

    banner_m = re.search(r'^\s*Banner\s+(\S+)', out, re.M)
    if banner_m:
        b_out, _ = docker_exec(f'test -f {banner_m.group(1)} && echo ok')
        checks['已設定登入警告標語'] = 'ok' in b_out
    else:
        checks['已設定登入警告標語'] = False

    return all(checks.values()), checks


def verify_challenge_2(container):
    checks = {}
    # Check that PasswordAuthentication is still enabled (not solved by challenge 14)
    sshd_out, _ = docker_exec('cat /etc/ssh/sshd_config')
    pa_on = re.search(r'^\s*PasswordAuthentication\s+yes', sshd_out, re.M | re.I)
    pa_off = re.search(r'^\s*PasswordAuthentication\s+no', sshd_out, re.M | re.I)
    pwd_auth_enabled = bool(pa_on) or not bool(pa_off)  # default is yes

    # Check the shadow hash — admin must NOT still have the admin123 hash
    shadow_out, _ = docker_exec('cat /etc/shadow')
    admin_line = re.search(r'^admin:([^:]*)', shadow_out, re.M)
    if admin_line:
        current_hash = admin_line.group(1)
        is_locked = current_hash.startswith('!') or current_hash == '*'
        # Extract salt from hash (format: $id$salt$hash)
        hash_to_check = current_hash.lstrip('!')  # strip lock prefix for hash check
        salt_m = re.match(r'(\$[^$]+\$[^$]+)\$', hash_to_check)
        if salt_m:
            salt_part = salt_m.group(1).split('$')[2]
            computed, _ = docker_exec(
                f"openssl passwd -6 -salt '{salt_part}' 'admin123' 2>/dev/null"
            )
            pwd_changed = computed.strip() != hash_to_check
        else:
            pwd_changed = True
        # Must BOTH change password AND keep account usable
        checks['弱密碼已更換為強密碼（且帳號仍可使用）'] = pwd_changed and not is_locked
    else:
        checks['弱密碼已更換為強密碼（且帳號仍可使用）'] = False
    return all(checks.values()), checks


def verify_challenge_3(container):
    checks = {}
    # Use curl inside the container to avoid firewall/redirect issues
    # -L follows HTTP→HTTPS redirect, -k allows self-signed certs
    upload_out, _ = docker_exec(
        'echo "<?php echo \\"EXEC_OK_\\".shell_exec(\\"id\\"); ?>" > /tmp/evil.php; '
        'CODE=$(curl -sLk -o /tmp/upload_resp.txt -w "%{http_code}" '
        '-F "file=@/tmp/evil.php;type=application/octet-stream" '
        'http://localhost/upload.php 2>/dev/null); '
        'BODY=$(cat /tmp/upload_resp.txt 2>/dev/null); '
        'echo "HTTP_CODE=$CODE|BODY=$BODY"'
    )
    code_m = re.search(r'HTTP_CODE=(\d+)', upload_out)
    http_code = code_m.group(1) if code_m else '000'
    upload_blocked = http_code != '200' or 'success' not in upload_out.lower()
    checks['PHP 檔案上傳被拒絕'] = upload_blocked

    # Always check .htaccess protection independently — even if upload is blocked,
    # attacker may bypass upload validation; defense-in-depth requires both layers
    htaccess_out, _ = docker_exec('cat /var/www/html/uploads/.htaccess 2>/dev/null')
    checks['上傳目錄有 .htaccess 防護'] = bool(
        re.search(r'php_flag\s+engine\s+off', htaccess_out, re.I)
        or re.search(r'SetHandler\s+None', htaccess_out, re.I)
        or re.search(r'RemoveHandler\s+\.php', htaccess_out, re.I)
        or re.search(r'<FilesMatch.*php.*>.*Deny\b', htaccess_out, re.S | re.I)
    )

    return all(checks.values()), checks


def verify_challenge_4(container):
    checks = {}

    def perm(path):
        out, _ = docker_exec(f'stat -c %a {path}')
        return out.strip()

    checks['密碼雜湊檔案的權限已限縮'] = perm('/etc/shadow') in ('640', '000', '400', '600')
    checks['應用程式設定檔已移除過度的寫入權限'] = perm('/opt/app/config.ini') in ('644', '640', '600', '400')
    checks['日誌目錄已移除全域可寫權限'] = perm('/var/log') in ('755', '750', '700')

    return all(checks.values()), checks


def verify_challenge_5(container):
    checks = {}
    out, _ = docker_exec('iptables -L INPUT -n -v')
    # 1. Default policy should be DROP
    checks['預設策略已設為拒絕所有未明確允許的流量'] = 'policy DROP' in out

    # 2. Allow established/related connections (stateful firewall)
    checks['已允許既有連線的回應封包通過（狀態追蹤）'] = bool(
        re.search(r'ACCEPT.*state\s+.*ESTABLISHED', out, re.I)
        or re.search(r'ACCEPT.*ctstate\s+.*ESTABLISHED', out, re.I)
    )

    # 3. Allow SSH (port 22)
    checks['已放行遠端管理所需的服務埠'] = bool(
        re.search(r'ACCEPT\s+tcp\s+.*dpt:22\b', out)
    )

    # 4. Allow HTTP (port 80)
    checks['已放行 Web 服務所需的服務埠'] = bool(
        re.search(r'ACCEPT\s+tcp\s+.*dpt:80\b', out)
    )

    # 5. Allow loopback
    checks['已允許本機內部通訊介面'] = bool(
        re.search(r'ACCEPT\s+.*\s+lo\s', out)
        or re.search(r'ACCEPT\s+all\s+--\s+lo', out)
    )

    # 6. At least 4 meaningful rules
    rule_lines = [l for l in out.splitlines()
                  if l.strip()
                  and not l.strip().startswith('Chain')
                  and not l.strip().startswith('pkts')
                  and not l.strip().startswith('#')]
    checks['防火牆規則數量足夠完整'] = len(rule_lines) >= 4

    return all(checks.values()), checks


def verify_challenge_6(container):
    checks = {}

    def perm(path):
        out, _ = docker_exec(f'stat -c %a {path}')
        return out.strip()

    script_perm = perm('/etc/cron.hourly/backup.sh')
    checks['排程腳本已移除不安全的寫入權限'] = (
        script_perm != '' and script_perm not in ('777', '776', '775', '766', '767')
    )
    checks['排程設定檔的權限已限縮至合理範圍'] = perm('/etc/cron.d/backup') in ('644', '640', '600')
    return all(checks.values()), checks


def verify_challenge_7(container):
    checks = {}
    out, _ = docker_exec('stat -c %a /usr/local/bin/vuln_tool')
    perm = out.strip()
    checks['可疑二進位檔的特殊權限位元已移除'] = not perm.startswith('4')
    find_out, _ = docker_exec('find /usr/local/bin/vuln_tool -perm -4000 2>/dev/null')
    checks['該檔案已無法被用於權限提升'] = '/usr/local/bin/vuln_tool' not in find_out
    return all(checks.values()), checks


def verify_challenge_8(container):
    checks = {}
    out, _ = docker_exec('cat /etc/rsyslog.conf')
    # Check there is at least one UNCOMMENTED auth,authpriv line
    auth_line = re.search(r'^\s*auth,authpriv\.\*\s+\S+', out, re.M)
    checks['認證相關的日誌記錄功能已啟用'] = bool(auth_line)
    checks['認證日誌有指定輸出至檔案'] = bool(re.search(r'auth,authpriv\.\*\s+/var/log/', out, re.M))
    return all(checks.values()), checks


def verify_challenge_9(container):
    checks = {}
    # Exclude zombie (defunct) processes — pgrep still returns zombies
    out, _ = docker_exec(
        "ps -eo stat,comm | awk '$1 !~ /Z/ && $2 == \"vsftpd\" {print $2}'"
    )
    checks['不必要的明文傳輸服務已停止'] = out.strip() == ''
    port_out, _ = docker_exec('ss -tlnp 2>/dev/null')
    checks['該服務的監聽埠已關閉'] = ':21 ' not in port_out and ':21\n' not in port_out
    return all(checks.values()), checks


def verify_challenge_10(container):
    checks = {}
    pam_out, _ = docker_exec('cat /etc/pam.d/common-password')
    minlen_m = re.search(r'minlen=(\d+)', pam_out)
    checks['已設定足夠的密碼最小長度'] = bool(minlen_m and int(minlen_m.group(1)) >= 12)
    checks['已要求密碼包含多種字元類型'] = bool(
        re.search(r'(ucredit|lcredit|dcredit|ocredit)\s*=\s*-\d', pam_out)
    )
    defs_out, _ = docker_exec('cat /etc/login.defs')
    m = re.search(r'^\s*PASS_MAX_DAYS\s+(\d+)', defs_out, re.M)
    checks['已限制密碼的最長有效天數'] = bool(m and int(m.group(1)) <= 90)
    return all(checks.values()), checks


def verify_challenge_11(container):
    checks = {}
    out, _ = docker_exec('cat /etc/sysctl.d/99-hardening.conf')

    def val(key):
        m = re.search(rf'^\s*{re.escape(key)}\s*=\s*(\S+)', out, re.M)
        return m.group(1) if m else None

    checks['已停用 IP 封包轉發功能']                      = val('net.ipv4.ip_forward') == '0'
    checks['已拒絕 ICMP 重導向封包']                      = val('net.ipv4.conf.all.accept_redirects') == '0'
    checks['已停止發送 ICMP 重導向封包']                   = val('net.ipv4.conf.all.send_redirects') == '0'
    checks['已拒絕來源路由封包']                           = val('net.ipv4.conf.all.accept_source_route') == '0'
    checks['已啟用記憶體位址隨機化防護（ASLR）']           = val('kernel.randomize_va_space') == '2'
    checks['已忽略 ICMP 廣播請求']                        = val('net.ipv4.icmp_echo_ignore_broadcasts') == '1'
    checks['已啟用硬連結存取保護']                         = val('fs.protected_hardlinks') == '1'
    checks['已啟用符號連結存取保護']                       = val('fs.protected_symlinks') == '1'
    return all(checks.values()), checks


def verify_challenge_12(container):
    checks = {}
    out, _ = docker_exec('cat /etc/security/faillock.conf')
    deny_m = re.search(r'^\s*deny\s*=\s*(\d+)', out, re.M)
    deny_val = int(deny_m.group(1)) if deny_m else 0
    # Must be between 1 and 10: non-zero lockout with a reasonable threshold
    checks['已設定合理的失敗登入鎖定次數'] = 1 <= deny_val <= 10
    unlock_m = re.search(r'^\s*unlock_time\s*=\s*(\d+)', out, re.M)
    unlock_val = int(unlock_m.group(1)) if unlock_m else 0
    checks['帳號鎖定後的等待時間足夠長'] = unlock_val >= 300
    return all(checks.values()), checks


def verify_challenge_13(container):
    checks = {}
    out, _ = docker_exec('cat /etc/sudoers.d/deploy 2>/dev/null || echo FILE_REMOVED')
    file_removed = 'FILE_REMOVED' in out
    has_nopasswd = bool(re.search(r'NOPASSWD', out, re.I))
    # Match patterns like: ALL=(ALL) NOPASSWD: ALL  or  ALL=(ALL) ALL  or  ALL=(ALL:ALL) ALL
    has_unrestricted = bool(
        re.search(r'ALL\s*=\s*\(ALL(?::ALL)?\)\s+(?:NOPASSWD:\s*)?ALL\s*$', out, re.M | re.I)
    )
    if file_removed:
        checks['已移除免密碼的特權提升設定'] = True
        checks['已移除無限制的管理員指令授權'] = True
    else:
        checks['已移除免密碼的特權提升設定'] = not has_nopasswd
        checks['已移除無限制的管理員指令授權'] = not has_unrestricted
    return all(checks.values()), checks


def verify_challenge_14(container):
    checks = {}
    out, _ = docker_exec('cat /etc/ssh/sshd_config')
    passwd_auth = re.search(r'^\s*PasswordAuthentication\s+(\S+)', out, re.M | re.I)
    checks['已停用較不安全的認證方式'] = bool(
        passwd_auth and passwd_auth.group(1).lower() == 'no'
    )
    # PubkeyAuthentication must be explicitly set to yes (not absent, not no)
    pubkey_auth = re.search(r'^\s*PubkeyAuthentication\s+(\S+)', out, re.M | re.I)
    checks['已明確啟用更安全的認證機制'] = bool(
        pubkey_auth and pubkey_auth.group(1).lower() == 'yes'
    )
    return all(checks.values()), checks


def verify_challenge_16(container):
    checks = {}
    out, _ = docker_exec('getfacl /usr/bin/find 2>/dev/null')
    it_m = re.search(r'group:it:([rwx-]+)', out)
    checks['目標群組的 ACL 規則已設定'] = bool(it_m)
    checks['目標群組已被限制執行該指令'] = bool(it_m and 'x' not in it_m.group(1))
    exec_out, exit_code = docker_exec(
        'su -s /bin/sh svcuser -c "/usr/bin/find /tmp -maxdepth 0" 2>&1'
    )
    checks['群組成員實際執行時已被拒絕'] = exit_code != 0 or 'Permission denied' in exec_out
    return all(checks.values()), checks


def verify_challenge_17(container):
    checks = {}
    out, _ = docker_exec('grep -h webadmin /etc/sudoers /etc/sudoers.d/* 2>/dev/null')
    checks['目標帳號已建立 sudo 授權規則'] = 'webadmin' in out
    checks['執行特權指令時需要驗證身份'] = 'webadmin' in out and 'NOPASSWD' not in out
    checks['授權範圍已限縮至特定指令'] = bool(
        re.search(r'webadmin.*=.*\(.*\)\s+/(?!ALL\b)\S+', out)
    ) and not bool(re.search(r'webadmin.*=.*\(.*\)\s+ALL\b', out))
    return all(checks.values()), checks


def verify_challenge_18(container):
    checks = {}
    out, _ = docker_exec('ls /home/')
    users = [u for u in out.split() if u]
    for user in users:
        perm, _ = docker_exec(f'stat -c %a /home/{user} 2>/dev/null')
        checks[f'/home/{user} 已限制為僅擁有者可存取'] = perm.strip() == '700'
    return all(checks.values()), checks


def verify_challenge_19(container):
    checks = {}
    # Check HTTPS port 443 is listening
    port_out, _ = docker_exec('ss -tlnp 2>/dev/null')
    checks['加密傳輸服務已啟動'] = ':443 ' in port_out or ':443\n' in port_out
    # Check RSA 2048 cert
    cert_out, _ = docker_exec(
        'find /etc/ssl/certs /etc/apache2 -name "*.crt" 2>/dev/null'
        ' | head -1'
        ' | xargs -I{} openssl x509 -in {} -text -noout 2>/dev/null'
        ' | grep "Public-Key"'
    )
    checks['憑證使用符合要求的金鑰長度'] = '2048' in cert_out
    # Check HTTP redirects to HTTPS using curl inside container
    code_out, _ = docker_exec(
        'curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null'
    )
    loc_out, _ = docker_exec(
        'curl -si http://localhost/ 2>/dev/null | grep -i "^Location:" | head -1'
    )
    checks['HTTP 自動重導向至 HTTPS'] = (
        code_out.strip() in ('301', '302', '307', '308')
        and 'https' in loc_out.lower()
    )
    return all(checks.values()), checks


def verify_challenge_20(container):
    checks = {}
    out, _ = docker_exec('iptables -t nat -L PREROUTING -n -v 2>/dev/null')
    rule_lines = [l for l in out.splitlines()
                  if l.strip()
                  and 'DNAT' in l
                  and not l.strip().startswith('#')]
    checks['已建立封包目標位址轉換規則'] = len(rule_lines) >= 1
    checks['轉發目標已指向正確的內部服務埠'] = bool(re.search(r'to:.*:80\b', out))
    return all(checks.values()), checks


def verify_challenge_15(container):
    checks = {}
    shadow_out, _ = docker_exec('cat /etc/shadow')

    empty = [line.split(':')[0] for line in shadow_out.splitlines()
             if len(line.split(':')) >= 2 and line.split(':')[1] == '']

    checks['第一個可疑帳號的空密碼已修復']   = 'ghost'   not in empty
    checks['第二個可疑帳號的空密碼已修復'] = 'phantom' not in empty

    def locked(user):
        m = re.search(rf'^{re.escape(user)}:(!|\*)', shadow_out, re.M)
        return bool(m)

    checks['第一個可疑帳號已鎖定或設有密碼']   = True if 'ghost'   not in empty else locked('ghost')
    checks['第二個可疑帳號已鎖定或設有密碼'] = True if 'phantom' not in empty else locked('phantom')

    return all(checks.values()), checks


def verify_challenge_21(container):
    checks = {}
    php_ini, _ = docker_exec("php -r 'echo php_ini_loaded_file();'")
    php_ini = php_ini.strip()
    out, _ = docker_exec(f'cat {php_ini}')

    expose = re.search(r'^\s*expose_php\s*=\s*(\S+)', out, re.M)
    checks['已隱藏伺服器端程式語言的版本資訊'] = bool(
        expose and expose.group(1).lower() in ('off', '0')
    )
    display = re.search(r'^\s*display_errors\s*=\s*(\S+)', out, re.M)
    checks['已停止對外顯示程式錯誤細節'] = bool(
        display and display.group(1).lower() in ('off', '0')
    )
    allow_inc = re.search(r'^\s*allow_url_include\s*=\s*(\S+)', out, re.M)
    checks['已關閉遠端檔案引入功能'] = bool(
        allow_inc and allow_inc.group(1).lower() in ('off', '0')
    )
    # Check disable_functions contains dangerous command execution functions
    disable_m = re.search(r'^\s*disable_functions\s*=\s*(.+)', out, re.M)
    if disable_m:
        disabled = disable_m.group(1).lower()
        dangerous = ['system', 'exec', 'passthru', 'shell_exec', 'popen', 'proc_open']
        has_all = all(fn in disabled for fn in dangerous)
        checks['已停用危險的指令執行函數'] = has_all
    else:
        checks['已停用危險的指令執行函數'] = False
    return all(checks.values()), checks


def verify_challenge_22(container):
    checks = {}
    out, _ = docker_exec('cat /etc/apache2/apache2.conf')
    # Check that Options Indexes is not enabled for /var/www/html/data
    data_block = re.search(
        r'<Directory\s+/var/www/html/data\s*>(.*?)</Directory>',
        out, re.S | re.I
    )
    if data_block:
        block_content = data_block.group(1)
        has_indexes = bool(re.search(r'Options\s+.*\bIndexes\b', block_content))
        has_neg_indexes = bool(re.search(r'Options\s+.*-Indexes', block_content))
        checks['目錄瀏覽功能已停用'] = not has_indexes or has_neg_indexes
    else:
        # Block removed entirely is also fine
        checks['目錄瀏覽功能已停用'] = True

    # Functional check: curl the directory and confirm no listing
    curl_out, _ = docker_exec(
        'curl -sL http://localhost/data/ 2>/dev/null'
    )
    checks['目錄列表實際已關閉'] = 'secret.txt' not in curl_out
    return all(checks.values()), checks


def verify_challenge_23(container):
    checks = {}
    out, _ = docker_exec('cat /etc/nginx/sites-enabled/vulnerable 2>/dev/null '
                         '|| cat /etc/nginx/sites-available/vulnerable 2>/dev/null')

    has_config = bool(out.strip()) and 'No such file' not in out

    # Check autoindex is off — config must still exist (can't just delete it)
    autoindex_on = re.findall(r'autoindex\s+on', out, re.I)
    checks['目錄自動列表已停用'] = has_config and len(autoindex_on) == 0

    # Functional check: path traversal via alias misconfiguration
    # --path-as-is prevents curl from normalizing ../ in the URL
    traversal_out, _ = docker_exec(
        'curl -s --path-as-is http://localhost:8081/secret../html/ 2>/dev/null'
    )
    # If traversal works, attacker can browse /var/www/html/ (Apache web root)
    # Check for signs of successful traversal: Apache content or directory listing
    checks['alias 路徑穿越漏洞已修復'] = has_config and (
        'upload' not in traversal_out.lower()
        and 'index of /secret' not in traversal_out.lower()
        and '檔案上傳' not in traversal_out
    )

    # Functional check: /data/ should still serve files but NOT list directory
    data_out, _ = docker_exec(
        'curl -s http://localhost:8081/data/ 2>/dev/null'
    )
    checks['/data/ 目錄存取已不再列出檔案清單'] = has_config and (
        'index of' not in data_out.lower() and 'secret.txt' not in data_out
    )

    return all(checks.values()), checks
