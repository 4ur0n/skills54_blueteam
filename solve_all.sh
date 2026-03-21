#!/bin/bash
# 解題腳本 — 對 sec_challenge 容器套用修補
#
# 用法：
#   ./solve_all.sh              # 解全部 23 題
#   ./solve_all.sh -s 3 -e 7    # 解第 3~7 題
#   ./solve_all.sh -s 5         # 從第 5 題解到最後
#   ./solve_all.sh -e 10        # 從第 1 題解到第 10 題
#   ./solve_all.sh -c 4         # 解第 1~4 題（等同 -e 4）
#   ./solve_all.sh 3 7 15       # 只解第 3、7、15 題
#
# 執行前請確認容器已啟動：docker compose up -d

set -e
CONTAINER=sec_challenge

D() {
    docker exec "$CONTAINER" bash -c "$1"
}

ok()  { echo "[✓] $1"; }
hdr() { echo; echo "══════════════════════════════════════"; echo "  $1"; echo "══════════════════════════════════════"; }

should_run() {
    local n=$1
    for t in "${TASKS[@]}"; do
        [[ "$t" == "$n" ]] && return 0
    done
    return 1
}

# ── 解析參數 ─────────────────────────────────────────────────
START=1
END=23
SPECIFIC=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -s|--start)  START="$2"; shift 2 ;;
        -e|--end)    END="$2";   shift 2 ;;
        -c|--continue) END="$2"; shift 2 ;;
        -h|--help)
            echo "用法："
            echo "  ./solve_all.sh              # 全部"
            echo "  ./solve_all.sh -s 3 -e 7    # 第 3~7 題"
            echo "  ./solve_all.sh -s 5         # 第 5 題到最後"
            echo "  ./solve_all.sh -e 10        # 第 1~10 題"
            echo "  ./solve_all.sh -c 4         # 第 1~4 題"
            echo "  ./solve_all.sh 3 7 15       # 只解第 3、7、15 題"
            exit 0
            ;;
        *)
            # 數字參數 → 指定題號
            if [[ "$1" =~ ^[0-9]+$ ]]; then
                SPECIFIC+=("$1")
            fi
            shift
            ;;
    esac
done

# 建立要執行的題目清單
TASKS=()
if [[ ${#SPECIFIC[@]} -gt 0 ]]; then
    TASKS=("${SPECIFIC[@]}")
else
    for ((i=START; i<=END; i++)); do
        TASKS+=("$i")
    done
fi

echo "📋 將解題：${TASKS[*]}"
echo

# ── 題目函數 ──────────────────────────────────────────────────

solve_1() {
    hdr "題目 1 — SSH 服務配置安全"
    D "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/'      /etc/ssh/sshd_config"
    D "sed -i 's/^MaxAuthTries.*/MaxAuthTries 3/'              /etc/ssh/sshd_config"
    D "sed -i 's/^X11Forwarding.*/X11Forwarding no/'           /etc/ssh/sshd_config"
    D "sed -i 's/^LoginGraceTime.*/LoginGraceTime 30/'         /etc/ssh/sshd_config"
    D "grep -q '^Banner' /etc/ssh/sshd_config \
        || echo 'Banner /etc/ssh/banner' >> /etc/ssh/sshd_config"
    D "echo 'WARNING: Authorized use only.' > /etc/ssh/banner"
    ok "題目 1 完成"
}

solve_2() {
    hdr "題目 2 — SSH 弱密碼"
    D "echo 'admin:Str0ng#Pass2024!' | chpasswd"
    ok "題目 2 完成"
}

solve_3() {
    hdr "題目 3 — Web 上傳漏洞"
    D "cat > /var/www/html/upload.php << 'PHPEOF'
<?php
\$allowed_ext  = ['jpg','jpeg','png','gif'];
\$allowed_mime = ['image/jpeg','image/png','image/gif','image/webp'];
\$upload_dir   = '/var/www/html/uploads/';

if (!isset(\$_FILES['file']) || \$_FILES['file']['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    echo 'Upload error.';
    exit;
}

\$ext = strtolower(pathinfo(\$_FILES['file']['name'], PATHINFO_EXTENSION));
if (!in_array(\$ext, \$allowed_ext)) {
    http_response_code(403);
    echo 'File type not allowed.';
    exit;
}

\$finfo = finfo_open(FILEINFO_MIME_TYPE);
\$mime  = finfo_file(\$finfo, \$_FILES['file']['tmp_name']);
finfo_close(\$finfo);
if (!in_array(\$mime, \$allowed_mime)) {
    http_response_code(403);
    echo 'Invalid MIME type.';
    exit;
}

\$dest = \$upload_dir . basename(\$_FILES['file']['name']);
move_uploaded_file(\$_FILES['file']['tmp_name'], \$dest);
echo 'Upload successful.';
PHPEOF"
    D "echo 'php_flag engine off' > /var/www/html/uploads/.htaccess"
    ok "題目 3 完成"
}

solve_4() {
    hdr "題目 4 — 最小權限原則"
    D "chmod 640 /etc/shadow"
    D "chmod 644 /opt/app/config.ini"
    D "chmod 755 /var/log"
    ok "題目 4 完成"
}

solve_5() {
    hdr "題目 5 — 防火牆配置"
    D "iptables -F INPUT 2>/dev/null; iptables -P INPUT DROP"
    D "iptables -A INPUT -i lo -j ACCEPT"
    D "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"
    D "iptables -A INPUT -p tcp --dport 22 -j ACCEPT"
    D "iptables -A INPUT -p tcp --dport 80 -j ACCEPT"
    ok "題目 5 完成"
}

solve_6() {
    hdr "題目 6 — Cron 任務安全"
    D "chmod 755 /etc/cron.hourly/backup.sh"
    D "chmod 644 /etc/cron.d/backup"
    ok "題目 6 完成"
}

solve_7() {
    hdr "題目 7 — SUID/SGID 稽核"
    D "chmod u-s /usr/local/bin/vuln_tool"
    ok "題目 7 完成"
}

solve_8() {
    hdr "題目 8 — 系統日誌配置"
    D "sed -i 's|^#\s*auth,authpriv\.\*|auth,authpriv.*|g' /etc/rsyslog.conf"
    D "grep -q 'auth,authpriv\.\*.*auth.log' /etc/rsyslog.conf \
        || echo 'auth,authpriv.*   /var/log/auth.log' >> /etc/rsyslog.conf"
    ok "題目 8 完成"
}

solve_9() {
    hdr "題目 9 — 不必要服務移除"
    D "pkill vsftpd 2>/dev/null; true"
    ok "題目 9 完成"
}

solve_10() {
    hdr "題目 10 — 密碼策略強化"
    D "sed -i '/pam_pwquality\.so/ s/$/ minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' \
        /etc/pam.d/common-password"
    D "grep -qP 'pam_pwquality.*minlen=\d+.*minlen=\d+' /etc/pam.d/common-password && \
        sed -i 's/\(pam_pwquality\.so[^\"]*\)minlen=[0-9]* ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 \(.*minlen=\)/\1\2/' \
        /etc/pam.d/common-password; true"
    D "sed -i 's/^PASS_MAX_DAYS\s.*/PASS_MAX_DAYS\t90/' /etc/login.defs"
    ok "題目 10 完成"
}

solve_11() {
    hdr "題目 11 — sysctl 核心安全參數"
    D "cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
# Security hardening — fixed values
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
kernel.randomize_va_space = 2
net.ipv4.icmp_echo_ignore_broadcasts = 1
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF"
    D "sysctl -p /etc/sysctl.d/99-hardening.conf 2>/dev/null; true"
    ok "題目 11 完成"
}

solve_12() {
    hdr "題目 12 — PAM 登入失敗鎖定"
    D "sed -i 's/^deny\s*=.*/deny = 5/'               /etc/security/faillock.conf"
    D "sed -i 's/^unlock_time\s*=.*/unlock_time = 900/' /etc/security/faillock.conf"
    ok "題目 12 完成"
}

solve_13() {
    hdr "題目 13 — sudoers NOPASSWD 風險"
    D "rm -f /etc/sudoers.d/deploy"
    ok "題目 13 完成"
}

solve_14() {
    hdr "題目 14 — SSH 停用密碼認證"
    D "sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/'  /etc/ssh/sshd_config"
    D "grep -q '^PubkeyAuthentication' /etc/ssh/sshd_config \
        && sed -i 's/^PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config \
        || echo 'PubkeyAuthentication yes' >> /etc/ssh/sshd_config"
    ok "題目 14 完成"
}

solve_15() {
    hdr "題目 15 — 空密碼帳號鎖定"
    D "passwd -l ghost"
    D "passwd -l phantom"
    ok "題目 15 完成"
}

solve_16() {
    hdr "題目 16 — ACL 存取控制"
    D "setfacl -m g:it:r-- /usr/bin/find"
    ok "題目 16 完成"
}

solve_17() {
    hdr "題目 17 — sudo 最小授權"
    D "echo 'webadmin ALL=(ALL) /usr/bin/find' > /etc/sudoers.d/webadmin && chmod 440 /etc/sudoers.d/webadmin"
    ok "題目 17 完成"
}

solve_18() {
    hdr "題目 18 — 家目錄權限"
    D "chmod 700 /home/*"
    ok "題目 18 完成"
}

solve_19() {
    hdr "題目 19 — HTTPS 與強制重導向"
    D "openssl req -x509 -newkey rsa:2048 \
        -keyout /etc/ssl/private/server.key \
        -out /etc/ssl/certs/server.crt \
        -days 365 -nodes \
        -subj '/CN=localhost' 2>/dev/null"
    D "a2enmod ssl 2>/dev/null; true"
    D "cat > /etc/apache2/sites-available/default-ssl.conf << 'EOF'
<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile    /etc/ssl/certs/server.crt
    SSLCertificateKeyFile /etc/ssl/private/server.key
    DocumentRoot /var/www/html
</VirtualHost>
EOF"
    D "a2ensite default-ssl 2>/dev/null; true"
    D "sed -i 's|DocumentRoot /var/www/html|DocumentRoot /var/www/html\n    Redirect permanent / https://localhost/|' \
        /etc/apache2/sites-available/000-default.conf 2>/dev/null; true"
    D "apache2ctl graceful 2>/dev/null || pkill -HUP apache2 2>/dev/null; true"
    sleep 3
    ok "題目 19 完成"
}

solve_20() {
    hdr "題目 20 — iptables DNAT 轉發"
    D "iptables -t nat -A PREROUTING -p tcp --dport 9090 -j DNAT --to-destination 127.0.0.1:80"
    D "iptables -t nat -A OUTPUT    -p tcp --dport 9090 -j DNAT --to-destination 127.0.0.1:80"
    ok "題目 20 完成"
}

solve_21() {
    hdr "題目 21 — PHP 安全設定"
    D "PHP_INI=\$(php -r 'echo php_ini_loaded_file();') && \
        sed -i 's/^expose_php\s*=.*/expose_php = Off/' \"\$PHP_INI\" && \
        sed -i 's/^display_errors\s*=.*/display_errors = Off/' \"\$PHP_INI\" && \
        sed -i 's/^allow_url_include\s*=.*/allow_url_include = Off/' \"\$PHP_INI\" && \
        sed -i 's/^;*disable_functions\s*=.*/disable_functions = system,exec,passthru,shell_exec,popen,proc_open/' \"\$PHP_INI\""
    ok "題目 21 完成"
}

solve_22() {
    hdr "題目 22 — Apache 目錄列表防護"
    D "sed -i 's/Options Indexes FollowSymLinks/Options FollowSymLinks/' /etc/apache2/apache2.conf"
    ok "題目 22 完成"
}

solve_23() {
    hdr "題目 23 — Nginx 安全配置"
    D "sed -i 's|location /secret {|location /secret/ {|' /etc/nginx/sites-available/vulnerable"
    D "sed -i 's/autoindex on/autoindex off/g' /etc/nginx/sites-available/vulnerable"
    D "nginx -s reload 2>/dev/null || service nginx restart 2>/dev/null; true"
    ok "題目 23 完成"
}

# ── 執行選定的題目 ────────────────────────────────────────────

for t in "${TASKS[@]}"; do
    if declare -f "solve_$t" > /dev/null 2>&1; then
        "solve_$t"
    else
        echo "[!] 題目 $t 不存在，跳過"
    fi
done

# ── 重載服務 ──────────────────────────────────────────────────
hdr "重載服務"
D "kill -HUP \$(cat /var/run/sshd.pid 2>/dev/null) 2>/dev/null || pkill -HUP sshd; true"
D "apache2ctl graceful 2>/dev/null || service apache2 restart 2>/dev/null; true"
ok "服務已重載"

echo
SOLVED=${#TASKS[@]}
echo "================================================================"
echo "  共解 $SOLVED 題（${TASKS[*]}）"
echo "  請至 http://localhost:5000 驗證結果。"
echo "================================================================"
