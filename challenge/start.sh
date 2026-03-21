#!/bin/bash

# ── 設定密碼（執行期設定，強制使用 SHA512）───
sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
# 強制 PAM 也使用 SHA512（覆蓋 yescrypt 預設）
sed -i 's/\byescrypt\b/sha512/g' /etc/pam.d/common-password 2>/dev/null || true
echo 'root:toor'         | chpasswd -c SHA512
echo 'admin:admin123'    | chpasswd -c SHA512
echo 'svcuser:svcpass123'| chpasswd -c SHA512
passwd -d ghost          # 清空密碼（題目 15 漏洞）
passwd -d phantom        # 清空密碼（題目 15 漏洞）

# ── 修正 PAM loginuid（容器環境必須改為 optional）───────────
sed -i 's/^session\s*required\s*pam_loginuid.so/session optional pam_loginuid.so/' \
    /etc/pam.d/sshd 2>/dev/null || true

# ── 啟動服務 ─────────────────────────────────────────────────
echo "[*] Starting SSH..."
service ssh start || /usr/sbin/sshd

echo "[*] Starting Apache..."
service apache2 start || true

echo "[*] Starting rsyslog..."
rsyslogd || true

echo "[*] Starting cron..."
service cron start || cron || true

echo "[*] Starting vsftpd (challenge 9)..."
vsftpd /etc/vsftpd.conf &

echo "[*] Starting Nginx (challenge 23)..."
service nginx start || nginx || true

echo "[*] All services started. Container ready."
exec tail -f /dev/null
