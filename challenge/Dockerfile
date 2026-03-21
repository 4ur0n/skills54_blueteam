FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# ── 安裝所有需要的套件 ──────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    apache2 \
    php \
    libapache2-mod-php \
    vsftpd \
    iptables \
    iproute2 \
    cron \
    rsyslog \
    sudo \
    libpam-pwquality \
    libpam-runtime \
    acl \
    openssl \
    nginx \
    vim \
    nano \
    net-tools \
    procps \
    inetutils-ping \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ── SSH 基本設定 ─────────────────────────────────────────────
RUN mkdir /var/run/sshd && ssh-keygen -A

# ── 建立使用者（密碼在 start.sh 執行期設定，避免 build 時 PAM 未初始化）
RUN useradd -m -s /bin/bash admin
RUN useradd -m -s /bin/bash deploy
RUN useradd -m -s /bin/bash svcuser
RUN useradd -m -s /bin/bash ghost
RUN useradd -m -s /bin/bash phantom
RUN useradd -m -s /bin/bash webadmin

# ── 挑戰 1：不安全的 sshd_config ────────────────────────────
COPY sshd_config /etc/ssh/sshd_config

# ── 挑戰 3：Web 上傳漏洞 ────────────────────────────────────
RUN mkdir -p /var/www/html/uploads && chmod 777 /var/www/html/uploads
COPY upload.php     /var/www/html/upload.php
COPY web_index.html /var/www/html/index.html
RUN a2enmod rewrite
RUN echo '<Directory /var/www/html/uploads>\n    AllowOverride All\n    Options -Indexes\n</Directory>' \
    >> /etc/apache2/sites-enabled/000-default.conf

# ── 挑戰 4：不安全的檔案權限 ────────────────────────────────
RUN chmod 644 /etc/shadow
RUN mkdir -p /opt/app && \
    printf 'db_password=SuperSecret123\napi_key=sk-abc123xyz\n' > /opt/app/config.ini && \
    chmod 777 /opt/app/config.ini
RUN chmod 777 /var/log

# ── 挑戰 5：無防火牆規則（預設 ACCEPT 全開）────────────────
# 不需配置，iptables 預設為空

# ── 挑戰 6：Cron 不安全權限 ─────────────────────────────────
RUN printf '#!/bin/bash\n# Hourly backup task\nfind /tmp -mtime +1 -delete\n' \
    > /etc/cron.hourly/backup.sh && chmod 777 /etc/cron.hourly/backup.sh
RUN printf '# Backup cleanup\n0 * * * * root /etc/cron.hourly/backup.sh\n' \
    > /etc/cron.d/backup && chmod 666 /etc/cron.d/backup

# ── 挑戰 7：不必要的 SUID 二進位 ────────────────────────────
RUN cp /usr/bin/id /usr/local/bin/vuln_tool && chmod u+s /usr/local/bin/vuln_tool

# ── 挑戰 8：rsyslog auth 日誌被停用 ─────────────────────────
RUN sed -i 's|^auth,authpriv\.\*|#auth,authpriv.*|g' /etc/rsyslog.conf

# ── 挑戰 9：vsftpd 不必要服務（由 start.sh 啟動）───────────
# vsftpd 已安裝，start.sh 負責啟動

# ── 挑戰 10：密碼策略過於寬鬆 ──────────────────────────────
RUN sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t99999/' /etc/login.defs

# ── 挑戰 11：sysctl 不安全參數 ──────────────────────────────
RUN cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_redirects = 1
net.ipv4.conf.all.send_redirects = 1
net.ipv4.conf.all.accept_source_route = 1
kernel.randomize_va_space = 0
net.ipv4.icmp_echo_ignore_broadcasts = 0
fs.protected_hardlinks = 0
fs.protected_symlinks = 0
EOF

# ── 挑戰 12：PAM faillock 無鎖定限制 ────────────────────────
RUN cat > /etc/security/faillock.conf << 'EOF'
deny = 0
unlock_time = 0
fail_interval = 900
EOF

# ── 挑戰 13：sudoers NOPASSWD ALL ───────────────────────────
RUN echo "deploy ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/deploy && \
    chmod 440 /etc/sudoers.d/deploy

# ── 挑戰 14：SSH PasswordAuthentication yes（已含在 sshd_config）

# ── 挑戰 15：空密碼帳號（ghost、phantom 已建立並清空密碼）───

# ── 挑戰 16：setfacl — IT 群組 ──────────────────────────────
RUN groupadd it && usermod -aG it svcuser

# ── 挑戰 17：sudo 限定指令 ──────────────────────────────────
# webadmin 無任何 sudo 設定，需自行加入正確規則

# ── 挑戰 18：家目錄權限過於開放 ─────────────────────────────
RUN for u in admin deploy svcuser ghost phantom webadmin; do \
        chmod 755 /home/$u; \
    done

# ── 挑戰 19：HTTPS（SSL module 未啟用，需自行設定）──────────
# a2enmod ssl 由玩家自行執行

# ── 挑戰 20：iptables DNAT（無預設規則）─────────────────────
# 不需配置，NAT 表預設為空

# ── 挑戰 21：PHP 安全設定（php.ini 不安全配置）─────────────
RUN PHP_INI=$(php -r 'echo php_ini_loaded_file();') && \
    sed -i 's/^expose_php\s*=.*/expose_php = On/' "$PHP_INI" && \
    sed -i 's/^display_errors\s*=.*/display_errors = On/' "$PHP_INI" && \
    sed -i 's/^;*allow_url_include\s*=.*/allow_url_include = On/' "$PHP_INI"

# ── 挑戰 22：Apache 目錄列表（啟用 Indexes）──────────────────
RUN mkdir -p /var/www/html/data && \
    echo "secret_file_content" > /var/www/html/data/secret.txt && \
    echo "another_file" > /var/www/html/data/readme.txt
RUN printf '<Directory /var/www/html/data>\n    Options Indexes FollowSymLinks\n    AllowOverride None\n    Require all granted\n</Directory>\n' \
    >> /etc/apache2/apache2.conf

# ── 挑戰 23：Nginx 安全配置（alias path traversal + autoindex）
COPY nginx_vuln.conf /etc/nginx/sites-available/vulnerable
RUN ln -sf /etc/nginx/sites-available/vulnerable /etc/nginx/sites-enabled/vulnerable && \
    rm -f /etc/nginx/sites-enabled/default
RUN mkdir -p /var/www/nginx/data && \
    echo "nginx_secret" > /var/www/nginx/data/secret.txt

# ── 啟動腳本 ────────────────────────────────────────────────
COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 22 80 21 443 8081

CMD ["/start.sh"]
