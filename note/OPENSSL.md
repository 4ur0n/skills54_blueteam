# OpenSSL + Apache HTTPS 筆記

## 一、產生自簽憑證

```bash
openssl req -x509 -newkey rsa:2048 \
    -keyout /etc/ssl/private/server.key \
    -out /etc/ssl/certs/server.crt \
    -days 365 -nodes \
    -subj '/CN=localhost'
```

### 參數意義

| 參數 | 說明 |
|------|------|
| `-x509` | 產生自簽憑證（不送 CA） |
| `-newkey rsa:2048` | 產生 RSA 2048 bits 新私鑰 |
| `-keyout` | 私鑰存到哪（不能外洩） |
| `-out` | 憑證存到哪（公開的） |
| `-days 365` | 有效期 365 天 |
| `-nodes` | 私鑰不加密（no DES），Apache 啟動時不用手動輸密碼 |
| `-subj '/CN=localhost'` | 憑證資訊，CN = Common Name |

### 常見路徑

```
私鑰：/etc/ssl/private/server.key
憑證：/etc/ssl/certs/server.crt
```

### 查看憑證資訊

```bash
openssl x509 -in /etc/ssl/certs/server.crt -text -noout
```

---

## 二、Apache 啟用 SSL

### 1. 啟用 SSL 模組

```bash
a2enmod ssl
```

### 2. 建立 HTTPS VirtualHost

編輯 `/etc/apache2/sites-available/default-ssl.conf`：

```apache
<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile    /etc/ssl/certs/server.crt
    SSLCertificateKeyFile /etc/ssl/private/server.key
    DocumentRoot /var/www/html
</VirtualHost>
```

### 3. 啟用站台

```bash
a2ensite default-ssl
```

### 4. 重啟

```bash
service apache2 restart
```

---

## 三、HTTP 重導向至 HTTPS

編輯 `/etc/apache2/sites-available/000-default.conf`，在 `<VirtualHost *:80>` 裡加：

```apache
Redirect permanent / https://localhost/
```

重啟：

```bash
service apache2 restart
```

---

## 四、驗證

```bash
# 確認 443 有在聽
ss -tlnp | grep 443

# 測試 HTTPS
curl -k https://localhost/

# 測試重導向（應該回 301 + Location: https）
curl -sI http://localhost/ | head -5

# 查看憑證金鑰長度
openssl x509 -in /etc/ssl/certs/server.crt -text -noout | grep "Public-Key"
```

---

## 五、完整流程（競賽速解）

```bash
# 1. 產生憑證
openssl req -x509 -newkey rsa:2048 \
    -keyout /etc/ssl/private/server.key \
    -out /etc/ssl/certs/server.crt \
    -days 365 -nodes \
    -subj '/CN=localhost'

# 2. 啟用 SSL
a2enmod ssl

# 3. 寫 HTTPS VirtualHost
cat > /etc/apache2/sites-available/default-ssl.conf << 'EOF'
<VirtualHost *:443>
    SSLEngine on
    SSLCertificateFile    /etc/ssl/certs/server.crt
    SSLCertificateKeyFile /etc/ssl/private/server.key
    DocumentRoot /var/www/html
</VirtualHost>
EOF

# 4. 啟用站台
a2ensite default-ssl

# 5. 加重導向（在 80 port 的 VirtualHost 裡）
sed -i '/<VirtualHost \*:80>/a\    Redirect permanent / https://localhost/' \
    /etc/apache2/sites-available/000-default.conf

# 6. 重啟
service apache2 restart
```

---

## 六、易錯重點

1. **忘記 `-nodes`** → 產生憑證時要求輸入密碼，Apache 每次重啟也要輸
2. **憑證路徑錯** → `default-ssl.conf` 預設指向 `snakeoil.pem`，要改成你的
3. **忘記 `a2enmod ssl`** → Apache 不認識 `SSLEngine` 指令
4. **忘記 `a2ensite default-ssl`** → 站台沒啟用，443 不會聽
5. **Redirect 加錯位置** → 要加在 `<VirtualHost *:80>` 裡面，不是 `*:443`
6. **混用 `-Indexes` 和 `FollowSymLinks`** → `Options` 要嘛都帶符號，要嘛都不帶
