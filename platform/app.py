from flask import Flask, render_template, jsonify, request
import challenges as ch

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('security_hardening/index.html', challenges=ch.CHALLENGES)


@app.route('/api/verify/<int:challenge_id>', methods=['POST'])
def verify(challenge_id):
    challenge = next((c for c in ch.CHALLENGES if c['id'] == challenge_id), None)
    if not challenge:
        return jsonify({'error': 'Challenge not found'}), 404

    verifier_func = getattr(ch, f'verify_challenge_{challenge_id}', None)
    if not verifier_func:
        return jsonify({'error': 'Verifier not found'}), 404

    try:
        passed, checks = verifier_func(challenge['container'])
    except Exception as e:
        passed = False
        checks = {'系統錯誤': f'{type(e).__name__}: {e}'}

    return jsonify({
        'passed': passed,
        'checks': {k: bool(v) for k, v in checks.items()},
        'challenge_id': challenge_id,
    })


# ── Forensics ──────────────────────────────────────────────────

FORENSICS_ANSWERS = {
    1:  {'answer': '10.99.88.77', 'title': '攻擊來源 IP', 'points': 2,
         'hint': '觀察哪個 IP 發送了最多異常請求',
         'format': '例：192.168.1.100'},
    2:  {'answer': 'corp-internal.local', 'title': '攻擊目標 Domain', 'points': 2,
         'hint': '看 HTTP Host header 或 DNS 查詢',
         'format': '例：example.com'},
    3:  {'answer': ['sqlmap', 'nikto'], 'title': '攻擊工具名稱（可能不止一個）', 'points': 3,
         'hint': '檢查 HTTP 請求的 User-Agent 欄位', 'multi': True,
         'format': '例：toolA, toolB（用逗號分隔）'},
    4:  {'answer': 'sql injection', 'title': '攻擊弱點類型', 'points': 3,
         'hint': '觀察 POST 請求的 payload 內容',
         'format': '例：XSS、SQL Injection、RCE 等'},
    5:  {'answer': '/login.php', 'title': '弱點 URL', 'points': 2,
         'hint': '攻擊 payload 是送到哪個路徑',
         'format': '例：/path/to/page.php'},
    6:  {'answer': ['admin', 'P@ssw0rd!2025'], 'title': '管理者（admin）的帳號與密碼', 'points': 3,
         'hint': 'Follow TCP Stream 看 UNION SELECT 回傳的資料，找權限最高的帳號', 'multi': True,
         'format': '格式：帳號 / 密碼（例：admin / password123）'},
    7:  {'answer': '/uploads/help.php', 'title': 'WebShell 路徑', 'points': 3,
         'hint': '看 POST 上傳和後續的 GET 請求帶 cmd 參數',
         'format': '例：/path/to/shell.php'},
    8:  {'answer': '185.199.33.44:4444', 'title': 'C2 中繼站 IP 及連接埠', 'points': 3,
         'hint': '找受害者主動外連的異常 IP 和非標準 port',
         'format': '格式：IP:port（例：1.2.3.4:8080）'},
    9:  {'answer': 'update-service.evil.net', 'title': 'C2 中繼站 Domain', 'points': 2,
         'hint': '看受害者發出的 DNS 查詢',
         'format': '例：evil.example.com'},
    10: {'answer': 'sk54{p4ck3t_f0r3ns1cs_m4st3r_2025}', 'title': '特徵碼 FLAG', 'points': 4,
         'hint': 'Follow TCP Stream 搜尋 sk54{',
         'format': '格式：sk54{...}'},
}


MEMORY_ANSWERS = {
    1:  {'answer': 'windows 10', 'title': '作業系統', 'points': 2,
         'hint': '使用 windows.info 或 registry.printkey 查看',
         'format': '例：Windows 10、Windows 10 Pro、Windows Server 2019'},
    2:  {'answer': 'DESKTOP-8BINKVB', 'title': '電腦名稱', 'points': 3,
         'hint': '使用 windows.envars 搜尋 COMPUTERNAME',
         'format': '例：WIN-XXXXXX'},
    3:  {'answer': 'alex', 'title': '當前使用者名稱', 'points': 3,
         'hint': '觀察 explorer.exe 或使用者目錄路徑中的名稱',
         'format': '例：admin、john'},
    4:  {'answer': 'ChromeSetup.exe', 'title': '可疑的惡意檔案名稱', 'points': 4,
         'hint': '使用 windows.pstree 或 windows.cmdline，找出從使用者 Downloads 目錄執行的異常程式',
         'format': '例：malware.exe'},
    5:  {'answer': '4628', 'title': '惡意程序的 PID', 'points': 3,
         'hint': '找到可疑程序後，記錄其 PID',
         'format': '例：1234'},
    6:  {'answer': 'explorer.exe', 'title': '惡意程序的父程序名稱', 'points': 3,
         'hint': '使用 windows.pstree 查看可疑程序的 PPID 對應的程序',
         'format': '例：svchost.exe'},
    7:  {'answer': ['192.168.19.133', '2.16.149.135'], 'title': '受害主機 IP 及連線到的可疑外部 IP（port 80）', 'points': 4,
         'hint': '使用 windows.netscan 找 ESTABLISHED 連線，注意非 443 的 HTTP 連線', 'multi': True,
         'format': '格式：受害IP, 外部IP（例：192.168.1.1, 10.0.0.1）'},
    8:  {'answer': 'C:\\Users\\alex\\Downloads\\ChromeSetup.exe', 'title': '惡意程序的完整檔案路徑', 'points': 4,
         'hint': '使用 windows.cmdline 或 windows.pstree 的 Path 欄位',
         'format': '例：C:\\Users\\xxx\\file.exe'},
    9:  {'answer': 'sk54{r4mn1t_m3m0ry_f0r3ns1cs_2025}', 'title': '使用掃描工具找出記憶體中的特徵碼（FLAG）', 'points': 6,
         'hint': '使用 regexscan.RegExScan 或 strings + grep 搜尋 sk54{ 開頭的字串',
         'format': '格式：sk54{...}'},
    10: {'answer': ['Windows 10 Enterprise Evaluation', '22H2', '19045', '10', '2006'],
         'title': '透過 Registry 查詢完整的作業系統版本資訊', 'points': 4, 'multi': True,
         'hint': '使用 windows.registry.printkey 查詢 Microsoft\\Windows NT\\CurrentVersion，找出 ProductName、DisplayVersion、CurrentBuildNumber、CurrentMajorVersionNumber、UBR',
         'format': '格式：ProductName / DisplayVersion / CurrentBuildNumber / CurrentMajorVersion / UBR'},
}


@app.route('/forensics')
def forensics():
    return render_template('network/forensics.html', questions=FORENSICS_ANSWERS)


@app.route('/memory')
def memory():
    return render_template('mem/memory.html', questions=MEMORY_ANSWERS)


@app.route('/api/forensics/verify', methods=['POST'])
def forensics_verify():
    data = request.get_json() or {}
    qid = data.get('id')
    user_answer = data.get('answer', '').strip()

    if not qid or qid not in FORENSICS_ANSWERS:
        return jsonify({'error': 'Invalid question'}), 400

    q = FORENSICS_ANSWERS[qid]
    correct = False

    if q.get('multi'):
        # All parts must be present (case-insensitive)
        correct = all(
            part.lower() in user_answer.lower()
            for part in q['answer']
        )
    else:
        correct = user_answer.lower().strip('/') == q['answer'].lower().strip('/')

    return jsonify({
        'id': qid,
        'correct': correct,
        'points': q['points'] if correct else 0,
        'max_points': q['points'],
    })


@app.route('/api/memory/verify', methods=['POST'])
def memory_verify():
    data = request.get_json() or {}
    qid = data.get('id')
    user_answer = data.get('answer', '').strip()

    if not qid or qid not in MEMORY_ANSWERS:
        return jsonify({'error': 'Invalid question'}), 400

    q = MEMORY_ANSWERS[qid]
    correct = False

    if q.get('multi'):
        correct = all(
            part.lower() in user_answer.lower()
            for part in q['answer']
        )
    else:
        # Normalize paths and case for comparison
        ua = user_answer.lower().replace('/', '\\').strip('\\').strip()
        ans = q['answer'].lower().replace('/', '\\').strip('\\').strip()
        correct = ua == ans or ua in ans or ans in ua

    return jsonify({
        'id': qid,
        'correct': correct,
        'points': q['points'] if correct else 0,
        'max_points': q['points'],
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
