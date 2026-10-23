#!/usr/bin/env python3
"""Cyber-Shield: сервер проекта (только стандартная библиотека Python 3.8+).

Что делает:
  * раздаёт сайт из папки public/;
  * POST /api/url           - сверка ссылки с Google Safe Browsing и VirusTotal (ключи хранятся здесь, не в браузере);
  * POST /api/phone/lookup  - сколько жалоб пользователей есть на номер;
  * POST /api/phone/report  - добавить жалобу на номер (номера хранятся только в виде SHA-256 хеша);
  * POST /api/file          - сверка SHA-256 файла с VirusTotal (сам файл никуда не загружается);
  * /api/auth/*, /api/me*, /api/history*, /api/progress, /api/export - личный кабинет (пароли хранятся как scrypt-хеш);
  * GET  /api/status        - какие сервисы подключены.
Сервер НЕ открывает присланные ссылки сам (так нет риска SSRF): он только спрашивает о них базы угроз.
"""
import base64, hashlib, hmac, http.cookies, json, os, re, secrets, sqlite3, threading, time, urllib.error, urllib.parse, urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / 'public'

def load_env():
    f = ROOT / '.env'
    if f.exists():
        for line in f.read_text(encoding='utf-8').splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"\''))
load_env()

SB_KEY = os.getenv('SAFE_BROWSING_KEY', '').strip()
VT_KEY = os.getenv('VIRUSTOTAL_KEY', '').strip()
PORT = int(os.getenv('PORT', '8000'))
HOST = os.getenv('HOST', '127.0.0.1')
SALT = os.getenv('PHONE_SALT', 'cyber-shield-change-me')
SB_URL = os.getenv('CS_SB_URL', 'https://safebrowsing.googleapis.com/v4/threatMatches:find')
VT_URL = os.getenv('CS_VT_URL', 'https://www.virustotal.com/api/v3')
CATEGORIES = {'bank', 'invest', 'prize', 'family', 'spam', 'other'}
KINDS = {'url', 'sms', 'phone', 'qr', 'file', 'password', 'ip'}
LEVELS = {'low', 'medium', 'high'}
SESSION_DAYS = 30
SECURE_COOKIES = os.getenv('SECURE_COOKIES', '') == '1'
LESSON_IDS = {'phishing', 'social', 'accounts', 'twofa', 'data'}

# ---------- утилиты ----------
_lock = threading.Lock()
_hits = {}
_cache = {}

def allow(key, limit, window=60):
    now = time.time()
    with _lock:
        q = [t for t in _hits.get(key, []) if now - t < window]
        if len(q) >= limit:
            _hits[key] = q
            return False
        q.append(now)
        _hits[key] = q
        return True

def sha(s):
    return hashlib.sha256((SALT + s).encode('utf-8')).hexdigest()

def http_json(url, data=None, headers=None, method=None, timeout=8):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode('utf-8') or '{}'
        return r.status, json.loads(raw)

def clean_url(u):
    if not isinstance(u, str) or len(u) > 2000:
        return None
    u = u.strip()
    if re.search(r'[\s\x00-\x1f]', u):
        return None
    p = urllib.parse.urlparse(u)
    if p.scheme not in ('http', 'https') or not p.hostname:
        return None
    return u

# ---------- репутация ссылок ----------
def sb_check(url):
    if not SB_KEY:
        return {'status': 'off'}
    body = {'client': {'clientId': 'cyber-shield', 'clientVersion': '1.0'},
            'threatInfo': {'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                           'platformTypes': ['ANY_PLATFORM'], 'threatEntryTypes': ['URL'], 'threatEntries': [{'url': url}]}}
    try:
        _, d = http_json(SB_URL + '?key=' + urllib.parse.quote(SB_KEY), json.dumps(body).encode(),
                         {'Content-Type': 'application/json'}, 'POST')
    except Exception as e:
        print('[safe-browsing] ошибка:', type(e).__name__)
        return {'status': 'error'}
    m = d.get('matches')
    if m:
        return {'status': 'threat', 'types': sorted({x.get('threatType', '') for x in m})}
    return {'status': 'clean'}

def vt_check(url):
    if not VT_KEY:
        return {'status': 'off'}
    uid = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
    hdr = {'x-apikey': VT_KEY}
    try:
        try:
            _, d = http_json('%s/urls/%s' % (VT_URL, uid), headers=hdr)
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
            # адрес ещё не анализировался: отправляем на анализ, результат будет при повторной проверке
            http_json(VT_URL + '/urls', ('url=' + urllib.parse.quote(url, safe='')).encode(),
                      dict(hdr, **{'Content-Type': 'application/x-www-form-urlencoded'}), 'POST')
            return {'status': 'queued'}
        st = d.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        total = sum(st.get(k, 0) for k in ('harmless', 'malicious', 'suspicious', 'undetected'))
        flagged = st.get('malicious', 0) + st.get('suspicious', 0)
        if total == 0:
            return {'status': 'queued'}
        return {'status': 'threat' if flagged else 'clean', 'flagged': flagged, 'total': total}
    except Exception as e:
        print('[virustotal] ошибка:', type(e).__name__)
        return {'status': 'error'}

def check_url(url):
    now = time.time()
    hit = _cache.get(url)
    if hit and now - hit[0] < 600:
        return hit[1]
    res = {'safebrowsing': sb_check(url), 'virustotal': vt_check(url)}
    if all(v.get('status') != 'error' for v in res.values()):
        _cache[url] = (now, res)
        if len(_cache) > 500:
            _cache.pop(next(iter(_cache)))
    return res

# ---------- база жалоб ----------
def db():
    return sqlite3.connect(str(ROOT / 'reports.db'), timeout=10)

def init_db():
    with db() as c:
        c.execute('CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY, phash TEXT NOT NULL, category TEXT NOT NULL, ts INTEGER NOT NULL, ihash TEXT NOT NULL)')
        c.execute('CREATE INDEX IF NOT EXISTS i_phash ON reports(phash)')

def norm_phone(v):
    return v if isinstance(v, str) and re.fullmatch(r'\+\d{7,15}', v) else None

def phone_lookup(phone):
    c = db()
    try:
        rows = c.execute('SELECT category, COUNT(*), MAX(ts) FROM reports WHERE phash=? GROUP BY category', (sha(phone),)).fetchall()
        recent = c.execute('SELECT COUNT(*) FROM reports WHERE phash=? AND ts>?', (sha(phone), int(time.time()) - 30 * 86400)).fetchone()[0]
    finally:
        c.close()
    return {'count': sum(r[1] for r in rows), 'last30': recent, 'categories': {r[0]: r[1] for r in rows},
            'last': max([r[2] for r in rows], default=None)}

def phone_report(phone, cat, ip):
    c = db()
    try:
        ih, ph, now = sha('ip:' + ip), sha(phone), int(time.time())
        if c.execute('SELECT 1 FROM reports WHERE phash=? AND ihash=? AND ts>?', (ph, ih, now - 86400)).fetchone():
            return False
        c.execute('INSERT INTO reports(phash, category, ts, ihash) VALUES(?,?,?,?)', (ph, cat, now, ih))
        c.commit()
        return True
    finally:
        c.close()


def vt_file(h):
    if not VT_KEY:
        return {'status': 'off'}
    try:
        _, d = http_json('%s/files/%s' % (VT_URL, h), headers={'x-apikey': VT_KEY})
    except urllib.error.HTTPError as e:
        return {'status': 'unknown'} if e.code == 404 else {'status': 'error'}
    except Exception as e:
        print('[virustotal-file] ошибка:', type(e).__name__)
        return {'status': 'error'}
    at = d.get('data', {}).get('attributes', {})
    st = at.get('last_analysis_stats', {})
    total = sum(st.get(k, 0) for k in ('harmless', 'malicious', 'suspicious', 'undetected'))
    flagged = st.get('malicious', 0) + st.get('suspicious', 0)
    if total == 0:
        return {'status': 'unknown'}
    label = (at.get('popular_threat_classification') or {}).get('suggested_threat_label')
    return {'status': 'threat' if flagged else 'clean', 'flagged': flagged, 'total': total, 'label': label if isinstance(label, str) else None}

# ---------- личный кабинет ----------
def b64(b):
    return base64.b64encode(b).decode()

def pw_hash(pw):
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)
    return 'scrypt$%s$%s' % (b64(salt), b64(h))

def pw_check(pw, stored):
    try:
        _, salt, h = stored.split('$')
        calc = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt), n=2 ** 14, r=8, p=1, maxmem=64 * 1024 * 1024, dklen=32)
        return hmac.compare_digest(calc, base64.b64decode(h))
    except Exception:
        return False

DUMMY = None
def init_accounts():
    global DUMMY
    DUMMY = pw_hash('dummy-password')
    with db() as c:
        c.execute('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, pw TEXT NOT NULL, created INTEGER NOT NULL)')
        c.execute('CREATE TABLE IF NOT EXISTS sessions(tok TEXT PRIMARY KEY, uid INTEGER NOT NULL, exp INTEGER NOT NULL)')
        c.execute('CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY, uid INTEGER NOT NULL, kind TEXT NOT NULL, level TEXT NOT NULL, label TEXT NOT NULL, ts INTEGER NOT NULL)')
        c.execute('CREATE INDEX IF NOT EXISTS i_hist ON history(uid, ts)')
        c.execute('CREATE TABLE IF NOT EXISTS progress(uid INTEGER PRIMARY KEY, data TEXT NOT NULL)')

def clean_text(s, n):
    return re.sub(r'[\x00-\x1f\x7f]', '', s).strip()[:n] if isinstance(s, str) else ''

EMAIL_RE = re.compile(r'^[^@\s]{1,64}@[^@\s]{1,200}\.[^@\s]{2,}$')
WEAK = {'password', '12345678', '123456789', 'qwerty123', 'qwertyuiop', '11111111', 'iloveyou', 'password1', 'qwerty12', '1234567890', '87654321', 'abcd1234'}

def new_session(c, uid):
    tok = secrets.token_urlsafe(32)
    exp = int(time.time()) + SESSION_DAYS * 86400
    c.execute('INSERT INTO sessions(tok, uid, exp) VALUES(?,?,?)', (hashlib.sha256(tok.encode()).hexdigest(), uid, exp))
    c.execute('DELETE FROM sessions WHERE exp<?', (int(time.time()),))
    return tok

def user_from_token(tok):
    if not tok:
        return None
    c = db()
    try:
        r = c.execute('SELECT u.id,u.email,u.name,u.created FROM sessions s JOIN users u ON u.id=s.uid WHERE s.tok=? AND s.exp>?', (hashlib.sha256(tok.encode()).hexdigest(), int(time.time()))).fetchone()
    finally:
        c.close()
    return {'id': r[0], 'email': r[1], 'name': r[2], 'created': r[3]} if r else None

# ---------- HTTP ----------
PRIVATE = ('/api/auth/', '/api/me', '/api/history', '/api/progress', '/api/export')

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=str(PUBLIC), **k)

    def end_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cache-Control', 'no-cache')
        super().end_headers()

    def list_directory(self, path):
        self.send_error(404)
        return None

    def is_private(self, p):
        return p.startswith(PRIVATE)

    def reply(self, code, obj, private=False, cookie=None, headers=None):
        data = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        if not private:
            self.send_header('Access-Control-Allow-Origin', '*')
        if cookie:
            self.send_header('Set-Cookie', cookie)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        try:
            n = int(self.headers.get('Content-Length') or 0)
            if 0 < n <= 16384:
                d = json.loads(self.rfile.read(n).decode('utf-8'))
                return d if isinstance(d, dict) else None
        except Exception:
            pass
        return None

    def cookie_for(self, tok, clear=False):
        age = 0 if clear else SESSION_DAYS * 86400
        return 'cs_session=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=%d%s' % ('' if clear else tok, age, '; Secure' if SECURE_COOKIES else '')

    def current_user(self):
        try:
            ck = http.cookies.SimpleCookie(self.headers.get('Cookie', ''))
            return user_from_token(ck['cs_session'].value) if 'cs_session' in ck else None
        except Exception:
            return None

    def guard(self):
        """CSRF-защита личных запросов: тот же origin и служебный заголовок (их нельзя подделать с чужого сайта)."""
        origin = self.headers.get('Origin')
        if origin and urllib.parse.urlparse(origin).netloc != self.headers.get('Host'):
            return False
        return self.headers.get('X-CS') == '1'

    def do_OPTIONS(self):
        p = urllib.parse.urlparse(self.path).path
        if self.is_private(p):
            return self.reply(403, {'error': 'forbidden'}, private=True)
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        p = urllib.parse.urlparse(self.path).path
        if p == '/api/status':
            return self.reply(200, {'safebrowsing': bool(SB_KEY), 'virustotal': bool(VT_KEY), 'reports': True, 'accounts': True})
        if self.is_private(p):
            return self.private_get(p)
        if p.startswith('/api/'):
            return self.reply(404, {'error': 'not_found'})
        return super().do_GET()

    def do_POST(self):
        p = urllib.parse.urlparse(self.path).path
        ip = self.client_address[0]
        d = self.body()
        if d is None:
            return self.reply(400, {'error': 'bad_request'}, private=self.is_private(p))
        if self.is_private(p):
            return self.private_post(p, d, ip)
        if p == '/api/url':
            if not allow('url:' + ip, 20):
                return self.reply(429, {'error': 'rate_limit'})
            u = clean_url(d.get('url'))
            if not u:
                return self.reply(400, {'error': 'bad_url'})
            return self.reply(200, check_url(u))
        if p == '/api/file':
            if not allow('file:' + ip, 20):
                return self.reply(429, {'error': 'rate_limit'})
            h = d.get('sha256')
            if not isinstance(h, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', h):
                return self.reply(400, {'error': 'bad_hash'})
            key = 'file:' + h.lower()
            hit = _cache.get(key)
            if hit and time.time() - hit[0] < 600:
                return self.reply(200, hit[1])
            res = vt_file(h.lower())
            if res['status'] != 'error':
                _cache[key] = (time.time(), res)
            return self.reply(200, res)
        if p in ('/api/phone/lookup', '/api/phone/report'):
            ph = norm_phone(d.get('phone'))
            if not ph:
                return self.reply(400, {'error': 'bad_phone'})
            if p.endswith('lookup'):
                if not allow('look:' + ip, 60):
                    return self.reply(429, {'error': 'rate_limit'})
                return self.reply(200, phone_lookup(ph))
            if d.get('category') not in CATEGORIES:
                return self.reply(400, {'error': 'bad_category'})
            if not allow('rep:' + ip, 10, 3600):
                return self.reply(429, {'error': 'rate_limit'})
            return self.reply(200, {'ok': True}) if phone_report(ph, d['category'], ip) else self.reply(409, {'error': 'duplicate'})
        return self.reply(404, {'error': 'not_found'})

    # ----- личный кабинет -----
    def private_get(self, p):
        if not self.guard():
            return self.reply(403, {'error': 'forbidden'}, private=True)
        u = self.current_user()
        if not u:
            return self.reply(401, {'error': 'unauthorized'}, private=True)
        pub = {'name': u['name'], 'email': u['email'], 'created': u['created']}
        c = db()
        try:
            if p == '/api/me':
                return self.reply(200, {'user': pub}, private=True)
            if p == '/api/history':
                rows = c.execute('SELECT kind,level,label,ts FROM history WHERE uid=? ORDER BY ts DESC, id DESC LIMIT 300', (u['id'],)).fetchall()
                return self.reply(200, {'items': [{'kind': r[0], 'level': r[1], 'label': r[2], 'ts': r[3]} for r in rows]}, private=True)
            r = c.execute('SELECT data FROM progress WHERE uid=?', (u['id'],)).fetchone()
            prog = json.loads(r[0]) if r else {}
            if p == '/api/progress':
                return self.reply(200, prog, private=True)
            if p == '/api/export':
                rows = c.execute('SELECT kind,level,label,ts FROM history WHERE uid=? ORDER BY ts', (u['id'],)).fetchall()
                out = {'user': pub, 'history': [{'kind': a, 'level': b, 'label': l, 'ts': t} for a, b, l, t in rows], 'progress': prog}
                return self.reply(200, out, private=True, headers={'Content-Disposition': 'attachment; filename="cyber-shield-data.json"'})
        finally:
            c.close()
        return self.reply(404, {'error': 'not_found'}, private=True)

    def private_post(self, p, d, ip):
        if not self.guard():
            return self.reply(403, {'error': 'forbidden'}, private=True)
        R = lambda code, obj, **k: self.reply(code, obj, private=True, **k)
        if p == '/api/auth/register':
            if not allow('reg:' + ip, 5, 3600):
                return R(429, {'error': 'rate_limit'})
            email, name, pw = clean_text(d.get('email'), 254).lower(), clean_text(d.get('name'), 60), d.get('password')
            if not EMAIL_RE.match(email):
                return R(400, {'error': 'bad_email'})
            if not name:
                return R(400, {'error': 'bad_name'})
            if not isinstance(pw, str) or not 8 <= len(pw) <= 128 or pw.lower() in WEAK or len(set(pw)) < 3:
                return R(400, {'error': 'weak_password'})
            c = db()
            try:
                try:
                    cur = c.execute('INSERT INTO users(email,name,pw,created) VALUES(?,?,?,?)', (email, name, pw_hash(pw), int(time.time())))
                except sqlite3.IntegrityError:
                    return R(409, {'error': 'email_taken'})
                tok = new_session(c, cur.lastrowid)
                c.commit()
            finally:
                c.close()
            return R(200, {'ok': True}, cookie=self.cookie_for(tok))
        if p == '/api/auth/login':
            email, pw = clean_text(d.get('email'), 254).lower(), d.get('password')
            if not allow('login:' + ip, 10, 600) or not allow('loginmail:' + email, 5, 600):
                return R(429, {'error': 'rate_limit'})
            c = db()
            try:
                r = c.execute('SELECT id,pw FROM users WHERE email=?', (email,)).fetchone() if isinstance(pw, str) else None
                ok = pw_check(pw, r[1] if r else DUMMY) if isinstance(pw, str) else False
                if not (r and ok):
                    return R(401, {'error': 'bad_credentials'})
                tok = new_session(c, r[0])
                c.commit()
            finally:
                c.close()
            return R(200, {'ok': True}, cookie=self.cookie_for(tok))
        if p == '/api/auth/logout':
            try:
                ck = http.cookies.SimpleCookie(self.headers.get('Cookie', ''))
                if 'cs_session' in ck:
                    c = db()
                    c.execute('DELETE FROM sessions WHERE tok=?', (hashlib.sha256(ck['cs_session'].value.encode()).hexdigest(),))
                    c.commit()
                    c.close()
            except Exception:
                pass
            return R(200, {'ok': True}, cookie=self.cookie_for('', clear=True))
        u = self.current_user()
        if not u:
            return R(401, {'error': 'unauthorized'})
        c = db()
        try:
            if p == '/api/me/update':
                name = clean_text(d.get('name'), 60)
                if not name:
                    return R(400, {'error': 'bad_name'})
                c.execute('UPDATE users SET name=? WHERE id=?', (name, u['id']))
                c.commit()
                return R(200, {'ok': True})
            if p == '/api/me/password':
                old, new = d.get('old'), d.get('new')
                row = c.execute('SELECT pw FROM users WHERE id=?', (u['id'],)).fetchone()
                if not (isinstance(old, str) and pw_check(old, row[0])):
                    return R(401, {'error': 'bad_credentials'})
                if not isinstance(new, str) or not 8 <= len(new) <= 128 or new.lower() in WEAK or len(set(new)) < 3:
                    return R(400, {'error': 'weak_password'})
                c.execute('UPDATE users SET pw=? WHERE id=?', (pw_hash(new), u['id']))
                c.execute('DELETE FROM sessions WHERE uid=?', (u['id'],))
                tok = new_session(c, u['id'])
                c.commit()
                return R(200, {'ok': True}, cookie=self.cookie_for(tok))
            if p == '/api/me/delete':
                row = c.execute('SELECT pw FROM users WHERE id=?', (u['id'],)).fetchone()
                if not (isinstance(d.get('password'), str) and pw_check(d['password'], row[0])):
                    return R(401, {'error': 'bad_credentials'})
                for t in ('sessions', 'history', 'progress'):
                    c.execute('DELETE FROM %s WHERE uid=?' % t, (u['id'],))
                c.execute('DELETE FROM users WHERE id=?', (u['id'],))
                c.commit()
                return R(200, {'ok': True}, cookie=self.cookie_for('', clear=True))
            if p == '/api/history/add':
                if d.get('kind') not in KINDS or d.get('level') not in LEVELS:
                    return R(400, {'error': 'bad_request'})
                if not allow('hist:%d' % u['id'], 60):
                    return R(429, {'error': 'rate_limit'})
                c.execute('INSERT INTO history(uid,kind,level,label,ts) VALUES(?,?,?,?,?)', (u['id'], d['kind'], d['level'], clean_text(d.get('label'), 80), int(time.time())))
                c.execute('DELETE FROM history WHERE uid=? AND id NOT IN (SELECT id FROM history WHERE uid=? ORDER BY id DESC LIMIT 300)', (u['id'], u['id']))
                c.commit()
                return R(200, {'ok': True})
            if p == '/api/history/clear':
                c.execute('DELETE FROM history WHERE uid=?', (u['id'],))
                c.commit()
                return R(200, {'ok': True})
            if p == '/api/progress':
                ac, ck = d.get('academy'), d.get('checkup')
                if not isinstance(ac, dict) or not isinstance(ck, list) or len(ck) > 20:
                    return R(400, {'error': 'bad_request'})
                ac = {k: {'score': max(0, min(5, int(v.get('score', 0))))} for k, v in ac.items() if k in LESSON_IDS and isinstance(v, dict) and isinstance(v.get('score', 0), int)}
                ck = [x for x in ck if isinstance(x, str) and re.fullmatch(r'chk\d{1,2}', x)]
                c.execute('INSERT INTO progress(uid,data) VALUES(?,?) ON CONFLICT(uid) DO UPDATE SET data=excluded.data', (u['id'], json.dumps({'academy': ac, 'checkup': ck})))
                c.commit()
                return R(200, {'ok': True})
        finally:
            c.close()
        return R(404, {'error': 'not_found'})

    def log_message(self, fmt, *args):
        line = str(args[0]) if args else ''
        if '/api/' in line:
            print('[api]', ' '.join(line.split(' ')[:2]))

if __name__ == '__main__':
    init_db()
    init_accounts()
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print('Cyber-Shield: http://%s:%d' % (HOST, PORT))
    print('  Google Safe Browsing:', 'подключён' if SB_KEY else 'ключ не задан')
    print('  VirusTotal          :', 'подключён' if VT_KEY else 'ключ не задан')
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print('\nОстановлено')
