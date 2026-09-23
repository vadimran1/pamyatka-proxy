# -*- coding: utf-8 -*-
"""Вход в Памятку через Discord — пробная версия аккаунтов.

Паролей и базы данных нет: кто вы, подтверждает Discord, а сервер
выдаёт подписанный пропуск на 30 дней. Подпись делается ключом,
выведенным из секрета Discord-приложения, поэтому хранить отдельно
ничего не нужно, а подделать пропуск без секрета нельзя. Секрет
лежит только в переменных Vercel — в программе его нет.

Как пропуск попадает в программу. Программа поднимает у себя на
127.0.0.1 одноразовый приёмник и открывает браузер. Человек входит в
Discord, Discord возвращает его сюда, а отсюда браузер уходит на тот
самый приёмник с пропуском. Уйти можно только на 127.0.0.1 — адрес
жёстко задан здесь, из запроса берётся лишь номер порта, — так что
увести пропуск на чужой сайт нельзя.

Статистика. Программа при запуске шлёт анонимную отметку: случайный
номер установки и версию — без ника, без данных о человеке. Сервер
складывает номера в HyperLogLog-счётчики Redis: они считают уникальных
почти точно и не хранят сами номера в читаемом виде. Смотреть отчёт
может только автор — по входу через Discord и списку PAMYATKA_ADMIN_IDS.

Адреса (все через /auth):
  ?step=status          настроены ли вход и хранилище
  ?step=start&port&nonce  начать вход — уводит на Discord
  ?code&state           Discord вернул человека — меняем код на профиль
  ?step=me              кто владелец пропуска (Authorization: Bearer)
  POST ?step=ping       отметка о запуске {id, ver, token?}
  ?step=stats           отчёт для автора (Authorization: Bearer)
"""
import os, re, json, time, hmac, base64, hashlib
import urllib.request, urllib.parse, urllib.error
from http.server import BaseHTTPRequestHandler

CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "").strip()
CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "").strip()
BASE = os.environ.get("PAMYATKA_BASE_URL",
                      "https://pamyatka-proxy.vercel.app").rstrip("/")
REDIRECT = BASE + "/auth"
TTL = 30 * 24 * 3600                   # пропуск живёт месяц
STATE_TTL = 600                        # на сам вход — десять минут
# пробные «подписчики»: Discord ID через запятую в переменной Vercel
VIP = {x.strip() for x in os.environ.get("PAMYATKA_VIP_IDS", "").split(",")
       if x.strip()}
UA = "PamyatkaAuth/1.0 (+https://pamyatka-proxy.vercel.app)"
ADMINS = {x.strip() for x in
          os.environ.get("PAMYATKA_ADMIN_IDS", "").split(",") if x.strip()}
def _find_redis():
    """Адрес и ключ REST-доступа к Redis.

    При подключении хранилища Vercel разрешает дать переменным свою
    приставку: вместо KV_REST_API_URL выходит, скажем,
    STORAGE_KV_REST_API_URL. Поэтому ищем по окончанию имени, а не по
    точному совпадению. Ключ «только для чтения» не подходит — пропускаем.
    """
    env = os.environ
    for url_end, tok_end in (("KV_REST_API_URL", "KV_REST_API_TOKEN"),
                             ("REDIS_REST_URL", "REDIS_REST_TOKEN"),
                             ("REDIS_REST_API_URL", "REDIS_REST_API_TOKEN")):
        for name in sorted(env):
            if name.endswith(url_end) and env[name].startswith(("https://", "http://")):
                pre = name[:-len(url_end)]
                tok = env.get(pre + tok_end, "")
                if tok:
                    return env[name].rstrip("/"), tok
    return "", ""


def storage_names():
    """Имена (не значения!) переменных, похожих на хранилище, — для
    подсказки, если подключение не нашлось."""
    marks = ("KV_", "REDIS", "UPSTASH")
    return sorted(n for n in os.environ
                  if any(m in n for m in marks)
                  and "READ_ONLY" not in n)


class RedisError(Exception):
    pass


CRLF = bytes([13, 10])


def _resp_pack(cmd):
    """Команда в протоколе Redis: массив строк с длинами."""
    out = [b"*" + str(len(cmd)).encode() + CRLF]
    for a in cmd:
        b = a if isinstance(a, bytes) else str(a).encode("utf-8")
        out.append(b"$" + str(len(b)).encode() + CRLF + b + CRLF)
    return b"".join(out)


def _resp_read(f):
    line = f.readline()
    if not line:
        raise ConnectionError("Redis закрыл соединение")
    kind, rest = line[:1], line[1:].rstrip(CRLF)
    if kind == b"+":
        return rest.decode("utf-8", "replace")
    if kind == b"-":
        return RedisError(rest.decode("utf-8", "replace"))
    if kind == b":":
        return int(rest)
    if kind == b"$":
        n = int(rest)
        if n < 0:
            return None
        return f.read(n + 2)[:n].decode("utf-8", "replace")
    if kind == b"*":
        n = int(rest)
        if n < 0:
            return None
        return [_resp_read(f) for _ in range(n)]
    raise ConnectionError("непонятный ответ Redis")


def _resp_pipeline(url, cmds):
    """Несколько команд одним заходом по обычному подключению Redis."""
    import socket, ssl
    u = urllib.parse.urlparse(url)
    host, port = u.hostname, u.port or 6379
    raw = socket.create_connection((host, port), timeout=6)
    sock = (ssl.create_default_context().wrap_socket(
        raw, server_hostname=host) if u.scheme == "rediss" else raw)
    pre = []
    if u.password:
        pw = urllib.parse.unquote(u.password)
        user = urllib.parse.unquote(u.username or "")
        pre.append(["AUTH", user, pw] if user else ["AUTH", pw])
    db = (u.path or "").strip("/")
    if db.isdigit() and db != "0":
        pre.append(["SELECT", db])
    try:
        sock.sendall(b"".join(_resp_pack(c) for c in pre + list(cmds)))
        f = sock.makefile("rb")
        res = [_resp_read(f) for _ in range(len(pre) + len(cmds))]
    finally:
        sock.close()
    for r in res[:len(pre)]:
        if isinstance(r, RedisError):
            raise r                    # не пустили — дальше смысла нет
    return [None if isinstance(r, RedisError) else r
            for r in res[len(pre):]]


def _find_tcp():
    """Адрес обычного подключения: …REDIS_URL или …KV_URL с redis://."""
    for name in sorted(os.environ):
        v = os.environ[name]
        if (name.endswith("REDIS_URL") or name.endswith("KV_URL")) and \
                v.startswith(("redis://", "rediss://")):
            return v
    return ""


REDIS_URL, REDIS_TOKEN = _find_redis()
# веб-доступа нет — пробуем обычное подключение (так даёт хранилище «Redis»)
REDIS_TCP = "" if (REDIS_URL and REDIS_TOKEN) else _find_tcp()
STORE = bool((REDIS_URL and REDIS_TOKEN) or REDIS_TCP)
KEEP = 400 * 24 * 3600                # дневные счётчики живут чуть больше года
MSK = 3 * 3600                        # сутки считаем по Москве, а не по UTC


# ------------------------------------------------------------ хранилище ---
def redis(*cmds):
    """Несколько команд Redis одним запросом. Без хранилища — None."""
    if not (REDIS_URL and REDIS_TOKEN):
        return _resp_pipeline(REDIS_TCP, cmds) if REDIS_TCP else None
    req = urllib.request.Request(
        REDIS_URL + "/pipeline", data=json.dumps(list(cmds)).encode("utf-8"),
        method="POST", headers={"Authorization": "Bearer " + REDIS_TOKEN,
                                "Content-Type": "application/json",
                                "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=8) as r:
        return [x.get("result") for x in json.loads(r.read().decode())]


def day(offset=0):
    return time.strftime("%Y-%m-%d",
                         time.gmtime(time.time() + MSK - offset * 86400))


def record_ping(install_id, ver, uid=None):
    d = day()
    cmds = [["PFADD", "u:d:" + d, install_id], ["EXPIRE", "u:d:" + d, KEEP],
            ["PFADD", "u:all", install_id],
            ["INCR", "open:d:" + d], ["EXPIRE", "open:d:" + d, KEEP],
            ["PFADD", "u:v:" + ver, install_id], ["SADD", "versions", ver]]
    if uid:
        cmds += [["PFADD", "acc:d:" + d, uid], ["EXPIRE", "acc:d:" + d, KEEP],
                 ["PFADD", "acc:all", uid]]
    return redis(*cmds)


def report():
    days = [day(i) for i in range(30)]
    n = len(days)
    cmds = [["PFCOUNT", "u:d:" + d] for d in days]            # по дням
    cmds += [["GET", "open:d:" + d] for d in days]
    cmds += [["GET", "q:d:" + d] for d in days]
    cmds += [["PFCOUNT"] + ["u:d:" + d for d in days[:7]],    # неделя
             ["PFCOUNT"] + ["u:d:" + d for d in days],        # месяц
             ["PFCOUNT", "u:all"], ["PFCOUNT", "acc:all"],
             ["PFCOUNT", "acc:d:" + days[0]], ["SMEMBERS", "versions"],
             ["HGETALL", "qnet:d:" + days[0]]]
    r = redis(*cmds)
    users, opens, qs = r[:n], r[n:2 * n], r[2 * n:3 * n]
    week, month, total, acc_all, acc_today, vers, qnet = r[3 * n:]
    vers = vers or []
    vcount = (redis(*[["PFCOUNT", "u:v:" + v] for v in vers]) or []
              if vers else [])
    qnet = dict(zip(qnet[::2], qnet[1::2])) if qnet else {}
    return {
        "days": [{"day": d, "users": int(u or 0), "opens": int(o or 0),
                  "questions": int(q or 0)}
                 for d, u, o, q in zip(days, users, opens, qs)],
        "today": int(users[0] or 0), "week": int(week or 0),
        "month": int(month or 0), "total": int(total or 0),
        "accounts": int(acc_all or 0), "accounts_today": int(acc_today or 0),
        "versions": sorted(({"ver": v, "users": int(c or 0)}
                            for v, c in zip(vers, vcount)),
                           key=lambda x: -x["users"]),
        "questions_today_by_net": {k: int(v) for k, v in qnet.items()},
        **subs_report(),
    }


# ------------------------------------------------------------- подписка ---
PRICE = int(os.environ.get("PAMYATKA_PRICE", "50") or 50)
DAYS = int(os.environ.get("PAMYATKA_SUB_DAYS", "30") or 30)
WALLET = os.environ.get("YOOMONEY_WALLET", "").strip()
YM_SECRET = os.environ.get("YOOMONEY_SECRET", "").strip()
PAYWALL = os.environ.get("PAMYATKA_PAYWALL", "").strip().lower() in (
    "1", "on", "yes", "true")
FOREVER = 4102444800                   # 2100 год: для списка PAMYATKA_VIP_IDS


def sub_until(uid):
    """До какого момента у человека подписка (0 — нет)."""
    if not uid:
        return 0
    if uid in VIP:
        return FOREVER
    try:
        r = redis(["GET", "sub:" + uid])
        return int((r or [0])[0] or 0)
    except Exception:
        return 0


def extend_sub(uid, days):
    """Продлить подписку: к сроку, если ещё идёт, иначе от сейчас."""
    now = int(time.time())
    cur = sub_until(uid)
    if days <= 0:
        redis(["DEL", "sub:" + uid], ["SREM", "subs", uid])
        return 0
    until = max(now, cur if cur < FOREVER else now) + days * 86400
    redis(["SET", "sub:" + uid, str(until)], ["SADD", "subs", uid])
    return until


def month():
    return time.strftime("%Y-%m", time.gmtime(time.time() + MSK))


def ym_valid(f):
    """Подпись уведомления ЮMoney: sha1 от полей через & с секретом."""
    raw = "&".join([f.get("notification_type", ""), f.get("operation_id", ""),
                    f.get("amount", ""), f.get("currency", ""),
                    f.get("datetime", ""), f.get("sender", ""),
                    f.get("codepro", ""), YM_SECRET, f.get("label", "")])
    good = hashlib.sha1(raw.encode("utf-8")).hexdigest()
    return hmac.compare_digest(good, (f.get("sha1_hash") or "").lower())


def handle_payment(f):
    """Уведомление об оплате: проверяем и продлеваем. Возвращает итог."""
    if not YM_SECRET or not ym_valid(f):
        return "bad-signature"
    if f.get("test_notification") == "true":
        return "test-ok"               # кнопка «Протестировать» в ЮMoney
    if f.get("unaccepted") == "true":
        return "unaccepted"            # деньги ещё не зачислены
    if f.get("currency") != "643":
        return "not-rub"
    m = re.match(r"^pm1:([0-9]{5,25})$", f.get("label") or "")
    if not m:
        return "no-label"
    uid = m.group(1)
    try:
        paid = float(f.get("withdraw_amount") or 0)
        got = float(f.get("amount") or 0)
    except ValueError:
        return "bad-amount"
    # платящий вносит сумму целиком, а на кошелёк приходит за вычетом
    # комиссии: смотрим, сколько он заплатил, а если этого поля нет —
    # сколько пришло, с поправкой на комиссию
    if not (paid >= PRICE or got >= PRICE * 0.95):
        return "too-little"
    op = f.get("operation_id") or ""
    first = redis(["SET", "op:" + op, "1", "NX", "EX", 400 * 86400])
    if not first or first[0] is None:
        return "duplicate"             # ЮMoney иногда повторяет уведомление
    until = extend_sub(uid, DAYS)
    mo = month()
    note = json.dumps({"uid": uid, "rub": paid or got, "at": int(time.time()),
                       "until": until}, ensure_ascii=False)
    redis(["INCRBYFLOAT", "rev:m:" + mo, str(paid or got)],
          ["INCR", "pays:m:" + mo],
          ["LPUSH", "paylog", note], ["LTRIM", "paylog", 0, 49])
    return "ok"


def subs_report():
    uids = (redis(["SMEMBERS", "subs"]) or [[]])[0] or []
    untils = redis(*[["GET", "sub:" + u] for u in uids]) if uids else []
    now = time.time()
    active = sum(1 for t in (untils or []) if t and int(t) > now)
    mo = month()
    rev, pays, log = redis(["GET", "rev:m:" + mo], ["GET", "pays:m:" + mo],
                           ["LRANGE", "paylog", 0, 9])
    return {"subs_active": active + len(VIP),
            "revenue_month": round(float(rev or 0), 2),
            "payments_month": int(pays or 0),
            "recent_payments": [json.loads(x) for x in (log or [])]}


PAY_PAGE = """<!doctype html><html lang="ru"><meta charset="utf-8">
<title>Памятка RMRP — подписка</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;
background:#0b0f17;color:#eef2f8;font:16px/1.5 "Segoe UI",system-ui,sans-serif}
.c{max-width:28rem;padding:2rem 2.2rem;border-radius:1.2rem;text-align:center;
background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12)}
h1{font-size:1.35rem;margin:0 0 .4rem}p{color:rgba(238,242,248,.7);margin:.3rem 0}
.p{font-size:2.4rem;font-weight:700;margin:.6rem 0}button{font:inherit;border:0;
border-radius:.8rem;padding:.75rem 1.2rem;margin:.35rem;cursor:pointer;
color:#fff;background:linear-gradient(135deg,#5b9dff,#7b6bff)}
button.w{background:rgba(255,255,255,.12)}small{color:rgba(238,242,248,.45)}</style>
<div class="c"><h1>Подписка на нейросети</h1>
<p>Gemini и Grok в помощнике Памятки на {days} дней.</p>
<div class="p">{price} ₽</div>
<form method="POST" action="https://yoomoney.ru/quickpay/confirm">
<input type="hidden" name="receiver" value="{wallet}">
<input type="hidden" name="quickpay-form" value="button">
<input type="hidden" name="sum" value="{price}">
<input type="hidden" name="label" value="{label}">
<input type="hidden" name="successURL" value="{back}">
<button name="paymentType" value="AC">Оплатить картой</button>
<button class="w" name="paymentType" value="PC">Кошельком ЮMoney</button>
</form>
<p><small>Discord ID: {uid}. После оплаты вернитесь в Памятку —
подписка включится в течение минуты.</small></p></div></html>"""


# ------------------------------------------------------------- подпись ---
def _b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _key():
    # ключ подписи выводится из секрета приложения: ещё одну переменную
    # заводить не нужно, а без секрета пропуск не подделать
    return hmac.new(CLIENT_SECRET.encode("utf-8"), b"pamyatka-session-v1",
                    hashlib.sha256).digest()


def sign(payload):
    body = _b64(json.dumps(payload, ensure_ascii=False,
                           separators=(",", ":")).encode("utf-8"))
    mac = _b64(hmac.new(_key(), body.encode("ascii"),
                        hashlib.sha256).digest())
    return body + "." + mac


def verify(token):
    """Содержимое пропуска, если подпись верна и срок не вышел."""
    if not CLIENT_SECRET or not isinstance(token, str) or \
            token.count(".") != 1 or len(token) > 4096:
        return None
    try:
        body, mac = token.split(".")
        good = _b64(hmac.new(_key(), body.encode("ascii"),
                             hashlib.sha256).digest())
        if not hmac.compare_digest(good.encode("ascii"),
                                   mac.encode("ascii")):
            return None
        data = json.loads(_unb64(body).decode("utf-8"))
    except Exception:
        return None
    if not isinstance(data, dict) or data.get("exp", 0) < time.time():
        return None
    return data


# ------------------------------------------------------------- Discord ---
def _discord(url, form=None, bearer=None):
    hdr = {"User-Agent": UA, "Accept": "application/json"}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode("ascii")
        hdr["Content-Type"] = "application/x-www-form-urlencoded"
    if bearer:
        hdr["Authorization"] = "Bearer " + bearer
    req = urllib.request.Request(url, data=data, headers=hdr,
                                 method="POST" if data else "GET")
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode("utf-8"))


def profile_from_code(code):
    tok = _discord("https://discord.com/api/oauth2/token", form={
        "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code", "code": code,
        "redirect_uri": REDIRECT})
    me = _discord("https://discord.com/api/users/@me",
                  bearer=tok["access_token"])
    uid = str(me.get("id") or "")
    now = int(time.time())
    return {"uid": uid,
            "name": me.get("global_name") or me.get("username") or "",
            "login": me.get("username") or "",
            "avatar": me.get("avatar") or "",
            "plan": "vip" if uid in VIP else "free",
            "iat": now, "exp": now + TTL}


# ---------------------------------------------------------------- страница ---
PAGE = """<!doctype html><html lang="ru"><meta charset="utf-8">
<title>Памятка RMRP — вход</title>
<style>body{margin:0;height:100vh;display:grid;place-items:center;
background:#0b0f17;color:#eef2f8;font:16px/1.5 "Segoe UI",system-ui,sans-serif}
.c{max-width:30rem;padding:2rem 2.2rem;border-radius:1.2rem;text-align:center;
background:rgba(255,255,255,.06);border:1px solid rgba(255,255,255,.12)}
h1{font-size:1.3rem;margin:0 0 .5rem}p{color:rgba(238,242,248,.7);margin:0}</style>
<div class="c"><h1>{title}</h1><p>{text}</p></div></html>"""


def _page(title, text):
    esc = lambda s: (str(s).replace("&", "&amp;").replace("<", "&lt;")
                     .replace(">", "&gt;"))
    return PAGE.replace("{title}", esc(title)).replace("{text}", esc(text))


def _port(v):
    try:
        p = int(v)
    except (TypeError, ValueError):
        return None
    return p if 1024 <= p <= 65535 else None


def _loopback(port, **q):
    # адрес возврата задан жёстко: только своя машина, только http
    return "http://127.0.0.1:%d/done?%s" % (port, urllib.parse.urlencode(q))


ID_RE = re.compile(r"^[0-9a-f]{16,40}$")
VER_RE = re.compile(r"^[0-9]{1,3}([.][0-9]{1,3}){0,2}$")


class handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json; charset=utf-8",
              extra=None):
        raw = body if isinstance(body, bytes) else (
            json.dumps(body, ensure_ascii=False) if ctype.startswith(
                "application/json") else body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _html(self, code, title, text):
        self._send(code, _page(title, text), "text/html; charset=utf-8")

    def _go(self, url):
        self._send(302, b"", "text/plain", {"Location": url})

    def do_POST(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        step = (q.get("step") or [""])[0]
        if step == "yoomoney":
            n = min(int(self.headers.get("Content-Length") or 0), 8192)
            form = {k: v[0] for k, v in urllib.parse.parse_qs(
                self.rfile.read(n).decode("utf-8", "replace"),
                keep_blank_values=True).items()}
            try:
                res = handle_payment(form)
            except Exception as e:
                res = "error " + type(e).__name__
            print("ЮMoney:", res, form.get("operation_id"), form.get("label"))
            # 200 даже на отказ: иначе ЮMoney будет слать повторы без конца
            return self._send(200, {"result": res})
        if step == "grant":
            auth = self.headers.get("Authorization", "")
            who = verify(auth[7:] if auth.startswith("Bearer ") else "")
            if not who or who.get("uid") not in ADMINS:
                return self._send(403, {"error": "только для автора"})
            try:
                n = min(int(self.headers.get("Content-Length") or 0), 2048)
                body = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
                uid, days = str(body.get("uid") or ""), int(body.get("days"))
            except Exception:
                return self._send(400, {"error": "нужны uid и days"})
            if not re.match(r"^[0-9]{5,25}$", uid) or not -1 <= days <= 3650:
                return self._send(400, {"error": "не тот uid или срок"})
            if not STORE:
                return self._send(503, {"error": "хранилище не подключено"})
            return self._send(200, {"uid": uid,
                                    "until": extend_sub(uid, days)})
        if step != "ping":
            return self._send(404, {"error": "нет такого адреса"})
        try:
            n = min(int(self.headers.get("Content-Length") or 0), 4096)
            body = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
        except Exception:
            return self._send(400, {"error": "не JSON"})
        iid = str(body.get("id") or "").lower()
        ver = str(body.get("ver") or "")
        # берём только то, что похоже на номер установки и версию, —
        # чтобы в счётчики нельзя было накидать мусора
        if not ID_RE.match(iid) or not VER_RE.match(ver):
            return self._send(400, {"error": "не тот формат"})
        who = verify(str(body.get("token") or ""))
        try:
            stored = record_ping(iid, ver, who and who.get("uid"))
        except Exception as e:
            return self._send(200, {"ok": True, "stored": False,
                                    "why": type(e).__name__})
        return self._send(200, {"ok": True, "stored": stored is not None})

    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        g = lambda k: (q.get(k) or [""])[0]
        step = g("step")
        ready = bool(CLIENT_ID and CLIENT_SECRET)

        if step == "status":
            out = {"configured": ready, "stats": STORE,
                   "pay": bool(WALLET and YM_SECRET), "price": PRICE,
                   "days": DAYS, "paywall": PAYWALL}
            if not out["stats"]:
                out["storage_vars"] = storage_names()
            return self._send(200, out)

        if step == "stats":
            auth = self.headers.get("Authorization", "")
            who = verify(auth[7:] if auth.startswith("Bearer ") else "")
            if not who:
                return self._send(401, {"error": "Войдите через Discord."})
            if who.get("uid") not in ADMINS:
                return self._send(403, {"error": "Статистику видит только "
                                        "автор. Ваш Discord ID: %s"
                                        % who.get("uid"),
                                        "uid": who.get("uid")})
            if not STORE:
                seen = storage_names()
                why = ("Хранилище не подключено: Vercel → Storage → Upstash "
                       "for Redis, затем Redeploy." if not seen else
                       "Хранилище видно, но без REST-доступа. Найдены "
                       "переменные: %s. Нужна пара …KV_REST_API_URL и "
                       "…KV_REST_API_TOKEN (есть у Upstash for Redis)."
                       % ", ".join(seen))
                return self._send(503, {"error": why, "storage_vars": seen})
            try:
                return self._send(200, report())
            except Exception as e:
                return self._send(502, {"error": "Хранилище не ответило: %s"
                                        % type(e).__name__})

        if step == "me":
            auth = self.headers.get("Authorization", "")
            data = verify(auth[7:] if auth.startswith("Bearer ") else "")
            if not data:
                return self._send(401, {"error": "пропуск недействителен"})
            # план пересчитываем при каждой проверке: оплатил — подписка
            # появилась без нового входа, кончилась — пропала
            until = sub_until(data.get("uid"))
            data["sub_until"] = until
            data["plan"] = "vip" if until > time.time() else "free"
            data["price"], data["paywall"] = PRICE, PAYWALL
            return self._send(200, data)

        if step == "pay":
            uid = g("uid")
            if not re.match(r"^[0-9]{5,25}$", uid):
                return self._html(400, "Не тот адрес",
                                  "Откройте оплату из программы.")
            if not WALLET:
                return self._html(503, "Оплата ещё не подключена",
                                  "Автор пока не подключил приём оплаты.")
            page = PAY_PAGE
            for k, v in (("{days}", DAYS), ("{price}", PRICE),
                         ("{wallet}", WALLET), ("{label}", "pm1:" + uid),
                         ("{back}", BASE + "/auth?step=paid"), ("{uid}", uid)):
                page = page.replace(k, str(v))
            return self._send(200, page, "text/html; charset=utf-8")

        if step == "paid":
            return self._html(200, "Спасибо за оплату",
                              "Вернитесь в Памятку: подписка включится в "
                              "течение минуты. Вкладку можно закрыть.")

        if not ready:
            return self._html(503, "Вход ещё не настроен",
                              "Автор программы пока не подключил вход "
                              "через Discord. Закройте вкладку.")

        if step == "start":
            port, nonce = _port(g("port")), g("nonce")[:64]
            if not port or len(nonce) < 12:
                return self._html(400, "Не тот адрес",
                                  "Начните вход из самой программы.")
            state = sign({"port": port, "nonce": nonce,
                          "exp": int(time.time()) + STATE_TTL})
            return self._go("https://discord.com/oauth2/authorize?" +
                            urllib.parse.urlencode({
                                "client_id": CLIENT_ID,
                                "response_type": "code",
                                "redirect_uri": REDIRECT,
                                "scope": "identify",
                                "prompt": "none",
                                "state": state}))

        # возврат от Discord
        st = verify(g("state"))
        if not st or not _port(st.get("port")):
            return self._html(400, "Вход устарел",
                              "Начните вход заново из программы.")
        port, nonce = st["port"], st["nonce"]
        if g("error"):
            return self._go(_loopback(port, nonce=nonce,
                                      error="Вход отменён в Discord"))
        code = g("code")
        if not code:
            return self._go(_loopback(port, nonce=nonce,
                                      error="Discord не вернул код"))
        try:
            prof = profile_from_code(code)
        except urllib.error.HTTPError as e:
            return self._go(_loopback(port, nonce=nonce,
                                      error="Discord отказал: %s" % e.code))
        except Exception as e:
            return self._go(_loopback(port, nonce=nonce,
                                      error="Discord недоступен: %s"
                                      % type(e).__name__))
        try:
            redis(["PFADD", "acc:all", prof["uid"]])
        except Exception:
            pass                       # статистика не должна мешать входу
        return self._go(_loopback(port, nonce=nonce, token=sign(prof)))
