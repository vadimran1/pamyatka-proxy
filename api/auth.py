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
# хранилище: Upstash Redis из маркетплейса Vercel кладёт одну из этих пар
REDIS_URL = (os.environ.get("KV_REST_API_URL") or
             os.environ.get("UPSTASH_REDIS_REST_URL") or "").rstrip("/")
REDIS_TOKEN = (os.environ.get("KV_REST_API_TOKEN") or
               os.environ.get("UPSTASH_REDIS_REST_TOKEN") or "")
KEEP = 400 * 24 * 3600                # дневные счётчики живут чуть больше года
MSK = 3 * 3600                        # сутки считаем по Москве, а не по UTC


# ------------------------------------------------------------ хранилище ---
def redis(*cmds):
    """Несколько команд Redis одним запросом. Без хранилища — None."""
    if not (REDIS_URL and REDIS_TOKEN):
        return None
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
    }


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
        if (q.get("step") or [""])[0] != "ping":
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
            return self._send(200, {"configured": ready,
                                    "stats": bool(REDIS_URL and REDIS_TOKEN)})

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
            if not (REDIS_URL and REDIS_TOKEN):
                return self._send(503, {"error": "Хранилище не подключено: "
                                        "Vercel → Storage → Upstash Redis."})
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
            # план пересчитываем при каждой проверке: убрали из списка —
            # подписка пропала без перевыпуска пропуска
            data["plan"] = "vip" if data.get("uid") in VIP else "free"
            return self._send(200, data)

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
