# -*- coding: utf-8 -*-
"""Форум предложений Памятки RMRP.

Предложения, голоса и комментарии лежат в том же Redis (Upstash), что и
/auth. Регистрации нет: писать может любой, а от спама защищают лимиты
по адресу и поле-ловушка для ботов. Модерирует автор — по ключу из
переменной Vercel PAMYATKA_FORUM_KEY (без неё модерация выключена).

Как хранится (все ключи с приставкой fs:):
  fs:seq            счётчик номеров
  fs:p:<id>         предложение целиком, JSON
  fs:new            ZSET: номер -> время, по нему же список
  fs:votes          HASH: номер -> голосов
  fs:ccount         HASH: номер -> комментариев
  fs:v:<id>         SET: кто голосовал (хэш адреса)
  fs:mine:<voter>   SET: за что голосовал этот человек
  fs:c:<id>         LIST: комментарии, JSON
Так список целиком читается за пять команд Redis, а не за сотни —
бесплатного тарифа Upstash хватает надолго.

Адреса (все через /forum):
  GET  ?step=status                 подключено ли хранилище
  GET  ?step=list                   предложения (новые сверху, до 300)
  GET  ?step=comments&id=N          комментарии к предложению
  POST ?step=add      {name, text, hp}
  POST ?step=vote     {id}          голос; повторно — снять голос
  POST ?step=comment  {id, name, text, hp}
  POST ?step=admin    {id, action, value, cid}   заголовок X-Forum-Key
       action: delete | status | reply | delcomment
  GET  ?step=admin                  проверить ключ (X-Forum-Key)
"""
import os, re, json, time, hmac, hashlib, secrets
import urllib.request, urllib.parse
from http.server import BaseHTTPRequestHandler

UA = "PamyatkaForum/1.0 (+https://pamyatka-proxy.vercel.app)"
FORUM_KEY = os.environ.get("PAMYATKA_FORUM_KEY", "").strip()
SALT = os.environ.get("PAMYATKA_FORUM_SALT", "") or "pamyatka-forum-v1"
LIST_MAX = 300                     # сколько последних предложений отдаём
COMMENTS_MAX = 200                 # комментариев под одним предложением
STATUSES = {"": "", "review": "На рассмотрении", "planned": "В планах",
            "done": "Сделано", "rejected": "Отклонено"}
# лимиты: (сколько, за сколько секунд)
LIMITS = {"add": [(3, 600), (10, 86400)],
          "comment": [(10, 600), (60, 86400)],
          "vote": [(60, 600)]}


# ------------------------------------------------------------ хранилище ---
# То же подключение, что в auth.py: REST Upstash или обычный redis://.
# Код скопирован, а не импортирован: на Vercel каждая функция живёт сама
# по себе, и импорт соседнего файла может не доехать.
def _find_redis():
    env = os.environ
    for url_end, tok_end in (("KV_REST_API_URL", "KV_REST_API_TOKEN"),
                             ("REDIS_REST_URL", "REDIS_REST_TOKEN"),
                             ("REDIS_REST_API_URL", "REDIS_REST_API_TOKEN")):
        for name in sorted(env):
            if name.endswith(url_end) and env[name].startswith(("https://", "http://")):
                tok = env.get(name[:-len(url_end)] + tok_end, "")
                if tok:
                    return env[name].rstrip("/"), tok
    return "", ""


def _find_tcp():
    for name in sorted(os.environ):
        v = os.environ[name]
        if (name.endswith("REDIS_URL") or name.endswith("KV_URL")) and \
                v.startswith(("redis://", "rediss://")):
            return v
    return ""


class RedisError(Exception):
    pass


CRLF = bytes([13, 10])


def _resp_pack(cmd):
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
        return None if n < 0 else f.read(n + 2)[:n].decode("utf-8", "replace")
    if kind == b"*":
        n = int(rest)
        return None if n < 0 else [_resp_read(f) for _ in range(n)]
    raise ConnectionError("непонятный ответ Redis")


def _resp_pipeline(url, cmds):
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
            raise r
    return [None if isinstance(r, RedisError) else r for r in res[len(pre):]]


REDIS_URL, REDIS_TOKEN = _find_redis()
REDIS_TCP = "" if (REDIS_URL and REDIS_TOKEN) else _find_tcp()
STORE = bool((REDIS_URL and REDIS_TOKEN) or REDIS_TCP)


def redis(*cmds):
    """Несколько команд Redis одним заходом."""
    if not (REDIS_URL and REDIS_TOKEN):
        if not REDIS_TCP:
            raise RedisError("хранилище не подключено")
        return _resp_pipeline(REDIS_TCP, cmds)
    req = urllib.request.Request(
        REDIS_URL + "/pipeline", data=json.dumps(list(cmds)).encode("utf-8"),
        method="POST", headers={"Authorization": "Bearer " + REDIS_TOKEN,
                                "Content-Type": "application/json",
                                "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=8) as r:
        return [x.get("result") for x in json.loads(r.read().decode())]


# ---------------------------------------------------------------- помощь ---
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f​-‏‪-‮⁦-⁩]")
ID_RE = re.compile(r"^[0-9]{1,9}$")


def clean(s, limit, multiline=True):
    """Убрать управляющие символы и лишние пустые строки."""
    s = CTRL_RE.sub("", str(s or "")).replace("\r", "")
    if not multiline:
        s = s.replace("\n", " ")
    s = re.sub(r"\n{3,}", "\n\n", s)
    s = re.sub(r"[ \t]{2,}", " ", s).strip()
    return s[:limit]


def _hash_map(flat):
    """HGETALL отдаёт плоский список [k, v, k, v] — делаем словарь."""
    if isinstance(flat, dict):
        return flat
    flat = flat or []
    return dict(zip(flat[::2], flat[1::2]))


def voter_of(ip):
    return hmac.new(SALT.encode(), ("v|" + ip).encode(),
                    hashlib.sha256).hexdigest()[:24]


def over_limit(kind, voter):
    """True, если с этого адреса уже слишком часто."""
    cmds = []
    for n, win in LIMITS[kind]:
        k = "fs:rl:%s:%d:%s" % (kind, win, voter)
        cmds += [["SET", k, 0, "EX", win, "NX"], ["INCR", k]]
    res = redis(*cmds)
    for i, (n, _) in enumerate(LIMITS[kind]):
        if int(res[i * 2 + 1] or 0) > n:
            return True
    return False


def public(p, votes, ccount, mine):
    """Предложение в том виде, в каком его видит сайт."""
    return {"id": p["id"], "name": p.get("name") or "Аноним",
            "text": p.get("text", ""), "ts": p.get("ts", 0),
            "status": p.get("status", ""),
            "status_text": STATUSES.get(p.get("status", ""), ""),
            "reply": p.get("reply", ""), "reply_ts": p.get("reply_ts", 0),
            "votes": int(votes or 0), "comments": int(ccount or 0),
            "voted": p["id"] in mine}


# ---------------------------------------------------------------- действия ---
def list_posts(voter):
    ids = redis(["ZREVRANGE", "fs:new", 0, LIST_MAX - 1])[0] or []
    if not ids:
        return []
    raw, votes, cc, mine = redis(["MGET"] + ["fs:p:" + i for i in ids],
                                 ["HGETALL", "fs:votes"],
                                 ["HGETALL", "fs:ccount"],
                                 ["SMEMBERS", "fs:mine:" + voter])
    votes, cc, mine = _hash_map(votes), _hash_map(cc), set(mine or [])
    out = []
    for i, r in zip(ids, raw or []):
        if not r:
            continue
        try:
            p = json.loads(r)
        except ValueError:
            continue
        out.append(public(p, votes.get(i), cc.get(i), mine))
    return out


def add_post(name, text, voter):
    pid = str(redis(["INCR", "fs:seq"])[0])
    now = int(time.time())
    p = {"id": pid, "name": name, "text": text, "ts": now, "status": "",
         "reply": "", "who": voter}
    redis(["SET", "fs:p:" + pid, json.dumps(p, ensure_ascii=False)],
          ["ZADD", "fs:new", now, pid],
          # автор сразу «голосует» за своё предложение
          ["SADD", "fs:v:" + pid, voter], ["HINCRBY", "fs:votes", pid, 1],
          ["SADD", "fs:mine:" + voter, pid])
    return public(p, 1, 0, {pid})


def toggle_vote(pid, voter):
    exists, added = redis(["EXISTS", "fs:p:" + pid],
                          ["SADD", "fs:v:" + pid, voter])
    if not exists:
        redis(["SREM", "fs:v:" + pid, voter])
        return None
    if added:
        n = redis(["HINCRBY", "fs:votes", pid, 1],
                  ["SADD", "fs:mine:" + voter, pid])[0]
        return {"id": pid, "voted": True, "votes": int(n)}
    redis(["SREM", "fs:v:" + pid, voter])
    n = redis(["HINCRBY", "fs:votes", pid, -1],
              ["SREM", "fs:mine:" + voter, pid])[0]
    return {"id": pid, "voted": False, "votes": max(int(n), 0)}


def get_comments(pid):
    rows = redis(["LRANGE", "fs:c:" + pid, 0, -1])[0] or []
    out = []
    for r in rows:
        try:
            c = json.loads(r)
        except ValueError:
            continue
        out.append({"cid": c.get("cid"), "name": c.get("name") or "Аноним",
                    "text": c.get("text", ""), "ts": c.get("ts", 0),
                    "author": bool(c.get("author"))})
    return out


def add_comment(pid, name, text, voter, author=False):
    if not redis(["EXISTS", "fs:p:" + pid])[0]:
        return None
    c = {"cid": secrets.token_hex(5), "name": name, "text": text,
         "ts": int(time.time()), "who": voter, "author": author}
    n = redis(["RPUSH", "fs:c:" + pid, json.dumps(c, ensure_ascii=False)],
              ["LTRIM", "fs:c:" + pid, -COMMENTS_MAX, -1])[0]
    redis(["HSET", "fs:ccount", pid, min(int(n), COMMENTS_MAX)])
    return {"cid": c["cid"], "name": name or "Аноним", "text": text,
            "ts": c["ts"], "author": author}


def admin_action(pid, action, value, cid):
    if action == "delete":
        voters = redis(["SMEMBERS", "fs:v:" + pid])[0] or []
        cmds = [["DEL", "fs:p:" + pid, "fs:v:" + pid, "fs:c:" + pid],
                ["ZREM", "fs:new", pid], ["HDEL", "fs:votes", pid],
                ["HDEL", "fs:ccount", pid]]
        cmds += [["SREM", "fs:mine:" + v, pid] for v in voters]
        redis(*cmds)
        return {"id": pid, "deleted": True}
    if action == "delcomment":
        rows = redis(["LRANGE", "fs:c:" + pid, 0, -1])[0] or []
        for r in rows:
            try:
                if json.loads(r).get("cid") == cid:
                    redis(["LREM", "fs:c:" + pid, 1, r])
                    redis(["HINCRBY", "fs:ccount", pid, -1])
                    return {"id": pid, "cid": cid, "deleted": True}
            except ValueError:
                continue
        return None
    raw = redis(["GET", "fs:p:" + pid])[0]
    if not raw:
        return None
    p = json.loads(raw)
    if action == "status":
        if value not in STATUSES:
            raise ValueError("нет такого статуса")
        p["status"] = value
    elif action == "reply":
        p["reply"] = clean(value, 1000)
        p["reply_ts"] = int(time.time()) if p["reply"] else 0
    else:
        raise ValueError("нет такого действия")
    redis(["SET", "fs:p:" + pid, json.dumps(p, ensure_ascii=False)])
    votes, cc = redis(["HGET", "fs:votes", pid], ["HGET", "fs:ccount", pid])
    out = public(p, votes, cc, set())
    del out["voted"]                   # голос модератора тут ни при чём —
    return out                         # пусть сайт оставит то, что было


# ---------------------------------------------------------------- сервер ---
class handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def _ip(self):
        fwd = (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        return fwd or (self.headers.get("X-Real-Ip") or "").strip() or \
            (self.client_address[0] if self.client_address else "?")

    def _is_admin(self):
        key = self.headers.get("X-Forum-Key", "")
        return bool(len(FORUM_KEY) >= 8 and key and
                    hmac.compare_digest(key.encode(), FORUM_KEY.encode()))

    def _body(self):
        n = min(int(self.headers.get("Content-Length") or 0), 16384)
        return json.loads(self.rfile.read(n).decode("utf-8") or "{}")

    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        step = (q.get("step") or [""])[0]
        if step == "status":
            return self._send(200, {"ok": True, "store": STORE,
                                    "moderation": len(FORUM_KEY) >= 8})
        if step == "admin":
            return self._send(200 if self._is_admin() else 403,
                              {"admin": self._is_admin()})
        if not STORE:
            return self._send(503, {"error": "Форум скоро откроется.",
                                    "store": False})
        try:
            if step == "list":
                return self._send(200, {"posts": list_posts(voter_of(self._ip())),
                                        "statuses": STATUSES})
            if step == "comments":
                pid = (q.get("id") or [""])[0]
                if not ID_RE.match(pid):
                    return self._send(400, {"error": "не тот номер"})
                return self._send(200, {"id": pid, "comments": get_comments(pid)})
        except Exception as e:
            print("форум:", step, type(e).__name__, e)
            return self._send(502, {"error": "Хранилище не ответило, "
                                             "попробуйте через минуту."})
        return self._send(404, {"error": "нет такого адреса"})

    def do_POST(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        step = (q.get("step") or [""])[0]
        if not STORE:
            return self._send(503, {"error": "Форум скоро откроется.",
                                    "store": False})
        try:
            body = self._body()
            if not isinstance(body, dict):
                raise ValueError
        except Exception:
            return self._send(400, {"error": "не JSON"})
        voter = voter_of(self._ip())
        pid = str(body.get("id") or "")
        try:
            if step == "admin":
                if not self._is_admin():
                    return self._send(403, {"error": "Неверный ключ модератора."})
                if not ID_RE.match(pid):
                    return self._send(400, {"error": "не тот номер"})
                try:
                    res = admin_action(pid, str(body.get("action") or ""),
                                       str(body.get("value") or ""),
                                       str(body.get("cid") or ""))
                except ValueError as e:
                    return self._send(400, {"error": str(e)})
                return self._send(200 if res else 404,
                                  res or {"error": "Не найдено."})

            if step not in ("add", "vote", "comment"):
                return self._send(404, {"error": "нет такого адреса"})
            # поле-ловушка: человек его не видит, бот заполняет
            if body.get("hp"):
                return self._send(200, {"ok": True})
            if over_limit(step, voter):
                return self._send(429, {"error": "Слишком часто. Подождите "
                                                 "немного и попробуйте снова."})

            if step == "add":
                name = clean(body.get("name"), 32, multiline=False)
                text = clean(body.get("text"), 1000)
                if len(text) < 10:
                    return self._send(400, {"error": "Опишите предложение "
                                                     "подробнее — хотя бы 10 символов."})
                return self._send(200, add_post(name, text, voter))

            if not ID_RE.match(pid):
                return self._send(400, {"error": "не тот номер"})

            if step == "vote":
                res = toggle_vote(pid, voter)
                return self._send(200 if res else 404,
                                  res or {"error": "Предложение не найдено."})

            name = clean(body.get("name"), 32, multiline=False)
            text = clean(body.get("text"), 500)
            if len(text) < 2:
                return self._send(400, {"error": "Пустой комментарий."})
            author = self._is_admin()
            res = add_comment(pid, name or ("Автор" if author else ""),
                              text, voter, author)
            return self._send(200 if res else 404,
                              res or {"error": "Предложение не найдено."})
        except Exception as e:
            print("форум:", step, type(e).__name__, e)
            return self._send(502, {"error": "Хранилище не ответило, "
                                             "попробуйте через минуту."})
