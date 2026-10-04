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
  ?step=pay&uid         оплата подписки — уводит на страницу Platega
  ?step=paid&o          возврат после оплаты: проверяем и включаем
  POST ?step=platega    уведомление Platega об оплате (callback)

Подписка. Срок подписки, заказы и платежи хранятся в Postgres (Neon),
там же, где форум. Уведомлению Platega на слово не верим: по номеру
транзакции сами спрашиваем у Platega статус и сумму и только потом
продлеваем. Каждый платёж засчитывается один раз.
"""
import os, re, json, time, hmac, base64, hashlib, secrets
import urllib.request, urllib.parse, urllib.error
from http.server import BaseHTTPRequestHandler

CLIENT_ID = os.environ.get("DISCORD_CLIENT_ID", "").strip()
CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "").strip()
BASE = os.environ.get("PAMYATKA_BASE_URL",
                      "https://pamyatka-proxy.vercel.app").rstrip("/")
REDIRECT = BASE + "/auth"
TTL = 90 * 24 * 3600                   # пропуск живёт три месяца: вход
                                       # теперь обязателен, дёргать чаще незачем
COOKIE = "pm_s"                        # пропуск сайта — в HttpOnly-куке
DOWNLOAD_URL = os.environ.get(
    "PAMYATKA_DOWNLOAD_URL",
    "https://raw.githubusercontent.com/vadimran1/RMRP/main/"
    "Setup-Pamyatka-RMRP.exe")
STATE_TTL = 600                        # на сам вход — десять минут
# пробные «подписчики»: Discord ID через запятую в переменной Vercel
VIP = {x.strip() for x in os.environ.get("PAMYATKA_VIP_IDS", "").split(",")
       if x.strip()}
UA = "PamyatkaAuth/1.0 (+https://pamyatka-proxy.vercel.app)"
# Закрыть проект (вход, скачивание, оплата — страница «Проект закрыт»):
# PAMYATKA_CLOSED=1 в переменных Vercel.
CLOSED = os.environ.get("PAMYATKA_CLOSED", "0").strip() in ("1", "yes", "true")
CLOSED_TITLE = "Проект закрыт"
CLOSED_TEXT = ("Памятка RMRP больше не развивается: вход, скачивание, "
               "подписка и нейросети отключены. Спасибо всем, кто пользовался!")
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


# ------------------------------------------------------------ Postgres ---
# Подписки и платежи — в Postgres (Neon), как форум. Vercel кладёт адрес в
# DATABASE_URL (бывает с приставкой: STORAGE_DATABASE_URL), поэтому ищем
# по окончанию имени.
def _find_pg():
    env = os.environ
    for end in ("DATABASE_URL", "POSTGRES_URL"):
        for name in sorted(env):
            if name.endswith(end) and env[name].startswith(
                    ("postgres://", "postgresql://")):
                return env[name]
    return ""


PG_URL = _find_pg()
PG_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS pm_subs (
        uid TEXT PRIMARY KEY, until BIGINT NOT NULL, updated BIGINT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS pm_orders (
        id TEXT PRIMARY KEY, uid TEXT NOT NULL, rub NUMERIC NOT NULL,
        tx TEXT UNIQUE, created BIGINT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS pm_payments (
        tx TEXT PRIMARY KEY, uid TEXT NOT NULL, rub NUMERIC NOT NULL,
        status TEXT NOT NULL, at BIGINT NOT NULL, until BIGINT)""",
    # статистика: кто запускал в какой день, установки, аккаунты, счётчики
    """CREATE TABLE IF NOT EXISTS pm_seen (
        day TEXT NOT NULL, iid TEXT NOT NULL, opens INTEGER NOT NULL,
        PRIMARY KEY (day, iid))""",
    """CREATE TABLE IF NOT EXISTS pm_inst (
        iid TEXT PRIMARY KEY, ver TEXT NOT NULL, first TEXT NOT NULL,
        last TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS pm_acc (
        uid TEXT PRIMARY KEY, first TEXT NOT NULL, last TEXT NOT NULL,
        web INTEGER NOT NULL DEFAULT 0, dl INTEGER NOT NULL DEFAULT 0)""",
    """CREATE TABLE IF NOT EXISTS pm_accday (
        day TEXT NOT NULL, uid TEXT NOT NULL, PRIMARY KEY (day, uid))""",
    """CREATE TABLE IF NOT EXISTS pm_count (
        day TEXT NOT NULL, name TEXT NOT NULL, n INTEGER NOT NULL,
        PRIMARY KEY (day, name))""",
)
_pg = {"conn": None, "ready": False}


def pg(fn, *args):
    """fn(cur, *args) в одной транзакции Postgres.

    Neon усыпляет базу, и соединение тёплого экземпляра может оказаться
    мёртвым — тогда один раз переподключаемся. При первом заходе
    создаём таблицы.
    """
    import psycopg2
    for attempt in (0, 1):
        try:
            c = _pg["conn"]
            if c is None or c.closed:
                c = _pg["conn"] = psycopg2.connect(
                    PG_URL, connect_timeout=10, application_name="pamyatka-auth")
            with c:                            # commit, а при ошибке rollback
                with c.cursor() as cur:
                    cur.execute("SET LOCAL statement_timeout = 8000")
                    if not _pg["ready"]:
                        for sql in PG_SCHEMA:
                            cur.execute(sql)
                    res = fn(cur, *args)
            _pg["ready"] = True
            return res
        except (psycopg2.OperationalError, psycopg2.InterfaceError):
            old, _pg["conn"] = _pg["conn"], None
            try:
                old.close()
            except Exception:
                pass
            if attempt:
                raise


# где живут подписки и статистика: Postgres, а если его нет — Redis
SUBS = "postgres" if PG_URL else ("redis" if STORE else "")
STATS = SUBS
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


def _iid(install_id):
    """Номер установки → солёный хэш: одинаковый для одной установки,
    но обратно не восстановить."""
    return hashlib.sha256(("pamyatka-iid-v1:" + install_id).encode()).hexdigest()[:24]


def _pg_account(cur, uid, d, web=0, dl=0):
    cur.execute("INSERT INTO pm_acc (uid, first, last, web, dl) "
                "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (uid) DO UPDATE SET "
                "last = %s, web = CASE WHEN pm_acc.web > %s THEN pm_acc.web ELSE %s END, "
                "dl = CASE WHEN pm_acc.dl > %s THEN pm_acc.dl ELSE %s END",
                (uid, d, d, web, dl, d, web, web, dl, dl))
    cur.execute("INSERT INTO pm_accday (day, uid) VALUES (%s, %s) "
                "ON CONFLICT (day, uid) DO NOTHING", (d, uid))


def _pg_count(cur, d, name, n=1):
    cur.execute("INSERT INTO pm_count (day, name, n) VALUES (%s, %s, %s) "
                "ON CONFLICT (day, name) DO UPDATE SET n = pm_count.n + %s",
                (d, name, n, n))


def note_account(uid, web=False, dl=False):
    """Аккаунт вошёл / скачал — в статистику. Ошибки глотаем: счётчик
    не должен мешать ни входу, ни скачиванию."""
    try:
        d = day()
        if STATS == "postgres":
            def f(cur):
                _pg_account(cur, uid, d, int(web), int(dl))
                if dl:
                    _pg_count(cur, d, "dl")
            return pg(f)
        cmds = [["PFADD", "acc:all", uid]]
        if web:
            cmds.append(["PFADD", "web:all", uid])
        if dl:
            cmds += [["PFADD", "dl:all", uid], ["INCR", "dl:d:" + d],
                     ["EXPIRE", "dl:d:" + d, KEEP]]
        redis(*cmds)
    except Exception as e:
        print("статистика:", type(e).__name__, e)


def record_ping(install_id, ver, uid=None):
    d = day()
    if STATS == "postgres":
        h = _iid(install_id)

        def f(cur):
            cur.execute("INSERT INTO pm_seen (day, iid, opens) VALUES (%s, %s, 1) "
                        "ON CONFLICT (day, iid) DO UPDATE SET opens = pm_seen.opens + 1",
                        (d, h))
            cur.execute("INSERT INTO pm_inst (iid, ver, first, last) "
                        "VALUES (%s, %s, %s, %s) ON CONFLICT (iid) DO UPDATE SET "
                        "ver = %s, last = %s", (h, ver, d, d, ver, d))
            if uid:
                _pg_account(cur, uid, d)
            return True
        return pg(f)
    cmds = [["PFADD", "u:d:" + d, install_id], ["EXPIRE", "u:d:" + d, KEEP],
            ["PFADD", "u:all", install_id],
            ["INCR", "open:d:" + d], ["EXPIRE", "open:d:" + d, KEEP],
            ["PFADD", "u:v:" + ver, install_id], ["SADD", "versions", ver]]
    if uid:
        cmds += [["PFADD", "acc:d:" + d, uid], ["EXPIRE", "acc:d:" + d, KEEP],
                 ["PFADD", "acc:all", uid]]
    return redis(*cmds)


def report_pg():
    days = [day(i) for i in range(30)]
    d0, d6, d29 = days[0], days[6], days[29]

    def f(cur):
        cur.execute("SELECT day, COUNT(*), SUM(opens) FROM pm_seen "
                    "WHERE day >= %s GROUP BY day", (d29,))
        per = {d: (int(u), int(o or 0)) for d, u, o in cur.fetchall()}
        cur.execute("SELECT day, n FROM pm_count WHERE name = 'q' AND day >= %s", (d29,))
        qs = {d: int(n) for d, n in cur.fetchall()}
        cur.execute("SELECT COUNT(DISTINCT iid) FROM pm_seen WHERE day >= %s", (d6,))
        week = int(cur.fetchone()[0])
        cur.execute("SELECT COUNT(DISTINCT iid) FROM pm_seen WHERE day >= %s", (d29,))
        month_ = int(cur.fetchone()[0])
        cur.execute("SELECT COUNT(*) FROM pm_inst")
        total = int(cur.fetchone()[0])
        cur.execute("SELECT COUNT(*), COALESCE(SUM(web), 0), COALESCE(SUM(dl), 0) FROM pm_acc")
        acc_all, web_all, dl_all = (int(x) for x in cur.fetchone())
        cur.execute("SELECT COUNT(*) FROM pm_accday WHERE day = %s", (d0,))
        acc_today = int(cur.fetchone()[0])
        # версия — та, с которой установка заходила последней
        cur.execute("SELECT ver, COUNT(*) FROM pm_inst GROUP BY ver")
        vers = [{"ver": v, "users": int(n)} for v, n in cur.fetchall()]
        cur.execute("SELECT name, n FROM pm_count WHERE day = %s", (d0,))
        cnt = {k: int(n) for k, n in cur.fetchall()}
        # больше года не храним
        cur.execute("DELETE FROM pm_seen WHERE day < %s", (day(400),))
        cur.execute("DELETE FROM pm_accday WHERE day < %s", (day(400),))
        return per, qs, week, month_, total, acc_all, web_all, dl_all, acc_today, vers, cnt
    per, qs, week, month_, total, acc_all, web_all, dl_all, acc_today, vers, cnt = pg(f)
    return {
        "days": [{"day": d, "users": per.get(d, (0, 0))[0],
                  "opens": per.get(d, (0, 0))[1], "questions": qs.get(d, 0)}
                 for d in days],
        "today": per.get(d0, (0, 0))[0], "week": week, "month": month_,
        "total": total, "accounts": acc_all, "accounts_today": acc_today,
        "versions": sorted(vers, key=lambda x: -x["users"]),
        "questions_today_by_net": {k[2:]: v for k, v in cnt.items()
                                   if k.startswith("q:")},
        **subs_report(),
        "downloaders": dl_all, "downloads_today": cnt.get("dl", 0),
        "site_logins": web_all,
        "storage": "postgres",
    }


def report():
    if STATS == "postgres":
        return report_pg()
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
        **downloads_report(),
    }


def downloads_report():
    d = day()
    r = redis(["PFCOUNT", "dl:all"], ["GET", "dl:d:" + d],
              ["PFCOUNT", "web:all"])
    return {"downloaders": int(r[0] or 0), "downloads_today": int(r[1] or 0),
            "site_logins": int(r[2] or 0)}


# ------------------------------------------------------------- подписка ---
PRICE = int(os.environ.get("PAMYATKA_PRICE", "50") or 50)
DAYS = int(os.environ.get("PAMYATKA_SUB_DAYS", "30") or 30)
# Нейросети — только по подписке. Выключить: PAMYATKA_PAYWALL=0.
PAYWALL = os.environ.get("PAMYATKA_PAYWALL", "1").strip().lower() not in (
    "0", "off", "no", "false")
FOREVER = 4102444800                   # 2100 год: для списка PAMYATKA_VIP_IDS
UID_RE = re.compile(r"^[0-9]{5,25}$")
TX_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                   r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
ORDER_RE = re.compile(r"^[0-9a-f]{24}$")


def _pg_until(cur, uid):
    cur.execute("SELECT until FROM pm_subs WHERE uid = %s", (uid,))
    row = cur.fetchone()
    return int(row[0]) if row else 0


def _pg_extend(cur, uid, days):
    """Продлить в той же транзакции: к сроку, если ещё идёт, иначе от сейчас."""
    now = int(time.time())
    if days <= 0:
        cur.execute("DELETE FROM pm_subs WHERE uid = %s", (uid,))
        return 0
    add = days * 86400
    cur.execute(
        "INSERT INTO pm_subs (uid, until, updated) VALUES (%s, %s, %s) "
        "ON CONFLICT (uid) DO UPDATE SET until = CASE WHEN pm_subs.until > %s "
        "THEN pm_subs.until ELSE %s END + %s, updated = %s RETURNING until",
        (uid, now + add, now, now, now, add, now))
    return int(cur.fetchone()[0])


def sub_until(uid):
    """До какого момента у человека подписка (0 — нет)."""
    if not uid:
        return 0
    if uid in VIP:
        return FOREVER
    try:
        if SUBS == "postgres":
            return pg(_pg_until, uid)
        r = redis(["GET", "sub:" + uid])
        return int((r or [0])[0] or 0)
    except Exception:
        return 0


def extend_sub(uid, days):
    """Продлить подписку (выдача автором). days <= 0 — снять."""
    if SUBS == "postgres":
        return pg(_pg_extend, uid, days)
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


def subs_rows():
    """Все подписки: [{uid, until}] — для автора."""
    if SUBS == "postgres":
        def q(cur):
            cur.execute("SELECT uid, until FROM pm_subs")
            return [{"uid": u, "until": int(t)} for u, t in cur.fetchall()]
        return pg(q)
    uids = (redis(["SMEMBERS", "subs"]) or [[]])[0] or []
    untils = redis(*[["GET", "sub:" + u] for u in uids]) if uids else []
    return [{"uid": u, "until": int(t or 0)} for u, t in zip(uids, untils or [])]


def subs_report():
    now = time.time()
    try:
        active = sum(1 for r in subs_rows() if r["until"] > now)
    except Exception:
        active = 0
    out = {"subs_active": active + len(VIP), "revenue_month": 0.0,
           "payments_month": 0, "recent_payments": []}
    if SUBS != "postgres":
        return out
    # начало месяца по Москве
    import calendar
    t = time.gmtime(now + MSK)
    start = calendar.timegm((t.tm_year, t.tm_mon, 1, 0, 0, 0)) - MSK

    def q(cur):
        cur.execute("SELECT COALESCE(SUM(rub), 0), COUNT(*) FROM pm_payments "
                    "WHERE status = 'CONFIRMED' AND at >= %s", (start,))
        rev, n = cur.fetchone()
        cur.execute("SELECT uid, rub, at, until, status FROM pm_payments "
                    "ORDER BY at DESC LIMIT 10")
        log = [{"uid": u, "rub": float(r), "at": int(a), "until": int(un or 0),
                "status": s} for u, r, a, un, s in cur.fetchall()]
        return float(rev), int(n), log
    try:
        out["revenue_month"], out["payments_month"], out["recent_payments"] = pg(q)
    except Exception:
        pass
    return out


# --------------------------------------------------------------- Platega ---
PLATEGA_ID = os.environ.get("PLATEGA_MERCHANT_ID", "").strip()
PLATEGA_SECRET = os.environ.get("PLATEGA_SECRET", "").strip()
PLATEGA_API = os.environ.get("PLATEGA_API_URL",
                             "https://app.platega.io").strip().rstrip("/")
# оплату принимаем, только когда есть и Platega, и где записать подписку
PAY_READY = bool(PLATEGA_ID and PLATEGA_SECRET and SUBS == "postgres")
ORDERS_PER_HOUR = 10                   # защита от накрутки заказов


def platega(method, path, body=None):
    """Запрос к API Platega. Ошибка HTTP — исключение с текстом ответа."""
    req = urllib.request.Request(
        PLATEGA_API + path, method=method,
        data=json.dumps(body, ensure_ascii=False).encode("utf-8") if body else None,
        headers={"X-MerchantId": PLATEGA_ID, "X-Secret": PLATEGA_SECRET,
                 "Content-Type": "application/json", "Accept": "application/json",
                 "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode("utf-8") or "{}")


def new_order(uid):
    """Заказ в базе + транзакция в Platega. Возвращает ссылку на оплату."""
    oid = secrets.token_hex(12)
    now = int(time.time())

    def add(cur):
        cur.execute("SELECT COUNT(*) FROM pm_orders WHERE uid = %s AND created > %s",
                    (uid, now - 3600))
        if int(cur.fetchone()[0]) >= ORDERS_PER_HOUR:
            return False
        cur.execute("INSERT INTO pm_orders (id, uid, rub, created) "
                    "VALUES (%s, %s, %s, %s)", (oid, uid, PRICE, now))
        return True
    if not pg(add):
        raise ValueError("слишком много попыток оплаты — подождите час")
    r = platega("POST", "/v2/transaction/process", {
        "paymentDetails": {"amount": PRICE, "currency": "RUB"},
        "description": "Памятка RMRP: подписка на нейросети, %d дней" % DAYS,
        "return": BASE + "/auth?step=paid&o=" + oid,
        "failedUrl": BASE + "/auth?step=payfail",
        "payload": "pm1:" + uid,
        "orderId": oid,
        "metadata": {"userId": uid, "userName": "discord:" + uid}})
    tx = str(r.get("transactionId") or r.get("id") or "")
    url = str(r.get("url") or r.get("redirect") or "")
    if not TX_RE.match(tx) or not url.startswith("https://"):
        raise ValueError("Platega ответила без ссылки на оплату")

    def link(cur):
        cur.execute("UPDATE pm_orders SET tx = %s WHERE id = %s", (tx, oid))
    pg(link)
    return url


def settle(tx):
    """Сверить транзакцию с Platega и, если оплачена, продлить подписку.

    Возвращает (итог, uid, срок). Безопасно вызывать сколько угодно раз:
    платёж засчитывается один раз.
    """
    if not TX_RE.match(tx or ""):
        return "bad-id", None, 0
    st = platega("GET", "/transaction/" + tx)
    status = str(st.get("status") or "").upper()
    det = st.get("paymentDetails") or {}
    try:
        amount = float(det.get("amount") or 0)
    except (TypeError, ValueError):
        amount = 0.0
    currency = str(det.get("currency") or "").upper()

    def order(cur):
        cur.execute("SELECT uid, rub FROM pm_orders WHERE tx = %s", (tx,))
        return cur.fetchone()
    row = pg(order)
    if row:
        uid, want = row[0], float(row[1])
    else:
        # заказа нет (например, база была пуста) — берём метку из платежа
        m = re.match(r"^pm1:([0-9]{5,25})$", str(st.get("payload") or ""))
        if not m:
            return "unknown-order", None, 0
        uid, want = m.group(1), float(PRICE)

    if status == "CHARGEBACKED":
        def back(cur):
            cur.execute("UPDATE pm_payments SET status = 'CHARGEBACKED' "
                        "WHERE tx = %s AND status = 'CONFIRMED' RETURNING uid", (tx,))
            if not cur.fetchone():
                return False
            cur.execute("UPDATE pm_subs SET until = until - %s, updated = %s "
                        "WHERE uid = %s", (DAYS * 86400, int(time.time()), uid))
            return True
        return ("chargeback" if pg(back) else "chargeback-noop"), uid, 0
    if status != "CONFIRMED":
        return status.lower() or "unknown", uid, 0
    if currency != "RUB" or amount + 0.01 < want:
        return "too-little", uid, 0

    res, until = pg(_pg_credit, tx, uid, amount)
    return res, uid, until


def _pg_credit(cur, tx, uid, amount):
    """Засчитать платёж один раз и продлить подписку — одной транзакцией."""
    cur.execute("INSERT INTO pm_payments (tx, uid, rub, status, at) "
                "VALUES (%s, %s, %s, 'CONFIRMED', %s) "
                "ON CONFLICT (tx) DO NOTHING RETURNING tx",
                (tx, uid, amount, int(time.time())))
    if not cur.fetchone():
        return "duplicate", _pg_until(cur, uid)
    until = _pg_extend(cur, uid, DAYS)
    cur.execute("UPDATE pm_payments SET until = %s WHERE tx = %s", (until, tx))
    return "ok", until


# ---------------------------------------------------------------- ЮMoney ---
# Запасной способ, пока нет ключей Platega: перевод на кошелёк и
# HTTP-уведомление о зачислении, подписанное sha1 с секретом.
WALLET = os.environ.get("YOOMONEY_WALLET", "").strip()
YM_SECRET = os.environ.get("YOOMONEY_SECRET", "").strip()
YM_READY = bool(WALLET and YM_SECRET and SUBS == "postgres")
PROVIDER = "platega" if PAY_READY else ("yoomoney" if YM_READY else "")


def ym_valid(f):
    """Подпись уведомления ЮMoney: sha1 от полей через & с секретом."""
    raw = "&".join([f.get("notification_type", ""), f.get("operation_id", ""),
                    f.get("amount", ""), f.get("currency", ""),
                    f.get("datetime", ""), f.get("sender", ""),
                    f.get("codepro", ""), YM_SECRET, f.get("label", "")])
    good = hashlib.sha1(raw.encode("utf-8")).hexdigest()
    return hmac.compare_digest(good, (f.get("sha1_hash") or "").lower())


def handle_yoomoney(f):
    """Уведомление ЮMoney: проверяем подпись и сумму, продлеваем один раз."""
    if not YM_READY or not ym_valid(f):
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
    if not re.match(r"^[0-9A-Za-z_.-]{1,64}$", op):
        return "no-operation"
    res, _ = pg(_pg_credit, "ym:" + op, m.group(1), paid or got)
    return res


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


def _date(ts):
    return time.strftime("%d.%m.%Y", time.gmtime(ts + MSK))


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


def _cookie_token(headers):
    for part in (headers.get("Cookie") or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k == COOKIE:
            return v
    return ""


def _who(headers):
    """Кто пришёл: пропуск программы (Bearer) или куки сайта."""
    auth = headers.get("Authorization", "")
    tok = auth[7:] if auth.startswith("Bearer ") else _cookie_token(headers)
    return verify(tok), tok


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
        if CLOSED:
            # отметки старых версий и уведомления об оплате просто принимаем:
            # хранилища больше нет, а повторять запрос им незачем
            return self._send(200, {"ok": False, "closed": True})
        if step == "yoomoney":
            n = min(int(self.headers.get("Content-Length") or 0), 8192)
            form = {k: v[0] for k, v in urllib.parse.parse_qs(
                self.rfile.read(n).decode("utf-8", "replace"),
                keep_blank_values=True).items()}
            try:
                res = handle_yoomoney(form)
            except Exception as e:
                print("ЮMoney: ошибка", type(e).__name__, e)
                # не 200 — ЮMoney пришлёт уведомление ещё раз
                return self._send(500, {"error": type(e).__name__})
            print("ЮMoney:", res, form.get("operation_id"), form.get("label"))
            # на отказ — тоже 200: иначе ЮMoney будет слать повторы без конца
            return self._send(200, {"result": res})
        if step == "platega":
            # Platega подписывает уведомление нашими же MerchantId и ключом
            mid = self.headers.get("X-MerchantId", "")
            sec = self.headers.get("X-Secret", "")
            if not (PAY_READY and hmac.compare_digest(mid, PLATEGA_ID)
                    and hmac.compare_digest(sec, PLATEGA_SECRET)):
                return self._send(403, {"error": "не Platega"})
            try:
                n = min(int(self.headers.get("Content-Length") or 0), 8192)
                body = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
                tx = str(body.get("id") or "")
            except Exception:
                return self._send(400, {"error": "не JSON"})
            try:
                res, uid, _ = settle(tx)     # статус и сумму — у Platega
            except Exception as e:
                print("Platega: ошибка", tx, type(e).__name__, e)
                # не 200 — пусть Platega повторит уведомление позже
                return self._send(500, {"error": type(e).__name__})
            print("Platega:", res, tx, uid)
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
            if not SUBS:
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

        if CLOSED:
            if step == "status":
                return self._send(200, {"configured": False, "stats": False,
                                        "pay": False, "price": 0, "days": 0,
                                        "paywall": False, "closed": True})
            if step == "me":
                return self._send(410, {"error": CLOSED_TEXT, "closed": True})
            if step == "logout":
                return self._send(302, b"", "text/plain", {
                    "Location": BASE + "/",
                    "Set-Cookie": COOKIE + "=; Path=/; Max-Age=0; HttpOnly; "
                                           "Secure; SameSite=Lax"})
            if step not in ("stats", "subs", "sub"):
                return self._html(410, CLOSED_TITLE, CLOSED_TEXT)

        if step == "status":
            out = {"configured": ready, "stats": bool(STATS),
                   "pay": bool(PROVIDER), "price": PRICE, "days": DAYS,
                   "paywall": PAYWALL, "subs": SUBS or False,
                   "provider": PROVIDER or False}
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
            if not STATS:
                seen = storage_names()
                why = ("Хранилище не подключено: Vercel → Storage → Neon "
                       "(Postgres), затем Redeploy." if not seen else
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
            data, _ = _who(self.headers)
            if not data:
                return self._send(401, {"error": "пропуск недействителен"})
            # план пересчитываем при каждой проверке: оплатил — подписка
            # появилась без нового входа, кончилась — пропала
            until = sub_until(data.get("uid"))
            data["sub_until"] = until
            data["plan"] = "vip" if until > time.time() else "free"
            data["price"], data["paywall"] = PRICE, PAYWALL
            return self._send(200, data)

        if step in ("subs", "sub"):
            who, _ = _who(self.headers)
            if not who or who.get("uid") not in ADMINS:
                return self._send(403, {"error": "только для автора"})
            if not SUBS:
                return self._send(503, {"error": "хранилище не подключено"})
            if step == "sub":
                uid = g("uid")
                if not re.match(r"^[0-9]{5,25}$", uid):
                    return self._send(400, {"error": "нужен Discord ID"})
                return self._send(200, {"uid": uid, "until": sub_until(uid),
                                        "vip": uid in VIP})
            rows = subs_rows()
            now = time.time()
            return self._send(200, {
                "active": sorted([r for r in rows if r["until"] > now],
                                 key=lambda r: r["until"]),
                "expired": len([r for r in rows if 0 < r["until"] <= now]),
                "vip": sorted(VIP)})

        if step == "download":
            who, _ = _who(self.headers)
            if not who:
                # не вошёл — сначала вход, потом сразу обратно к скачиванию
                return self._go(BASE + "/auth?step=start&web=1&next=download")
            note_account(who["uid"], dl=True)   # ошибки внутри глотаются
            return self._go(DOWNLOAD_URL)

        if step == "logout":
            return self._send(302, b"", "text/plain", {
                "Location": BASE + "/",
                "Set-Cookie": COOKIE + "=; Path=/; Max-Age=0; HttpOnly; "
                                       "Secure; SameSite=Lax"})

        if step == "pay":
            uid = g("uid")
            if not UID_RE.match(uid):
                return self._html(400, "Не тот адрес",
                                  "Откройте оплату из программы.")
            if YM_READY and not PAY_READY:       # ключей Platega пока нет
                page = PAY_PAGE
                for k, v in (("{days}", DAYS), ("{price}", PRICE),
                             ("{wallet}", WALLET), ("{label}", "pm1:" + uid),
                             ("{back}", BASE + "/auth?step=paid"), ("{uid}", uid)):
                    page = page.replace(k, str(v))
                return self._send(200, page, "text/html; charset=utf-8")
            if not PAY_READY:
                return self._html(503, "Оплата ещё не подключена",
                                  "Автор пока не подключил приём оплаты.")
            try:
                return self._go(new_order(uid))
            except ValueError as e:
                return self._html(429, "Не получилось", str(e))
            except Exception as e:
                print("Platega: не создал платёж", type(e).__name__, e)
                return self._html(502, "Оплата временно недоступна",
                                  "Платёжный сервис не ответил. Попробуйте "
                                  "через пару минут.")

        if step == "paid":
            oid = g("o")
            res, until = "", 0
            if ORDER_RE.match(oid) and PAY_READY:
                try:
                    def tx_of(cur):
                        cur.execute("SELECT tx FROM pm_orders WHERE id = %s", (oid,))
                        r = cur.fetchone()
                        return r[0] if r else None
                    tx = pg(tx_of)
                    if tx:
                        res, _, until = settle(tx)
                except Exception as e:
                    print("Platega: проверка после оплаты", type(e).__name__, e)
            if res in ("ok", "duplicate") and until:
                return self._html(200, "Подписка включена",
                                  "Нейросети доступны до %s. Вернитесь в "
                                  "Памятку — вкладку можно закрыть." % _date(until))
            return self._html(200, "Спасибо за оплату",
                              "Как только платёж подтвердится, подписка "
                              "включится сама — обычно за минуту. Вернитесь "
                              "в Памятку, вкладку можно закрыть.")

        if step == "payfail":
            return self._html(200, "Оплата не прошла",
                              "Деньги не списаны. Можно попробовать ещё раз "
                              "из Памятки.")

        if not ready:
            return self._html(503, "Вход ещё не настроен",
                              "Автор программы пока не подключил вход "
                              "через Discord. Закройте вкладку.")

        if step == "start" and g("web") == "1":
            nxt = g("next") if g("next") in ("download", "home") else "home"
            state = sign({"web": 1, "next": nxt,
                          "exp": int(time.time()) + STATE_TTL})
            return self._go("https://discord.com/oauth2/authorize?" +
                            urllib.parse.urlencode({
                                "client_id": CLIENT_ID,
                                "response_type": "code",
                                "redirect_uri": REDIRECT,
                                "scope": "identify",
                                "prompt": "none",
                                "state": state}))

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
        if st and st.get("web") == 1:
            if g("error") or not g("code"):
                return self._go(BASE + "/?login=cancel")
            try:
                prof = profile_from_code(g("code"))
            except Exception:
                return self._go(BASE + "/?login=fail")
            note_account(prof["uid"], web=True)
            to = (BASE + "/auth?step=download" if st.get("next") == "download"
                  else BASE + "/?login=ok")
            return self._send(302, b"", "text/plain", {
                "Location": to,
                "Set-Cookie": "%s=%s; Path=/; Max-Age=%d; HttpOnly; Secure; "
                              "SameSite=Lax" % (COOKIE, sign(prof), TTL)})
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
        note_account(prof["uid"])      # статистика не мешает входу
        return self._go(_loopback(port, nonce=nonce, token=sign(prof)))
