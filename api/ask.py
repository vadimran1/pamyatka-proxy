# -*- coding: utf-8 -*-
"""Прокладка Памятки RMRP для Vercel.

Файл собран скриптом make_vercel.py — правьте не здесь, а промт в
ai.py, потом пересоберите.

Ключ лежит в переменных окружения Vercel, в программе его нет.
"""
import os, re, json, time, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler

KNOWN = ("gemini", "deepseek", "odirouter", "orcarouter")

# В переменную легко вписать не то. Неизвестное значение молча
# заменяем на gemini и НЕ показываем наружу: если туда случайно
# попал ключ, он не должен утечь через открытую проверку /ask.
_raw = os.environ.get("PAMYATKA_PROVIDER", "").strip().lower()
PROVIDER = _raw if _raw in KNOWN else "gemini"
PROVIDER_OK = (not _raw) or (_raw in KNOWN)

# Ключи можно держать оба сразу — берётся тот, что подходит выбранной
# сети. Так переключение это одна строчка PAMYATKA_PROVIDER, а не
# перевставка ключа (и не ошибка «ключ от другой сети»).
# Несколько допустимых имён: если переменную не дают пересоздать,
# просто добавьте ключ под другим именем из этого списка.
KEY_NAMES = {
    "gemini": ("PAMYATKA_KEY_GEMINI", "PAMYATKA_GEMINI_KEY",
               "PAMYATKA_GM", "GEMINI_API_KEY", "PAMYATKA_KEY"),
    "deepseek": ("PAMYATKA_KEY_DEEPSEEK", "PAMYATKA_DEEPSEEK_KEY",
                 "PAMYATKA_DS", "DEEPSEEK_API_KEY", "PAMYATKA_KEY"),
    "odirouter": ("PAMYATKA_KEY_ODIROUTER", "PAMYATKA_ODIROUTER_KEY",
                  "PAMYATKA_OR", "ODIROUTER_API_KEY", "PAMYATKA_KEY"),
    "orcarouter": ("PAMYATKA_KEY_ORCAROUTER", "PAMYATKA_ORCAROUTER_KEY",
                   "PAMYATKA_ORCA", "ORCAROUTER_API_KEY", "PAMYATKA_KEY"),
}

ORCA_BASE = os.environ.get("PAMYATKA_ORCA_BASE",
                           "https://api.orcarouter.ai").rstrip("/")

ODIROUTER_BASE = os.environ.get("PAMYATKA_ODIROUTER_BASE",
                                "https://api.odirouter.ai").rstrip("/")


def key_for(provider):
    """Первое непустое из допустимых имён. Позже в списке — запасные."""
    for name in KEY_NAMES.get(provider, ()):
        v = os.environ.get(name, "").strip()
        if v:
            return v
    return ""


def key_source(provider):
    """Из какой переменной взят ключ — для проверки /ask."""
    for name in KEY_NAMES.get(provider, ()):
        if os.environ.get(name, "").strip():
            return name
    return ""


def _ver(model_id):
    """Номер версии из имени вида gemini-2.5-flash."""
    m = re.search(r"([0-9]+)(?:[.]([0-9]+))?", model_id)
    if not m:
        return (0, 0)
    return (int(m.group(1)), int(m.group(2) or 0))


def _rank_gemini(model_id):
    """Чем выше, тем лучше для бесплатного тарифа."""
    i = model_id.lower()
    if "embedding" in i or "aqa" in i or "image" in i or "tts" in i:
        return None                      # не для текстовых ответов
    if "flash" in i and "lite" not in i:
        base = 3                         # быстрые и бесплатные
    elif "flash" in i:
        base = 2                         # lite — слабее
    elif "pro" in i:
        base = 1                         # обычно вне бесплатного тарифа
    else:
        return None
    if "preview" in i or "exp" in i:
        base -= 0.5                      # нестабильные
    return (base,) + _ver(i)


_models_cache = {}


def models_for(provider, key):
    """Список моделей по убыванию предпочтения."""
    if provider in _models_cache:
        return _models_cache[provider]
    out = []
    try:
        if provider == "orcarouter":
            req = urllib.request.Request(
                ORCA_BASE + "/v1/models",
                headers={"Authorization": "Bearer " + key} if key else {})
            with urllib.request.urlopen(req, timeout=20) as r:
                ids = [m.get("id", "") for m in
                       json.loads(r.read().decode()).get("data", [])
                       if isinstance(m.get("id"), str)]
            free = [i for i in ids if "free" in i.lower()]
            # собственная бесплатная модель сервиса — первой
            free.sort(key=lambda i: (not i.startswith("orcarouter/"), i))
            out = free or ids
        elif provider == "odirouter":
            req = urllib.request.Request(
                ODIROUTER_BASE + "/v1/models",
                headers={"Authorization": "Bearer " + key})
            with urllib.request.urlopen(req, timeout=20) as r:
                ids = [m.get("id", "") for m in
                       json.loads(r.read().decode()).get("data", [])]
            # сперва то, что просили, потом всё остальное
            pref = [i for i in ids if "grok" in i.lower()]
            out = pref + [i for i in ids if i not in pref]
        elif provider == "deepseek":
            req = urllib.request.Request(
                "https://api.deepseek.com/models",
                headers={"Authorization": "Bearer " + key})
            with urllib.request.urlopen(req, timeout=20) as r:
                ids = [m.get("id", "") for m in
                       json.loads(r.read().decode()).get("data", [])]
            # обычный чат быстрее и дешевле рассуждающего
            out = ([i for i in ids if i == "deepseek-chat"] +
                   [i for i in ids if i != "deepseek-chat"])
        else:
            req = urllib.request.Request(
                "https://generativelanguage.googleapis.com/v1beta/models",
                headers={"x-goog-api-key": key})
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read().decode())
            scored = []
            for m in data.get("models", []):
                if "generateContent" not in m.get(
                        "supportedGenerationMethods", []):
                    continue
                mid = m.get("name", "").replace("models/", "")
                rank = _rank_gemini(mid)
                if rank:
                    scored.append((rank, mid))
            scored.sort(reverse=True)
            out = [mid for _, mid in scored]
    except Exception:
        out = []
    if not out:
        out = FALLBACK.get(provider, [])
    _models_cache[provider] = out[:4]
    return _models_cache[provider]


FALLBACK = {"gemini": ["gemini-2.5-flash", "gemini-2.0-flash",
                       "gemini-flash-latest"],
            "deepseek": ["deepseek-chat"],
            "odirouter": ["grok-4.5"],
            "orcarouter": ["orcarouter/free",
                           "deepseek/deepseek-v4-flash-free",
                           "z-ai/glm-5.3-flash-free"]}


KEY = key_for(PROVIDER)
MODEL = os.environ.get("PAMYATKA_MODEL", "").strip()
SECRET = os.environ.get("PAMYATKA_SECRET", "").strip()
RATE_N = int(os.environ.get("PAMYATKA_RATE", "20") or 20)
RATE_WINDOW = 600
TIMEOUT = 60
MAX_BODY = 2 * 1024 * 1024

DEFAULTS = {"gemini": "gemini-3.5-flash", "deepseek": "deepseek-chat"}

SYSTEM = """Ты — помощник сотрудника по законодательству игрового проекта RMRP (ролевой сервер по мотивам России). Отвечаешь коротко и по делу.

ГЛАВНОЕ ПРАВИЛО
Это выдуманное игровое законодательство, оно НЕ совпадает с настоящим
российским правом. Всё, что ты знаешь о реальных законах РФ, здесь
неприменимо — не подставляй реальные статьи, сроки и суммы.

ЧТО ТЕБЕ ДАЮТ
1. КАТАЛОГ — полный список всех статей законки: акт, номер, название
   и наказание, если оно есть. Это исчерпывающий перечень: других
   статей не существует.
2. ВЫДЕРЖКИ — подробные тексты статей, которые поиск счёл близкими к
   вопросу. Поиск часто промахивается.

КАК ИСКАТЬ ОТВЕТ
Сначала посмотри ВЫДЕРЖКИ. Если там нет подходящей статьи — ищи по
КАТАЛОГУ по названию: вопрос про угон ищи среди статей со словом
«завладение» и «угон», про драку — «побои», «причинение вреда».
Не хватайся за первую статью из выдержек, если она явно не про то.
Общие статьи вроде «Уголовное законодательство состоит из настоящего
Кодекса» или «Основные понятия» почти никогда не являются ответом —
человек спрашивает про конкретное деяние.

ЧЕГО НЕЛЬЗЯ ДЕЛАТЬ
- придумывать номера статей, сроки, размеры штрафов и наказаний
- брать цифры «по памяти» — только из КАТАЛОГА или ВЫДЕРЖЕК
- ссылаться на статью, которой нет в КАТАЛОГЕ
Если подходящей статьи нет нигде — прямо скажи: «В загруженной законке
такого нет», и предложи, как переформулировать.

Если статья нашлась в КАТАЛОГЕ, но её подробного текста нет в
ВЫДЕРЖКАХ — отвечай по строке каталога: название и наказание оттуда
достоверны. Не додумывай детали состава, которых не видишь.

КАК ОТВЕЧАТЬ
1. Первая строка — прямой ответ. Если спрашивают про наказание или
   срок, начни с него: «5 лет лишения свободы» или «штраф 20.000 ₽».
2. Дальше одно-два предложения, что именно образует состав.
3. В конце строка «Источник: УК ст. 47» — акт и номер ровно так, как
   они написаны в КАТАЛОГЕ. Если источников несколько, перечисли их.

СТИЛЬ
Живой русский язык, без канцелярита и без воды. Не пересказывай
вопрос. Не извиняйся. Не пиши вступлений вроде «конечно» и
«согласно предоставленной информации». Максимум 6 строк.
Не рассуждай вслух и не показывай ход мыслей — только готовый ответ.

Понимай разговорные формулировки: «ствол» — оружие, «тачка» —
транспортное средство, «бухой» — состояние опьянения, «обезьянник» —
камера предварительного заключения, «замочил» — убийство.

Если спрашивают про порядок действий (как задержать, что зачитать),
дай нумерованные шаги строго по выдержкам."""

# Ограничение живёт в памяти экземпляра. На serverless экземпляры
# приходят и уходят, поэтому это не жёсткий лимит, а смягчение всплесков.
_hits = {}


def _allowed(ip):
    now = time.time()
    q = [t for t in _hits.get(ip, []) if now - t < RATE_WINDOW]
    if len(q) >= RATE_N:
        _hits[ip] = q
        return False
    q.append(now)
    _hits[ip] = q
    if len(_hits) > 2000:
        _hits.clear()
    return True


def _post(url, payload, headers):
    data = json.dumps(payload).encode("utf-8")
    # без своего User-Agent уходит «Python-urllib», а его Cloudflare
    # у некоторых шлюзов режет молча: пустой 403 вместо ответа
    hdr = {"Content-Type": "application/json",
           "User-Agent": "PamyatkaProxy/1.0",
           "Accept": "application/json"}
    hdr.update(headers)
    req = urllib.request.Request(url, data=data, method="POST", headers=hdr)
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8"))


def _prompt(question, context, catalog):
    parts = []
    if catalog.strip():
        parts.append("КАТАЛОГ ВСЕХ СТАТЕЙ ЗАКОНКИ\n"
                     "(акт, номер, название, наказание)\n\n" + catalog)
    if context.strip():
        parts.append("ВЫДЕРЖКИ — подробные тексты похожих статей\n\n"
                     + context)
    parts.append("ВОПРОС: " + question)
    return "\n\n=====\n\n".join(parts)


def ask_model(question, context, catalog, provider=None, key=None,
              want_model=""):
    """Пробуем модели по очереди: перегружена одна — берём следующую."""
    provider = provider or PROVIDER
    key = key or key_for(provider)
    if want_model:
        models = [want_model]
    elif MODEL:
        models = [MODEL]
    else:
        models = models_for(provider, key)
    last = None
    for model in models or [DEFAULTS.get(provider, "")]:
        try:
            return _one(question, context, catalog, provider, key, model)
        except urllib.error.HTTPError as e:
            # занята или нет такой — пробуем следующую; остальное наверх
            if e.code in (404, 429, 500, 503):
                last = e
                continue
            raise
    if last:
        raise last
    raise RuntimeError("нет доступных моделей")


def _text_from_responses(data):
    """Ответ Responses API: пробуем все известные укладки."""
    t = data.get("output_text")
    if isinstance(t, str) and t.strip():
        return t
    if isinstance(t, list) and t:
        return "".join(x for x in t if isinstance(x, str))
    chunks = []
    for item in (data.get("output") or []):
        if not isinstance(item, dict):
            continue
        for c in (item.get("content") or []):
            if isinstance(c, dict):
                v = c.get("text") or c.get("output_text") or ""
                if isinstance(v, dict):
                    v = v.get("value", "")
                if v:
                    chunks.append(v)
    if chunks:
        return "".join(chunks)
    # на случай, если сервис отвечает в стиле chat/completions
    ch = (data.get("choices") or [{}])[0]
    return ((ch.get("message") or {}).get("content")
            or ch.get("text") or "")


def _one(question, context, catalog, provider, key, model):
    prompt = _prompt(question, context, catalog)
    if provider == "orcarouter":
        data = _post(ORCA_BASE + "/v1/chat/completions",
                     {"model": model,
                      "messages": [{"role": "system", "content": SYSTEM},
                                   {"role": "user", "content": prompt}],
                      "temperature": 0.2, "max_tokens": 700,
                      "stream": False},
                     {"Authorization": "Bearer " + key})
        return _text_from_responses(data).strip()
    if provider == "odirouter":
        # шлюз One API: работает в формате chat/completions,
        # эндпоинта /v1/responses у него нет
        data = _post(ODIROUTER_BASE + "/v1/chat/completions",
                     {"model": model,
                      "messages": [{"role": "system", "content": SYSTEM},
                                   {"role": "user", "content": prompt}],
                      "temperature": 0.2, "max_tokens": 700,
                      "stream": False},
                     {"Authorization": "Bearer " + key})
        return _text_from_responses(data).strip()
    if provider == "deepseek":
        data = _post("https://api.deepseek.com/chat/completions",
                     {"model": model,
                      "messages": [{"role": "system", "content": SYSTEM},
                                   {"role": "user", "content": prompt}],
                      "temperature": 0.2, "max_tokens": 700,
                      "stream": False},
                     {"Authorization": "Bearer " + key})
        ch = (data.get("choices") or [{}])[0]
        return ((ch.get("message") or {}).get("content") or "").strip()
    data = _post(
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "%s:generateContent" % model,
        {"systemInstruction": {"parts": [{"text": SYSTEM}]},
         "contents": [{"role": "user", "parts": [{"text": prompt}]}],
         "generationConfig": {"temperature": 0.2, "maxOutputTokens": 700}},
        {"x-goog-api-key": key})
    cands = data.get("candidates") or []
    if not cands:
        return ""
    parts = (cands[0].get("content") or {}).get("parts") or []
    return "".join(p.get("text", "") for p in parts).strip()


class handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    PROBE = {"orcarouter": ORCA_BASE + "/v1/models",
             "odirouter": ODIROUTER_BASE + "/v1/models",
             "deepseek": "https://api.deepseek.com/models",
             "gemini": "https://generativelanguage.googleapis.com"
                       "/v1beta/models"}

    def do_GET(self):
        # ?probe=сеть — дозванивается ли сервер до провайдера вообще.
        # Адреса фиксированы списком, ключи не участвуют.
        q = (self.path.split("?", 1) + [""])[1]
        want = ""
        for part in q.split("&"):
            if part.startswith("probe="):
                want = part[6:].strip().lower()
        if want:
            url = self.PROBE.get(want)
            if not url:
                return self._send(400, {"error": "неизвестная сеть"})
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "PamyatkaProxy"})
                with urllib.request.urlopen(req, timeout=25) as r:
                    return self._send(200, {
                        "probe": want, "http": r.status, "reachable": True,
                        "server": r.headers.get("server", ""),
                        "body": r.read(160).decode("utf-8", "replace")})
            except urllib.error.HTTPError as e:
                body = ""
                try:
                    body = e.read(200).decode("utf-8", "replace")
                except Exception:
                    pass
                # свой JSON с ошибкой = сервис ответил; пусто = заслон
                return self._send(200, {
                    "probe": want, "http": e.code,
                    "reachable": bool(body.strip()),
                    "server": e.headers.get("server", ""), "body": body})
            except Exception as e:
                return self._send(200, {"probe": want, "reachable": False,
                                        "error": str(e)[:150]})

        have = [n for n in KNOWN if key_for(n)]
        out = {"ok": True, "provider": PROVIDER, "key": bool(KEY),
               "keys": have,
               "key_from": {n: key_source(n) for n in KNOWN
                            if key_for(n)},
               "model": MODEL or (models_for(PROVIDER, KEY)[:1] or [""])[0],
               "models": models_for(PROVIDER, KEY) if KEY else []}
        if not PROVIDER_OK:
            out["warning"] = ("в PAMYATKA_PROVIDER не gemini и не "
                              "deepseek — значение проигнорировано")
        self._send(200, out)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            return self._send(413, {"error": "слишком большой запрос"})
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            return self._send(400, {"error": "не разобрал запрос"})

        if SECRET and (payload.get("secret") or "").strip() != SECRET:
            return self._send(403, {"error": "неверное слово доступа"})

        ip = (self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
              or self.client_address[0])
        if not _allowed(ip):
            return self._send(429, {"error": "слишком часто, подождите"})

        question = (payload.get("question") or "").strip()
        if not question:
            return self._send(400, {"error": "пустой вопрос"})

        # сеть выбирает пользователь в программе; чужое значение не берём
        want = (payload.get("provider") or "").strip().lower()
        provider = want if want in KNOWN else PROVIDER
        # программа может попросить конкретную модель у этой сети
        want_model = (payload.get("model") or "").strip()
        key = key_for(provider)
        if not key:
            return self._send(500, {
                "error": "на сервере нет ключа для сети %s — добавьте "
                         "PAMYATKA_KEY_%s" % (provider, provider.upper())})

        # порядок обхода: сначала выбранная сеть, затем запасные
        order = [provider] + [n for n in KNOWN
                              if n != provider and key_for(n)]
        answer, used, last = "", provider, None
        for n, prov in enumerate(order):
            try:
                answer = ask_model(question, payload.get("context") or "",
                                   payload.get("catalog") or "", prov,
                                   key_for(prov),
                                   want_model if prov == provider else "")
                used = prov
                last = None
                break
            except urllib.error.HTTPError as e:
                last = e
                # 503/429/500 — сеть занята, имеет смысл попробовать другую;
                # 401/402 — ключ или деньги, перебор ничего не даст
                if e.code not in (429, 500, 502, 503) or n == len(order) - 1:
                    break
            except Exception as e:
                last = e
                if n == len(order) - 1:
                    break
        if last is not None:
            raise last
        provider = used

        try:
            pass
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read().decode("utf-8"))
                msg = (msg.get("error") or {})
                msg = msg.get("message") if isinstance(msg, dict) else ""
            except Exception:
                msg = ""
            code = {401: "ключ не принят", 402: "кончились деньги на счёте",
                    429: "лимит запросов исчерпан"}.get(e.code)
            # текст от провайдера нужен, чтобы понять причину:
            # ключей в нём не бывает, только описание отказа
            # при блокировке тело пустое, зато заголовки выдают,
            # кто именно отказал — сервис или защита перед ним
            hdr = {}
            try:
                for h in ("server", "cf-ray", "cf-mitigated",
                          "content-type"):
                    v = e.headers.get(h)
                    if v:
                        hdr[h] = v[:60]
            except Exception:
                pass
            return self._send(502, {
                "error": code or ("ошибка %s" % e.code),
                "http": e.code, "provider": provider,
                "detail": (msg or "")[:300], "headers": hdr})
        except Exception as e:
            return self._send(502, {"error": "не дозвонился до модели: %s"
                                             % e})
        if not answer:
            return self._send(502, {"error": "модель вернула пустой ответ"})
        self._send(200, {"answer": answer, "provider": provider})
