# -*- coding: utf-8 -*-
"""Прокладка Памятки RMRP для Vercel.

Файл собран скриптом make_vercel.py — правьте не здесь, а промт в
ai.py, потом пересоберите.

Ключ лежит в переменных окружения Vercel, в программе его нет.
"""
import os, json, time, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler

KEY = os.environ.get("PAMYATKA_KEY", "").strip()
PROVIDER = os.environ.get("PAMYATKA_PROVIDER", "gemini").strip()
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
    hdr = {"Content-Type": "application/json"}
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


def ask_model(question, context, catalog):
    model = MODEL or DEFAULTS.get(PROVIDER, "")
    prompt = _prompt(question, context, catalog)
    if PROVIDER == "deepseek":
        data = _post("https://api.deepseek.com/chat/completions",
                     {"model": model,
                      "messages": [{"role": "system", "content": SYSTEM},
                                   {"role": "user", "content": prompt}],
                      "temperature": 0.2, "max_tokens": 700,
                      "stream": False},
                     {"Authorization": "Bearer " + KEY})
        ch = (data.get("choices") or [{}])[0]
        return ((ch.get("message") or {}).get("content") or "").strip()
    data = _post(
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "%s:generateContent" % model,
        {"systemInstruction": {"parts": [{"text": SYSTEM}]},
         "contents": [{"role": "user", "parts": [{"text": prompt}]}],
         "generationConfig": {"temperature": 0.2, "maxOutputTokens": 700}},
        {"x-goog-api-key": KEY})
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

    def do_GET(self):
        self._send(200, {"ok": True, "provider": PROVIDER,
                         "key": bool(KEY)})

    def do_POST(self):
        if not KEY:
            return self._send(500, {"error": "на сервере не задан ключ "
                                             "(переменная PAMYATKA_KEY)"})
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

        try:
            answer = ask_model(question, payload.get("context") or "",
                               payload.get("catalog") or "")
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read().decode("utf-8"))
                msg = (msg.get("error") or {})
                msg = msg.get("message") if isinstance(msg, dict) else ""
            except Exception:
                msg = ""
            code = {401: "ключ не принят", 402: "кончились деньги на счёте",
                    429: "лимит запросов исчерпан"}.get(e.code)
            return self._send(502, {"error": code or
                                    ("ошибка %s: %s" % (e.code, msg[:120]))})
        except Exception as e:
            return self._send(502, {"error": "не дозвонился до модели: %s"
                                             % e})
        if not answer:
            return self._send(502, {"error": "модель вернула пустой ответ"})
        self._send(200, {"answer": answer, "provider": PROVIDER})
