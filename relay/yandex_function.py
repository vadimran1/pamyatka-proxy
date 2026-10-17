# -*- coding: utf-8 -*-
"""Ретранслятор Памятки на Yandex Cloud Functions (Python 3.12).

Когда провайдер режет Vercel, программа идёт сюда, а отсюда — на Vercel.
Путь приходит в параметре ?path=/auth (у прямого вызова функции свой адрес).
Пересылает только запросы Памятки (/auth, /ask): это не открытый прокси.
Точка входа: index.handler
"""
import base64
import urllib.error
import urllib.parse
import urllib.request

ORIGIN = "https://pamyatka-proxy.vercel.app"
PATHS = {"/auth", "/ask"}
PASS = {"authorization", "content-type", "user-agent", "accept"}


def handler(event, context):
    q = dict(event.get("queryStringParameters") or {})
    path = q.pop("path", "")
    if path not in PATHS:
        return {"statusCode": 200 if not path else 404,
                "headers": {"Content-Type": "text/plain; charset=utf-8"},
                "body": "Памятка: ретранслятор работает"}
    url = ORIGIN + path + ("?" + urllib.parse.urlencode(q) if q else "")
    method = event.get("httpMethod") or "GET"
    body = None
    if method not in ("GET", "HEAD"):
        raw = event.get("body") or ""
        body = base64.b64decode(raw) if event.get("isBase64Encoded") else raw.encode("utf-8")
    hdr = {k: v for k, v in (event.get("headers") or {}).items() if k.lower() in PASS}
    req = urllib.request.Request(url, data=body, headers=hdr, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=55)
        status, data, ctype = r.status, r.read(), r.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:
        status, data, ctype = e.code, e.read(), e.headers.get("Content-Type", "")
    return {"statusCode": status,
            "headers": {"Content-Type": ctype or "application/json"},
            "body": base64.b64encode(data).decode("ascii"),
            "isBase64Encoded": True}
