// Ретранслятор Памятки на Yandex Cloud Functions (Node.js 18+). Точка входа: index.handler
// Путь приходит в ?path=/auth. Из РФ-дата-центра Vercel не открывается,
// поэтому идём через Cloudflare-ретранслятор. Пропуск — в X-Pm-Auth:
// заголовок Authorization Яндекс считает своим ключом и отвечает 403.
const ORIGIN = "https://pamyatka-relay.bdfsgegge.workers.dev";
const PATHS = ["/auth", "/ask"];
const PASS = ["content-type", "user-agent", "accept"];

module.exports.handler = async function (event) {
const q = Object.assign({}, event.queryStringParameters || {});
const path = q.path || "";
delete q.path;
if (!PATHS.includes(path)) {
return { statusCode: path ? 404 : 200, headers: { "Content-Type": "text/plain; charset=utf-8" }, body: "Памятка: ретранслятор работает" };
}
const qs = new URLSearchParams(q).toString();
const url = ORIGIN + path + (qs ? "?" + qs : "");
const method = event.httpMethod || "GET";
const headers = {};
for (const [k, v] of Object.entries(event.headers || {})) {
const key = k.toLowerCase();
if (PASS.includes(key)) headers[key] = v;
if (key === "x-pm-auth") headers["authorization"] = v;
}
const init = { method, headers, redirect: "manual" };
if (method !== "GET" && method !== "HEAD" && event.body) {
init.body = event.isBase64Encoded ? Buffer.from(event.body, "base64") : event.body;
}
try {
const r = await fetch(url, init);
const data = Buffer.from(await r.arrayBuffer());
return { statusCode: r.status, headers: { "Content-Type": r.headers.get("content-type") || "application/json" }, body: data.toString("base64"), isBase64Encoded: true };
} catch (e) {
return { statusCode: 502, headers: { "Content-Type": "application/json" }, body: JSON.stringify({ error: "relay: " + String(e && e.cause || e) }) };
}
};
