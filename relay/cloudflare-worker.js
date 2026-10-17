// Ретранслятор Памятки на Cloudflare Workers.
// Когда провайдер режет Vercel, программа идёт сюда, а отсюда — на Vercel.
// Пересылает только запросы Памятки (/auth, /ask): это не открытый прокси.
const ORIGIN = "https://pamyatka-proxy.vercel.app";
const PATHS = new Set(["/auth", "/ask"]);
const PASS = ["authorization", "content-type", "user-agent", "accept"];

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (!PATHS.has(url.pathname)) {
      return new Response("Памятка: ретранслятор работает", {
        status: url.pathname === "/" ? 200 : 404,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }
    const headers = new Headers();
    for (const h of PASS) {
      const v = request.headers.get(h);
      if (v) headers.set(h, v);
    }
    const init = { method: request.method, headers, redirect: "manual" };
    if (request.method !== "GET" && request.method !== "HEAD") {
      init.body = await request.arrayBuffer();
    }
    const r = await fetch(ORIGIN + url.pathname + url.search, init);
    return new Response(r.body, { status: r.status, headers: r.headers });
  },
};
