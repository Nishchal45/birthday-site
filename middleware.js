// middleware.js — Vercel Routing Middleware for non-Next apps

export const config = {
    // protect everything except static assets & common files
    matcher: ["/((?!assets|favicon.ico|robots.txt).*)"],
  };
  
  // optional logging to a Google Apps Script endpoint set in env var LOG_ENDPOINT
  async function log(event, req, extra = {}) {
    const endpoint = process.env.LOG_ENDPOINT;
    if (!endpoint) return;
    const url = new URL(req.url);
    const ip =
      req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
      req.headers.get("x-real-ip") || "unknown";
    const ua = req.headers.get("user-agent") || "";
    const ref = req.headers.get("referer") || "";
    const payload = { event, ts: new Date().toISOString(), url: url.toString(), ref, ip, ua, ...extra };
    try {
      await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "text/plain" },
        body: JSON.stringify(payload),
      });
    } catch {}
  }
  
  export default async function middleware(req) {
    const url = new URL(req.url);
    const token = process.env.ACCESS_TOKEN || "";
    const qp = url.searchParams.get("t");
  
    // read the cookie
    const cookieHeader = req.headers.get("cookie") || "";
    const cookieVal =
      cookieHeader.split(";").map(s => s.trim()).find(s => s.startsWith("bday_auth="))?.split("=")[1] || "";
  
    await log("attempt", req, { token_ok: qp === token || cookieVal === token });
  
    // token via query → set cookie + redirect to clean URL
    if (qp && token && qp === token) {
      url.searchParams.delete("t");
      const res = new Response(null, { status: 302, headers: { Location: url.toString() } });
      res.headers.append(
        "Set-Cookie",
        `bday_auth=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${60 * 60 * 24 * 7}`
      );
      await log("granted", req, { token_ok: true, note: "via query token" });
      return res;
    }
  
    // valid cookie → allow
    if (cookieVal && token && cookieVal === token) {
      await log("visit", req, { token_ok: true });
      return; // continue
    }
  
    // denied → gate page
    await log("denied", req, { token_ok: false });
    const gate = `<!doctype html><html lang="en"><head><meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/><title>Private</title>
  <style>body{margin:0;display:grid;place-items:center;height:100vh;background:#0b0f1a;color:#f7f8ff;font-family:system-ui,Segoe UI,Roboto,Arial}
  .card{background:rgba(255,255,255,.06);border-radius:16px;padding:24px 20px;box-shadow:0 10px 30px rgba(0,0,0,.45);width:min(420px,92vw);text-align:center}
  h1{margin:0 0 8px;font-size:22px}p{margin:0 0 16px;color:#9aa3b2}.row{display:flex;gap:8px}
  input{flex:1;padding:12px;border-radius:10px;border:1px solid #2b3148;background:#101522;color:#f7f8ff;outline:none}
  button{padding:12px 16px;border-radius:10px;border:none;font-weight:700;cursor:pointer;background:linear-gradient(135deg,#ff7bd3,#ffd166);color:#0b0f1a}
  small{display:block;margin-top:12px;color:#9aa3b2}</style></head><body>
  <div class="card"><h1>Private link</h1><p>This page needs permission. Ask the owner for the access code.</p>
  <div class="row"><input id="code" type="password" placeholder="Enter code"/><button id="go">Open</button></div>
  <small>Tip: the link can also include <code>?t=CODE</code></small></div>
  <script>
  document.getElementById('go').addEventListener('click', ()=>{const v=document.getElementById('code').value.trim();if(!v)return;const u=new URL(location.href);u.searchParams.set('t',v);location.href=u.toString();});
  document.getElementById('code').addEventListener('keyup', (e)=>{ if(e.key==='Enter') document.getElementById('go').click(); });
  </script></body></html>`;
    return new Response(gate, { status: 401, headers: { "Content-Type": "text/html; charset=utf-8" } });
  }
  