// middleware.js
import { NextResponse } from "next/server";

export const config = {
  matcher: ["/((?!_next|assets|favicon.ico|robots.txt).*)"], // protect everything except static
};

async function log(event, req, extra = {}) {
  const endpoint = process.env.LOG_ENDPOINT;
  if (!endpoint) return; // no-op if not set

  const url = new URL(req.url);
  const headers = req.headers;
  const ip =
    headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    headers.get("x-real-ip") ||
    "unknown";
  const ua = headers.get("user-agent") || "";
  const ref = headers.get("referer") || "";

  const payload = {
    event,
    ts: new Date().toISOString(),
    url: url.toString(),
    ref,
    ip,
    ua,
    ...extra,
  };

  try {
    await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: JSON.stringify(payload),
    });
  } catch (_) { /* never block on logging */ }
}

export async function middleware(req) {
  const url = new URL(req.url);
  const token = process.env.ACCESS_TOKEN || "";
  const cookie = req.cookies.get("bday_auth")?.value || "";
  const qp = url.searchParams.get("t");

  // Log every attempt
  await log("attempt", req, { token_ok: qp === token || cookie === token });

  // If query param matches, set cookie + strip ?t=
  if (qp && token && qp === token) {
    const cleaned = new URL(url);
    cleaned.searchParams.delete("t");

    const res = NextResponse.redirect(cleaned);
    res.cookies.set("bday_auth", token, {
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 2, // 2 days
    });

    await log("granted", req, { token_ok: true, note: "via query token" });
    return res;
  }

  // If valid cookie, let them in
  if (cookie && token && cookie === token) {
    await log("visit", req, { token_ok: true });
    return NextResponse.next();
  }

  // Otherwise show gate page + log denied
  await log("denied", req, { token_ok: false });

  const gate = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Private</title>
<style>
  body{margin:0;display:grid;place-items:center;height:100vh;background:#0b0f1a;color:#f7f8ff;font-family:system-ui,Segoe UI,Roboto,Arial}
  .card{background:rgba(255,255,255,.06);border-radius:16px;padding:24px 20px;box-shadow:0 10px 30px rgba(0,0,0,.45);width:min(420px,92vw);text-align:center}
  h1{margin:0 0 8px;font-size:22px}
  p{margin:0 0 16px;color:#9aa3b2}
  .row{display:flex;gap:8px}
  input{flex:1;padding:12px;border-radius:10px;border:1px solid #2b3148;background:#101522;color:#f7f8ff;outline:none}
  button{padding:12px 16px;border-radius:10px;border:none;font-weight:700;cursor:pointer;background:linear-gradient(135deg,#ff7bd3,#ffd166);color:#0b0f1a}
  small{display:block;margin-top:12px;color:#9aa3b2}
</style></head>
<body>
  <div class="card">
    <h1>Private link</h1>
    <p>This page needs permission. Ask the owner for the access code.</p>
    <div class="row">
      <input id="code" type="password" placeholder="Enter code"/>
      <button id="go">Open</button>
    </div>
    <small>Tip: the link can also include <code>?t=CODE</code></small>
  </div>
<script>
  document.getElementById('go').addEventListener('click', ()=>{
    const v = document.getElementById('code').value.trim();
    if(!v) return;
    const u = new URL(location.href);
    u.searchParams.set('t', v);
    location.href = u.toString();
  });
  document.getElementById('code').addEventListener('keyup', (e)=>{ if(e.key==='Enter') document.getElementById('go').click(); });
</script>
</body></html>`;

  return new NextResponse(gate, { status: 401, headers: { "Content-Type": "text/html; charset=utf-8" } });
}
