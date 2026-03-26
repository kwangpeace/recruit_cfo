import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import pg from "pg";
import crypto from "crypto";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));

function parseCookies(header) {
  if (!header) return {};
  const out = {};
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    out[k] = decodeURIComponent(v);
  }
  return out;
}

function sign(value, secret) {
  return crypto.createHmac("sha256", secret).update(value).digest("hex");
}

const AUTH_PASSWORD = process.env.AUTH_PASSWORD || "1234";
const AUTH_SECRET = process.env.AUTH_SECRET || "dev-secret-change-me";
const AUTH_COOKIE = "cfo_auth";

function isAuthed(req) {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies[AUTH_COOKIE];
  if (!token || typeof token !== "string") return false;
  const [payload, sig] = token.split(".");
  if (!payload || !sig) return false;
  const expected = sign(payload, AUTH_SECRET);
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
  } catch {
    return false;
  }
  if (payload !== "ok") return false;
  return true;
}

function authCookieValue() {
  const payload = "ok";
  const sig = sign(payload, AUTH_SECRET);
  return `${payload}.${sig}`;
}

function setAuthCookie(res) {
  const secure = process.env.NODE_ENV === "production";
  const parts = [
    `${AUTH_COOKIE}=${encodeURIComponent(authCookieValue())}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
  ];
  if (secure) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function clearAuthCookie(res) {
  const secure = process.env.NODE_ENV === "production";
  const parts = [
    `${AUTH_COOKIE}=`,
    "Path=/",
    "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
    "HttpOnly",
    "SameSite=Lax",
  ];
  if (secure) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

function loginPageHtml(nextPath) {
  const safeNext = typeof nextPath === "string" && nextPath.startsWith("/") ? nextPath : "/";
  return `<!doctype html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>접속 비밀번호</title>
  <style>
    :root{--bg:#0b1020;--card:#0f172a;--text:#e5e7eb;--muted:#9ca3af;--line:rgba(148,163,184,.25);--accent:#38bdf8}
    *{box-sizing:border-box;margin:0;padding:0}
    body{min-height:100vh;display:grid;place-items:center;background:radial-gradient(1200px 800px at 20% 20%, rgba(56,189,248,.18), transparent 60%),radial-gradient(900px 700px at 80% 30%, rgba(99,102,241,.18), transparent 60%),var(--bg);color:var(--text);font-family:system-ui,-apple-system,"Segoe UI","Noto Sans KR",sans-serif}
    .card{width:min(420px,92vw);background:linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03));border:1px solid var(--line);border-radius:16px;padding:18px 18px 16px;box-shadow:0 22px 80px rgba(0,0,0,.45)}
    h1{font-size:16px;letter-spacing:-.2px;margin-bottom:6px}
    p{font-size:12px;color:var(--muted);line-height:1.5;margin-bottom:14px}
    .row{display:flex;gap:8px}
    input{flex:1;padding:10px 12px;border-radius:12px;border:1px solid var(--line);background:rgba(2,6,23,.55);color:var(--text);outline:none}
    input:focus{border-color:rgba(56,189,248,.7);box-shadow:0 0 0 4px rgba(56,189,248,.14)}
    button{padding:10px 12px;border-radius:12px;border:1px solid rgba(56,189,248,.35);background:rgba(56,189,248,.12);color:var(--text);cursor:pointer;font-weight:600}
    button:hover{background:rgba(56,189,248,.18)}
    .err{margin-top:10px;font-size:12px;color:#fecaca;display:none}
    .foot{margin-top:12px;font-size:11px;color:var(--muted)}
    a{color:var(--accent);text-decoration:none}
  </style>
</head>
<body>
  <main class="card">
    <h1>비밀번호를 입력하세요</h1>
    <p>이 페이지는 비밀번호를 아는 사람만 볼 수 있습니다.</p>
    <form id="f" method="post" action="/login">
      <input type="hidden" name="next" value="${safeNext.replaceAll('"', "&quot;")}" />
      <div class="row">
        <input name="password" type="password" inputmode="numeric" autocomplete="current-password" placeholder="비밀번호" autofocus />
        <button type="submit">입장</button>
      </div>
      <div id="err" class="err">비밀번호가 올바르지 않습니다.</div>
      <div class="foot">관리자에게 비밀번호를 문의하세요.</div>
    </form>
    <script>
      (function(){
        const qs = new URLSearchParams(location.search);
        if(qs.get("error")==="1") document.getElementById("err").style.display="block";
      })();
    </script>
  </main>
</body>
</html>`;
}

app.get("/login", (req, res) => {
  const nextPath = typeof req.query.next === "string" ? req.query.next : "/";
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.status(200).send(loginPageHtml(nextPath));
});

app.post("/login", (req, res) => {
  const password = req.body?.password;
  const nextPathRaw = req.body?.next;
  const nextPath = typeof nextPathRaw === "string" && nextPathRaw.startsWith("/") ? nextPathRaw : "/";
  if (password !== AUTH_PASSWORD) {
    return res.redirect(`/login?next=${encodeURIComponent(nextPath)}&error=1`);
  }
  setAuthCookie(res);
  return res.redirect(nextPath);
});

app.post("/logout", (_req, res) => {
  clearAuthCookie(res);
  res.redirect("/login");
});

app.use((req, res, next) => {
  if (req.path === "/login" || req.path === "/logout") return next();
  if (isAuthed(req)) return next();
  const nextPath = req.originalUrl || "/";
  return res.redirect(`/login?next=${encodeURIComponent(nextPath)}`);
});

// Static site
app.use(express.static(path.join(__dirname, "public")));

// Postgres (Railway recommended)
const { Pool } = pg;
const connectionString = process.env.DATABASE_URL;
const pool = connectionString
  ? new Pool({
      connectionString,
      // Railway Postgres commonly requires SSL in production
      ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
    })
  : null;

async function ensureDb() {
  if (!pool) return;
  await pool.query(`
    create table if not exists evaluations (
      id text primary key,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now(),
      name text not null,
      payload jsonb not null
    );
  `);
}

app.get("/api/health", async (_req, res) => {
  try {
    await ensureDb();
    res.json({ ok: true, db: !!pool });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message ?? e) });
  }
});

// Save or update evaluation (shared)
app.post("/api/evaluations", async (req, res) => {
  const { id, name, payload } = req.body ?? {};
  if (!pool) return res.status(500).json({ ok: false, error: "DATABASE_URL is not set" });
  if (!id || typeof id !== "string") return res.status(400).json({ ok: false, error: "id required" });
  if (!name || typeof name !== "string") return res.status(400).json({ ok: false, error: "name required" });
  if (!payload || typeof payload !== "object") return res.status(400).json({ ok: false, error: "payload required" });

  await ensureDb();
  await pool.query(
    `
    insert into evaluations (id, name, payload)
    values ($1, $2, $3::jsonb)
    on conflict (id) do update
      set name = excluded.name,
          payload = excluded.payload,
          updated_at = now()
    `,
    [id, name, JSON.stringify(payload)]
  );
  res.json({ ok: true });
});

// List evaluations for shared view
app.get("/api/evaluations", async (req, res) => {
  const limit = Math.min(parseInt(req.query.limit ?? "50", 10) || 50, 200);
  if (!pool) return res.status(500).json({ ok: false, error: "DATABASE_URL is not set" });
  await ensureDb();
  const { rows } = await pool.query(
    `select id, created_at, updated_at, name, payload from evaluations order by updated_at desc limit $1`,
    [limit]
  );
  res.json({ ok: true, rows });
});

// Get one evaluation
app.get("/api/evaluations/:id", async (req, res) => {
  if (!pool) return res.status(500).json({ ok: false, error: "DATABASE_URL is not set" });
  await ensureDb();
  const { rows } = await pool.query(
    `select id, created_at, updated_at, name, payload from evaluations where id = $1`,
    [req.params.id]
  );
  if (!rows[0]) return res.status(404).json({ ok: false, error: "not found" });
  res.json({ ok: true, row: rows[0] });
});

// Fallback to index.html (single page)
app.get("*", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

const port = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
app.listen(port, () => {
  console.log(`listening on http://localhost:${port}`);
});

