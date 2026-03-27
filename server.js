import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import pg from "pg";
import crypto from "crypto";
import multer from "multer";
import https from "https";

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
  if (String(req.originalUrl || "").startsWith("/api/")) {
    return res.status(401).json({ ok: false, error: "unauthorized" });
  }
  return res.redirect(`/login?next=${encodeURIComponent(nextPath)}`);
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
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

function extractJson(text) {
  if (typeof text !== "string") throw new Error("AI response is not text");
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) throw new Error("JSON not found in AI response");
  const raw = text.slice(start, end + 1);
  return JSON.parse(raw);
}

function nearestAllowed(value, allowed) {
  const n = Number(value);
  if (!Number.isFinite(n)) return allowed[0];
  let best = allowed[0];
  let bestDist = Math.abs(n - best);
  for (const a of allowed) {
    const d = Math.abs(n - a);
    if (d < bestDist) {
      bestDist = d;
      best = a;
    }
  }
  return best;
}

async function extractResumeText(file) {
  if (!file?.buffer) throw new Error("no resume file");
  const mime = String(file.mimetype || "");
  const name = String(file.originalname || file.filename || "").toLowerCase();

  // txt
  if (mime.includes("text/") || name.endsWith(".txt")) {
    return file.buffer.toString("utf8");
  }

  // pdf
  if (mime.includes("pdf") || name.endsWith(".pdf")) {
    // PDF는 Gemini에 바이너리로 직접 전달하는 방식이 더 안정적입니다.
    return "";
  }

  // docx
  if (mime.includes("officedocument.wordprocessingml.document") || name.endsWith(".docx")) {
    const mod = await import("mammoth");
    const mammoth = mod?.default ?? mod;
    if (!mammoth?.extractRawText) throw new Error("mammoth.extractRawText not found");
    const parsed = await mammoth.extractRawText({ buffer: file.buffer });
    return parsed?.value || "";
  }

  // fallback: treat as text
  return file.buffer.toString("utf8");
}

async function callGeminiGenerateContent({ apiKey, model, prompt, extraParts = [] }) {
  if (!apiKey) throw new Error("GEMINI_API_KEY is not set");
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;

  const body = {
    contents: [
      {
        role: "user",
        parts: [{ text: prompt }, ...extraParts]
      }
    ],
    generationConfig: {
      temperature: 0.2,
      maxOutputTokens: 400
    }
  };

  const data = await new Promise((resolve, reject) => {
    const u = new URL(url);
    const payload = JSON.stringify(body);
    const req = https.request(
      {
        method: "POST",
        hostname: u.hostname,
        path: u.pathname + u.search,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload)
        }
      },
      (resp) => {
        let raw = "";
        resp.on("data", (chunk) => {
          raw += chunk;
        });
        resp.on("end", () => {
          try {
            resolve(JSON.parse(raw || "{}"));
          } catch (e) {
            reject(e);
          }
        });
      }
    );
    req.on("error", reject);
    req.write(payload);
    req.end();
  });

  const respOk = true;
  // status code가 node https 응답에서 자동으로 전달되지 않으므로, 실패는 data/구조로 판단합니다.
  // (Gemini는 보통 error 객체를 내려줍니다.)
  if (data?.error) {
    throw new Error(String(data?.error?.message || data?.error));
  }
  const text =
    data?.candidates?.[0]?.content?.parts?.map((p) => p?.text).join("") ||
    data?.candidates?.[0]?.content?.parts?.[0]?.text ||
    JSON.stringify(data);

  return { text, data };
}

function isQuotaErrorMessage(msg) {
  const s = String(msg || "").toLowerCase();
  return s.includes("quota exceeded") || s.includes("rate limit") || s.includes("429");
}

const GEMINI_ITEMS = [
  {
    key: "A1",
    label: "A1. 재무/회계 경력 연수",
    allowed: [0, 4, 7, 10],
    mapping: "10=20년+ & 스타트업 CFO / 7=15~19년 & 스타트업 재무총괄 / 4=15년+ 대기업 재무 / 0=15년 미만"
  },
  {
    key: "A2",
    label: "A2. 대규모 투자유치 / IPO 실적",
    allowed: [0, 3, 7, 10],
    mapping: "10=Series B+ & IPO 모두 / 7=Series B+ 직접 리딩 / 3=Series A 또는 참여 / 0=해당 없음"
  },
  {
    key: "A3",
    label: "A3. AI / SaaS 비즈니스 이해도",
    allowed: [0, 3, 6, 10],
    mapping: "10=AI/SaaS CFO 직접 경험 / 6=테크 스타트업 재무 경험 / 3=IT 인접 / 0=전무"
  },
  {
    key: "B1",
    label: "B1. IR 전략 수립 및 실행력",
    allowed: [0, 3, 6, 10],
    mapping: "10=후속 라운드 전략·실행 직접 / 6=IR 자료·투자자 미팅 / 3=IR 지원 수준 / 0=없음"
  },
  {
    key: "B2",
    label: "B2. 재무계획 & 캐시플로우 관리",
    allowed: [0, 2, 6, 10],
    mapping: "10=Burn rate·런웨이 직접 통제 / 6=예산 수립·관리 / 2=분석 보조 / 0=없음"
  },
  {
    key: "B3",
    label: "B3. 내부 통제 & 거버넌스 구축",
    allowed: [0, 2, 6, 10],
    mapping: "10=IPO 대비 시스템 직접 구축 / 6=내부통제 개선 리딩 / 2=감사 대응 참여 / 0=없음"
  },
  {
    key: "B4",
    label: "B4. VC·PE·금융권 네트워크",
    allowed: [0, 2, 6, 10],
    mapping: "10=Top-tier VC/PE 다수 직접 / 6=국내 주요 VC / 2=금융권 일반 / 0=없음"
  },
  {
    key: "C1",
    label: "C1. 글로벌 확장 경험",
    allowed: [0, 4, 8],
    mapping: "8=해외 법인 설립·운영 리딩 / 4=해외 법인 재무 관리 참여 / 0=없음"
  },
  {
    key: "C2",
    label: "C2. 기술 특례 상장 프로세스 리딩",
    allowed: [0, 4, 7],
    mapping: "7=기술 특례 상장 직접 리딩 / 4=일반 IPO 직접 리딩 / 0=없음"
  },
  {
    key: "C3",
    label: "C3. MBA / CPA 자격증",
    allowed: [0, 3, 5],
    mapping: "5=MBA+CPA / 3=둘 중 하나 / 0=없음"
  },
  {
    key: "D1",
    label: "D1. 스타트업 환경 적응력",
    allowed: [0, 1, 3, 5],
    mapping: "5=스타트업 창업·초기 멤버 / 3=스타트업 임원 / 1=대기업 경험만 / 0=없음"
  },
  {
    key: "D2",
    label: "D2. CEO 협업·데이터 기반 의사결정",
    allowed: [0, 1, 3, 5],
    mapping: "5=CEO 직접 보좌·사업성 분석 리딩 / 3=C-level 협업 / 1=간접 참여 / 0=없음"
  }
];

app.post(
  "/api/gemini/evaluate",
  upload.single("resume"),
  async (req, res) => {
    try {
      const apiKey = process.env.GEMINI_API_KEY;
      const preferredModel = process.env.GEMINI_MODEL || "gemini-1.5-flash";
      const file = req.file;
      if (!file) return res.status(400).json({ ok: false, error: "resume file is required" });

      const mime = String(file.mimetype || "");
      const originalName = String(file.originalname || "").toLowerCase();
      const isPdf = mime.includes("pdf") || originalName.endsWith(".pdf");
      const resumeTextRaw = await extractResumeText(file);
      const resumeText = String(resumeTextRaw || "").slice(0, 12000);
      const candidateName = String(req.body?.candidateName || "").slice(0, 80);

      const itemsText = GEMINI_ITEMS.map((it, idx) => {
        return `${idx + 1}) ${it.label}\n- allowed: ${JSON.stringify(it.allowed)}\n- 기준: ${it.mapping}`;
      }).join("\n\n");

      const prompt = `너는 채용 평가 도우미야. 아래 이력서 내용만 근거로, CFO 후보자 점수를 평가해줘.

반드시 아래 12개 항목에 대해 각 점수를 지정하고, 점수는 allowed 값 중 하나만 선택해.
이력서에 정보가 부족하면 "가장 보수적으로" 낮은 점수를 선택해.

${itemsText}

평가 결과는 반드시 JSON만 출력해. 다른 글 금지.
형식:
{
  "scores": [A1, A2, A3, B1, B2, B3, B4, C1, C2, C3, D1, D2]
}

이력서(이름: ${candidateName || "알수없음"})를 기반으로 평가해.
${isPdf ? "첨부된 PDF 파일 내용을 우선 근거로 사용하고, 텍스트가 추가되었으면 함께 참고해." : "아래 텍스트를 근거로 사용해."}

이력서 텍스트:
${resumeText || "(텍스트 없음 - 첨부 파일 참고)"}`;

      const extraParts = [];
      if (isPdf) {
        extraParts.push({
          inline_data: {
            mime_type: "application/pdf",
            data: file.buffer.toString("base64")
          }
        });
      }

      const fallbackModels = [
        preferredModel,
        "gemini-1.5-flash",
        "gemini-1.5-pro",
      ].filter((m, i, arr) => m && arr.indexOf(m) === i);

      let text = "";
      let usedModel = preferredModel;
      let lastErr = null;
      for (let i = 0; i < fallbackModels.length; i++) {
        const model = fallbackModels[i];
        try {
          const out = await callGeminiGenerateContent({ apiKey, model, prompt, extraParts });
          text = out.text;
          usedModel = model;
          lastErr = null;
          break;
        } catch (e) {
          lastErr = e;
          const isQuota = isQuotaErrorMessage(e?.message);
          const hasNext = i < fallbackModels.length - 1;
          if (!isQuota || !hasNext) throw e;
        }
      }
      if (lastErr) throw lastErr;

      const parsed = extractJson(text);
      const scoresRaw = parsed?.scores;
      if (!Array.isArray(scoresRaw) || scoresRaw.length !== 12) {
        throw new Error("AI returned invalid scores array");
      }

      const scores = scoresRaw.map((v, i) => {
        const allowed = GEMINI_ITEMS[i]?.allowed || [];
        return allowed.includes(v) ? v : nearestAllowed(v, allowed);
      });

      return res.json({ ok: true, scores, model: usedModel, modelText: text.slice(0, 800) });
    } catch (e) {
      console.error("[gemini/evaluate] error", e);
      return res.status(500).json({ ok: false, error: String(e?.message ?? e) });
    }
  }
);

// Ensure multer/upload errors return JSON (not HTML)
app.use((err, req, res, next) => {
  if (!err) return next();
  const isApi = String(req.originalUrl || "").startsWith("/api/");
  if (!isApi) return next(err);
  if (err?.code === "LIMIT_FILE_SIZE") {
    return res.status(413).json({ ok: false, error: "file too large (max 5MB)" });
  }
  return res.status(400).json({ ok: false, error: String(err?.message ?? err) });
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

