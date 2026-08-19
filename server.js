// AI 学习看板 —— 后端服务（零外部依赖，Node 内置模块）
// 功能：静态托管 public/ + 用户注册/登录/登出/进度 + 管理员后台 + 安全问题找回密码
// 首个注册用户自动成为管理员。
//
// 跨域鉴权说明：看板（前端）与后端可能在不同域名（如看板在 CloudStudio、后端在 Hugging Face）。
// 跨域时浏览器不会自动携带 Cookie，因此本服务改用「Bearer Token」鉴权：
//   - 注册/登录成功时，在 JSON 响应里返回 token；
//   - 看板把 token 存到 localStorage，之后每次请求通过 Authorization: Bearer <token> 头带上；
//   - 服务端既认 Authorization 头，也兼容同域下的 Cookie（便于同源部署）。
// CORS 已放行 Authorization 头与常见方法，方便跨域调用。
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const PUB = path.join(ROOT, "public");
// 数据目录：优先用环境变量 DATA_DIR；Hugging Face Spaces 开启「持久化存储」后通常挂载在 /data；
// 否则回退到程序目录下的 server_data（本地运行 / 未开持久化时使用）。
const DATA = process.env.DATA_DIR || (fs.existsSync("/data") ? path.join("/data", "server_data") : path.join(ROOT, "server_data"));
const USERS_FILE = path.join(DATA, "users.json");
const SESS_FILE = path.join(DATA, "sessions.json");
const PROG_DIR = path.join(DATA, "progress");

for (const d of [DATA, PROG_DIR]) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}
function loadJSON(p, def) {
  try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch (e) { return def; }
}
function saveJSON(p, obj) {
  fs.writeFileSync(p, JSON.stringify(obj, null, 2), "utf8");
}

let users = loadJSON(USERS_FILE, {});          // { uid: {uid,username,role,pwHash,pwSalt,secQ,secAHash,secASalt,createdAt} }
let sessions = loadJSON(SESS_FILE, {});          // { token: {uid, expires} }

function persistUsers() { saveJSON(USERS_FILE, users); }
function persistSessions() { saveJSON(SESS_FILE, sessions); }

function hash(pw, salt) { return crypto.scryptSync(pw, salt, 64).toString("hex"); }
function newSalt() { return crypto.randomBytes(16).toString("hex"); }
function newToken() { return crypto.randomBytes(32).toString("hex"); }
function uid() { return "u" + crypto.randomBytes(6).toString("hex"); }

function sessionUser(token) {
  if (!token) return null;
  const s = sessions[token];
  if (!s) return null;
  if (s.expires < Date.now()) { delete sessions[token]; persistSessions(); return null; }
  return users[s.uid] || null;
}

// ---------- HTTP helpers ----------
function send(res, code, obj, headers) {
  res.writeHead(code, Object.assign({ "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS" }, headers || {}));
  res.end(obj === undefined ? "" : JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let d = "";
    req.on("data", c => { d += c; if (d.length > 1e6) req.destroy(); });
    req.on("end", () => { try { resolve(d ? JSON.parse(d) : {}); } catch (e) { reject(e); } });
    req.on("error", reject);
  });
}
function getCookie(req, name) {
  const c = req.headers.cookie || "";
  const m = c.match(new RegExp("(?:^|; )" + name + "=([^;]+)"));
  return m ? m[1] : null;
}
// 取 token：优先 Authorization: Bearer 头（跨域场景），回退到 Cookie（同域场景）
function getToken(req) {
  const h = req.headers["authorization"] || "";
  if (h.toLowerCase().startsWith("bearer ")) return h.slice(7).trim();
  return getCookie(req, "tok");
}
function setSessionCookie(res, token) {
  res.setHeader("Set-Cookie", "tok=" + token + "; Path=/; Max-Age=2592000; SameSite=Lax");
}
function clearSessionCookie(res) {
  res.setHeader("Set-Cookie", "tok=; Path=/; Max-Age=0; SameSite=Lax");
}
function publicUser(u) {
  return { uid: u.uid, username: u.username, role: u.role, createdAt: u.createdAt };
}

// ---------- API ----------
async function handleApi(req, res, pathname) {
  // CORS preflight
  if (req.method === "OPTIONS") { send(res, 204, ""); return; }

  // /api/me
  if (pathname === "/api/me" && req.method === "GET") {
    const u = sessionUser(getToken(req));
    if (u) send(res, 200, { ok: true, username: u.username, role: u.role });
    else send(res, 200, { ok: false });
    return;
  }

  // /api/register
  if (pathname === "/api/register" && req.method === "POST") {
    const b = await readBody(req);
    const username = String(b.username || "").trim();
    const password = String(b.password || "");
    const secQ = String(b.secQ || "").trim();
    const secA = String(b.secA || "").trim();
    if (username.length < 2 || username.length > 20) return send(res, 400, { ok: false, msg: "用户名需 2-20 个字符" });
    if (!/^[\w一-龥]+$/.test(username)) return send(res, 400, { ok: false, msg: "用户名只能用字母、数字、中文" });
    if (password.length < 6) return send(res, 400, { ok: false, msg: "密码至少 6 位" });
    if (!secQ || !secA) return send(res, 400, { ok: false, msg: "请填写找回密码的问题与答案" });
    if (Object.values(users).some(u => u.username === username)) return send(res, 409, { ok: false, msg: "该用户名已被注册" });
    const role = Object.keys(users).length === 0 ? "admin" : "user";
    const pwSalt = newSalt(), secASalt = newSalt();
    const id = uid();
    users[id] = {
      uid: id, username, role,
      pwSalt, pwHash: hash(password, pwSalt),
      secQ, secASalt, secAHash: hash(secA.toLowerCase(), secASalt),
      createdAt: new Date().toISOString()
    };
    persistUsers();
    const token = newToken();
    sessions[token] = { uid: id, expires: Date.now() + 2592000000 };
    persistSessions();
    setSessionCookie(res, token);
    return send(res, 200, { ok: true, role, username, firstAdmin: role === "admin", token });
  }

  // /api/login
  if (pathname === "/api/login" && req.method === "POST") {
    const b = await readBody(req);
    const username = String(b.username || "").trim();
    const password = String(b.password || "");
    const u = Object.values(users).find(x => x.username === username);
    if (!u || hash(password, u.pwSalt) !== u.pwHash) return send(res, 401, { ok: false, msg: "用户名或密码错误" });
    const token = newToken();
    sessions[token] = { uid: u.uid, expires: Date.now() + 2592000000 };
    persistSessions();
    setSessionCookie(res, token);
    return send(res, 200, { ok: true, role: u.role, username: u.username, token });
  }

  // /api/logout
  if (pathname === "/api/logout" && req.method === "POST") {
    const t = getToken(req);
    if (t) { delete sessions[t]; persistSessions(); }
    clearSessionCookie(res);
    return send(res, 200, { ok: true });
  }

  // /api/forgot  → 返回安全问题
  if (pathname === "/api/forgot" && req.method === "POST") {
    const b = await readBody(req);
    const username = String(b.username || "").trim();
    const u = Object.values(users).find(x => x.username === username);
    if (!u) return send(res, 404, { ok: false, msg: "找不到该用户" });
    return send(res, 200, { ok: true, secQ: u.secQ });
  }

  // /api/reset  → 用安全问题重置密码
  if (pathname === "/api/reset" && req.method === "POST") {
    const b = await readBody(req);
    const username = String(b.username || "").trim();
    const secA = String(b.secA || "").trim();
    const newPassword = String(b.newPassword || "");
    const u = Object.values(users).find(x => x.username === username);
    if (!u) return send(res, 404, { ok: false, msg: "找不到该用户" });
    if (hash(secA.toLowerCase(), u.secASalt) !== u.secAHash) return send(res, 400, { ok: false, msg: "安全问题答案不正确" });
    if (newPassword.length < 6) return send(res, 400, { ok: false, msg: "新密码至少 6 位" });
    u.pwSalt = newSalt(); u.pwHash = hash(newPassword, u.pwSalt);
    persistUsers();
    return send(res, 200, { ok: true });
  }

  // 以下接口需要登录
  const u = sessionUser(getToken(req));
  if (!u) return send(res, 401, { ok: false, msg: "请先登录" });

  // /api/progress  GET/POST
  if (pathname === "/api/progress") {
    const pf = path.join(PROG_DIR, u.uid + ".json");
    if (req.method === "GET") {
      return send(res, 200, loadJSON(pf, {}));
    }
    if (req.method === "POST") {
      const b = await readBody(req);
      const clean = {};
      for (const key of ["done", "mout", "mq", "qbest"]) {
        if (b[key] && typeof b[key] === "object") clean[key] = b[key];
      }
      saveJSON(pf, clean);
      return send(res, 200, { ok: true });
    }
  }

  // ---- 管理员接口 ----
  if (pathname.startsWith("/api/admin/") && u.role !== "admin") {
    return send(res, 403, { ok: false, msg: "需要管理员权限" });
  }
  if (pathname === "/api/admin/users" && req.method === "GET") {
    const list = Object.values(users).map(x => ({
      uid: x.uid, username: x.username, role: x.role, createdAt: x.createdAt,
      progressCount: Object.keys(loadJSON(path.join(PROG_DIR, x.uid + ".json"), {})).length
    }));
    return send(res, 200, { ok: true, users: list });
  }
  if (pathname === "/api/admin/stats" && req.method === "GET") {
    const all = Object.values(users);
    let totalDone = 0, activeUsers = 0;
    all.forEach(x => {
      const p = loadJSON(path.join(PROG_DIR, x.uid + ".json"), {});
      const done = p.done || {};
      const c = Object.values(done).filter(Boolean).length;
      if (c > 0) activeUsers++;
      totalDone += c;
    });
    return send(res, 200, { ok: true, stats: { totalUsers: all.length, activeUsers, totalModulesDone: totalDone } });
  }
  if (pathname.startsWith("/api/admin/progress/") && req.method === "GET") {
    const tid = pathname.split("/").pop();
    const tu = users[tid];
    if (!tu) return send(res, 404, { ok: false, msg: "用户不存在" });
    const p = loadJSON(path.join(PROG_DIR, tid + ".json"), {});
    const done = p.done || {};
    const doneCount = Object.values(done).filter(Boolean).length;
    return send(res, 200, { ok: true, username: tu.username, progress: p, doneCount });
  }
  if (pathname.startsWith("/api/admin/users/") && req.method === "DELETE") {
    const tid = pathname.split("/").pop();
    if (tid === u.uid) return send(res, 400, { ok: false, msg: "不能删除自己" });
    if (!users[tid]) return send(res, 404, { ok: false, msg: "用户不存在" });
    delete users[tid]; persistUsers();
    const pf = path.join(PROG_DIR, tid + ".json");
    if (fs.existsSync(pf)) fs.unlinkSync(pf);
    return send(res, 200, { ok: true });
  }

  send(res, 404, { ok: false, msg: "接口不存在" });
}

// ---------- 静态文件 ----------
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8",
  ".png": "image/png", ".svg": "image/svg+xml", ".ico": "image/x-icon" };
function serveStatic(req, res, pathname) {
  let rel = pathname === "/" ? "/index.html" : pathname;
  const safe = path.normalize(rel).replace(/^(\.\.[\/\\])+/, "");
  // 1) 优先 public/（render-backend/public/）
  const fp = path.join(PUB, safe);
  if (fp.startsWith(PUB) && fs.existsSync(fp) && !fs.statSync(fp).isDirectory()) {
    res.writeHead(200, { "Content-Type": MIME[path.extname(fp)] || "application/octet-stream" });
    return res.end(fs.readFileSync(fp));
  }
  // 2) 仓库根目录（扁平部署：index.html / intro.html 直接拖到 GitHub 仓库根）
  const rf = path.join(ROOT, safe);
  if (rf.startsWith(ROOT) && fs.existsSync(rf) && !fs.statSync(rf).isDirectory()) {
    res.writeHead(200, { "Content-Type": MIME[path.extname(rf)] || "application/octet-stream" });
    return res.end(fs.readFileSync(rf));
  }
  // 3) SPA 兜底到 index.html：优先 public/，其次仓库根目录
  const idxPub = path.join(PUB, "index.html");
  const idxRoot = path.join(ROOT, "index.html");
  const idx = fs.existsSync(idxPub) ? idxPub : (fs.existsSync(idxRoot) ? idxRoot : null);
  if (idx) { res.writeHead(200, { "Content-Type": MIME[".html"] }); return res.end(fs.readFileSync(idx)); }
  return send(res, 404, { ok: false, msg: "not found" });
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://localhost");
  const p = url.pathname;
  if (p.startsWith("/api/")) {
    handleApi(req, res, p).catch(e => send(res, 500, { ok: false, msg: "服务器错误", err: String(e) }));
  } else {
    serveStatic(req, res, p);
  }
});
server.listen(PORT, () => {
  console.log("AI 学习看板后端已启动: http://localhost:" + PORT);
  console.log("数据目录:", DATA);
  console.log("管理员提示：首个注册的用户将自动成为管理员。");
});
