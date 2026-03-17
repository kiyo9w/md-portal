import express from 'express';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || 18901);
const HOST = process.env.HOST || '0.0.0.0';
const NOTES_DIR = path.resolve(process.env.MD_NOTES_DIR || path.join(__dirname, '..', 'data', 'md-portal', 'notes'));
const LEGACY_NOTES_DIR = path.join(__dirname, 'notes');
const PUBLISH_TOKEN = process.env.PUBLISH_TOKEN || '';
const PORTAL_PASSWORD = String(process.env.MD_PORTAL_PASSWORD || '').trim();
const PRIVATE_LINK_SECRET = String(process.env.PRIVATE_LINK_SECRET || PORTAL_PASSWORD || '').trim();
const AUTH_COOKIE = 'md_portal_auth';
const AUTH_TOKEN = PORTAL_PASSWORD
  ? crypto.createHash('sha256').update(PORTAL_PASSWORD).digest('hex').slice(0, 32)
  : '';
const AUTH_MAX_FAIL = Number(process.env.AUTH_MAX_FAIL || 8);
const AUTH_LOCK_MS = Number(process.env.AUTH_LOCK_MS || 5 * 60 * 1000);
const authAttempts = new Map();
const ACCESS_COOKIE = 'md_portal_access';
const ACCESS_SESSION_MS = Number(process.env.ACCESS_SESSION_MS || 7 * 24 * 60 * 60 * 1000);
const ACCESS_CODES_FILE = path.resolve(process.env.MD_ACCESS_CODES_FILE || path.join(__dirname, '..', 'data', 'md-portal', 'access-codes.json'));
const ACCESS_EVENTS_FILE = path.resolve(process.env.MD_ACCESS_EVENTS_FILE || path.join(__dirname, '..', 'data', 'md-portal', 'access-events.jsonl'));
const accessSessions = new Map();

const FS_ROOT = path.resolve(process.env.MD_FILE_ROOT || path.join(__dirname, '..'));
const FS_MAX_READ_BYTES = Number(process.env.MD_FILE_MAX_READ_BYTES || 512 * 1024);
const FS_BLOCK_SEGMENTS = new Set(['.secrets', 'credentials', '.ssh', 'node_modules', '.git']);
const FS_BLOCK_FILES = new Set(['.env', '.env.local', 'auth-profiles.json', 'device-auth.json', 'github_pat', 'id_rsa', 'id_ed25519']);
const FS_ALLOW_EXT = new Set(['.md', '.txt', '.json', '.jsonl', '.yaml', '.yml', '.log', '.csv', '.xml']);

if (!fs.existsSync(NOTES_DIR)) fs.mkdirSync(NOTES_DIR, { recursive: true });
fs.mkdirSync(path.dirname(ACCESS_CODES_FILE), { recursive: true });
if (!fs.existsSync(ACCESS_CODES_FILE)) fs.writeFileSync(ACCESS_CODES_FILE, JSON.stringify({ codes: [] }, null, 2));
if (!fs.existsSync(ACCESS_EVENTS_FILE)) fs.writeFileSync(ACCESS_EVENTS_FILE, '');
if (NOTES_DIR !== LEGACY_NOTES_DIR && fs.existsSync(LEGACY_NOTES_DIR)) {
  for (const name of fs.readdirSync(LEGACY_NOTES_DIR)) {
    if (!name.endsWith('.md')) continue;
    const src = path.join(LEGACY_NOTES_DIR, name);
    const dst = path.join(NOTES_DIR, name);
    if (!fs.existsSync(dst)) fs.copyFileSync(src, dst);
  }
}

app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

function safeName(input) {
  const base = path.basename(input || '');
  if (!base.endsWith('.md')) return null;
  if (!/^[a-zA-Z0-9._-]+\.md$/.test(base)) return null;
  return base;
}

function parseCookies(req) {
  const raw = req.headers.cookie || '';
  return raw.split(';').reduce((acc, part) => {
    const i = part.indexOf('=');
    if (i < 0) return acc;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k) acc[k] = decodeURIComponent(v);
    return acc;
  }, {});
}

function secureEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a || '')).digest();
  const hb = crypto.createHash('sha256').update(String(b || '')).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function getClientIp(req) {
  const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return fwd || req.socket?.remoteAddress || 'unknown';
}

function isAuthLimited(req) {
  const ip = getClientIp(req);
  const st = authAttempts.get(ip);
  if (!st) return { limited: false, retryAfterMs: 0 };
  if (Date.now() >= st.until) {
    authAttempts.delete(ip);
    return { limited: false, retryAfterMs: 0 };
  }
  return { limited: true, retryAfterMs: Math.max(0, st.until - Date.now()) };
}

function markAuthFailure(req) {
  const ip = getClientIp(req);
  const now = Date.now();
  const st = authAttempts.get(ip) || { count: 0, until: now };
  st.count += 1;
  st.until = st.count >= AUTH_MAX_FAIL ? (now + AUTH_LOCK_MS) : now;
  authAttempts.set(ip, st);
}

function clearAuthFailure(req) {
  const ip = getClientIp(req);
  authAttempts.delete(ip);
}

function readAccessCodes() {
  try {
    const raw = fs.readFileSync(ACCESS_CODES_FILE, 'utf8');
    const data = JSON.parse(raw || '{}');
    const rows = Array.isArray(data.codes) ? data.codes : [];
    return rows.filter((x) => x && typeof x === 'object');
  } catch {
    return [];
  }
}

function writeAccessCodes(codes) {
  fs.writeFileSync(ACCESS_CODES_FILE, JSON.stringify({ codes }, null, 2), 'utf8');
}

function hashAccessCode(code) {
  return crypto.createHash('sha256').update(String(code || '')).digest('hex');
}

function cleanupAccessSessions() {
  const now = Date.now();
  for (const [token, row] of accessSessions.entries()) {
    if (!row || now >= Number(row.expiresAt || 0)) accessSessions.delete(token);
  }
}

function createAccessSession(codeId, resources, req) {
  cleanupAccessSessions();
  const token = crypto.randomBytes(24).toString('hex');
  const now = Date.now();
  const expiresAt = now + ACCESS_SESSION_MS;
  accessSessions.set(token, {
    token,
    codeId,
    resources: Array.isArray(resources) ? resources : [],
    createdAt: now,
    expiresAt,
    ip: getClientIp(req),
  });
  return { token, expiresAt };
}

function getScopedAccess(req) {
  cleanupAccessSessions();
  const cookies = parseCookies(req);
  const token = String(cookies[ACCESS_COOKIE] || '');
  if (!token) return null;
  const row = accessSessions.get(token);
  if (!row) return null;
  if (Date.now() >= Number(row.expiresAt || 0)) {
    accessSessions.delete(token);
    return null;
  }
  return row;
}

function listAllowedNotes(scoped) {
  if (!scoped || !Array.isArray(scoped.resources)) return [];
  return scoped.resources
    .filter((r) => r && r.type === 'note' && typeof r.value === 'string')
    .map((r) => safeName(r.value))
    .filter(Boolean);
}

function listAllowedFiles(scoped) {
  if (!scoped || !Array.isArray(scoped.resources)) return [];
  return scoped.resources
    .filter((r) => r && r.type === 'file' && typeof r.value === 'string')
    .map((r) => cleanRelativePath(r.value))
    .filter(Boolean);
}

function canAccessNote(req, name) {
  if (hasPortalAccess(req)) return true;
  if (hasPrivateToken(req, name)) return true;
  const scoped = getScopedAccess(req);
  if (!scoped) return false;
  return listAllowedNotes(scoped).includes(name);
}

function canAccessFile(req, relativePath) {
  if (hasPortalAccess(req)) return true;
  const scoped = getScopedAccess(req);
  if (!scoped) return false;
  const rel = cleanRelativePath(relativePath);
  return listAllowedFiles(scoped).includes(rel);
}

function appendAccessEvent(event) {
  const row = {
    at: new Date().toISOString(),
    ip: event.ip || '',
    ua: String(event.ua || '').slice(0, 240),
    type: event.type || '',
    codeId: event.codeId || null,
    value: event.value || null,
    ok: Boolean(event.ok),
  };
  fs.appendFileSync(ACCESS_EVENTS_FILE, JSON.stringify(row) + '\n', 'utf8');
}

function recentAccessEvents(limit = 200) {
  try {
    const raw = fs.readFileSync(ACCESS_EVENTS_FILE, 'utf8');
    const lines = raw.split('\n').filter(Boolean);
    const rows = lines.slice(-limit).map((line) => {
      try { return JSON.parse(line); } catch { return null; }
    }).filter(Boolean);
    return rows.reverse();
  } catch {
    return [];
  }
}

function hasPortalAccess(req) {
  if (!PORTAL_PASSWORD) return true;
  const cookies = parseCookies(req);
  return secureEqual(cookies[AUTH_COOKIE], AUTH_TOKEN);
}

function hasWriteAccess(req) {
  if (hasPortalAccess(req)) return true;
  if (!PUBLISH_TOKEN) return false;
  const auth = String(req.header('authorization') || '');
  if (!auth.startsWith('Bearer ')) return false;
  return secureEqual(auth.slice(7), PUBLISH_TOKEN);
}

function isPrivateBypass(req) {
  return String(req.query?.private || '') === '1';
}

function signPrivateNote(name, secret = PRIVATE_LINK_SECRET) {
  if (!secret) return '';
  return crypto.createHmac('sha256', String(secret)).update(name).digest('hex').slice(0, 24);
}

function hasPrivateToken(req, name) {
  if (!isPrivateBypass(req)) return false;
  const token = String(req.query?.token || '');
  if (!token) return false;

  const candidates = [
    signPrivateNote(name, PRIVATE_LINK_SECRET),
    signPrivateNote(name, PORTAL_PASSWORD),
  ].filter(Boolean);

  for (const expected of candidates) {
    try {
      if (crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))) return true;
    } catch {
      // ignore and keep checking
    }
  }
  return false;
}

function cleanRelativePath(input) {
  const raw = String(input || '').trim();
  if (!raw || raw === '.') return '';
  const normalized = path.posix.normalize(raw.replace(/\\/g, '/'));
  return normalized.replace(/^\/+/, '');
}

function isPathBlocked(relativePath) {
  const parts = cleanRelativePath(relativePath).split('/').filter(Boolean);
  for (const p of parts) {
    if (FS_BLOCK_SEGMENTS.has(p)) return true;
  }
  const base = path.basename(relativePath || '');
  if (FS_BLOCK_FILES.has(base)) return true;
  if (base.startsWith('.env')) return true;
  return false;
}

function resolveSafePath(relativePath) {
  const rel = cleanRelativePath(relativePath);
  if (rel.includes('..')) return null;
  const candidate = path.resolve(FS_ROOT, rel);
  if (!(candidate === FS_ROOT || candidate.startsWith(FS_ROOT + path.sep))) return null;
  return candidate;
}

function isAllowedTextFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  return FS_ALLOW_EXT.has(ext);
}

app.get('/api/notes', (req, res) => {
  const scoped = getScopedAccess(req);
  if (!hasPortalAccess(req) && !scoped) return res.status(401).json({ error: 'password_required' });

  const allowNotes = hasPortalAccess(req) ? null : new Set(listAllowedNotes(scoped));
  const files = fs.readdirSync(NOTES_DIR)
    .filter((n) => n.endsWith('.md'))
    .filter((n) => !allowNotes || allowNotes.has(n))
    .map((name) => {
      const full = path.join(NOTES_DIR, name);
      const stat = fs.statSync(full);
      return { name, mtimeMs: stat.mtimeMs, size: stat.size };
    })
    .sort((a, b) => b.mtimeMs - a.mtimeMs);
  res.json({ notes: files, scope: hasPortalAccess(req) ? 'admin' : 'code' });
});

app.get('/api/note/:name', (req, res) => {
  const name = safeName(req.params.name);
  if (!name) return res.status(400).json({ error: 'invalid_note_name' });

  if (!canAccessNote(req, name)) {
    return res.status(401).json({ error: 'password_required' });
  }

  const full = path.join(NOTES_DIR, name);
  if (!fs.existsSync(full)) return res.status(404).json({ error: 'not_found' });
  const markdown = fs.readFileSync(full, 'utf8');

  const scoped = getScopedAccess(req);
  if (scoped || hasPrivateToken(req, name)) {
    appendAccessEvent({
      ip: getClientIp(req),
      ua: req.headers['user-agent'],
      type: hasPrivateToken(req, name) ? 'private_note_read' : 'code_note_read',
      value: name,
      codeId: scoped ? scoped.codeId : null,
      ok: true,
    });
  }

  res.json({ name, markdown });
});

app.get('/api/auth/status', (req, res) => {
  const admin = hasPortalAccess(req);
  const scoped = getScopedAccess(req);
  res.json({
    required: Boolean(PORTAL_PASSWORD),
    unlocked: admin || Boolean(scoped),
    mode: admin ? 'admin' : (scoped ? 'code' : 'locked'),
    allowed_notes: listAllowedNotes(scoped),
    allowed_files: listAllowedFiles(scoped),
  });
});

app.post('/api/auth/unlock', (req, res) => {
  if (!PORTAL_PASSWORD) return res.json({ ok: true, required: false, mode: 'admin' });

  const limit = isAuthLimited(req);
  if (limit.limited) {
    return res.status(429).json({ ok: false, error: 'too_many_attempts', retry_after_ms: limit.retryAfterMs });
  }

  const inputCode = String(req.body?.password || '').trim();
  const proto = String(req.headers['x-forwarded-proto'] || '').toLowerCase();
  const secureFlag = (req.secure || proto.includes('https')) ? '; Secure' : '';

  if (secureEqual(inputCode, PORTAL_PASSWORD)) {
    clearAuthFailure(req);
    res.setHeader('Set-Cookie', [
      `${AUTH_COOKIE}=${encodeURIComponent(AUTH_TOKEN)}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax${secureFlag}`,
      `${ACCESS_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${secureFlag}`,
    ]);
    appendAccessEvent({
      ip: getClientIp(req),
      ua: req.headers['user-agent'],
      type: 'unlock_admin',
      ok: true,
    });
    return res.json({ ok: true, mode: 'admin' });
  }

  const codeHash = hashAccessCode(inputCode);
  const matched = readAccessCodes().find((row) => row.enabled !== false && String(row.codeHash || '') === codeHash);
  if (!matched) {
    markAuthFailure(req);
    appendAccessEvent({
      ip: getClientIp(req),
      ua: req.headers['user-agent'],
      type: 'unlock_code',
      ok: false,
    });
    return res.status(401).json({ ok: false, error: 'invalid_password' });
  }

  clearAuthFailure(req);
  const session = createAccessSession(matched.id, matched.resources || [], req);
  const ttlSec = Math.max(60, Math.floor((session.expiresAt - Date.now()) / 1000));
  res.setHeader('Set-Cookie', [
    `${ACCESS_COOKIE}=${encodeURIComponent(session.token)}; Path=/; Max-Age=${ttlSec}; HttpOnly; SameSite=Lax${secureFlag}`,
    `${AUTH_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${secureFlag}`,
  ]);

  appendAccessEvent({
    ip: getClientIp(req),
    ua: req.headers['user-agent'],
    type: 'unlock_code',
    codeId: matched.id,
    value: matched.label || matched.id,
    ok: true,
  });

  return res.json({
    ok: true,
    mode: 'code',
    label: matched.label || null,
    allowed_notes: (matched.resources || []).filter((x) => x.type === 'note').map((x) => x.value),
    allowed_files: (matched.resources || []).filter((x) => x.type === 'file').map((x) => x.value),
  });
});

app.put('/api/note/:name', (req, res) => {
  if (!hasWriteAccess(req)) return res.status(401).json({ error: 'unauthorized' });

  const name = safeName(req.params.name);
  if (!name) return res.status(400).json({ error: 'invalid_note_name' });

  const full = path.join(NOTES_DIR, name);
  if (!fs.existsSync(full)) return res.status(404).json({ error: 'not_found' });

  const markdown = String(req.body?.markdown || '');
  if (!markdown.trim()) return res.status(400).json({ error: 'empty_markdown' });

  fs.writeFileSync(full, markdown, 'utf8');
  const stat = fs.statSync(full);
  return res.json({ ok: true, name, size: stat.size, mtimeMs: stat.mtimeMs });
});

app.delete('/api/note/:name', (req, res) => {
  if (!hasWriteAccess(req)) return res.status(401).json({ error: 'unauthorized' });

  const name = safeName(req.params.name);
  if (!name) return res.status(400).json({ error: 'invalid_note_name' });

  const full = path.join(NOTES_DIR, name);
  if (!fs.existsSync(full)) return res.status(404).json({ error: 'not_found' });

  fs.unlinkSync(full);
  return res.json({ ok: true, deleted: name });
});

app.post('/api/publish', (req, res) => {
  if (!hasWriteAccess(req)) return res.status(401).json({ error: 'unauthorized' });

  const titleRaw = String(req.body?.title || 'note').trim();
  const markdown = String(req.body?.markdown || '');
  if (!markdown.trim()) return res.status(400).json({ error: 'empty_markdown' });

  const slug = titleRaw
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60) || 'note';

  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const file = `${stamp}-${slug}.md`;
  fs.writeFileSync(path.join(NOTES_DIR, file), markdown, 'utf8');

  const note = encodeURIComponent(file);
  const token = signPrivateNote(file);
  const privateQuery = token ? `?note=${note}&token=${token}` : `?note=${note}`;

  res.json({
    ok: true,
    note: file,
    view: `/?note=${note}`,
    private_view: `/private/${privateQuery}`,
    private_token: token || undefined,
  });
});

app.get('/api/access/resources', (req, res) => {
  const scoped = getScopedAccess(req);
  if (!hasPortalAccess(req) && !scoped) return res.status(401).json({ error: 'password_required' });

  if (hasPortalAccess(req)) {
    const notes = fs.readdirSync(NOTES_DIR)
      .filter((n) => n.endsWith('.md'))
      .sort();
    return res.json({
      resources: notes.map((name) => ({ type: 'note', value: name, label: name })),
      mode: 'admin',
    });
  }

  const resources = [];
  for (const name of listAllowedNotes(scoped)) {
    resources.push({ type: 'note', value: name, label: name });
  }
  for (const rel of listAllowedFiles(scoped)) {
    resources.push({ type: 'file', value: rel, label: rel });
  }
  return res.json({ resources, mode: 'code' });
});

app.get('/api/access-codes', (req, res) => {
  if (!hasPortalAccess(req)) return res.status(401).json({ error: 'unauthorized' });
  const codes = readAccessCodes().map((row) => ({
    id: row.id,
    label: row.label || '',
    enabled: row.enabled !== false,
    codePreview: row.codePreview || '',
    resources: Array.isArray(row.resources) ? row.resources : [],
    createdAt: row.createdAt || null,
    updatedAt: row.updatedAt || null,
  }));
  res.json({ codes });
});

app.post('/api/access-codes', (req, res) => {
  if (!hasPortalAccess(req)) return res.status(401).json({ error: 'unauthorized' });

  const code = String(req.body?.code || '').trim();
  const label = String(req.body?.label || '').trim();
  const enabled = req.body?.enabled !== false;
  const resourcesRaw = Array.isArray(req.body?.resources) ? req.body.resources : [];

  if (!code) return res.status(400).json({ error: 'code_required' });
  if (code.length < 4) return res.status(400).json({ error: 'code_too_short' });

  const resources = [];
  for (const r of resourcesRaw) {
    if (!r || typeof r !== 'object') continue;
    const type = r.type === 'file' ? 'file' : (r.type === 'note' ? 'note' : '');
    const value = String(r.value || '').trim();
    if (!type || !value) continue;
    if (type === 'note') {
      const safe = safeName(value);
      if (!safe) continue;
      resources.push({ type, value: safe });
    } else {
      const rel = cleanRelativePath(value);
      if (!rel || isPathBlocked(rel)) continue;
      resources.push({ type, value: rel });
    }
  }

  if (!resources.length) return res.status(400).json({ error: 'resources_required' });

  const codeHash = hashAccessCode(code);
  const now = new Date().toISOString();
  const codes = readAccessCodes();
  const dup = codes.find((x) => String(x.codeHash || '') === codeHash);
  if (dup) return res.status(409).json({ error: 'duplicate_code' });

  const row = {
    id: crypto.randomUUID(),
    label: label || 'Shared access',
    enabled,
    codeHash,
    codePreview: `${code.slice(0, 2)}***${code.slice(-2)}`,
    resources,
    createdAt: now,
    updatedAt: now,
  };
  codes.push(row);
  writeAccessCodes(codes);

  res.json({ ok: true, code: {
    id: row.id,
    label: row.label,
    enabled: row.enabled,
    codePreview: row.codePreview,
    resources: row.resources,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  } });
});

app.put('/api/access-codes/:id', (req, res) => {
  if (!hasPortalAccess(req)) return res.status(401).json({ error: 'unauthorized' });
  const id = String(req.params.id || '');
  const codes = readAccessCodes();
  const idx = codes.findIndex((x) => x.id === id);
  if (idx < 0) return res.status(404).json({ error: 'not_found' });

  const row = codes[idx];
  if (typeof req.body?.label === 'string') row.label = String(req.body.label).trim() || row.label;
  if (typeof req.body?.enabled === 'boolean') row.enabled = req.body.enabled;

  if (Array.isArray(req.body?.resources)) {
    const resources = [];
    for (const r of req.body.resources) {
      if (!r || typeof r !== 'object') continue;
      const type = r.type === 'file' ? 'file' : (r.type === 'note' ? 'note' : '');
      const value = String(r.value || '').trim();
      if (!type || !value) continue;
      if (type === 'note') {
        const safe = safeName(value);
        if (!safe) continue;
        resources.push({ type, value: safe });
      } else {
        const rel = cleanRelativePath(value);
        if (!rel || isPathBlocked(rel)) continue;
        resources.push({ type, value: rel });
      }
    }
    if (resources.length) row.resources = resources;
  }

  if (typeof req.body?.code === 'string' && String(req.body.code).trim()) {
    const code = String(req.body.code).trim();
    const codeHash = hashAccessCode(code);
    const dup = codes.find((x, i) => i !== idx && String(x.codeHash || '') === codeHash);
    if (dup) return res.status(409).json({ error: 'duplicate_code' });
    row.codeHash = codeHash;
    row.codePreview = `${code.slice(0, 2)}***${code.slice(-2)}`;
  }

  row.updatedAt = new Date().toISOString();
  codes[idx] = row;
  writeAccessCodes(codes);
  res.json({ ok: true, code: {
    id: row.id,
    label: row.label,
    enabled: row.enabled !== false,
    codePreview: row.codePreview || '',
    resources: row.resources || [],
    createdAt: row.createdAt || null,
    updatedAt: row.updatedAt || null,
  } });
});

app.delete('/api/access-codes/:id', (req, res) => {
  if (!hasPortalAccess(req)) return res.status(401).json({ error: 'unauthorized' });
  const id = String(req.params.id || '');
  const codes = readAccessCodes();
  const next = codes.filter((x) => x.id !== id);
  if (next.length === codes.length) return res.status(404).json({ error: 'not_found' });
  writeAccessCodes(next);
  res.json({ ok: true, deleted: id });
});

app.get('/api/access-events', (req, res) => {
  if (!hasPortalAccess(req)) return res.status(401).json({ error: 'unauthorized' });
  res.json({ events: recentAccessEvents(300) });
});

app.get('/api/access/file-read', (req, res) => {
  const relative = cleanRelativePath(req.query?.path || '');
  if (!relative) return res.status(400).json({ error: 'path_required' });
  if (isPathBlocked(relative)) return res.status(403).json({ error: 'blocked_path' });
  if (!canAccessFile(req, relative)) return res.status(401).json({ error: 'password_required' });

  const full = resolveSafePath(relative);
  if (!full) return res.status(400).json({ error: 'invalid_path' });

  let stat;
  try {
    stat = fs.statSync(full);
  } catch {
    return res.status(404).json({ error: 'not_found' });
  }
  if (!stat.isFile()) return res.status(400).json({ error: 'not_file' });
  if (!isAllowedTextFile(full)) return res.status(400).json({ error: 'unsupported_file_type' });
  if (stat.size > FS_MAX_READ_BYTES) return res.status(413).json({ error: 'file_too_large', maxBytes: FS_MAX_READ_BYTES });

  appendAccessEvent({
    ip: getClientIp(req),
    ua: req.headers['user-agent'],
    type: 'file_read',
    value: relative,
    codeId: (getScopedAccess(req) || {}).codeId || null,
    ok: true,
  });

  const content = fs.readFileSync(full, 'utf8');
  res.json({
    ok: true,
    path: relative,
    name: path.basename(relative),
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    content,
  });
});

app.get('/api/fs/list', (req, res) => {
  if (!hasPortalAccess(req)) return res.status(401).json({ error: 'password_required' });

  const relative = cleanRelativePath(req.query?.path || '');
  if (isPathBlocked(relative)) return res.status(403).json({ error: 'blocked_path' });

  const full = resolveSafePath(relative);
  if (!full) return res.status(400).json({ error: 'invalid_path' });

  let stat;
  try {
    stat = fs.statSync(full);
  } catch {
    return res.status(404).json({ error: 'not_found' });
  }
  if (!stat.isDirectory()) return res.status(400).json({ error: 'not_directory' });

  const items = fs.readdirSync(full, { withFileTypes: true })
    .filter((d) => !isPathBlocked(path.posix.join(relative, d.name)))
    .map((d) => {
      const rel = path.posix.join(relative, d.name);
      const abs = resolveSafePath(rel);
      if (!abs) return null;
      let s;
      try { s = fs.statSync(abs); } catch { return null; }
      return {
        name: d.name,
        path: rel,
        type: d.isDirectory() ? 'dir' : 'file',
        size: s.size,
        mtimeMs: s.mtimeMs,
        allowedText: d.isDirectory() ? true : isAllowedTextFile(abs),
      };
    })
    .filter(Boolean)
    .sort((a, b) => (a.type === b.type ? a.name.localeCompare(b.name) : (a.type === 'dir' ? -1 : 1)));

  res.json({
    ok: true,
    root: FS_ROOT,
    path: relative,
    parent: relative ? path.posix.dirname(relative) === '.' ? '' : path.posix.dirname(relative) : null,
    items,
  });
});

app.get('/api/fs/read', (req, res) => {
  if (!hasPortalAccess(req)) return res.status(401).json({ error: 'password_required' });

  const relative = cleanRelativePath(req.query?.path || '');
  if (!relative) return res.status(400).json({ error: 'path_required' });
  if (isPathBlocked(relative)) return res.status(403).json({ error: 'blocked_path' });

  const full = resolveSafePath(relative);
  if (!full) return res.status(400).json({ error: 'invalid_path' });

  let stat;
  try {
    stat = fs.statSync(full);
  } catch {
    return res.status(404).json({ error: 'not_found' });
  }
  if (!stat.isFile()) return res.status(400).json({ error: 'not_file' });
  if (!isAllowedTextFile(full)) return res.status(400).json({ error: 'unsupported_file_type' });
  if (stat.size > FS_MAX_READ_BYTES) return res.status(413).json({ error: 'file_too_large', maxBytes: FS_MAX_READ_BYTES });

  const content = fs.readFileSync(full, 'utf8');
  res.json({
    ok: true,
    path: relative,
    name: path.basename(relative),
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    content,
  });
});

app.get('/health', (_req, res) => res.send('ok'));

app.get(/^\/private(?:\/.*)?$/, (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, HOST, () => {
  console.log(`[md-portal] listening on http://${HOST}:${PORT}`);
});
