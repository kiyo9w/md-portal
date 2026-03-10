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
const NOTES_DIR = path.join(__dirname, 'notes');
const PUBLISH_TOKEN = process.env.PUBLISH_TOKEN || '';
const PORTAL_PASSWORD = String(process.env.MD_PORTAL_PASSWORD || '').trim();
const PRIVATE_LINK_SECRET = String(process.env.PRIVATE_LINK_SECRET || PORTAL_PASSWORD || '').trim();
const AUTH_COOKIE = 'md_portal_auth';
const AUTH_TOKEN = PORTAL_PASSWORD
  ? crypto.createHash('sha256').update(PORTAL_PASSWORD).digest('hex').slice(0, 32)
  : '';

if (!fs.existsSync(NOTES_DIR)) fs.mkdirSync(NOTES_DIR, { recursive: true });

app.use(express.json({ limit: '2mb' }));
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

function hasPortalAccess(req) {
  if (!PORTAL_PASSWORD) return true;
  const cookies = parseCookies(req);
  return cookies[AUTH_COOKIE] === AUTH_TOKEN;
}

function isPrivateBypass(req) {
  return String(req.query?.private || '') === '1';
}

function signPrivateNote(name) {
  if (!PRIVATE_LINK_SECRET) return '';
  return crypto.createHmac('sha256', PRIVATE_LINK_SECRET).update(name).digest('hex').slice(0, 24);
}

function hasPrivateToken(req, name) {
  if (!isPrivateBypass(req)) return false;
  const token = String(req.query?.token || '');
  if (!token) return false;
  const expected = signPrivateNote(name);
  if (!expected) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected));
  } catch {
    return false;
  }
}

app.get('/api/notes', (req, res) => {
  if (!hasPortalAccess(req)) return res.status(401).json({ error: 'password_required' });

  const files = fs.readdirSync(NOTES_DIR)
    .filter((n) => n.endsWith('.md'))
    .map((name) => {
      const full = path.join(NOTES_DIR, name);
      const stat = fs.statSync(full);
      return { name, mtimeMs: stat.mtimeMs, size: stat.size };
    })
    .sort((a, b) => b.mtimeMs - a.mtimeMs);
  res.json({ notes: files });
});

app.get('/api/note/:name', (req, res) => {
  const name = safeName(req.params.name);
  if (!name) return res.status(400).json({ error: 'invalid_note_name' });

  const allowedByPortal = hasPortalAccess(req);
  const allowedByPrivateToken = hasPrivateToken(req, name);
  if (!allowedByPortal && !allowedByPrivateToken) {
    return res.status(401).json({ error: 'password_required' });
  }

  const full = path.join(NOTES_DIR, name);
  if (!fs.existsSync(full)) return res.status(404).json({ error: 'not_found' });
  const markdown = fs.readFileSync(full, 'utf8');
  res.json({ name, markdown });
});

app.get('/api/auth/status', (req, res) => {
  res.json({ required: Boolean(PORTAL_PASSWORD), unlocked: hasPortalAccess(req) });
});

app.post('/api/auth/unlock', (req, res) => {
  if (!PORTAL_PASSWORD) return res.json({ ok: true, required: false });

  const password = String(req.body?.password || '');
  if (password !== PORTAL_PASSWORD) {
    return res.status(401).json({ ok: false, error: 'invalid_password' });
  }

  res.setHeader('Set-Cookie', `${AUTH_COOKIE}=${encodeURIComponent(AUTH_TOKEN)}; Path=/; Max-Age=2592000; HttpOnly; SameSite=Lax`);
  return res.json({ ok: true });
});

app.post('/api/publish', (req, res) => {
  if (PUBLISH_TOKEN) {
    const auth = req.header('authorization') || '';
    if (auth !== `Bearer ${PUBLISH_TOKEN}`) return res.status(401).json({ error: 'unauthorized' });
  }

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

app.get('/health', (_req, res) => res.send('ok'));

app.get(/^\/private(?:\/.*)?$/, (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, HOST, () => {
  console.log(`[md-portal] listening on http://${HOST}:${PORT}`);
});
