import 'dotenv/config';
import express from 'express';
import cron from 'node-cron';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { createDatabase } from './db.js';
import { SyncEngine } from './sync.js';

const port = Number(process.env.PORT || 3000);
const databasePath = path.resolve(process.env.DATABASE_PATH || './data/sentinel.db');
const db = createDatabase(databasePath);
const engine = new SyncEngine(db, process.env);
const app = express();

const demoEmail = (process.env.DEMO_EMAIL || 'demo@sentinel.ai').trim().toLowerCase();
const demoPassword = process.env.DEMO_PASSWORD || 'Sentinel123!';
const existingDemo = db.prepare('SELECT id FROM users WHERE email = ?').get(demoEmail);
if (!existingDemo) {
  const demoSalt = crypto.randomBytes(16).toString('hex');
  db.prepare(`
    INSERT INTO users(name, email, password_hash, password_salt)
    VALUES (?, ?, ?, ?)
  `).run('Demo Operator', demoEmail, hashPassword(demoPassword, demoSalt), demoSalt);
}
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.resolve(__dirname, '../../../public');
app.get(['/', '/dashboard', '/vulnerabilities', '/sources', '/verification'], (req, res, next) => {
  if (!readSession(req)) return res.redirect('/login');
  next();
});
app.use(express.static(publicDir));

app.post('/api/auth/register', (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (name.length < 2) return res.status(400).json({ error: 'Name must be at least 2 characters' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'A valid email address is required' });
  }
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) {
    return res.status(409).json({ error: 'An account already exists for this email' });
  }

  const salt = crypto.randomBytes(16).toString('hex');
  const passwordHash = hashPassword(password, salt);
  const inserted = db.prepare(`
    INSERT INTO users(name, email, password_hash, password_salt)
    VALUES (?, ?, ?, ?)
  `).run(name, email, passwordHash, salt);
  const user = { id: inserted.lastInsertRowid, name, email };

  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  db.prepare(`
    INSERT INTO sessions(token_hash, user_id, expires_at)
    VALUES (?, ?, ?)
  `).run(hashToken(token), user.id, expiresAt);
  res.setHeader('Set-Cookie', `sentinel_session=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${7 * 24 * 60 * 60}`);
  res.status(201).json({ user });
});

app.post('/api/auth/login', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const row = db.prepare(`
    SELECT id, name, email, password_hash, password_salt
    FROM users
    WHERE email = ?
  `).get(email);
  if (!row || !crypto.timingSafeEqual(
    Buffer.from(row.password_hash, 'hex'),
    Buffer.from(hashPassword(password, row.password_salt), 'hex')
  )) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
  db.prepare(`
    INSERT INTO sessions(token_hash, user_id, expires_at)
    VALUES (?, ?, ?)
  `).run(hashToken(token), row.id, expiresAt);
  res.setHeader('Set-Cookie', `sentinel_session=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${7 * 24 * 60 * 60}`);
  res.json({ user: { id: row.id, name: row.name, email: row.email } });
});

app.post('/api/auth/logout', (req, res) => {
  const cookie = req.headers.cookie || '';
  const match = cookie.split(';').map(v => v.trim()).find(v => v.startsWith('sentinel_session='));
  if (match) {
    db.prepare('DELETE FROM sessions WHERE token_hash = ?')
      .run(hashToken(match.slice('sentinel_session='.length)));
  }
  res.setHeader('Set-Cookie', 'sentinel_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/auth/me', (req, res) => {
  const user = readSession(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  res.json({ user });
});

let syncRunning = false;

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function readSession(req) {
  const cookie = req.headers.cookie || '';
  const match = cookie.split(';').map(v => v.trim()).find(v => v.startsWith('sentinel_session='));
  if (!match) return null;
  const token = match.slice('sentinel_session='.length);
  return db.prepare(`
    SELECT u.id, u.name, u.email
    FROM sessions s
    JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.expires_at > ?
  `).get(hashToken(token), new Date().toISOString());
}

function requireAuth(req, res, next) {
  const user = readSession(req);
  if (!user) return res.status(401).json({ error: 'Authentication required' });
  req.user = user;
  next();
}

if (process.env.SYNC_ENABLED !== 'false') {
  const cronExpression = process.env.SYNC_CRON || '0 3 * * *';
  if (cron.validate(cronExpression)) {
    cron.schedule(cronExpression, async () => {
      if (syncRunning) return;
      syncRunning = true;
      try {
        await engine.syncAll();
      } finally {
        syncRunning = false;
      }
    });
  } else {
    console.error(`Invalid SYNC_CRON expression: ${cronExpression}`);
  }
}

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', database: fs.existsSync(databasePath), timestamp: new Date().toISOString() });
});

app.get('/api/analytics', requireAuth, (_req, res) => {
  const totals = db.prepare(`
    SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN LOWER(severity) = 'critical' THEN 1 ELSE 0 END) AS critical,
      SUM(CASE WHEN LOWER(severity) = 'high' THEN 1 ELSE 0 END) AS high
    FROM vulnerabilities
  `).get();
  const knownExploited = db.prepare(`
    SELECT COUNT(*) AS count FROM kev_records
  `).get();
  const epss = db.prepare(`
    SELECT
      COUNT(*) AS count,
      ROUND(AVG(score), 6) AS average,
      ROUND(MAX(score), 6) AS maximum
    FROM epss_scores
  `).get();
  const remediation = db.prepare(`
    SELECT
      COUNT(*) AS total,
      SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed
    FROM remediation_tasks
  `).get();
  const osv = db.prepare(`
    SELECT COUNT(*) AS count FROM osv_records
  `).get();

  res.json({
    totalVulnerabilities: totals.total,
    criticalVulnerabilities: totals.critical || 0,
    highVulnerabilities: totals.high || 0,
    knownExploited: knownExploited.count,
    epss,
    osv,
    remediation,
    freshness: db.prepare(`
      SELECT provider, availability, last_attempt_at, last_success_at, last_error, records_retrieved
      FROM source_status
    `).all(),
    calculatedAt: new Date().toISOString()
  });
});

app.get('/api/vulnerabilities', requireAuth, (req, res) => {
  const limit = Math.min(Number(req.query.limit || 50), 200);
  const offset = Math.max(Number(req.query.offset || 0), 0);
  const rows = db.prepare(`
    SELECT v.*,
      k.cve_id AS kev_cve_id,
      k.date_added AS kev_date_added,
      k.required_action AS kev_required_action,
      e.score AS epss_score,
      e.percentile AS epss_percentile,
      e.score_date AS epss_score_date
    FROM vulnerabilities v
    LEFT JOIN kev_records k ON k.cve_id = v.cve_id
    LEFT JOIN epss_scores e ON e.cve_id = v.cve_id
    ORDER BY v.published DESC, v.cve_id DESC
    LIMIT ? OFFSET ?
  `).all(limit, offset);
  res.json({
    data: rows.map(row => ({
      ...row,
      cwes: JSON.parse(row.cwes),
      cpes: JSON.parse(row.cpes),
      references: JSON.parse(row.references),
      sourceMetadata: JSON.parse(row.source_metadata),
      knownExploited: Boolean(row.kev_cve_id)
    })),
    count: db.prepare('SELECT COUNT(*) AS count FROM vulnerabilities').get().count,
    limit,
    offset
  });
});

app.get('/api/vulnerabilities/:cveId', requireAuth, (req, res) => {
  const cveId = String(req.params.cveId).toUpperCase();
  const row = db.prepare(`
    SELECT v.*,
      k.cve_id AS kev_cve_id,
      k.vendor_project AS kev_vendor,
      k.product AS kev_product,
      k.date_added AS kev_date_added,
      k.due_date AS kev_due_date,
      k.required_action AS kev_required_action,
      k.known_ransomware_campaign_use AS kev_ransomware,
      k.short_description AS kev_description,
      e.score AS epss_score,
      e.percentile AS epss_percentile,
      e.score_date AS epss_score_date,
      e.source_metadata AS epss_source_metadata
    FROM vulnerabilities v
    LEFT JOIN kev_records k ON k.cve_id = v.cve_id
    LEFT JOIN epss_scores e ON e.cve_id = v.cve_id
    WHERE v.cve_id = ?
  `).get(cveId);
  if (!row) return res.status(404).json({ error: 'CVE not found in the local verified dataset' });
  const sources = db.prepare(`
    SELECT provider, record_id, source_url, retrieved_at, last_modified,
      source_update, data_version, license
    FROM source_records
    WHERE record_id = ?
  `).all(cveId);
  res.json({
    ...row,
    cwes: JSON.parse(row.cwes),
    cpes: JSON.parse(row.cpes),
    references: JSON.parse(row.references),
    sourceMetadata: JSON.parse(row.source_metadata),
    epssSourceMetadata: row.epss_source_metadata ? JSON.parse(row.epss_source_metadata) : null,
    knownExploited: Boolean(row.kev_cve_id),
    sources
  });
});

app.get('/api/sources', requireAuth, (_req, res) => {
  const providers = [
    ['NIST NVD', 'https://nvd.nist.gov/', 'CVE, CVSS, CWE, CPE and references'],
    ['CISA KEV', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', 'Known exploited status and remediation actions'],
    ['FIRST EPSS', 'https://www.first.org/epss/', 'Exploit probability and percentile'],
    ['MITRE CVE', 'https://www.cve.org/', 'Original CVE metadata'],
    ['OSV', 'https://osv.dev/', 'Open-source package advisories'],
    ['GitHub Advisory Database', 'https://github.com/advisories', 'Package security advisories']
  ];
  const status = db.prepare(`
    SELECT provider, availability, last_attempt_at, last_success_at, last_error, records_retrieved
    FROM source_status
  `).all();
  res.json({
    nvdDisclaimer: 'This product uses data from the NVD API but is not endorsed or certified by the NVD.',
    providers: providers.map(([name, url, dataType]) => ({
      name,
      url,
      dataType,
      status: status.find(s => s.provider === name) || {
        availability: 'not_requested',
        last_attempt_at: null,
        last_success_at: null,
        last_error: null,
        records_retrieved: 0
      }
    }))
  });
});

app.get('/api/sync/history', requireAuth, (_req, res) => {
  res.json(db.prepare(`
    SELECT * FROM sync_history ORDER BY started_at DESC LIMIT 100
  `).all());
});

app.get('/api/verification', requireAuth, (_req, res) => {
  const nvdCount = db.prepare('SELECT COUNT(*) AS count FROM vulnerabilities').get().count;
  const kevCount = db.prepare('SELECT COUNT(*) AS count FROM kev_records').get().count;
  const epssCount = db.prepare('SELECT COUNT(*) AS count FROM epss_scores').get().count;
  const osvCount = db.prepare('SELECT COUNT(*) AS count FROM osv_records').get().count;
  const sourceCount = db.prepare('SELECT COUNT(*) AS count FROM source_records').get().count;
  const syncCount = db.prepare('SELECT COUNT(*) AS count FROM sync_history').get().count;
  const statuses = db.prepare('SELECT provider, availability, last_success_at, last_error FROM source_status').all();

  res.json({
    nvdVerifiedRecords: nvdCount,
    cisaKevVerifiedRecords: kevCount,
    epssVerifiedRecords: epssCount,
    osvVerifiedRecords: osvCount,
    provenanceRecords: sourceCount,
    synchronizationHistoryRecords: syncCount,
    sourceStatuses: statuses,
    checklist: {
      nvdApi: nvdCount > 0,
      cisaKev: kevCount > 0,
      epss: epssCount > 0,
      osv: osvCount > 0,
      provenance: sourceCount > 0,
      databaseBackedDashboard: nvdCount > 0,
      mockDataAudit: 'Run npm run verify:production',
      synchronizationHistory: syncCount > 0,
      aiGrounding: false,
      mlEvaluation: false,
      productionDeployment: false
    },
    calculatedAt: new Date().toISOString()
  });
});

app.get('/api/osv', requireAuth, (_req, res) => {
  const rows = db.prepare(`
    SELECT * FROM osv_records ORDER BY retrieved_at DESC, osv_id
  `).all();
  res.json({
    data: rows.map(row => ({
      ...row,
      cve_ids: JSON.parse(row.cve_ids),
      fixed_versions: JSON.parse(row.fixed_versions),
      references: JSON.parse(row.references),
      source_metadata: JSON.parse(row.source_metadata)
    })),
    count: rows.length
  });
});

app.post('/api/sync', requireAuth, async (_req, res) => {
  if (syncRunning) return res.status(409).json({ error: 'A synchronization job is already running' });
  syncRunning = true;
  try {
    const results = await engine.syncAll();
    res.json({ results, timestamp: new Date().toISOString() });
  } catch (error) {
    res.status(500).json({ error: error.message });
  } finally {
    syncRunning = false;
  }
});

app.get('*all', (req, res) => {
  if (req.path !== '/login' && req.path !== '/register' && !readSession(req)) {
    return res.redirect('/login');
  }
  res.sendFile(path.join(publicDir, 'index.html'));
});

app.listen(port, () => {
  console.log(`Sentinel AI listening at http://localhost:${port}`);
});
