import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { createDatabase } from '../apps/api/src/db.js';
import { SyncEngine } from '../apps/api/src/sync.js';
import { NvdClient, normalizeNvdRecord } from '../apps/api/src/integrations/nvd.js';
import { CisaKevClient } from '../apps/api/src/integrations/cisa-kev.js';
import { EpssClient } from '../apps/api/src/integrations/epss.js';
import { OsvClient, normalizeOsvVulnerability } from '../apps/api/src/integrations/osv.js';

test('duplicate imports are prevented by primary key', () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-')), 'test.db');
  const db = createDatabase(file);
  const retrievedAt = new Date().toISOString();
  const item = {
    cve: {
      id: 'CVE-TEST-0001',
      descriptions: [{ lang: 'en', value: 'Test record' }],
      published: retrievedAt,
      lastModified: retrievedAt,
      metrics: {},
      weaknesses: [],
      configurations: [],
      references: []
    }
  };
  const record = normalizeNvdRecord(item, retrievedAt);
  const insert = db.prepare(`
    INSERT INTO vulnerabilities(cve_id, description, retrieved_at, source_metadata)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(cve_id) DO UPDATE SET description = excluded.description
  `);
  insert.run(record.id, record.description, retrievedAt, JSON.stringify(record.metadata));
  insert.run(record.id, record.description, retrievedAt, JSON.stringify(record.metadata));
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM vulnerabilities').get().count, 1);
  db.close();
});

test('live NVD, CISA KEV and EPSS end-to-end integration', { timeout: 120_000 }, async () => {
  const cveId = 'CVE-2021-44228';
  const nvd = new NvdClient(process.env.NVD_API_KEY);
  const nvdPayload = await nvd.fetchCve(cveId);
  assert.equal(nvdPayload.vulnerabilities[0].cve.id, cveId);

  const kevPayload = await new CisaKevClient().fetchCatalog();
  assert.ok(Array.isArray(kevPayload.vulnerabilities));

  const epssPayload = await new EpssClient().fetchForCves([cveId]);
  assert.ok(Array.isArray(epssPayload.data));

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-live-'));
  const db = createDatabase(path.join(dir, 'sentinel.db'));
  const engine = new SyncEngine(db, process.env);
  const nvdResult = await engine.syncNvd();
  assert.ok(nvdResult.records > 0);
  const kevResult = await engine.syncKev();
  assert.ok(kevResult.records > 0);
  const epssResult = await engine.syncEpss();
  assert.ok(epssResult.records >= 0);

  const row = db.prepare('SELECT * FROM vulnerabilities WHERE cve_id = ?').get(cveId);
  assert.ok(row);
  assert.equal(row.cve_id, cveId);
  assert.ok(JSON.parse(db.prepare('SELECT source_metadata FROM vulnerabilities WHERE cve_id = ?').get(cveId).source_metadata));
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM source_records WHERE record_id = ?').get(cveId).count > 0, true);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM sync_history').get().count >= 3, true);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM kev_records WHERE cve_id = ?').get(cveId).count > 0, true);
  db.close();
});

test('live OSV package vulnerability integration', { timeout: 120_000 }, async () => {
  const osv = new OsvClient();
  const payload = await osv.queryPackage(
    'Maven',
    'org.apache.logging.log4j:log4j-core',
    '2.14.1'
  );
  assert.ok(payload.vulns.length > 0);
  const normalized = normalizeOsvVulnerability(
    payload.vulns[0],
    'Maven',
    'org.apache.logging.log4j:log4j-core',
    '2.14.1'
  );
  assert.ok(normalized.id);
  assert.equal(normalized.ecosystem, 'Maven');
  assert.ok(normalized.sourceUrl === undefined || normalized.metadata.sourceUrl);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sentinel-osv-'));
  const db = createDatabase(path.join(dir, 'sentinel.db'));
  const engine = new SyncEngine(db, process.env);
  const result = await engine.syncOsv();
  assert.ok(result.records > 0);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM osv_records').get().count > 0, true);
  assert.equal(db.prepare('SELECT COUNT(*) AS count FROM source_records').get().count > 0, true);
  db.close();
});
