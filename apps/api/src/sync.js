import { NvdClient, normalizeNvdRecord } from './integrations/nvd.js';
import { CisaKevClient, normalizeKevCatalog } from './integrations/cisa-kev.js';
import { EpssClient, normalizeEpss } from './integrations/epss.js';
import { MitreCveClient, normalizeMitreCve } from './integrations/mitre-cve.js';
import { OsvClient, normalizeOsvVulnerability } from './integrations/osv.js';

export class SyncEngine {
  constructor(db, env = {}) {
    this.db = db;
    this.nvd = new NvdClient(env.NVD_API_KEY);
    this.kev = new CisaKevClient();
    this.epss = new EpssClient();
    this.mitreCve = new MitreCveClient();
    this.osv = new OsvClient();
  }

  providerAttempt(provider, fn) {
    const now = new Date().toISOString();
    const started = this.db.prepare(`
      INSERT INTO sync_history(provider, status, started_at) VALUES (?, 'running', ?)
    `).run(provider, now);
    const attemptAt = this.db.prepare(`
      INSERT INTO source_status(provider, availability, last_attempt_at)
      VALUES (?, 'checking', ?)
      ON CONFLICT(provider) DO UPDATE SET
        availability = 'checking',
        last_attempt_at = excluded.last_attempt_at
    `);
    attemptAt.run(provider, now);

    return fn().then(result => {
      const completed = new Date().toISOString();
      this.db.prepare(`
        UPDATE source_status SET
          availability = 'available',
          last_success_at = ?,
          last_error = NULL,
          records_retrieved = ?
        WHERE provider = ?
      `).run(completed, result.records, provider);
      this.db.prepare(`
        UPDATE sync_history SET status = 'success', completed_at = ?, records_processed = ?, message = ?
        WHERE id = ?
      `).run(completed, result.records, result.message || null, started.lastInsertRowid);
      return result;
    }).catch(error => {
      const completed = new Date().toISOString();
      this.db.prepare(`
        UPDATE source_status SET
          availability = 'unavailable',
          last_attempt_at = ?,
          last_error = ?
        WHERE provider = ?
      `).run(completed, error.message, provider);
      this.db.prepare(`
        UPDATE sync_history SET status = 'failed', completed_at = ?, error = ?
        WHERE id = ?
      `).run(completed, error.message, started.lastInsertRowid);
      throw error;
    });
  }

  upsertSource(metadata, payload) {
    this.db.prepare(`
      INSERT INTO source_records(
        provider, record_id, source_url, retrieved_at, last_modified,
        source_update, data_version, license, payload
      ) VALUES (
        @provider, @recordId, @sourceUrl, @retrievedAt, @lastModified,
        @sourceUpdate, @dataVersion, @license, @payload
      )
      ON CONFLICT(provider, record_id) DO UPDATE SET
        source_url = excluded.source_url,
        retrieved_at = excluded.retrieved_at,
        last_modified = excluded.last_modified,
        source_update = excluded.source_update,
        data_version = excluded.data_version,
        license = excluded.license,
        payload = excluded.payload
    `).run({ ...metadata, payload: JSON.stringify(payload) });
  }

  syncNvd() {
    return this.providerAttempt('NIST NVD', async () => {
      const retrievedAt = new Date().toISOString();
      const knownIds = ['CVE-2021-44228', 'CVE-2024-3094'];
      const seen = new Map();

      for (const cveId of knownIds) {
        const payload = await this.nvd.fetchCve(cveId);
        for (const item of payload.vulnerabilities) {
          seen.set(item.cve.id, item);
        }
      }

      const recent = await this.nvd.fetchRecent(20);
      for (const item of recent.vulnerabilities) seen.set(item.cve.id, item);

      const upsert = this.db.transaction(() => {
        for (const item of seen.values()) {
          const record = normalizeNvdRecord(item, retrievedAt);
          this.db.prepare(`
            INSERT INTO vulnerabilities(
              cve_id, description, published, modified, severity, cvss_score,
              cvss_vector, cwes, cpes, "references", source_metadata, retrieved_at, updated_at
            ) VALUES (
              @id, @description, @published, @modified, @severity, @cvssScore,
              @cvssVector, @cwesJson, @cpesJson, @referencesJson, @metadataJson, @retrievedAt, @retrievedAt
            )
            ON CONFLICT(cve_id) DO UPDATE SET
              description = excluded.description,
              published = excluded.published,
              modified = excluded.modified,
              severity = excluded.severity,
              cvss_score = excluded.cvss_score,
              cvss_vector = excluded.cvss_vector,
              cwes = excluded.cwes,
              cpes = excluded.cpes,
              "references" = excluded."references",
              source_metadata = excluded.source_metadata,
              retrieved_at = excluded.retrieved_at,
              updated_at = excluded.updated_at
          `).run({
            id: record.id,
            description: record.description,
            published: record.published,
            modified: record.modified,
            severity: record.severity,
            cvssScore: record.cvssScore,
            cvssVector: record.cvssVector,
            cwesJson: JSON.stringify(record.cwes),
            cpesJson: JSON.stringify(record.cpes),
            referencesJson: JSON.stringify(record.references),
            metadataJson: JSON.stringify(record.metadata),
            retrievedAt
          });
          this.upsertSource(record.metadata, item);
        }
      });
      upsert();
      return { records: seen.size, message: `Imported ${seen.size} verified NVD CVE records` };
    });
  }

  syncKev() {
    return this.providerAttempt('CISA KEV', async () => {
      const retrievedAt = new Date().toISOString();
      const payload = await this.kev.fetchCatalog();
      const records = normalizeKevCatalog(payload, retrievedAt);
      const write = this.db.transaction(() => {
        for (const record of records) {
          this.db.prepare(`
            INSERT INTO kev_records(
              cve_id, vendor_project, product, date_added, due_date, required_action,
              known_ransomware_campaign_use, short_description, source_metadata, retrieved_at
            ) VALUES (
              @cveId, @vendorProject, @product, @dateAdded, @dueDate, @requiredAction,
              @knownRansomwareCampaignUse, @shortDescription, @metadataJson, @retrievedAt
            )
            ON CONFLICT(cve_id) DO UPDATE SET
              vendor_project = excluded.vendor_project,
              product = excluded.product,
              date_added = excluded.date_added,
              due_date = excluded.due_date,
              required_action = excluded.required_action,
              known_ransomware_campaign_use = excluded.known_ransomware_campaign_use,
              short_description = excluded.short_description,
              source_metadata = excluded.source_metadata,
              retrieved_at = excluded.retrieved_at
          `).run({
            ...record,
            metadataJson: JSON.stringify(record.metadata),
            retrievedAt
          });
          this.upsertSource(record.metadata, record);
        }
      });
      write();
      return { records: records.length, message: `Imported ${records.length} CISA KEV records` };
    });
  }

  syncEpss() {
    return this.providerAttempt('FIRST EPSS', async () => {
      const cveIds = this.db.prepare(
        'SELECT cve_id FROM vulnerabilities ORDER BY cve_id LIMIT 100'
      ).all().map(row => row.cve_id);
      if (!cveIds.length) return { records: 0, message: 'No CVE IDs available for EPSS lookup' };
      const retrievedAt = new Date().toISOString();
      const payload = await this.epss.fetchForCves(cveIds);
      const records = normalizeEpss(payload, retrievedAt);
      const write = this.db.transaction(() => {
        for (const record of records) {
          this.db.prepare(`
            INSERT INTO epss_scores(cve_id, score, percentile, score_date, source_metadata, retrieved_at)
            VALUES (@cveId, @score, @percentile, @scoreDate, @metadataJson, @retrievedAt)
            ON CONFLICT(cve_id) DO UPDATE SET
              score = excluded.score,
              percentile = excluded.percentile,
              score_date = excluded.score_date,
              source_metadata = excluded.source_metadata,
              retrieved_at = excluded.retrieved_at
          `).run({ ...record, metadataJson: JSON.stringify(record.metadata), retrievedAt });
          this.upsertSource(record.metadata, record);
        }
      });
      write();
      return { records: records.length, message: `Retrieved EPSS for ${records.length} CVEs` };
    });
  }

  syncOsv() {
    return this.providerAttempt('OSV', async () => {
      const packages = [
        { ecosystem: 'Maven', name: 'org.apache.logging.log4j:log4j-core', version: '2.14.1' },
        { ecosystem: 'npm', name: 'lodash', version: '4.17.20' }
      ];
      const retrievedAt = new Date().toISOString();
      const records = [];

      for (const pkg of packages) {
        const payload = await this.osv.queryPackage(pkg.ecosystem, pkg.name, pkg.version);
        for (const vulnerability of payload.vulns || []) {
          records.push(normalizeOsvVulnerability(
            vulnerability,
            pkg.ecosystem,
            pkg.name,
            pkg.version,
            retrievedAt
          ));
        }
      }

      const write = this.db.transaction(() => {
        for (const record of records) {
          this.db.prepare(`
            INSERT INTO osv_records(
              osv_id, ecosystem, package_name, queried_version, summary, details, severity,
              published, modified, cve_ids, fixed_versions, "references",
              source_metadata, retrieved_at
            ) VALUES (
              @id, @ecosystem, @packageName, @queriedVersion, @summary, @details, @severity,
              @published, @modified, @cveIdsJson, @fixedVersionsJson, @referencesJson,
              @metadataJson, @retrievedAt
            )
            ON CONFLICT(osv_id, ecosystem, package_name, queried_version) DO UPDATE SET
              summary = excluded.summary,
              details = excluded.details,
              severity = excluded.severity,
              published = excluded.published,
              modified = excluded.modified,
              cve_ids = excluded.cve_ids,
              fixed_versions = excluded.fixed_versions,
              "references" = excluded."references",
              source_metadata = excluded.source_metadata,
              retrieved_at = excluded.retrieved_at
          `).run({
            ...record,
            cveIdsJson: JSON.stringify(record.cveIds),
            fixedVersionsJson: JSON.stringify(record.fixedVersions),
            referencesJson: JSON.stringify(record.references),
            metadataJson: JSON.stringify(record.metadata),
            retrievedAt
          });
          this.upsertSource(record.metadata, record);
        }
      });
      write();
      return {
        records: records.length,
        message: `Retrieved ${records.length} OSV package vulnerabilities`
      };
    });
  }

  async syncAll() {
    const results = [];
    for (const [name, fn] of [
      ['NIST NVD', () => this.syncNvd()],
      ['CISA KEV', () => this.syncKev()],
      ['FIRST EPSS', () => this.syncEpss()],
      ['OSV', () => this.syncOsv()]
    ]) {
      try {
        results.push({ provider: name, ...await fn() });
      } catch (error) {
        results.push({ provider: name, status: 'failed', error: error.message });
      }
    }
    return results;
  }
}
