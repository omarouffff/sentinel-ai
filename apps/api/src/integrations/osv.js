import { fetchJson, sourceMetadata } from './http.js';

export class OsvClient {
  async queryPackage(ecosystem, packageName, version) {
    if (!ecosystem || !packageName || !version) {
      throw new Error('OSV package queries require ecosystem, package name and version');
    }
    const payload = await fetchJson('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package: { ecosystem, name: packageName }, version }),
      retries: 2
    });
    if (!payload || !Array.isArray(payload.vulns)) {
      throw new Error('OSV returned a response without a vulns array');
    }
    return payload;
  }
}

export function normalizeOsvVulnerability(vulnerability, ecosystem, packageName, version, retrievedAt = new Date().toISOString()) {
  if (!vulnerability?.id) throw new Error('OSV vulnerability is missing its id');
  const affected = (vulnerability.affected || []).filter(entry =>
    entry.package?.ecosystem === ecosystem && entry.package?.name === packageName
  );
  const ranges = affected.flatMap(entry => entry.ranges || []);
  const fixedVersions = [...new Set(
    ranges.flatMap(range => (range.events || []).filter(event => event.fixed).map(event => event.fixed))
  )];
  const cveIds = (vulnerability.aliases || []).filter(alias => /^CVE-\d{4}-\d{4,}$/.test(alias));

  return {
    id: vulnerability.id,
    ecosystem,
    packageName,
    queriedVersion: version,
    summary: vulnerability.summary || null,
    details: vulnerability.details || null,
    severity: (vulnerability.database_specific?.severity || null),
    published: vulnerability.published || null,
    modified: vulnerability.modified || null,
    cveIds,
    fixedVersions,
    references: vulnerability.references || [],
    metadata: sourceMetadata(
      'OSV',
      vulnerability.id,
      `https://osv.dev/vulnerability/${encodeURIComponent(vulnerability.id)}`,
      retrievedAt,
      { lastModified: vulnerability.modified, dataVersion: vulnerability.schema_version || null }
    )
  };
}
