import { fetchJson, sourceMetadata } from './http.js';

export const NVD_SOURCE_URL = 'https://nvd.nist.gov/';

export class NvdClient {
  constructor(apiKey) {
    this.apiKey = apiKey;
  }

  async fetchCve(cveId) {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
    const headers = this.apiKey ? { apiKey: this.apiKey } : {};
    const payload = await fetchJson(url, { headers, retries: 3, retryDelayMs: 2000 });
    if (!payload || !Array.isArray(payload.vulnerabilities)) {
      throw new Error('NVD returned a response without a vulnerabilities array');
    }
    if (payload.vulnerabilities.length !== 1) {
      throw new Error(`NVD returned ${payload.vulnerabilities.length} records for ${cveId}`);
    }
    return payload;
  }

  async fetchRecent(limit = 20) {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=${limit}`;
    const headers = this.apiKey ? { apiKey: this.apiKey } : {};
    const payload = await fetchJson(url, { headers, retries: 3, retryDelayMs: 2000 });
    if (!payload || !Array.isArray(payload.vulnerabilities)) {
      throw new Error('NVD returned a response without a vulnerabilities array');
    }
    return payload;
  }
}

export function normalizeNvdRecord(item, retrievedAt = new Date().toISOString()) {
  if (!item?.cve?.id) throw new Error('NVD CVE item is missing its id');
  const cve = item.cve;
  const english = cve.descriptions?.find(d => d.lang === 'en');
  const metrics = cve.metrics || {};
  const cvssV31 = metrics.cvssMetricV31?.[0]?.cvssData;
  const cvssV30 = metrics.cvssMetricV30?.[0]?.cvssData;
  const cvssV2 = metrics.cvssMetricV2?.[0]?.cvssData;
  const cvss = cvssV31 || cvssV30 || cvssV2;
  const cwes = (cve.weaknesses || [])
    .flatMap(w => w.description || [])
    .filter(d => d.lang === 'en')
    .map(d => d.value)
    .filter(value => /^CWE-\d+$/.test(value));

  return {
    id: cve.id,
    description: english?.value || null,
    published: cve.published || null,
    modified: cve.lastModified || null,
    severity: cvss?.baseSeverity || cvss?.baseSeverity || null,
    cvssScore: typeof cvss?.baseScore === 'number' ? cvss.baseScore : null,
    cvssVector: cvss?.vectorString || null,
    cwes: [...new Set(cwes)],
    cpes: (cve.configurations || []).flatMap(config =>
      (config.nodes || []).flatMap(node =>
        (node.cpeMatch || []).map(match => match.criteria).filter(Boolean)
      )
    ),
    references: (cve.references || []).map(r => ({ url: r.url, source: r.source, tags: r.tags || [] })),
    metadata: sourceMetadata(
      'NIST NVD',
      cve.id,
      `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.id)}`,
      retrievedAt,
      { lastModified: cve.lastModified, license: 'NVD data is provided by NIST; source disclaimer applies.' }
    )
  };
}
