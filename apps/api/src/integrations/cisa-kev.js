import { fetchJson, sourceMetadata } from './http.js';

export class CisaKevClient {
  async fetchCatalog() {
    const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
    const payload = await fetchJson(url, { retries: 3, retryDelayMs: 1500 });
    if (!payload || !Array.isArray(payload.vulnerabilities)) {
      throw new Error('CISA KEV returned a response without a vulnerabilities array');
    }
    return payload;
  }
}

export function normalizeKevCatalog(payload, retrievedAt = new Date().toISOString()) {
  return payload.vulnerabilities.map(vulnerability => ({
    cveId: vulnerability.cveID,
    vendorProject: vulnerability.vendorProject,
    product: vulnerability.product,
    dateAdded: vulnerability.dateAdded,
    dueDate: vulnerability.dueDate,
    requiredAction: vulnerability.requiredAction,
    knownRansomwareCampaignUse: vulnerability.knownRansomwareCampaignUse,
    shortDescription: vulnerability.shortDescription,
    metadata: sourceMetadata(
      'CISA KEV',
      vulnerability.cveID,
      'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      retrievedAt,
      { sourceUpdate: payload.dateReleased, dataVersion: payload.catalogVersion }
    )
  }));
}
