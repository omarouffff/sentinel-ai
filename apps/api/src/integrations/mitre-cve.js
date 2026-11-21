import { fetchJson, sourceMetadata } from './http.js';

export class MitreCveClient {
  async fetchCve(cveId) {
    const payload = await fetchJson(`https://cveawg.mitre.org/api/cve/${encodeURIComponent(cveId)}`, {
      retries: 2
    });
    if (!payload?.cveMetadata?.cveId) throw new Error(`MITRE CVE returned no record for ${cveId}`);
    return payload;
  }
}

export function normalizeMitreCve(payload, retrievedAt = new Date().toISOString()) {
  const metadata = payload.cveMetadata;
  const descriptions = payload.containers?.cna?.descriptions || [];
  return {
    cveId: metadata.cveId,
    description: descriptions.find(d => d.lang === 'en')?.value || null,
    state: metadata.state,
    dateReserved: metadata.dateReserved,
    datePublished: metadata.datePublished,
    dateUpdated: metadata.dateUpdated,
    metadata: sourceMetadata(
      'MITRE CVE',
      metadata.cveId,
      `https://www.cve.org/CVERecord?id=${metadata.cveId}`,
      retrievedAt,
      { lastModified: metadata.dateUpdated, sourceUpdate: metadata.dateUpdated }
    )
  };
}
