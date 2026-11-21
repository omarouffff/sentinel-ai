import { fetchJson, sourceMetadata } from './http.js';

export class EpssClient {
  async fetchForCves(cveIds) {
    if (!cveIds.length) return { data: [] };
    const url = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveIds.join(','))}`;
    const payload = await fetchJson(url, { retries: 3, retryDelayMs: 1500 });
    if (!payload || !Array.isArray(payload.data)) {
      throw new Error('EPSS returned a response without a data array');
    }
    return payload;
  }
}

export function normalizeEpss(payload, retrievedAt = new Date().toISOString()) {
  return payload.data.map(record => ({
    cveId: record.cve,
    score: Number(record.epss),
    percentile: Number(record.percentile),
    scoreDate: record.date || null,
    metadata: sourceMetadata(
      'FIRST EPSS',
      record.cve,
      `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(record.cve)}`,
      retrievedAt,
      { sourceUpdate: record.date }
    )
  }));
}
