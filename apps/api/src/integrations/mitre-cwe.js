import { fetchJson, sourceMetadata } from './http.js';

export class MitreCweClient {
  async fetchCwe(cweId) {
    const number = cweId.replace(/^CWE-/i, '');
    const payload = await fetchJson(`https://cwe.mitre.org/data/json/definition/${number}.json`, {
      retries: 2
    });
    if (!payload) throw new Error(`MITRE CWE returned no record for ${cweId}`);
    return payload;
  }
}
