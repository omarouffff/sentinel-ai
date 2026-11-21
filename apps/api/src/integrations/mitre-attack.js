import { fetchJson, sourceMetadata } from './http.js';

export class MitreAttackClient {
  async fetchEnterpriseBundle() {
    const url = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-17.1.json';
    return fetchJson(url, { retries: 2 });
  }
}
