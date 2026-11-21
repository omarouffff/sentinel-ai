import { fetchText } from './http.js';

export class MitreD3fendClient {
  async fetchOntology() {
    const url = 'https://raw.githubusercontent.com/mitre/d3fend/main/d3fend.ttl';
    return fetchText(url);
  }
}
