import { fetchJson, sourceMetadata } from './http.js';

export class GitHubAdvisoriesClient {
  constructor(token) {
    this.token = token;
  }

  async fetchGlobal(perPage = 100, cursor) {
    const params = new URLSearchParams({ per_page: String(perPage) });
    if (cursor) params.set('after', cursor);
    const payload = await fetchJson(`https://api.github.com/advisories?${params}`, {
      headers: {
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        ...(this.token ? { Authorization: `Bearer ${this.token}` } : {})
      },
      retries: 2
    });
    if (!Array.isArray(payload)) throw new Error('GitHub Advisories returned a non-array response');
    return payload;
  }
}

export function normalizeGitHubAdvisory(advisory, retrievedAt = new Date().toISOString()) {
  return {
    ghsaId: advisory.ghsa_id,
    cveId: advisory.cve_id || null,
    summary: advisory.summary,
    description: advisory.description,
    severity: advisory.severity,
    published: advisory.published_at,
    modified: advisory.updated_at,
    withdrawn: advisory.withdrawn_at,
    references: advisory.references || [],
    affected: (advisory.vulnerabilities || []).map(v => ({
      package: v.package,
      vulnerableVersionRange: v.vulnerable_version_range,
      firstPatchedVersion: v.first_patched_version
    })),
    metadata: sourceMetadata(
      'GitHub Advisory Database',
      advisory.ghsa_id,
      advisory.url || `https://github.com/advisories/${advisory.ghsa_id}`,
      retrievedAt,
      { lastModified: advisory.updated_at, dataVersion: advisory.ghsa_id }
    )
  };
}
