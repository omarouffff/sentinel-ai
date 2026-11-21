export async function fetchJson(url, {
  headers = {},
  method = 'GET',
  body,
  timeoutMs = 30_000,
  retries = 2,
  retryDelayMs = 1_000
} = {}) {
  let lastError;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, { headers, method, body, signal: controller.signal });
      if (!response.ok) {
        const body = await response.text();
        throw new Error(`HTTP ${response.status} ${response.statusText}: ${body.slice(0, 300)}`);
      }
      const text = await response.text();
      try {
        return JSON.parse(text);
      } catch (error) {
        throw new Error(`Invalid JSON from ${url}: ${error.message}`);
      }
    } catch (error) {
      lastError = error;
      if (attempt < retries) {
        await new Promise(resolve => setTimeout(resolve, retryDelayMs * (attempt + 1)));
      }
    } finally {
      clearTimeout(timer);
    }
  }
  throw lastError;
}

export async function fetchText(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs || 30_000);
  try {
    const response = await fetch(url, {
      headers: options.headers || {},
      signal: controller.signal
    });
    if (!response.ok) throw new Error(`HTTP ${response.status} ${response.statusText}`);
    return response.text();
  } finally {
    clearTimeout(timer);
  }
}

export function sourceMetadata(provider, recordId, sourceUrl, retrievedAt, extra = {}) {
  return {
    provider,
    recordId,
    sourceUrl,
    retrievedAt,
    lastModified: extra.lastModified ?? null,
    sourceUpdate: extra.sourceUpdate ?? null,
    dataVersion: extra.dataVersion ?? null,
    license: extra.license ?? null
  };
}
