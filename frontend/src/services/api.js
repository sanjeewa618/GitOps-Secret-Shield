const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

async function fetchJSON(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
  if (!res.ok) {
    let errorDetail = `Request failed: HTTP ${res.status}`;
    try {
      const err = await res.json();
      errorDetail = err.detail || errorDetail;
    } catch {
      // ignore
    }
    throw new Error(errorDetail);
  }
  return res.json();
}

export const api = {
  getBaseUrl() {
    return API_BASE;
  },

  async getBackendHealth() {
    return fetchJSON(`${API_BASE}/health`);
  },

  async getVaultHealth() {
    return fetchJSON(`${API_BASE}/api/v1/vault/health`);
  },

  async getStats() {
    return fetchJSON(`${API_BASE}/api/v1/incidents/stats`);
  },

  async getIncidents(params = {}) {
    const query = new URLSearchParams();
    if (params.skip !== undefined) query.set('skip', params.skip);
    if (params.limit !== undefined) query.set('limit', params.limit);
    if (params.status) query.set('status', params.status);
    if (params.severity) query.set('severity', params.severity);
    if (params.repository) query.set('repository', params.repository);

    return fetchJSON(`${API_BASE}/api/v1/incidents?${query.toString()}`);
  },

  async getIncident(incidentId) {
    return fetchJSON(`${API_BASE}/api/v1/incidents/${incidentId}`);
  },

  async updateIncident(incidentId, data) {
    return fetchJSON(`${API_BASE}/api/v1/incidents/${incidentId}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  },

  async rotateCredential(incidentId, payload = {}) {
    return fetchJSON(`${API_BASE}/api/v1/incidents/${incidentId}/rotate`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async getVaultSecret(incidentId) {
    return fetchJSON(`${API_BASE}/api/v1/incidents/${incidentId}/vault`);
  },
};
