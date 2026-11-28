const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const TOKEN_KEY = 'secret_shield_jwt';

export function getStoredToken() {
  return localStorage.getItem(TOKEN_KEY) || '';
}

export function setStoredToken(token) {
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
}

async function fetchJSON(url, options = {}) {
  const token = getStoredToken();
  const authHeader = token ? { Authorization: `Bearer ${token}` } : {};
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...authHeader,
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

  // Auth (Phase 2/3)
  async login(username, password) {
    const body = new URLSearchParams({ username, password });
    const res = await fetch(`${API_BASE}/api/v1/auth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Login failed: HTTP ${res.status}`);
    }
    const data = await res.json();
    setStoredToken(data.access_token);
    return data;
  },

  logout() {
    setStoredToken('');
  },

  async getMe() {
    return fetchJSON(`${API_BASE}/api/v1/auth/me`);
  },

  // Phase 1 & 2
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

  // Phase 3 – Intelligence, Correlation, Remediation & False Positives
  async getCorrelatedIncidents(incidentId) {
    return fetchJSON(`${API_BASE}/api/v1/incidents/${incidentId}/correlated`);
  },

  async getCorrelationGroups() {
    return fetchJSON(`${API_BASE}/api/v1/correlations`);
  },

  async scanGitHistory(payload = { max_commits: 25 }) {
    return fetchJSON(`${API_BASE}/api/v1/git-history/scan`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async getGitHistoryFindings() {
    return fetchJSON(`${API_BASE}/api/v1/git-history/findings`);
  },

  async getRemediationPlan(incidentId) {
    return fetchJSON(`${API_BASE}/api/v1/incidents/${incidentId}/remediation/plan`);
  },

  async executeRemediation(incidentId, payload) {
    return fetchJSON(`${API_BASE}/api/v1/incidents/${incidentId}/remediation/execute`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async getRemediationAudit(incidentId) {
    return fetchJSON(`${API_BASE}/api/v1/incidents/${incidentId}/remediation/audit`);
  },

  async getFalsePositives(includeInactive = false) {
    return fetchJSON(`${API_BASE}/api/v1/false-positives?include_inactive=${includeInactive}`);
  },

  async createFalsePositiveRule(payload) {
    return fetchJSON(`${API_BASE}/api/v1/false-positives`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async deactivateFalsePositiveRule(ruleId) {
    return fetchJSON(`${API_BASE}/api/v1/false-positives/${ruleId}`, {
      method: 'DELETE',
    });
  },

  async markIncidentFalsePositive(incidentId, payload) {
    return fetchJSON(`${API_BASE}/api/v1/incidents/${incidentId}/false-positive`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  },
};
