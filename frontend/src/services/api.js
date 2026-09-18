async function fetchJSON(path, options = {}) {

  const urls = [
    path,
    `http://127.0.0.1:8000${path}`,
    `http://localhost:8000${path}`
  ];
  
  let lastErr = null;
  for (const url of urls) {
    try {
      const res = await fetch(url, options);
      if (res.ok) return await res.json();
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error(`Failed to fetch ${path}`);
}

async function fetchText(path, options = {}) {
  const urls = [
    path,
    `http://127.0.0.1:8000${path}`,
    `http://localhost:8000${path}`
  ];
  
  let lastErr = null;
  for (const url of urls) {
    try {
      const res = await fetch(url, options);
      if (res.ok) return await res.text();
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr || new Error(`Failed to fetch text from ${path}`);
}

export const api = {
  // 1. Incidents
  async getIncidents() {
    return fetchJSON('/api/incidents');
  },

  async getIncident(id) {
    return fetchJSON(`/api/incidents/${id}`);
  },

  async createIncident(payload) {
    return fetchJSON('/api/incidents', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
  },

  async deleteIncident(id) {
    return fetchJSON(`/api/incidents/${id}`, {
      method: 'DELETE'
    });
  },

  async purgeIncidents() {
    return fetchJSON('/api/incidents/purge', {
      method: 'POST'
    });
  },

  async rescoreIncident(id, updatedEvidence) {
    return fetchJSON(`/api/incidents/${id}/rescore`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updatedEvidence)
    });
  },

  // 2. Machine Learning Metrics & Explainability
  async getMLMetrics() {
    return fetchJSON('/api/ml/metrics');
  },

  // 3. Storage & Cloud Status
  async getStorageStatus() {
    return fetchJSON('/api/storage/status');
  },

  async getAzureStatus() {
    return fetchJSON('/api/azure/status');
  },

  // 4. Reports & Exports
  getReportPdfUrl(id) {
    return `/api/incidents/${id}/report?format=pdf`;
  },

  async getReportMarkdown(id) {
    return fetchText(`/api/incidents/${id}/report?format=markdown`);
  },

  async getReportHtml(id) {
    return fetchText(`/api/incidents/${id}/report?format=html`);
  }
};

