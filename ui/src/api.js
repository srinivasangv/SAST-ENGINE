// Every call the dashboard makes to the Python API, in one place.
// Owner: Member 7 (UI + QA + Docs).
//
// Vite proxies /api to http://127.0.0.1:8000 (see vite.config.js), so these
// are all relative paths and nothing needs editing to move between machines.

async function request(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || `${response.status} ${response.statusText}`);
  }
  return payload;
}

export const api = {
  health: () => request("/api/health"),

  uploadProject: (filename, { content, base64 }) =>
    request("/api/upload", {
      method: "POST",
      body: JSON.stringify({ filename, content, data_b64: base64 }),
    }),

  listScans: () => request("/api/scans"),
  getScan: (id) => request(`/api/scans/${id}`),
  deleteScan: (id) => request(`/api/scans/${id}`, { method: "DELETE" }),
  scanStatus: (jobId) => request(`/api/scans/status/${jobId}`),

  startScan: (
    repoPath,
    {
      useLlm = null,
      withBaseline = true,
      withSemgrep = false,
      engine = "builtin",
      pushToDefectDojo = false,
    } = {}
  ) =>
    request("/api/scans", {
      method: "POST",
      body: JSON.stringify({
        repo_path: repoPath,
        use_llm: useLlm,
        with_baseline: withBaseline,
        with_semgrep: withSemgrep,
        engine,
        push_to_defectdojo: pushToDefectDojo,
      }),
    }),

  listFindings: (params = {}) => {
    const query = new URLSearchParams(
      Object.entries(params).filter(([, value]) => value)
    ).toString();
    return request(`/api/findings${query ? `?${query}` : ""}`);
  },
  getFinding: (id) => request(`/api/findings/${id}`),

  approve: (id, actor, note) =>
    request(`/api/findings/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({ actor, note }),
    }),
  reject: (id, actor, reason) =>
    request(`/api/findings/${id}/reject`, {
      method: "POST",
      body: JSON.stringify({ actor, reason }),
    }),
  applyFix: (id, actor) =>
    request(`/api/findings/${id}/apply`, {
      method: "POST",
      body: JSON.stringify({ actor }),
    }),

  approvals: () => request("/api/approvals"),
  sla: () => request("/api/sla"),
  dedupe: () => request("/api/dedupe"),
  comparison: () => request("/api/comparison"),

  defectDojoStatus: () => request("/api/defectdojo"),
  pushToDefectDojo: (scanId, includeSuppressed = false) =>
    request("/api/defectdojo/push", {
      method: "POST",
      body: JSON.stringify({ scan_id: scanId, include_suppressed: includeSuppressed }),
    }),

  exportDefectDojo: (scanId, includeSuppressed = false) =>
    request("/api/export/defectdojo", {
      method: "POST",
      body: JSON.stringify({ scan_id: scanId, include_suppressed: includeSuppressed }),
    }),
};
