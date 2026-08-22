import { useEffect, useState } from "react";
import { api } from "../api";

// Screen 6: the live DefectDojo connection. Push a stored scan, then read the
// findings straight back out of DefectDojo to prove the import landed.
export default function DefectDojoTab({ refreshToken, refresh }) {
  const [status, setStatus] = useState(null);
  const [scans, setScans] = useState([]);
  const [selected, setSelected] = useState("");
  const [includeSuppressed, setIncludeSuppressed] = useState(false);
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  function load() {
    api.defectDojoStatus().then(setStatus).catch((e) => setError(e.message));
    api
      .listScans()
      .then((data) => {
        setScans(data.scans);
        if (data.scans.length > 0 && !selected) setSelected(data.scans[0].id);
      })
      .catch((e) => setError(e.message));
  }

  useEffect(load, [refreshToken]);

  async function push() {
    setBusy(true);
    setError("");
    try {
      setResult(await api.pushToDefectDojo(selected, includeSuppressed));
      load();
      refresh();
    } catch (exception) {
      setError(exception.message);
    } finally {
      setBusy(false);
    }
  }

  if (!status) return <div className="panel muted">loading…</div>;

  const connected = status.authenticated;

  return (
    <>
      <div className="panel">
        <div className="row">
          <h2 style={{ margin: 0 }}>DefectDojo</h2>
          <span className={`badge ${connected ? "status-suppressed" : "status-confirmed"}`}>
            {connected ? "connected" : "not connected"}
          </span>
          <span className="pill mono">{status.url}</span>
          {connected && (
            <span className="pill">{status.findings_in_defectdojo} findings stored</span>
          )}
        </div>

        {!connected && (
          <>
            <p className="small error" style={{ marginTop: 10 }}>
              {status.error}
            </p>
            <p className="small muted">
              Start it with <code>cd ~/defectdojo &amp;&amp; docker compose up -d</code>,
              then put an API token in <code>~/.dd_token</code> or the{" "}
              <code>DEFECTDOJO_TOKEN</code> environment variable. The engine still
              works without it — findings are written as an import file instead.
            </p>
          </>
        )}

        {connected && (
          <>
            <p className="small muted" style={{ marginTop: 10 }}>
              Pushing creates the product and the engagement if they are missing, then
              imports the scan as a new test. Re-pushing the same repository adds
              another test to the same engagement rather than duplicating anything.
            </p>
            <div className="row" style={{ marginTop: 12 }}>
              <select value={selected} onChange={(e) => setSelected(e.target.value)}>
                {scans.map((scan) => (
                  <option key={scan.id} value={scan.id}>
                    {scan.repo} — {scan.confirmed} confirmed ({scan.started_at})
                  </option>
                ))}
              </select>
              <label className="check">
                <input
                  type="checkbox"
                  checked={includeSuppressed}
                  onChange={(e) => setIncludeSuppressed(e.target.checked)}
                />
                also send suppressed findings (flagged as false positives)
              </label>
              <button className="action" onClick={push} disabled={busy || !selected}>
                {busy ? "pushing…" : "Push to DefectDojo"}
              </button>
            </div>
          </>
        )}

        {error && <p className="error small">{error}</p>}
      </div>

      {result && (
        <div className="panel">
          <h2>{result.ok ? "Import complete" : "Import failed"}</h2>
          {result.ok ? (
            <>
              <div className="grid">
                <Tile value={result.submitted} label="submitted" />
                <Tile value={result.stored} label="stored in DefectDojo" />
                <Tile value={result.product_id} label="product id" />
                <Tile value={result.test_id} label="test id" />
              </div>
              <p className="small" style={{ marginTop: 12 }}>
                <a href={result.test_url} target="_blank" rel="noreferrer">
                  Open this test in DefectDojo
                </a>{" "}
                ·{" "}
                <a href={result.engagement_url} target="_blank" rel="noreferrer">
                  engagement
                </a>{" "}
                ·{" "}
                <a href={result.product_url} target="_blank" rel="noreferrer">
                  product
                </a>
              </p>
              {result.stored !== result.submitted && (
                <p className="small error">
                  {result.submitted} findings were submitted but {result.stored} were
                  stored. DefectDojo dropped some — check its deduplication settings.
                </p>
              )}
            </>
          ) : (
            <p className="small error">
              failed at <strong>{result.stage}</strong>: {result.error}
            </p>
          )}
        </div>
      )}

      {connected && status.recent?.length > 0 && (
        <div className="panel">
          <h2>Findings currently in DefectDojo</h2>
          <p className="small muted">
            Read back through the DefectDojo API — this is what a security engineer
            would see in their queue, not our copy of it.
          </p>
          <div className="scroll">
            <table>
              <thead>
                <tr>
                  <th>severity</th>
                  <th>title</th>
                  <th>location</th>
                  <th>CWE</th>
                  <th>state</th>
                </tr>
              </thead>
              <tbody>
                {status.recent.map((finding) => (
                  <tr key={finding.id}>
                    <td>
                      <span className={`badge sev-${(finding.severity || "").toLowerCase()}`}>
                        {finding.severity}
                      </span>
                    </td>
                    <td className="small">{finding.title}</td>
                    <td className="mono small">
                      {finding.file_path}:{finding.line}
                    </td>
                    <td className="mono small">{finding.cwe}</td>
                    <td className="small muted">
                      {finding.false_p ? "false positive" : finding.active ? "active" : "inactive"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </>
  );
}

function Tile({ value, label }) {
  return (
    <div className="tile">
      <div className="value">{value}</div>
      <div className="label">{label}</div>
    </div>
  );
}
