import { useEffect, useRef, useState } from "react";
import { api } from "../api";

// Screen 1: start a scan, watch the four stages tick past, see the CPG stats.
export default function ScansTab({ refreshToken, refresh }) {
  const [scans, setScans] = useState([]);
  const [repoPath, setRepoPath] = useState("testdata/vuln-flask");
  const [withBaseline, setWithBaseline] = useState(true);
  const [withSemgrep, setWithSemgrep] = useState(false);
  const [forceOffline, setForceOffline] = useState(false);
  const [engine, setEngine] = useState("builtin");
  const [pushDojo, setPushDojo] = useState(false);
  const [job, setJob] = useState(null);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState(null);
  const pollTimer = useRef(null);

  const [uploading, setUploading] = useState(false);
  const [uploadMsg, setUploadMsg] = useState("");
  const fileInputRef = useRef(null);

  const load = () =>
    api
      .listScans()
      .then((data) => setScans(data.scans))
      .catch((exception) => setError(exception.message));

  useEffect(() => {
    load();
  }, [refreshToken]);

  // Clear the poll timer if the component unmounts mid-scan.
  useEffect(() => () => clearTimeout(pollTimer.current), []);

  async function handleFileUpload(event) {
    const file = event.target.files?.[0];
    if (!file) return;

    setUploading(true);
    setError("");
    setUploadMsg("");

    try {
      const isZip = file.name.toLowerCase().endsWith(".zip");
      const reader = new FileReader();

      reader.onload = async (e) => {
        try {
          let payload;
          if (isZip) {
            const raw = e.target.result;
            const base64 = raw.includes(",") ? raw.split(",")[1] : raw;
            payload = { base64 };
          } else {
            payload = { content: e.target.result };
          }

          const res = await api.uploadProject(file.name, payload);
          if (res.ok) {
            setRepoPath(res.repo_path);
            setUploadMsg(`Project "${res.repo_name}" uploaded successfully! Path set to ${res.repo_path}`);
          }
        } catch (err) {
          setError(`Upload failed: ${err.message}`);
        } finally {
          setUploading(false);
          if (fileInputRef.current) fileInputRef.current.value = "";
        }
      };

      if (isZip) {
        reader.readAsDataURL(file);
      } else {
        reader.readAsText(file);
      }
    } catch (err) {
      setError(`Upload error: ${err.message}`);
      setUploading(false);
    }
  }

  async function start() {
    setError("");
    try {
      const started = await api.startScan(repoPath, {
        useLlm: forceOffline ? false : null,
        withBaseline,
        withSemgrep,
        engine,
        pushToDefectDojo: pushDojo,
      });
      setJob({ ...started, state: "queued" });
      poll(started.job_id);
    } catch (exception) {
      setError(exception.message);
    }
  }

  function poll(jobId) {
    pollTimer.current = setTimeout(async () => {
      try {
        const status = await api.scanStatus(jobId);
        setJob(status);
        if (status.state === "done") {
          await load();
          refresh();
        } else if (status.state !== "error") {
          poll(jobId);
        }
      } catch (exception) {
        setError(exception.message);
      }
    }, 700);
  }

  async function open(scanId) {
    setSelected(await api.getScan(scanId));
  }

  return (
    <>
      <div className="panel">
        <h2>Run a scan</h2>
        <div className="row">
          <input
            type="text"
            value={repoPath}
            onChange={(event) => setRepoPath(event.target.value)}
            placeholder="path to a repository or uploaded project"
            style={{ minWidth: 340 }}
          />
          <button className="action" onClick={start} disabled={job?.state === "running"}>
            {job?.state === "running" ? "scanning…" : "Scan"}
          </button>

          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileUpload}
            style={{ display: "none" }}
            accept=".zip,.py,.js,.jsx,.ts,.tsx,.json"
          />
          <button
            className="action ghost"
            onClick={() => fileInputRef.current?.click()}
            disabled={uploading || job?.state === "running"}
          >
            {uploading ? "Uploading..." : "📁 Upload Project File / Zip"}
          </button>

          <select value={engine} onChange={(event) => setEngine(event.target.value)}>
            <option value="builtin">engine: builtin (fast)</option>
            <option value="joern">engine: Joern (deep, ~20s)</option>
            <option value="both">engine: both</option>
          </select>
          <label className="check">
            <input
              type="checkbox"
              checked={withBaseline}
              onChange={(event) => setWithBaseline(event.target.checked)}
            />
            compare against Joern baseline
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={withSemgrep}
              onChange={(event) => setWithSemgrep(event.target.checked)}
            />
            also measure Semgrep
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={pushDojo}
              onChange={(event) => setPushDojo(event.target.checked)}
            />
            push to DefectDojo
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={forceOffline}
              onChange={(event) => setForceOffline(event.target.checked)}
            />
            force offline validator
          </label>
        </div>

        {uploadMsg && (
          <p className="small" style={{ marginTop: 8, color: "var(--accent)" }}>
            {uploadMsg}
          </p>
        )}

        <div className="row small muted" style={{ marginTop: 8 }}>
          {["testdata/vuln-flask", "testdata/vuln-express", "testdata/safe-app"].map((path) => (
            <button key={path} className="action ghost" onClick={() => setRepoPath(path)}>
              {path}
            </button>
          ))}
        </div>

        {job && (
          <div className="panel" style={{ marginTop: 14, marginBottom: 0 }}>
            <strong>{job.state}</strong>{" "}
            <span className="muted">
              {job.stage ? `— ${job.stage}: ${job.message}` : ""}
            </span>
            <div className="row" style={{ marginTop: 10, gap: 6 }}>
              {["prepare", "scan", "validate", "prove", "dedupe", "baseline", "defectdojo"].map((stage) => (
                <span
                  key={stage}
                  className="badge"
                  style={{
                    background: job.stage === stage ? "var(--accent)" : "var(--panel-2)",
                    color: job.stage === stage ? "#fff" : "var(--muted)",
                  }}
                >
                  {stage}
                </span>
              ))}
            </div>
          </div>
        )}
        {error && <p className="error small">{error}</p>}
      </div>

      <div className="panel">
        <h2>Scan history</h2>
        {scans.length === 0 ? (
          <div className="empty">No scans yet. Run one above.</div>
        ) : (
          <div className="scroll-x">
            <table>
              <thead>
                <tr>
                  <th>started</th>
                  <th>repository</th>
                  <th>Stage 2 raw</th>
                  <th>confirmed</th>
                  <th>suppressed</th>
                  <th>validator</th>
                  <th>time</th>
                  <th>action</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan.id}>
                    <td className="mono small">{scan.started_at}</td>
                    <td>{scan.repo}</td>
                    <td>{scan.raw_findings}</td>
                    <td>
                      <span className="badge status-confirmed">{scan.confirmed}</span>
                    </td>
                    <td>
                      <span className="badge status-suppressed">{scan.suppressed}</span>
                    </td>
                    <td className="muted small">{scan.validator}</td>
                    <td className="muted small">{scan.duration_ms} ms</td>
                    <td>
                      <button
                        className="action"
                        style={{ padding: "4px 10px", fontSize: "0.82rem" }}
                        onClick={() => open(scan.id)}
                      >
                        View Project
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selected && <ScanDetail scan={selected} onClose={() => setSelected(null)} />}
    </>
  );
}

function ScanDetail({ scan, onClose }) {
  const prepare = scan.stages.prepare;
  const [exported, setExported] = useState(null);

  return (
    <div className="panel">
      <div className="row">
        <h2 style={{ margin: 0 }}>{scan.repo}</h2>
        <span className="pill mono">{scan.id}</span>
        <span style={{ marginLeft: "auto" }} />
        <span className="pill">engine: {scan.engine || "builtin"}</span>
        <button
          className="action ghost"
          onClick={async () => setExported(await api.exportDefectDojo(scan.id))}
        >
          Export file
        </button>
        <button
          className="action"
          onClick={async () => setExported(await api.pushToDefectDojo(scan.id))}
        >
          Push to DefectDojo
        </button>
        <button className="action ghost" onClick={onClose}>
          close
        </button>
      </div>

      {exported && exported.path && (
        <p className="small">
          Wrote {exported.findings_exported} findings to <code>{exported.path}</code>.{" "}
          <span className="muted">{exported.how_to_import}</span>
        </p>
      )}
      {exported && exported.stage && (
        <p className="small">
          {exported.ok ? (
            <>
              Imported {exported.stored} of {exported.submitted} findings into
              DefectDojo.{" "}
              <a href={exported.test_url} target="_blank" rel="noreferrer">
                open the test
              </a>
            </>
          ) : (
            <span className="error">
              push failed at {exported.stage}: {exported.error}
            </span>
          )}
        </p>
      )}

      <h3>Stage 1 — Prepare (the Code Property Graph)</h3>
      <div className="grid">
        <Tile value={prepare.files} label="files parsed" />
        <Tile value={prepare.nodes} label="CPG nodes" />
        <Tile value={prepare.edges} label="CPG edges" />
        <Tile value={prepare.functions} label="functions" />
        <Tile value={prepare.routes} label="HTTP routes" />
        <Tile value={`${prepare.duration_ms} ms`} label="parse time" hint="no build required" />
      </div>

      <h3>Stages 2–4</h3>
      <div className="grid">
        <Tile value={scan.summary.raw_findings} label="Stage 2 reported" hint="pattern matching" />
        <Tile value={scan.summary.confirmed} label="Stage 3 confirmed" />
        <Tile value={scan.summary.suppressed} label="Stage 3 suppressed" />
        <Tile
          value={`${Math.round(scan.summary.suppression_rate * 100)}%`}
          label="suppression rate"
          hint={`validator: ${scan.summary.validator}`}
        />
        <Tile value={scan.stages.prove.proofs} label="PoCs generated" />
        <Tile value={scan.summary.sla_breached ?? 0} label="SLA breached" />
        <Tile
          value={scan.engine || "builtin"}
          label="scan engine"
          hint={Object.entries(scan.summary.by_engine || {})
            .map(([k, v]) => `${k}: ${v}`)
            .join(", ")}
        />
      </div>

      {scan.parse_errors?.length > 0 && (
        <>
          <h3>Files that would not parse</h3>
          <p className="small muted">
            The scan continued past these — one broken file never stops a scan.
          </p>
          <ul className="small mono">
            {scan.parse_errors.map((entry) => (
              <li key={entry.file}>
                {entry.file}: {entry.error}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

function Tile({ value, label, hint }) {
  return (
    <div className="tile">
      <div className="value">{value}</div>
      <div className="label">{label}</div>
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}
