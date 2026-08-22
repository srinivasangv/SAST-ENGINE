import { useEffect, useState } from "react";
import { api } from "../api";

// Screens 2 and 3: the findings table, and the detail view with the taint
// path, the validator's reasoning, the PoC, and the approval buttons.
export default function FindingsTab({ refreshToken, refresh }) {
  const [findings, setFindings] = useState([]);
  const [status, setStatus] = useState("confirmed");
  const [severity, setSeverity] = useState("");
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .listFindings({ status, severity })
      .then((data) => setFindings(data.findings))
      .catch((exception) => setError(exception.message));
  }, [status, severity, refreshToken]);

  return (
    <>
      <div className="panel">
        <div className="row">
          <h2 style={{ margin: 0 }}>Findings</h2>
          <select value={status} onChange={(event) => setStatus(event.target.value)}>
            <option value="confirmed">confirmed (real)</option>
            <option value="suppressed">suppressed by validation</option>
            <option value="">everything</option>
          </select>
          <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="">any severity</option>
            {["critical", "high", "medium", "low", "info"].map((level) => (
              <option key={level} value={level}>
                {level}
              </option>
            ))}
          </select>
          <span className="pill">{findings.length} shown</span>
        </div>
        {error && <p className="error small">{error}</p>}
      </div>

      <div className="panel">
        {findings.length === 0 ? (
          <div className="empty">Nothing here. Run a scan first.</div>
        ) : (
          <div className="scroll-x">
            <table>
              <thead>
                <tr>
                  <th>severity</th>
                  <th>CWE</th>
                  <th>vulnerability</th>
                  <th>location</th>
                  <th>repo</th>
                  <th>state</th>
                  <th>fix</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((finding) => (
                  <tr
                    key={finding.id}
                    className="clickable"
                    onClick={() => setSelected(finding)}
                  >
                    <td>
                      <span className={`badge sev-${finding.severity}`}>
                        {finding.severity}
                      </span>
                    </td>
                    <td className="mono small">{finding.cwe}</td>
                    <td>{finding.title}</td>
                    <td className="mono small">
                      {finding.file}:{finding.line}
                    </td>
                    <td className="small muted">{finding.repo}</td>
                    <td>
                      <span className={`badge status-${finding.status}`}>
                        {finding.status}
                      </span>
                    </td>
                    <td className="small muted">{finding.fix_status || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selected && (
        <FindingDetail
          finding={selected}
          onClose={() => setSelected(null)}
          onChanged={() => {
            setSelected(null);
            refresh();
          }}
        />
      )}
    </>
  );
}

function FindingDetail({ finding, onClose, onChanged }) {
  const [actor, setActor] = useState("security-lead");
  const [note, setNote] = useState("");
  const [message, setMessage] = useState(null);
  const validation = finding.validation || {};
  const poc = finding.poc || {};
  const fix = finding.suggested_fix || {};

  async function act(kind) {
    try {
      let result;
      if (kind === "approve") result = await api.approve(finding.id, actor, note);
      else if (kind === "reject") result = await api.reject(finding.id, actor, note);
      else result = await api.applyFix(finding.id, actor);

      setMessage(
        result.ok
          ? { good: true, text: result.patch || `fix ${kind}d` }
          : { good: false, text: result.error }
      );
      if (result.ok && kind !== "apply") setTimeout(onChanged, 900);
    } catch (exception) {
      setMessage({ good: false, text: exception.message });
    }
  }

  return (
    <div className="panel">
      <div className="row">
        <span className={`badge sev-${finding.severity}`}>{finding.severity}</span>
        <h2 style={{ margin: 0 }}>{finding.title}</h2>
        <span className="pill mono">{finding.cwe}</span>
        <span className="pill">{finding.owasp}</span>
        <span style={{ marginLeft: "auto" }} />
        <button className="action ghost" onClick={onClose}>
          close
        </button>
      </div>

      <p className="small muted" style={{ marginTop: 4 }}>
        {finding.file}:{finding.line} in <code>{finding.function}</code> · entry point:{" "}
        {finding.entry}
      </p>

      <h3>Why it is dangerous</h3>
      <p className="small">{finding.why_dangerous}</p>

      <h3>Taint path — attacker input to dangerous call</h3>
      <div>
        {(finding.taint_path || []).map((step, index) => (
          <div className="taint-step" key={index}>
            <div className="num">{index + 1}</div>
            <div style={{ flex: 1 }}>
              <div className="desc">
                line {step.line} — {step.description}
              </div>
              <pre className="mono">{step.code}</pre>
            </div>
          </div>
        ))}
      </div>

      <h3>
        Stage 3 verdict —{" "}
        {validation.validator === "claude" ? `Claude ${validation.model}` : "offline validator"}
      </h3>
      <div className="row">
        <span className={`badge status-${finding.status}`}>
          {validation.exploitable ? "exploitable" : "not exploitable"}
        </span>
        <span className="pill">confidence {Math.round((validation.confidence || 0) * 100)}%</span>
        {validation.fallback_reason && (
          <span className="pill">fell back: {validation.fallback_reason}</span>
        )}
      </div>
      <p className="small" style={{ marginTop: 8 }}>
        {validation.reasoning}
      </p>
      {validation.attack_scenario && (
        <p className="small muted">Attack scenario: {validation.attack_scenario}</p>
      )}

      {finding.status === "confirmed" && (
        <>
          <h3>Stage 4 — proof of concept</h3>
          <pre className="block">{poc.command}</pre>
          {poc.expected && (
            <p className="small muted">Expected result: {poc.expected}</p>
          )}

          <h3>Suggested fix (never applied automatically)</h3>
          <pre className="block">
            {fix.import_needed ? `+ ${fix.import_needed}\n` : ""}- {fix.current}
            {"\n"}+ {fix.replacement || fix.guidance}
          </pre>
          <p className="small muted">{fix.explanation || fix.guidance}</p>

          <h3>Human approval gate</h3>
          <div className="row">
            <input
              type="text"
              value={actor}
              onChange={(event) => setActor(event.target.value)}
              placeholder="your name"
            />
            <input
              type="text"
              value={note}
              onChange={(event) => setNote(event.target.value)}
              placeholder="note / reason"
              style={{ minWidth: 280 }}
            />
            <button className="action good" onClick={() => act("approve")}>
              Approve
            </button>
            <button className="action danger" onClick={() => act("reject")}>
              Reject
            </button>
            <button className="action ghost" onClick={() => act("apply")}>
              Apply approved fix
            </button>
            <span className="pill">current: {finding.fix_status || "pending_approval"}</span>
          </div>
          {message && (
            <pre className={`block ${message.good ? "" : "error"}`}>{message.text}</pre>
          )}
        </>
      )}

      {finding.status === "suppressed" && (
        <>
          <h3>Why this was suppressed</h3>
          <p className="small">{finding.suppression_reason}</p>
          <p className="small muted">
            The finding is kept rather than deleted, so the suppression can be reviewed
            and so the false-positive rate can be measured.
          </p>
        </>
      )}

      {finding.cluster_size > 1 && (
        <>
          <h3>Duplicates</h3>
          <p className="small">
            This exact pattern appears {finding.cluster_size} times across{" "}
            {(finding.cluster_repos || []).join(", ")} — one ticket, not{" "}
            {finding.cluster_size}.
          </p>
        </>
      )}

      <h3>Source</h3>
      <pre className="block">{finding.snippet}</pre>
    </div>
  );
}
