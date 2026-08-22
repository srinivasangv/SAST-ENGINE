import { useEffect, useState } from "react";
import { api } from "../api";

// Screen 5b: the approval queue and the SLA clock.
export default function WorkflowTab({ refreshToken, refresh }) {
  const [queue, setQueue] = useState(null);
  const [slaReport, setSlaReport] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([api.approvals(), api.sla()])
      .then(([approvals, sla]) => {
        setQueue(approvals);
        setSlaReport(sla);
      })
      .catch((exception) => setError(exception.message));
  }, [refreshToken]);

  if (error) return <div className="panel error">{error}</div>;
  if (!queue || !slaReport) return <div className="panel muted">loading…</div>;

  return (
    <>
      <div className="panel">
        <h2>Human approval gate</h2>
        <p className="small muted">
          Stage 4 writes a suggested fix for every confirmed finding. Nothing is applied
          until a person approves it — the engine refuses to apply an unapproved fix,
          and that refusal is enforced in code, not in a process document.
        </p>
        <div className="grid">
          <Tile value={queue.counts.pending_approval} label="pending approval" />
          <Tile value={queue.counts.approved} label="approved" />
          <Tile value={queue.counts.rejected} label="rejected" />
          <Tile value={queue.counts.applied} label="patch handed over" />
        </div>
      </div>

      {["pending_approval", "approved", "rejected", "applied"].map((state) => {
        const items = queue[state];
        if (!items || items.length === 0) return null;
        return (
          <div className="panel" key={state}>
            <h2>{state.replace("_", " ")}</h2>
            <div className="scroll-x">
              <table>
                <thead>
                  <tr>
                    <th>severity</th>
                    <th>vulnerability</th>
                    <th>location</th>
                    <th>suggested fix</th>
                    <th>who</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((item) => (
                    <tr key={item.id}>
                      <td>
                        <span className={`badge sev-${item.severity}`}>{item.severity}</span>
                      </td>
                      <td>{item.title}</td>
                      <td className="mono small">
                        {item.file}:{item.line}
                      </td>
                      <td className="mono small">{item.fix || "—"}</td>
                      <td className="small muted">
                        {item.actor || "—"}
                        {item.note ? ` — ${item.note}` : ""}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        );
      })}

      <div className="panel">
        <h2>SLA and escalation</h2>
        <p className="small muted">
          Each severity gets a clock. A confirmed finding that outlives its clock breaches
          and escalates. Applying a fix stops the clock.
        </p>
        <div className="row small">
          {Object.entries(slaReport.policy_hours).map(([severity, hours]) => (
            <span className="pill" key={severity}>
              {severity}: {hours}h → {slaReport.escalation_targets[severity]}
            </span>
          ))}
        </div>

        <div className="grid" style={{ marginTop: 12 }}>
          <Tile value={slaReport.counts.on_track || 0} label="on track" />
          <Tile value={slaReport.counts.at_risk || 0} label="at risk" />
          <Tile value={slaReport.breached} label="breached" />
          <Tile value={slaReport.counts.resolved || 0} label="resolved" />
        </div>

        {slaReport.escalations.length > 0 && (
          <>
            <h3>Escalations</h3>
            <div className="scroll-x">
              <table>
                <thead>
                  <tr>
                    <th>severity</th>
                    <th>finding</th>
                    <th>location</th>
                    <th>overdue by</th>
                    <th>escalate to</th>
                  </tr>
                </thead>
                <tbody>
                  {slaReport.escalations.map((row) => (
                    <tr key={row.finding_id}>
                      <td>
                        <span className={`badge sev-${row.severity}`}>{row.severity}</span>
                      </td>
                      <td>{row.title}</td>
                      <td className="mono small">
                        {row.file}:{row.line}
                      </td>
                      <td>{row.overdue_by_hours.toFixed(1)} h</td>
                      <td className="small">{row.escalate_to}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}

        <h3>All confirmed findings</h3>
        <div className="scroll-x">
          <table>
            <thead>
              <tr>
                <th>state</th>
                <th>severity</th>
                <th>finding</th>
                <th>age</th>
                <th>budget</th>
                <th>remaining</th>
                <th>fix</th>
              </tr>
            </thead>
            <tbody>
              {slaReport.findings.map((row) => (
                <tr key={row.finding_id}>
                  <td>
                    <span
                      className={`badge ${
                        row.state === "breached"
                          ? "status-confirmed"
                          : row.state === "resolved"
                            ? "status-suppressed"
                            : "sev-info"
                      }`}
                    >
                      {row.state}
                    </span>
                  </td>
                  <td>
                    <span className={`badge sev-${row.severity}`}>{row.severity}</span>
                  </td>
                  <td className="small">
                    {row.title}
                    <div className="mono muted">
                      {row.file}:{row.line}
                    </div>
                  </td>
                  <td className="small">{row.age_hours.toFixed(1)} h</td>
                  <td className="small muted">{row.budget_hours} h</td>
                  <td className="small">{row.hours_remaining.toFixed(1)} h</td>
                  <td className="small muted">{row.fix_status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
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
