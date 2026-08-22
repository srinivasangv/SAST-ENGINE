import { useEffect, useState } from "react";
import { api } from "../api";

// Screen 5a: the same vulnerability pattern collapsed into one cluster,
// across repositories and across languages.
export default function DedupeTab({ refreshToken }) {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [crossOnly, setCrossOnly] = useState(false);

  useEffect(() => {
    api.dedupe().then(setData).catch((exception) => setError(exception.message));
  }, [refreshToken]);

  if (error) return <div className="panel error">{error}</div>;
  if (!data) return <div className="panel muted">loading…</div>;

  const summary = data.summary;
  const clusters = crossOnly
    ? data.clusters.filter((cluster) => cluster.cross_repo)
    : data.clusters;

  return (
    <>
      <div className="panel">
        <h2>Cross-repository deduplication</h2>
        <p className="small muted">
          Findings are fingerprinted on <strong>CWE + where the input came from + the
          shape of the code</strong> — never on file paths or variable names. That is why
          the same bug written in Python and in JavaScript lands in one cluster.
        </p>
        <div className="grid">
          <Tile value={summary.findings_before} label="confirmed findings" />
          <Tile value={summary.clusters_after} label="unique patterns" />
          <Tile value={summary.duplicates_removed} label="duplicates collapsed" />
          <Tile
            value={`${Math.round(summary.reduction_rate * 100)}%`}
            label="ticket reduction"
          />
          <Tile value={summary.cross_repo_clusters} label="patterns in 2+ repos" />
        </div>
        <label className="check" style={{ marginTop: 12 }}>
          <input
            type="checkbox"
            checked={crossOnly}
            onChange={(event) => setCrossOnly(event.target.checked)}
          />
          show only patterns that span more than one repository
        </label>
      </div>

      {clusters.length === 0 ? (
        <div className="panel">
          <div className="empty">
            Nothing to show. Scan at least two repositories to see cross-repo clusters.
          </div>
        </div>
      ) : (
        clusters.map((cluster) => (
          <div className="panel" key={cluster.fingerprint}>
            <div className="row">
              <span className={`badge sev-${cluster.severity}`}>{cluster.severity}</span>
              <strong>{cluster.title}</strong>
              <span className="pill mono">{cluster.cwe}</span>
              <span className="pill">
                {cluster.count} occurrence{cluster.count === 1 ? "" : "s"}
              </span>
              {cluster.cross_repo && (
                <span className="badge status-confirmed">spans {cluster.repos.length} repos</span>
              )}
              <span style={{ marginLeft: "auto" }} />
              <span className="pill mono">shape {cluster.shape}</span>
            </div>

            <div className="scroll-x" style={{ marginTop: 10 }}>
              <table>
                <thead>
                  <tr>
                    <th>repository</th>
                    <th>location</th>
                    <th>language</th>
                    <th>finding id</th>
                  </tr>
                </thead>
                <tbody>
                  {cluster.locations.map((location) => (
                    <tr key={location.id}>
                      <td>{location.repo}</td>
                      <td className="mono small">
                        {location.file}:{location.line}
                      </td>
                      <td className="small muted">{location.language}</td>
                      <td className="mono small muted">{location.id}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {cluster.count > 1 && (
              <p className="small muted" style={{ marginTop: 8 }}>
                One remediation ticket covers all {cluster.count}.
              </p>
            )}
          </div>
        ))
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
