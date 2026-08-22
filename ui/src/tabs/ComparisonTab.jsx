import { useEffect, useState } from "react";
import { api } from "../api";

// Screen 4: the argument of the whole project, in one table per scan.
// Semgrep, then our Stage 2, then our Stage 3. If Stage 3 does not beat
// Stage 2 on precision without losing recall, this screen shows that too.
export default function ComparisonTab({ refreshToken }) {
  const [comparisons, setComparisons] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .comparison()
      .then((data) => setComparisons(data.comparisons))
      .catch((exception) => setError(exception.message));
  }, [refreshToken]);

  if (error) return <div className="panel error">{error}</div>;
  if (comparisons.length === 0) {
    return (
      <div className="panel">
        <div className="empty">
          No comparison yet. Run a scan with “compare against Joern baseline” ticked.
        </div>
      </div>
    );
  }

  return comparisons.map((comparison) => (
    <ComparisonCard key={comparison.scan_id} comparison={comparison} />
  ));
}

function ComparisonCard({ comparison }) {
  const suppression = comparison.suppression;
  // Joern is the primary baseline: a mature CPG tool with its own
  // inter-procedural data-flow engine, so beating it means beating real
  // analysis rather than beating regular expressions. Semgrep is optional.
  const rows = [
    {
      label: "Joern (baseline SAST)",
      block: comparison.joern,
      note: comparison.joern?.version ? `joern ${comparison.joern.version}` : "",
    },
    ...(comparison.semgrep
      ? [{
          label: "Semgrep (secondary baseline)",
          block: comparison.semgrep,
          note: comparison.semgrep.rules_config,
        }]
      : []),
    { label: "Ours — Stage 2 (pattern matching)", block: comparison.stage2_pattern_matching },
    { label: "Ours — Stage 3 (after LLM validation)", block: comparison.stage3_after_validation },
  ].filter((row) => row.block);

  return (
    <div className="panel">
      <div className="row">
        <h2 style={{ margin: 0 }}>{comparison.repo}</h2>
        <span className="pill mono">{comparison.scan_id}</span>
      </div>

      <div className="scroll-x">
        <table>
          <thead>
            <tr>
              <th>tool / stage</th>
              <th>findings</th>
              <th>true positives</th>
              <th>false positives</th>
              <th>missed</th>
              <th>precision</th>
              <th>recall</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => {
              const score = row.block.score || {};
              if (score.error) {
                return (
                  <tr key={row.label}>
                    <td>{row.label}</td>
                    <td colSpan={6} className="muted small">
                      unavailable — {score.error}
                    </td>
                  </tr>
                );
              }
              return (
                <tr key={row.label}>
                  <td>
                    {row.label}
                    {row.note && <div className="small muted mono">{row.note}</div>}
                  </td>
                  <td>{row.block.total_findings}</td>
                  <td>{score.true_positives}</td>
                  <td>{score.false_positives}</td>
                  <td>{score.false_negatives}</td>
                  <td>{percent(score.precision)}</td>
                  <td>{percent(score.recall)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <h3>What LLM validation changed</h3>
      <div className="grid">
        <Tile
          value={`${suppression.false_positives_removed} / ${suppression.false_positives_before}`}
          label="false positives removed"
          hint={`${percent(suppression.fp_suppression_rate)} of them`}
        />
        <Tile
          value={signed(suppression.precision_gain)}
          label="precision gain"
          good={suppression.precision_gain >= 0}
        />
        <Tile
          value={signed(suppression.recall_change)}
          label="recall change"
          good={suppression.recall_change >= 0}
          hint={suppression.recall_change === 0 ? "no real bugs lost" : ""}
        />
        <Tile
          value={percent(suppression.suppression_rate)}
          label="of raw findings suppressed"
          hint={`${suppression.raw_findings} → ${suppression.confirmed_findings}`}
        />
      </div>

      {comparison.vs_joern && (
        <>
          <h3>Against Joern, the primary baseline</h3>
          <div className="grid">
            <Tile
              value={signed(comparison.vs_joern.precision_gain)}
              label="precision vs Joern"
              good={comparison.vs_joern.precision_gain >= 0}
            />
            <Tile
              value={signed(comparison.vs_joern.recall_gain)}
              label="recall vs Joern"
              good={comparison.vs_joern.recall_gain >= 0}
            />
            <Tile
              value={comparison.vs_joern.false_positives_removed}
              label="fewer false positives"
              good={comparison.vs_joern.false_positives_removed >= 0}
            />
            <Tile
              value={comparison.vs_joern.joern_false_positives}
              label="Joern false positives"
            />
          </div>
        </>
      )}

      <h3>Overlap with the baseline</h3>
      <div className="grid">
        <Tile value={comparison.overlap.both_tools} label="found by both" />
        <Tile value={comparison.overlap.only_ours} label="only us" />
        <Tile value={comparison.overlap.only_baseline} label="only the baseline" />
      </div>
    </div>
  );
}

function Tile({ value, label, hint, good }) {
  return (
    <div className="tile">
      <div className={`value ${good === undefined ? "" : good ? "gain" : "loss"}`}>{value}</div>
      <div className="label">{label}</div>
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}

const percent = (value) =>
  value === undefined || value === null ? "—" : `${(value * 100).toFixed(1)}%`;

const signed = (value) =>
  value === undefined || value === null
    ? "—"
    : `${value >= 0 ? "+" : ""}${(value * 100).toFixed(1)}%`;
