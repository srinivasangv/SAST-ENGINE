import { useEffect, useState } from "react";
import { api } from "./api";
import ScansTab from "./tabs/ScansTab.jsx";
import FindingsTab from "./tabs/FindingsTab.jsx";
import ComparisonTab from "./tabs/ComparisonTab.jsx";
import DedupeTab from "./tabs/DedupeTab.jsx";
import WorkflowTab from "./tabs/WorkflowTab.jsx";
import DefectDojoTab from "./tabs/DefectDojoTab.jsx";

// Five screens, one piece of state to say which is showing. No router library:
// this is a single-page tool, and `useState` is the honest amount of machinery.
const TABS = [
  { id: "scans", label: "Scans", component: ScansTab },
  { id: "findings", label: "Findings", component: FindingsTab },
  { id: "comparison", label: "vs Baseline SAST", component: ComparisonTab },
  { id: "dedupe", label: "Deduplication", component: DedupeTab },
  { id: "workflow", label: "Approvals & SLA", component: WorkflowTab },
  { id: "defectdojo", label: "DefectDojo", component: DefectDojoTab },
];

// The header used to say "validator: Claude <model>" whenever a key was
// present. A key can be present and rejected -- ours returns 401 -- and then
// the offline validator is what actually ran, so the header was claiming a
// model that had never answered. Report what the last scan really used, and
// fall back to naming the configured provider only when nothing has run yet.
function validatorLabel(health) {
  const used = health.llm_last_used;
  if (used && used !== "offline") return `validator: ${used} ${health.llm_model}`;
  if (used === "offline") {
    return health.llm_configured
      ? `validator: offline (${health.llm_provider} did not answer)`
      : "validator: offline fallback";
  }
  if (!health.llm_configured) return "validator: offline fallback";
  return `validator: ${health.llm_provider} ${health.llm_model} — not yet used`;
}

function validatorDetail(health) {
  if (health.llm_last_used === "offline" && health.llm_configured) {
    return `${health.llm_provider} is configured but the last scan fell back to the deterministic validator. Run a scan to retry it.`;
  }
  return `configured: ${health.llm_provider || "none"} · last scan used: ${health.llm_last_used || "nothing scanned yet"}`;
}

export default function App() {
  const [tab, setTab] = useState("scans");
  const [health, setHealth] = useState(null);
  // Bumping this number is how one tab tells the others "data changed, reload".
  const [refreshToken, setRefreshToken] = useState(0);

  useEffect(() => {
    api.health().then(setHealth).catch(() => setHealth({ status: "unreachable" }));
  }, [refreshToken]);

  const refresh = () => setRefreshToken((value) => value + 1);
  const Active = TABS.find((entry) => entry.id === tab).component;

  return (
    <>
      <header>
        <h1>Multi-Stage Agentic SAST Engine</h1>
        <span className="stages">Prepare → Scan → Validate → Prove</span>
        <span style={{ marginLeft: "auto" }} />
        {health && health.status === "unreachable" && (
          <span className="pill">API unreachable — is server.py running?</span>
        )}
        {health && health.status !== "unreachable" && (
          <>
            <span className="pill" title={validatorDetail(health)}>
              {validatorLabel(health)}
            </span>
            <span className="pill">
              engines: builtin
              {health.engines?.joern ? " + joern" : " (joern not installed)"}
            </span>
            <span className="pill">
              DefectDojo:{" "}
              {health.defectdojo?.authenticated ? "connected" : "not connected"}
            </span>
          </>
        )}
      </header>

      <nav>
        {TABS.map((entry) => (
          <button
            key={entry.id}
            className={entry.id === tab ? "active" : ""}
            onClick={() => setTab(entry.id)}
          >
            {entry.label}
          </button>
        ))}
      </nav>

      <main>
        <Active refreshToken={refreshToken} refresh={refresh} />
      </main>
    </>
  );
}
