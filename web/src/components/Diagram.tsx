const CLIENTS = ["Claude", "ChatGPT", "Cursor", "any MCP client"];
const SOURCES = [
  { name: "CourseTable", detail: "GraphQL · courses, evals, worksheets" },
  { name: "Canvas", detail: "REST · syllabus content" },
  { name: "Degree Audit", detail: "REST · GPA, requirement blocks" },
];

export default function Diagram() {
  return (
    <div className="diagram">
      <div className="diagram-col">
        <div className="diagram-col-label">clients</div>
        {CLIENTS.map((c) => (
          <div key={c} className="diagram-node client">
            {c}
          </div>
        ))}
      </div>

      <div className="diagram-wire" aria-hidden="true">
        <svg viewBox="0 0 120 40" preserveAspectRatio="none">
          <path d="M0 20 H120" className="wire" />
          <circle r="2.4" className="pulse">
            <animateMotion dur="2.2s" repeatCount="indefinite" path="M0 20 H120" />
          </circle>
        </svg>
        <span className="wire-label">JSON-RPC / OAuth 2.0</span>
      </div>

      <div className="diagram-core">
        <div className="diagram-core-box">
          <div className="core-name">yalie-mcp</div>
          <div className="core-detail">stateless · 22 tools</div>
          <div className="core-detail dim">AES-256-GCM sealed tokens</div>
        </div>
      </div>

      <div className="diagram-wire" aria-hidden="true">
        <svg viewBox="0 0 120 40" preserveAspectRatio="none">
          <path d="M0 20 H120" className="wire" />
          <circle r="2.4" className="pulse">
            <animateMotion dur="1.8s" begin="0.4s" repeatCount="indefinite" path="M0 20 H120" />
          </circle>
        </svg>
        <span className="wire-label">authenticated per request</span>
      </div>

      <div className="diagram-col">
        <div className="diagram-col-label">yale data</div>
        {SOURCES.map((s) => (
          <div key={s.name} className="diagram-node source">
            <strong>{s.name}</strong>
            <span>{s.detail}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
