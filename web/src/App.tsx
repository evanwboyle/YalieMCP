import { useState, type ReactNode } from "react";
import { motion } from "framer-motion";
import AsciiHero from "./hero/AsciiHero";
import Demo from "./components/Demo";
import Diagram from "./components/Diagram";

const MCP_URL = "https://yalie-mcp.vercel.app/mcp";
const GITHUB_URL = "https://github.com/evanwboyle/YalieMCP";

const TOOL_GROUPS: { group: string; tools: { name: string; desc: string }[] }[] = [
  {
    group: "discovery",
    tools: [
      { name: "search_courses", desc: "filter by subject, rating, workload, skills, area" },
      { name: "get_course", desc: "full detail for a single listing" },
      { name: "get_course_by_code", desc: "lookup by code, e.g. CPSC 323" },
      { name: "compare_courses", desc: "side-by-side ratings and schedules" },
      { name: "list_seasons", desc: "every available semester" },
      { name: "get_catalog_metadata", desc: "subjects, schools, skill codes" },
    ],
  },
  {
    group: "evaluations",
    tools: [
      { name: "get_course_evaluations", desc: "summaries plus raw student comments" },
      { name: "get_evaluation_ratings", desc: "quantitative score distributions" },
      { name: "search_professors", desc: "ratings and teaching history" },
    ],
  },
  {
    group: "personal",
    tools: [
      { name: "get_worksheets", desc: "your CourseTable worksheets" },
      { name: "get_wishlist", desc: "saved courses across semesters" },
      { name: "update_worksheet_course", desc: "add or drop a course" },
      { name: "update_wishlist_course", desc: "manage the wishlist" },
      { name: "update_worksheet_metadata", desc: "rename, recolor, reorder" },
      { name: "get_friends_worksheets", desc: "what friends are shopping" },
      { name: "get_user_info", desc: "profile and friend graph" },
    ],
  },
  {
    group: "academics",
    tools: [
      { name: "get_degree_audit", desc: "GPA and requirement blocks" },
      { name: "get_syllabus_content", desc: "syllabus text pulled from Canvas" },
      { name: "get_major_requirements", desc: "scraped from the Yale catalog" },
      { name: "list_majors", desc: "every undergraduate major" },
      { name: "list_certificates", desc: "certificate programs" },
      { name: "get_curriculum_info", desc: "distributional requirements" },
    ],
  },
];

const STEPS = [
  {
    title: "Open Claude connectors",
    body: (
      <>
        Go to{" "}
        <a href="https://claude.ai/customize/connectors" target="_blank" rel="noopener noreferrer">
          claude.ai/customize/connectors
        </a>{" "}
        and choose <em>Add a custom connection</em>.
      </>
    ),
  },
  {
    title: "Paste the server URL",
    body: <>Drop the MCP endpoint above into the connection URL field.</>,
  },
  {
    title: "Authorize your Yale services",
    body: (
      <>
        An OAuth window walks you through CourseTable (required), Canvas, and Degree Audit. Each
        service unlocks more tools.
      </>
    ),
  },
  {
    title: "Ask anything",
    body: <>Search courses, compare professors, and audit your degree in plain English.</>,
  },
];

function CopyUrl() {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(MCP_URL).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <div className="copy-box" onClick={copy} role="button" tabIndex={0}>
      <span className="copy-prompt">$</span>
      <span className="copy-url">{MCP_URL}</span>
      <span className={`copy-action${copied ? " ok" : ""}`}>{copied ? "copied" : "copy"}</span>
    </div>
  );
}

function WheelSection({ id, children }: { id?: string; children: ReactNode }) {
  return (
    <motion.section
      id={id}
      className="section"
      initial={{ opacity: 0, y: 28 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-80px" }}
      transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.section>
  );
}

export default function App() {
  return (
    <>
      <nav className="nav">
        <span className="nav-brand">
          <span className="nav-dot" /> yalie-mcp
        </span>
        <div className="nav-links">
          <a href="#tools">tools</a>
          <a href="#demo">demo</a>
          <a href="#security">security</a>
          <a href={GITHUB_URL} target="_blank" rel="noopener noreferrer">
            github ↗
          </a>
        </div>
      </nav>

      <header className="hero">
        <AsciiHero />
        <div className="hero-content">
          <motion.p
            className="hero-kicker"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.6, duration: 0.8 }}
          >
            a model context protocol server for yale
          </motion.p>
          <motion.p
            className="hero-tagline"
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.8, duration: 0.8 }}
          >
            Course search, evaluations, worksheets, and your degree audit, wired directly into
            Claude. Stateless by design: no database, no logs, nothing stored.
          </motion.p>
          <motion.div
            className="hero-actions"
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 1.0, duration: 0.8 }}
          >
            <CopyUrl />
            <div className="hero-buttons">
              <a className="btn primary" href="https://claude.ai/customize/connectors" target="_blank" rel="noopener noreferrer">
                connect to claude
              </a>
              <a className="btn ghost" href={GITHUB_URL} target="_blank" rel="noopener noreferrer">
                view source
              </a>
            </div>
          </motion.div>
        </div>
        <div className="hero-scroll-hint" aria-hidden="true">
          scroll ↓
        </div>
      </header>

      <main>
        <WheelSection>
          <div className="section-head">
            <span className="section-num">01</span>
            <h2>How it&apos;s wired</h2>
            <p>
              One endpoint speaks MCP to any client and fans out to three Yale systems. Your
              session cookies travel encrypted inside your own access token, so the server keeps
              no state at all.
            </p>
          </div>
          <Diagram />
        </WheelSection>

        <WheelSection id="tools">
          <div className="section-head">
            <span className="section-num">02</span>
            <h2>
              22 tools <span className="accent">/</span> 4 domains
            </h2>
            <p>Everything CourseTable, Canvas, and the degree audit expose, typed with Zod and formatted for a language model.</p>
          </div>
          <div className="tool-groups">
            {TOOL_GROUPS.map((g) => (
              <div key={g.group} className="tool-group">
                <div className="tool-group-name"># {g.group}</div>
                {g.tools.map((t) => (
                  <div key={t.name} className="tool-row">
                    <code>{t.name}</code>
                    <span>{t.desc}</span>
                  </div>
                ))}
              </div>
            ))}
          </div>
        </WheelSection>

        <WheelSection id="demo">
          <div className="section-head">
            <span className="section-num">03</span>
            <h2>Watch a call happen</h2>
            <p>Real prompts, the exact tool each one triggers, and the shape of what comes back.</p>
          </div>
          <Demo />
        </WheelSection>

        <WheelSection>
          <div className="section-head">
            <span className="section-num">04</span>
            <h2>Connected in a minute</h2>
          </div>
          <ol className="steps">
            {STEPS.map((s, i) => (
              <li key={s.title} className="step">
                <span className="step-num">{String(i + 1).padStart(2, "0")}</span>
                <div>
                  <h3>{s.title}</h3>
                  <p>{s.body}</p>
                </div>
              </li>
            ))}
          </ol>
        </WheelSection>

        <WheelSection id="security">
          <div className="section-head">
            <span className="section-num">05</span>
            <h2>Nothing to breach</h2>
            <p>
              There is no database and no session store. Your Yale cookies are encrypted with
              AES-256-GCM and sealed inside the access token that only you hold; each request
              unseals them in memory, makes its calls, and forgets.
            </p>
          </div>
          <pre className="token-flow">
{`authorize ──▶ cookies verified against live Yale endpoints
          ──▶ sealed with AES-256-GCM into a code token   (10 min)
          ──▶ exchanged for access + refresh tokens       (30 / 60 days)
request   ──▶ token unsealed in memory ──▶ fan out ──▶ respond ──▶ forget`}
          </pre>
        </WheelSection>
      </main>

      <footer className="footer">
        <p>
          Built by <a href="https://github.com/evanwboyle" target="_blank" rel="noopener noreferrer">Evan Boyle</a>. Independent
          project, not affiliated with Yale University or CourseTable.
        </p>
      </footer>
    </>
  );
}
