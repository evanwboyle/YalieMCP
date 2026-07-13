import { useEffect, useRef, useState } from "react";

type Scenario = {
  label: string;
  prompt: string;
  tool: string;
  args: string;
  response: string;
};

const SCENARIOS: Scenario[] = [
  {
    label: "Find gut CS courses",
    prompt: "Find me some well-rated, low-workload CS courses for the spring",
    tool: "search_courses",
    args: '{ "subject": "CPSC", "min_rating": 4, "max_workload": 2.5 }',
    response:
      "Three strong picks for Spring 2025:\n\nCPSC 100 · Beyond Silicon: Tech & Society\n  rating 4.3 · workload 1.8 · Joan Feigenbaum\n\nCPSC 112 · Introduction to Programming\n  rating 4.5 · workload 2.4 · Benedict Brown\n\nCPSC 150 · Computing and the Arts\n  rating 4.1 · workload 2.1 · Holly Rushmeier\n\nAll three carry the QR distributional credit and have consistently strong evaluations.",
  },
  {
    label: "Compare two courses",
    prompt: "Compare CPSC 365 and CPSC 366 for me",
    tool: "compare_courses",
    args: '{ "codes": ["CPSC 365", "CPSC 366"] }',
    response:
      "            CPSC 365        CPSC 366\nrating      4.1 / 5         3.8 / 5\nworkload    3.9 / 5         4.2 / 5\nprofessor   Dana Angluin    Yang Cai\nschedule    TTh 1:00pm      MW 2:30pm\n\nCPSC 365 edges ahead on both rating and workload. CPSC 366 goes deeper into algorithmic game theory — worth it if that is your focus, but expect heavier problem sets.",
  },
  {
    label: "Search a professor",
    prompt: "Tell me about Professor Amin Karbasi",
    tool: "search_professors",
    args: '{ "name": "Amin Karbasi" }',
    response:
      "Amin Karbasi · Associate Professor of Electrical Engineering\naverage rating 4.6 / 5\n\nRecent courses:\n  CPSC 474 · Computational Intelligence for Games\n  CPSC 575 · Computational Vision and Biological Perception\n  EENG 439 · Active Learning, Optimization & Bandits\n\nStudents praise clear explanations and genuine enthusiasm. Workload is substantial but fair.",
  },
  {
    label: "Check degree progress",
    prompt: "How far along am I in the CS major?",
    tool: "get_degree_audit",
    args: '{ "include_blocks": true }',
    response:
      "Computer Science B.S. — 71% complete\n\nsatisfied\n  CPSC 201, 223, 323 · core sequence\n  CPSC 365 · algorithms\n\nremaining\n  senior requirement · CPSC 490 or approved sequence\n  2 electives at the 300+ level\n\nCumulative GPA 3.72 · major GPA 3.81",
  },
];

type Phase = "typing" | "calling" | "streaming" | "done";

export default function Demo() {
  const [active, setActive] = useState(0);
  const [typed, setTyped] = useState("");
  const [streamed, setStreamed] = useState("");
  const [phase, setPhase] = useState<Phase>("typing");
  const timers = useRef<number[]>([]);
  const windowRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    timers.current.forEach(clearInterval);
    timers.current = [];
    setTyped("");
    setStreamed("");
    setPhase("typing");
    const s = SCENARIOS[active];

    let i = 0;
    const typeTimer = window.setInterval(() => {
      i += 2;
      setTyped(s.prompt.slice(0, i));
      if (i >= s.prompt.length) {
        clearInterval(typeTimer);
        setPhase("calling");
        const callTimer = window.setTimeout(() => {
          setPhase("streaming");
          let j = 0;
          const streamTimer = window.setInterval(() => {
            j += 4;
            setStreamed(s.response.slice(0, j));
            if (j >= s.response.length) {
              clearInterval(streamTimer);
              setPhase("done");
            }
          }, 16);
          timers.current.push(streamTimer);
        }, 900);
        timers.current.push(callTimer);
      }
    }, 24);
    timers.current.push(typeTimer);
    return () => {
      timers.current.forEach(clearInterval);
      timers.current = [];
    };
  }, [active]);

  useEffect(() => {
    const el = windowRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [typed, streamed, phase]);

  const s = SCENARIOS[active];
  const showCall = phase === "calling" || phase === "streaming" || phase === "done";

  return (
    <div className="demo">
      <div className="demo-tabs" role="tablist">
        {SCENARIOS.map((sc, i) => (
          <button
            key={sc.label}
            role="tab"
            aria-selected={i === active}
            className={`demo-tab${i === active ? " active" : ""}`}
            onClick={() => setActive(i)}
          >
            {sc.label}
          </button>
        ))}
      </div>
      <div className="terminal">
        <div className="terminal-bar">
          <span className="dot red" />
          <span className="dot yellow" />
          <span className="dot green" />
          <span className="terminal-title">claude — connected to yalie-mcp</span>
        </div>
        <div className="terminal-body" ref={windowRef}>
          <div className="line user-line">
            <span className="prompt-char">›</span> {typed}
            {phase === "typing" && <span className="caret" />}
          </div>
          {showCall && (
            <div className={`tool-call${phase === "calling" ? " pending" : " ok"}`}>
              <span className="tool-status">{phase === "calling" ? "◌" : "✓"}</span>
              <span className="tool-name">{s.tool}</span>
              <span className="tool-args">{s.args}</span>
            </div>
          )}
          {(phase === "streaming" || phase === "done") && (
            <pre className="line response">
              {streamed}
              {phase === "streaming" && <span className="caret" />}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}
