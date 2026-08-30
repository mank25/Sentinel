import { useEffect, useRef, useState } from "react";

/**
 * The landing page.
 *
 * The hero is not a claim about the product, it is the product's defining
 * moment played back: evidence is gathered, a deterministic engine scores it,
 * and then the machine STOPS and will not continue until the visitor clicks.
 * Nothing on this page can talk you past that hold -- which is exactly the
 * guarantee Sentinel makes.
 *
 * The replay is a scripted reconstruction of a real run against the seeded
 * incident, not a live investigation; the console does the real thing.
 */

interface Probe {
  tool: string;
  arg: string;
  finding: string;
}

const PROBES: Probe[] = [
  {
    tool: "get_user_info",
    arg: "admin",
    finding: "active · role admin · MFA disabled",
  },
  {
    tool: "get_login_history",
    arg: "admin",
    finding: "51 events · 12 failures from 3 countries",
  },
  {
    tool: "get_ip_status",
    arg: "203.0.113.42",
    finding: "known malicious · Tor exit node",
  },
  {
    tool: "assess_user_risk",
    arg: "admin",
    finding: "evidence handed to the scoring engine",
  },
];

const SCORE = 85;
const RUN_MS = 780;
const GAP_MS = 240;

type Phase = "probing" | "scoring" | "held" | "approved" | "denied";

function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true
  );
}

function Interlock() {
  const still = prefersReducedMotion();

  const [phase, setPhase] = useState<Phase>(still ? "held" : "probing");
  const [done, setDone] = useState(still ? PROBES.length : 0);
  const [running, setRunning] = useState(still ? -1 : 0);
  const [score, setScore] = useState(still ? SCORE : 0);

  const timers = useRef<number[]>([]);

  const clear = () => {
    timers.current.forEach(window.clearTimeout);
    timers.current = [];
  };

  const at = (ms: number, fn: () => void) => {
    timers.current.push(window.setTimeout(fn, ms));
  };

  const play = () => {
    clear();
    setPhase("probing");
    setDone(0);
    setRunning(0);
    setScore(0);

    let clock = 0;

    PROBES.forEach((_, index) => {
      clock += RUN_MS;
      at(clock, () => {
        setDone(index + 1);
        setRunning(index + 1 < PROBES.length ? index + 1 : -1);
      });
      clock += GAP_MS;
    });

    at(clock, () => setPhase("scoring"));

    // The score is counted up, not faded in: it is arrived at, by an engine.
    for (let tick = 1; tick <= 17; tick += 1) {
      at(clock + tick * 34, () => setScore(Math.round((SCORE / 17) * tick)));
    }

    at(clock + 900, () => setPhase("held"));
  };

  useEffect(() => {
    if (!still) at(500, play);
    return clear;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const decide = (allowed: boolean) => {
    clear();
    setPhase(allowed ? "approved" : "denied");
  };

  const settled = phase === "approved" || phase === "denied";
  const scored = phase !== "probing";

  return (
    <div className={`interlock ${phase}`}>
      <div className="interlock-head">
        <span className="plate">Replay · incident SEC-1042</span>
        <span className="interlock-state">
          {phase === "probing" && "gathering evidence"}
          {phase === "scoring" && "scoring"}
          {phase === "held" && "stopped — waiting for you"}
          {phase === "approved" && "contained"}
          {phase === "denied" && "no action taken"}
        </span>
      </div>

      <ol className="probes">
        {PROBES.map((probe, index) => {
          const state =
            index < done ? "done" : index === running ? "run" : "wait";

          return (
            <li key={probe.tool} className={`probe ${state}`}>
              <span className="probe-mark" aria-hidden="true" />
              <code className="probe-call">
                {probe.tool}
                <span className="probe-arg">({probe.arg})</span>
              </code>
              <span className="probe-finding">
                {state === "done"
                  ? probe.finding
                  : state === "run"
                    ? "reading…"
                    : ""}
              </span>
            </li>
          );
        })}
      </ol>

      <div className={`engine-strip ${scored ? "in" : ""}`}>
        <div className="engine-strip-score">
          <span className="engine-strip-value">{score}</span>
          <span className="engine-strip-max">/ 100</span>
        </div>
        <div className="engine-strip-meta">
          <span className="level CRITICAL">
            {score >= SCORE ? "CRITICAL" : "SCORING"}
          </span>
          <span className="engine-strip-note">
            computed by <code>investigator/risk.py</code> — never by the model
          </span>
        </div>
      </div>

      <div className={`proposal ${phase !== "probing" && phase !== "scoring" ? "in" : ""}`}>
        <span className="plate danger">Destructive action proposed</span>
        <code className="proposal-call">contain_account(username="admin")</code>
        <p className="proposal-why">
          The agent asked for this. TrueForge did not run it — the turn is
          paused inside the protocol, and only a person can release it.
        </p>
      </div>

      {phase === "held" && (
        <div className="hold">
          <div className="hold-label">
            <span className="lamp" aria-hidden="true" />
            Awaiting human authorisation
          </div>
          <div className="hold-actions">
            <button className="btn-approve" onClick={() => decide(true)}>
              Authorise containment
            </button>
            <button className="btn-deny" onClick={() => decide(false)}>
              Deny
            </button>
          </div>
        </div>
      )}

      {settled && (
        <div className={`settled ${phase}`}>
          <div className="settled-line">
            {phase === "approved" ? (
              <>
                <strong>Authorised.</strong> <code>contain_account</code> ran,
                and the agent read the account back to prove it:{" "}
                <code>status: disabled</code>.
              </>
            ) : (
              <>
                <strong>Denied.</strong> The account was never touched. The
                agent finished its report without containment.
              </>
            )}
          </div>
          <button className="replay" onClick={play}>
            Replay the run
          </button>
        </div>
      )}
    </div>
  );
}

const OWNERS = [
  {
    role: "The agent",
    color: "steel",
    title: "decides what to look at",
    body: "A TrueForge agent picks its own line of enquiry and pulls evidence through read-only MCP tools. It can read everything and change nothing.",
  },
  {
    role: "The engine",
    color: "clear",
    title: "decides how bad it is",
    body: "Every score comes out of investigator/risk.py — plain Python over the evidence rows. The model writes the narrative; it never writes the number.",
  },
  {
    role: "The human",
    color: "signal",
    title: "decides what happens",
    body: "Containment is a separate, gated act. The run halts, shows you the exact call and the evidence behind it, and waits for as long as it takes.",
  },
];

const ENFORCEMENT = [
  {
    where: "mcp/sentinel_mcp/http_server.py",
    code: 'destructiveHint: true',
    note: "contain_account and block_ip are declared destructive at the tool boundary.",
  },
  {
    where: "the agent spec",
    code: 'require_approval_for_tools: ["@write", "@destructive"]',
    note: "The rule is configuration on the run, not a sentence in a prompt.",
  },
  {
    where: "TrueForge",
    code: "tool.approval_required",
    note: "The turn pauses inside the runtime and emits a gate. Nothing resumes without a decision.",
  },
];

export function Landing({ onEnter }: { onEnter: () => void }) {
  return (
    <div className="landing">
      <header className="lp-nav">
        <div className="lp-mark">
          <span className="lp-mark-name">Sentinel</span>
          <span className="lp-mark-sub">AI security investigator</span>
        </div>
        <nav>
          <a href="#control">Control</a>
          <a href="#gate">The gate</a>
          <a href="#run">Run it</a>
          <button className="btn-primary" onClick={onEnter}>
            Open the console
          </button>
        </nav>
      </header>

      <section className="hero">
        <div className="hero-copy">
          <p className="plate">Autonomous investigation · human containment</p>
          <h1>
            The agent investigates on its own.
            <br />
            <span className="hero-em">Then it stops for you.</span>
          </h1>
          <p className="hero-lede">
            Sentinel works a compromised account the way an analyst does — it
            chooses what evidence to pull, a deterministic engine scores what it
            finds, and the instant it wants to disable the account, the run
            halts and hands the decision to a person.
          </p>
          <div className="hero-actions">
            <button className="btn-primary" onClick={onEnter}>
              Open the console
            </button>
            <a className="ghost" href="#gate">
              Why the gate can't be talked around
            </a>
          </div>
        </div>

        <Interlock />
      </section>

      <section className="owners" id="control">
        <p className="plate section-plate">Who decides what</p>
        <div className="owner-grid">
          {OWNERS.map((owner) => (
            <article className={`owner ${owner.color}`} key={owner.role}>
              <span className="owner-role">{owner.role}</span>
              <h3>{owner.title}</h3>
              <p>{owner.body}</p>
            </article>
          ))}
        </div>
        <p className="owners-note">
          The same three colours run through the whole product. Amber means a
          person is required. Red means an action that destroys something. Green
          means checked and clear. Nothing is coloured for decoration.
        </p>
      </section>

      <section className="gate-proof" id="gate">
        <div className="gate-proof-copy">
          <p className="plate">The guarantee</p>
          <h2>
            The gate lives in the protocol,
            <br />
            not in the prompt.
          </h2>
          <p>
            A refusal written into a system prompt is a suggestion; it survives
            exactly until someone rewrites the prompt. Sentinel's hold is
            enforced in three places that the model has no access to, so
            rewriting its instructions changes nothing about what it is able to
            do.
          </p>
        </div>

        <ul className="enforcement">
          {ENFORCEMENT.map((point) => (
            <li key={point.where}>
              <span className="enf-where">{point.where}</span>
              <code className="enf-code">{point.code}</code>
              <span className="enf-note">{point.note}</span>
            </li>
          ))}
        </ul>
      </section>

      <section className="run" id="run">
        <div className="run-copy">
          <p className="plate">Run it yourself</p>
          <h2>Three services, one command.</h2>
          <p>
            The console ships pre-built, so a real run needs Python alone. It
            resets the seeded incident first, so approve and deny are both
            watchable in one sitting.
          </p>
          <button className="btn-primary" onClick={onEnter}>
            Open the console
          </button>
        </div>

        <pre className="terminal">
          <code>
            <span className="c">{"# seed the incident and check every service"}</span>
            {"\n"}python data/init_db.py{"\n"}python -m sentinel.demo --check{"\n\n"}
            <span className="c">{"# the browser console"}</span>
            {"\n"}python -m ui.server{"\n"}
            <span className="c">{"# → http://127.0.0.1:8792"}</span>
          </code>
        </pre>
      </section>

      <footer className="lp-foot">
        <span>Sentinel — built on TrueForge and the Model Context Protocol.</span>
        <span className="lp-foot-thesis">
          The agent investigates. The engine scores. The human authorises.
        </span>
      </footer>
    </div>
  );
}
