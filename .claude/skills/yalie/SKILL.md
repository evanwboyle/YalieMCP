---
name: yalie
description: "Every Yale academic tool YalieMCP had, plus offline course search and cross-source requirement matching no other Yale tool offers. Trigger phrases: `check my Yale degree audit`, `search Yale courses`, `find a course for my requirement`, `check my CourseTable worksheet`, `Yale course evaluations`, `use yalie`, `run yalie`."
author: "evanwboyle"
license: "Apache-2.0"
argument-hint: "<command> [args]"
allowed-tools: "Read Bash"
---

# Yalie CLI

## Prerequisites: Build the CLI

This skill drives the `yalie-pp-cli` binary, which lives in this repo at `cli/`. **You must verify the CLI is built and on `$PATH` before invoking any command from this skill.** This CLI is not published anywhere — it only exists as source in this repo (build it yourself, do not attempt `npx`/`go install` against any external package):

1. Build it from the repo root:
   ```bash
   cd cli && go build -o ./yalie-pp-cli ./cmd/yalie-pp-cli
   ```
2. Verify: `./cli/yalie-pp-cli --version` (or `yalie-pp-cli --version` if you've put it on `$PATH`, e.g. `mv cli/yalie-pp-cli ~/go/bin/`)
3. If invoking without putting it on `$PATH`, use the relative/absolute path `cli/yalie-pp-cli` (or wherever you moved it) for every command below instead of the bare `yalie-pp-cli` shown in examples.

If `--version` fails, rebuild (Go 1.26.6+ required) before proceeding with any skill commands.

Yalie unifies CourseTable, Canvas, Degree Audit, and the Yale Catalog into one fast, scriptable CLI with a local SQLite cache. It doesn't just mirror four disconnected web tools — it recommends courses for your remaining requirements, flags worksheet schedule conflicts, searches every worksheet syllabus at once, and browses full Canvas course content (pages, assignments, quizzes, grades, files) by joining and navigating data no single Yale tool combines.

## When to Use This CLI

Use Yalie for Yale course planning, degree-progress tracking, and requirement research: searching/comparing courses, checking evaluations before enrolling, tracking degree-audit progress over terms, and matching course history against major requirements.

## Anti-triggers

Do not use this CLI for:
- Do not use this CLI for actual course registration/enrollment — Yale's registration happens through the official student portal, not CourseTable or this CLI.
- Do not use this CLI to submit or modify official transcripts or grades — it only reads degree-audit data.

## Unique Capabilities

These capabilities aren't available in any other tool for this API.

### Local state that compounds
- **`audit recommend`** — See which of your remaining degree requirements have the best-rated available courses, without cross-checking two tools by hand.

  _Reach for this instead of chaining 'audit get' and 'courses search' by hand when the agent's task is picking a course toward a specific unmet requirement._

  ```bash
  yalie-pp-cli audit recommend --block "Humanities & Arts" --json
  ```
- **`worksheet conflicts`** — Flags real time overlaps between courses already saved in a worksheet, before you find out the hard way.

  _Use this whenever the task is validating a saved worksheet is schedulable, not just whether individual courses exist._

  ```bash
  yalie-pp-cli worksheet conflicts --season 202603
  ```
- **`worksheet syllabus-search`** — Search for a keyword or policy (e.g. 'no laptops', 'final exam') across every syllabus already fetched for your worksheet courses at once.

  _Use this over repeated single-course 'courses syllabus' calls when the task spans a whole worksheet._

  ```bash
  yalie-pp-cli worksheet syllabus-search "final exam" --season 202603
  ```
- **`majors fit`** — Check how much of a major's requirements your existing course history already satisfies, without declaring it.

  _Use this over 'majors requirements' whenever the task is personalized completion, not general requirement browsing._

  ```bash
  yalie-pp-cli majors fit "Computer Science" --json
  ```
- **`certificates fit`** — Check how much of a certificate program's requirements your existing course history already satisfies, without declaring it.

  _Use this over 'certificates list' whenever the task is personalized completion for a specific certificate, not general browsing._

  ```bash
  yalie-pp-cli certificates fit "Data Science" --json
  ```

### Agent-native plumbing
- **`canvas files list`** — Browse a Canvas course's file directory (names, sizes, folders) without downloading anything — pick what's worth fetching before you fetch it.

  _Always list before fetching a Canvas file — never bulk-download a course's Files section._

  ```bash
  yalie-pp-cli canvas files list 89687 --path "Readings"
  ```

## Command Reference

**courses** — Manage courses


**files** — Manage files

- `yalie-pp-cli files <id>` — Get metadata + download URL for one Canvas file by ID


### Finding the right command

When you know what you want to do but not which command does it, ask the CLI directly:

```bash
yalie-pp-cli which "<capability in your own words>"
```

`which` resolves a natural-language capability query to the best matching command from this CLI's curated feature index. Exit code `0` means at least one match; exit code `2` means no confident match — fall back to `--help` or use a narrower query.

## Recipes

### Find a highly-rated course for a remaining requirement

```bash
yalie-pp-cli audit recommend --block "Science" --select courses.title,courses.average_rating
```

Narrows the joined audit+evaluation output to just the fields needed to pick a course.

### Check a worksheet for schedule conflicts before finalizing

```bash
yalie-pp-cli worksheet conflicts --season 202603
```

Run before add/drop deadline to catch overlapping sections.

### Search every worksheet syllabus for a policy at once

```bash
yalie-pp-cli worksheet syllabus-search "final exam" --season 202603
```

Finds mentions of a keyword across all fetched syllabi for a worksheet in one pass.

## Auth Setup

CourseTable's public catalog and evaluation data need no auth. Worksheet/wishlist/friends actions and Degree Audit both require your Yale CAS-derived session cookie (copy `document.cookie` from a logged-in browser tab) — there is no student-facing API token for either. Canvas prefers an admin-issued Bearer access token if your Yale account has one, but falls back to the same session-cookie approach since Yale blocks self-service Canvas token generation for most students.

Run `yalie-pp-cli doctor` to verify setup.

## Agent Mode

Add `--agent` to any command. Expands to: `--json --compact --no-input --no-color`.

- **Pipeable** — JSON on stdout, errors on stderr
- **Filterable** — `--select` keeps a subset of fields. Dotted paths descend into nested structures; arrays traverse element-wise. Critical for keeping context small on verbose APIs:

  ```bash
  yalie-pp-cli files mock-value --agent --select content-type,display_name,filename
  ```
- **Previewable** — `--dry-run` shows the request without sending
- **Offline-friendly** — sync/search commands can use the local SQLite store when available
- **Non-interactive** — never prompts, every input is a flag
- **Read-only** — do not use this CLI for create, update, delete, publish, comment, upvote, invite, order, send, or other mutating requests

### Response envelope

Commands that read from the local store or the API wrap output in a provenance envelope:

```json
{
  "meta": {"source": "live" | "local", "synced_at": "...", "reason": "..."},
  "results": <data>
}
```

Parse `.results` for data and `.meta.source` to know whether it's live or local. A human-readable `N results (live)` summary is printed to stderr only when stdout is a terminal AND no machine-format flag (`--json`, `--csv`, `--compact`, `--quiet`, `--plain`, `--select`) is set — piped/agent consumers and explicit-format runs get pure JSON on stdout.

## Paths and state

Agents should treat the CLI's path resolver as part of the runtime contract:

- Use `--home <dir>` for one invocation, or set `YALIE_HOME=<dir>` to relocate all four path kinds under one root.
- Use per-kind env vars only when a specific kind must diverge: `YALIE_CONFIG_DIR`, `YALIE_DATA_DIR`, `YALIE_STATE_DIR`, `YALIE_CACHE_DIR`.
- Resolution order is per-kind env var, `--home`, `YALIE_HOME`, XDG (`XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, `XDG_CACHE_HOME`), then platform defaults.
- `config` contains settings like `config.toml` and profiles. `data` contains `credentials.toml`, `data.db`, cookies, and auth sidecars. `state` contains persisted queries, jobs, and `teach.log`. `cache` contains regenerable HTTP/cache files.
- Stored secrets live in `credentials.toml` under the data dir. Existing legacy `config.toml` secrets are read for compatibility and leave `config.toml` on the first auth write.
- Run `yalie-pp-cli doctor --fail-on warn` to surface path and credential-location warnings. `agent-context` exposes a schema v4 `paths` block for agents that need the resolved dirs.
- For MCP, pass relocation through the MCP host config. The MCP binary does not inherit CLI flags:

  ```json
  {
    "mcpServers": {
      "yalie": {
        "command": "yalie-pp-mcp",
        "env": {
          "YALIE_HOME": "/srv/yalie"
        }
      }
    }
  }
  ```

Fleet precedence: an inherited per-kind env var overrides an explicit `--home` for that kind. Use `YALIE_HOME` or per-kind vars as durable fleet levers, and use `--home` only for a single invocation. Relocation is not reversible by unsetting env vars; move files manually before clearing `YALIE_HOME`, or `doctor` will not find credentials left under the former root.

## Automatic learning

This CLI ships a self-capturing learning loop. The CLI does its own bookkeeping: every invocation is journaled locally, a failed flag followed by a corrected retry auto-derives a `flag_alias` candidate, and a `teach` on a query family without a playbook auto-synthesizes a `playbook_candidate` from the session's journal. Your job is judgment only: `recall` first, act on surfaced candidates, `teach` the final answer, `playbook amend` when you observe a correction. You never record failures by hand.

### Step 1: `recall` before any discovery

Before list/search/drill commands on a new user question, run:

```bash
yalie-pp-cli recall "<user's question>" --agent
```

The response envelope:

```json
{
  "query": "...",
  "normalized": "<normalized form>",
  "query_entities": ["..."],
  "found": true | false,
  "match_score": 0.0,
  "results": [
    { "resource_id": "...", "resource_type": "...", "venue": "...",
      "confidence": 2, "entity_match": "exact|partial|unknown",
      "source": "taught|preseed|pattern", "warnings": ["..."] }
  ],
  "mismatches": [ /* only when --debug-mismatches */ ],
  "warnings": [ /* top-level */ ],
  "candidates": [
    { "id": 12, "class": "flag_alias | playbook_candidate",
      "summary": "...", "sightings": 3, "last_seen": "...",
      "rationale": "...",
      "next_action": ["<trial command>", "yalie-pp-cli learnings confirm 12"] }
  ],
  "playbook": {
    "query_family": "...",
    "playbook": {
      "steps": [ { "cmd": "<command with {slot} substitution>", "purpose": "..." } ],
      "entity_slots": ["$ENTITY"],
      "expected_tool_calls": 3
    },
    "slots_resolved": { "$ENTITY": { "token": "<live token>", "canonical": "<canonical>" } },
    "notes": "<workarounds + gotchas for this query family>"
  },
  "notes": "<duplicate surface for non-playbook callers>"
}
```

Empty-store short-circuit: if the store has no learnings, playbooks, or candidates yet (recall finds nothing and `learnings list` and `learnings candidates` are both empty), skip recall for the rest of this session instead of taxing every query; resume recall-first once something has been taught.

### Step 2: decision tree

Read `candidates`, `playbook`, `notes`, `results[0]`, and warnings in that order:

```
if Candidates present (warnings include "candidates_present"):
    -> candidates are try-then-confirm, never facts. Follow each candidate's
       two-step next_action verbatim: run the trial command first, then run
       `learnings confirm <id>` only after the trial verified the behavior.
       Reject a wrong candidate with `learnings reject <id>`.
    -> NEVER re-teach something recall surfaced as a candidate; confirm or
       reject that candidate instead of teaching a duplicate.
    -> candidates ride alongside playbooks and resource hits, not instead of
       them; continue with the branches below after acting on them.

if Playbook present:
    -> READ Playbook.notes verbatim FIRST (workarounds + gotchas the CLI surface doesn't expose)
    -> replay Playbook.steps in order, substituting Playbook.slots_resolved entries
       for the entity slot tokens. If a step's slot is unresolved, fall back to
       discovery for that step only.
    -> the Playbook's expected_tool_calls is a budget; if you find yourself running
       materially more, record the divergence via `yalie-pp-cli playbook amend`
       at end-of-session.

elif Notes present (no Playbook):
    -> read Notes verbatim before any discovery step; they carry known gotchas
       for this query family even when no structured choreography exists yet.

elif Found AND Results[0].EntityMatch == "exact" AND Results[0].Confidence >= 2:
    -> skip discovery; fetch live data for Results[*].ResourceID in parallel

elif Found AND Results[0].EntityMatch == "partial":
    -> candidate hint, NOT a hit; read the resource title to validate before trusting

elif (any row in Mismatches[] when --debug-mismatches was passed):
    -> treat as cold start; the stored learning is for a different entity
       (different canonical resolved from query_entities)

else:  // Found == false, no playbook, no notes
    -> cold start; run discovery normally; teach the answer afterward (Step 4).
       If the family has no playbook yet, that teach auto-synthesizes a
       playbook candidate from this session's journal - you do not need to
       record one by hand.
```

Playbook and Notes are orthogonal to the per-resource path. A recall response can carry both a Playbook AND a `Results[]` hit - use both: the Playbook tells you which choreography to run; the resource hits short-circuit specific steps. Default to skipping `mismatches`; pass `--debug-mismatches` only when investigating cold-start surprises.

Candidate judgment details: `learnings confirm <id>` prints the candidate's full payload before materializing it - check that the printed payload matches the behavior you verified. `learnings reject <id>` tombstones the derivation signature so the same candidate does not resurface. The envelope carries only the few candidates worth acting on now; `yalie-pp-cli learnings candidates` lists the full open set.

Graceful degradation: if `learnings confirm` is an unknown command, you are driving an older binary - ignore the candidates guidance and follow the rest of the protocol.

### Step 3: always read `warnings`

- `low_confidence`: row exists at `confidence<2`. Treat as a hint, not a skip-discovery hit.
- `resource_not_in_store`: the local store doesn't have the resource the learning points at. The match validator couldn't classify entities — direct-fetch and re-evaluate.
- `cross_alias_match` (per-result): the row was taught under a different alias and matched the live query's canonical via `entity_lookups` (e.g., a "USA" teach satisfying a "United States" recall). Trust the resource_id.
- `similar_shape_different_entity:<canonical>` (top-level): a structurally matching row exists but its canonical entity differs from the live query's. Treated as cold start; the warning carries the conflicting canonical as a hint, but the row is NOT promoted into Results.
- `ambiguous_alias` (top-level): a single query entity resolved to multiple canonicals (e.g., "Cards" → Arizona Cardinals + St. Louis Cardinals). Surface the ambiguity from context before committing to a resource.
- `candidates_present` (top-level): the envelope carries a `candidates` section. Handle it via the candidates branch in Step 2 before anything else.
- Top-level `no_learnings_for_query_family`: the table had no rows above the Jaccard floor. Pure cold start.

### Step 4: `teach &` after finalizing your response - always

Teaching is unconditional. After resolving a query the store could not answer, background-teach the final resource mapping - no call-count threshold, no judging whether it was "worth" learning. The teach is the anchor of the loop: it triggers playbook synthesis for a family without a playbook, and same-referent phrasings fold into one family so near-duplicate teaches do not fragment the store. Fire it after assembling your user-facing response but BEFORE emitting it, with a shell `&` so the call returns immediately:

```bash
yalie-pp-cli teach --query "<user's question>" --resource-type <type> --resource <id1> --resource <id2>
# (append shell `&` to background it)
```

Silent on success. Errors only land in `teach.log` under the resolved state dir. Teach the **most specific** resource - if the user asked a broad question and you walked through parent records to find the specific answer, teach the leaf id, not the parent. The CLI uses seeded `entity_lookups` for cross-alias resolution at recall time, so a teach under one alias (e.g., "Niners") satisfies future queries under another alias (e.g., "49ers", "San Francisco") automatically.

PII rule: teach the structural question with identifiers stripped - never include names, emails, phone numbers, account ids, or other personal identifiers in taught queries or notes. The CLI scans teach queries for obvious email/phone shapes and warns, but does not block; strip before teaching rather than relying on the warning.

### Step 5: playbooks - optional flags, automatic synthesis

You do not need to decide whether a session "deserves" a playbook: a teach on a family without one auto-synthesizes a `playbook_candidate` from the session's journal, and the next session judges it via confirm/reject. Attach explicit playbook flags only when you already hold choreography worth recording verbatim - workarounds the CLI didn't surface (silently-dropped flags, undocumented params, pagination tricks, payload gotchas). Prefer the **integrated one-call form** - record the resource learning and the playbook in the same `teach` invocation:

```bash
# Common case: record both the resource learning AND the playbook in one call.
yalie-pp-cli teach \
  --query "<user's question>" \
  --resource <id> \
  --playbook-file ~/playbooks/<shape>.json \
  --playbook-notes-file ~/playbooks/<shape>-notes.md
# (append shell `&` to background it)

# Alternate: playbook-only (no resource to record alongside).
yalie-pp-cli teach-playbook \
  --query "<user's question>" \
  --playbook-file ~/playbooks/<shape>.json \
  --notes-file ~/playbooks/<shape>-notes.md
```

Playbook files are JSON with `steps`, `entity_slots`, `expected_tool_calls`. Notes files are markdown carrying the gotchas verbatim. File-free callers (MCP-only agents) pass the same content inline: `--playbook-json` and `--playbook-notes` on the integrated `teach` form, `--playbook-json` and `--notes` on `teach-playbook`. On the integrated `teach` form, the playbook flags are optional - omit them entirely for a resource-only teach. On the standalone `teach-playbook` form, at least one of the playbook and notes flags must be set; both empty is rejected. Playbooks are keyed on the structural query family (entities stripped) so a recipe taught from one entity-shaped query applies to every other query of the same shape, with `slots_resolved` binding the live query's canonical at recall time.

When you DO find a playbook on a future recall, treat it as ground truth: replay the steps with `slots_resolved` substitutions, skip the discovery that the choreography already documents, and read `notes` before any step.

### Step 6: `playbook amend &` when your debug response identifies a correction

If your debug-protocol response identifies a concrete correction the notes or playbook should know — a workaround, an undocumented endpoint shape, a stale field name, observed schema drift, an empty-payload fallback — fire `playbook amend` BEFORE emitting your user-facing response. Same fire-and-forget posture as `teach`.

```bash
yalie-pp-cli playbook amend \
  --query "<exact recall query string>" \
  --add-note "<your concrete correction>"
# (append shell `&` to background it)
```

What counts as worth amending: a behavior you OBSERVED this session that future-you would benefit from knowing. Examples worth amending:

- A workaround for a CLI surface that silently drops or misorders a flag.
- An undocumented endpoint shape (response wrapped in `{meta, results}`, payload nested two levels deeper than the docs claim).
- Observed schema drift (a field renamed, an index that shifted between seasons, a category label that the API now returns lower-cased).

What does NOT belong in notes:

- The year-specific or entity-specific answer to the user's question. That's the response, not a learning.
- Per-team / per-athlete / per-row data the playbook already retrieves at runtime.
- Statements that paraphrase what the existing notes already say.

The amend command appends to the family's existing notes with a timestamped marker (`[amend YYYY-MM-DDTHH:MMZ]: <text>`). Multiple amends accumulate; the audit trail is visible. If no playbook exists yet for the family, amend creates a notes-only one (so cold-start corrections still land).

#### PII discipline for amend notes

`playbook amend` notes are designed to potentially flow upstream as shared knowledge in future versions of the Printing Press. Keep them clean of user-identifying content so the upstream-contribution path stays open without retroactive scrubbing:

- **Do NOT embed** paths to user filesystems, personal API keys or tokens, user email addresses, user GitHub handles, or specific query histories tied to a single user.
- **Acceptable**: endpoint shapes, undocumented field names, API gotchas, observed schema drift, workarounds for CLI surfaces, generalizable pagination or retry tactics.

If a correction is only meaningful with user-specific context, it belongs in a personal note, not in the playbook amend.

### Measuring the loop

`yalie-pp-cli learnings stats` reports recall hit rate, teach-to-reuse, playbook resolution rate, and candidate confirm/reject counts from the local `learn_events` table. Rates are null until they have a denominator; everything stays on this machine. Use it to check whether the loop is earning its keep for this CLI.

### Disabling learning

- `--no-learn` on a single command short-circuits both `recall` and the `teach` write path. Use for deterministic agent flows or tests that must not be affected by accumulated learnings.
- `YALIE_NO_LEARN=true` in the environment globally disables the pipeline.

## Agent Feedback

When you (or the agent) notice something off about this CLI, record it:

```
yalie-pp-cli feedback "the --since flag is inclusive but docs say exclusive"
yalie-pp-cli feedback --stdin < notes.txt
yalie-pp-cli feedback list --json --limit 10
```

Entries are stored locally as `feedback.jsonl` under the resolved data dir. They are never POSTed unless `YALIE_FEEDBACK_ENDPOINT` is set AND either `--send` is passed or `YALIE_FEEDBACK_AUTO_SEND=true`. Default behavior is local-only.

Write what *surprised* you, not a bug report. Short, specific, one line: that is the part that compounds.

## Output Delivery

Every command accepts `--deliver <sink>`. The output goes to the named sink in addition to (or instead of) stdout, so agents can route command results without hand-piping. Three sinks are supported:

| Sink | Effect |
|------|--------|
| `stdout` | Default; write to stdout only |
| `file:<path>` | Atomically write output to `<path>` (tmp + rename) |
| `webhook:<url>` | POST the output body to the URL (`application/json` or `application/x-ndjson` when `--compact`) |

Unknown schemes are refused with a structured error naming the supported set. Webhook failures return non-zero and log the URL + HTTP status on stderr.

## Named Profiles

A profile is a saved set of flag values, reused across invocations. Use it when a scheduled or recurring agent reuses the same saved flags while providing different input each run.

```
yalie-pp-cli profile save briefing --json
yalie-pp-cli --profile briefing files mock-value
yalie-pp-cli profile list --json
yalie-pp-cli profile show briefing
yalie-pp-cli profile delete briefing --yes
```

Explicit flags always win over profile values; profile values win over defaults. `agent-context` lists all available profiles under `available_profiles` so introspecting agents discover them at runtime.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 2 | Usage error (wrong arguments) |
| 3 | Resource not found |
| 4 | Authentication required |
| 5 | API error (upstream issue) |
| 7 | Rate limited (wait and retry) |
| 10 | Config error |

## Argument Parsing

Parse `$ARGUMENTS`:

1. **Empty, `help`, or `--help`** → show `yalie-pp-cli --help` output
2. **Anything else** → Direct Use (execute as CLI command with `--agent`)

## MCP Server (alternative to this CLI skill)

This repo also builds an MCP server binary (`cmd/yalie-pp-mcp`) for hosts that speak MCP directly instead of shelling out to the CLI. You normally don't need this if you're using this CLI skill — it's an alternative integration path, not a dependency of it.

1. Build it:
   ```bash
   cd cli && go build -o ./yalie-pp-mcp ./cmd/yalie-pp-mcp
   ```
2. Register with Claude Code:
   ```bash
   claude mcp add yalie -- /absolute/path/to/cli/yalie-pp-mcp
   ```
3. Verify: `claude mcp list`

## Direct Use

1. Check if built and on `$PATH`: `which yalie-pp-cli`. If not found, check for a built binary at `cli/yalie-pp-cli` in this repo; if that's missing too, build it (see Prerequisites at the top of this skill).
2. Match the user query to the best command from the Unique Capabilities and Command Reference above.
3. Execute with the `--agent` flag:
   ```bash
   yalie-pp-cli <command> [subcommand] [args] --agent
   ```
4. If ambiguous, drill into subcommand help: `yalie-pp-cli <command> --help`.
