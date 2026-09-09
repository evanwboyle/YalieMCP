# Yalie CLI

**Every Yale academic tool YalieMCP had, plus offline course search and cross-source requirement matching no other Yale tool offers.**

Yalie unifies CourseTable, Canvas, Degree Audit, and the Yale Catalog into one fast, scriptable CLI with a local SQLite cache. It doesn't just mirror four disconnected web tools — it recommends courses for your remaining requirements, flags worksheet schedule conflicts, searches every worksheet syllabus at once, and browses full Canvas course content (pages, assignments, quizzes, grades, files) by joining and navigating data no single Yale tool combines.

## Install

This CLI lives inside the [YalieMCP](https://github.com/evanwboyle/YalieMCP) repo, at `cli/`. It is not published to any external package registry — build it from source (requires Go 1.26.6 or newer):

```bash
git clone https://github.com/evanwboyle/YalieMCP.git
cd YalieMCP/cli
go build -o ./yalie-pp-cli ./cmd/yalie-pp-cli
```

Put the resulting binary on your `$PATH` (or invoke it by its full path):

```bash
mv yalie-pp-cli ~/go/bin/   # or any directory already on $PATH
yalie-pp-cli --version
```

### Claude Code skill

This CLI ships with a matching Claude Code skill at [`.claude/skills/yalie/SKILL.md`](../.claude/skills/yalie/SKILL.md) in the repo root — see that file for what it teaches an agent to do. The skill activates automatically for any Claude Code session opened in this repo (or a project that copies the `.claude/skills/yalie/` directory in); it assumes `yalie-pp-cli` is already built and on `$PATH` per the steps above.

### MCP server (Claude Desktop / other MCP hosts)

The same source also builds an MCP server binary, `yalie-pp-mcp`, for hosts that speak MCP directly instead of shelling out to a CLI:

```bash
go build -o ./yalie-pp-mcp ./cmd/yalie-pp-mcp
```

Add it to your MCP host's config (e.g. Claude Desktop's `~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "yalie": {
      "command": "/absolute/path/to/yalie-pp-mcp",
      "env": {
        "COURSETABLE_COOKIE": "<your CourseTable session cookie>",
        "CANVAS_COOKIE": "<your Canvas session cookie>",
        "AUDIT_COOKIE": "<your Degree Audit session cookie>"
      }
    }
  }
}
```

(`YALIE_BEARER_AUTH` also works for Canvas if your Yale account has an admin-issued token — see Authentication below. Most students will use the cookie env vars instead.)

## Authentication

CourseTable's public catalog and evaluation data need no auth. Worksheet/wishlist/friends actions and Degree Audit both require your Yale CAS-derived session cookie (copy `document.cookie` from a logged-in browser tab) — there is no student-facing API token for either. Canvas prefers an admin-issued Bearer access token if your Yale account has one, but falls back to the same session-cookie approach since Yale blocks self-service Canvas token generation for most students.

## Quick Start

```bash
# Health check first — works without any credentials.
yalie-pp-cli doctor --dry-run

# No auth needed — confirms the public CourseTable connection works.
yalie-pp-cli seasons list

# Search the public course catalog.
yalie-pp-cli courses search --subject CPSC --json

# Populate the local cache for offline search and cross-source commands.
yalie-pp-cli sync --resources courses,evaluations --season 202603

# The flagship cross-source command — requires Degree Audit and evaluations to be synced.
yalie-pp-cli audit recommend --json

```

## Unique Features

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

## Usage

Run `yalie-pp-cli --help` for the full command reference and flag list.

## Paths & environment variables

This CLI separates local files into four path kinds:

| Kind | Contents |
|------|----------|
| `config` | User-editable settings such as `config.toml` and saved profiles |
| `data` | Durable local data: `credentials.toml`, `data.db`, cookies, browser-session proof files, and other auth sidecars |
| `state` | Runtime state such as persisted queries, jobs, and `teach.log` |
| `cache` | Regenerable HTTP/cache files |

Each kind resolves independently. The ladder is:

1. Per-kind env var: `YALIE_CONFIG_DIR`, `YALIE_DATA_DIR`, `YALIE_STATE_DIR`, or `YALIE_CACHE_DIR`
2. `--home <dir>` for this invocation
3. `YALIE_HOME` for a flat relocated root
4. XDG env vars: `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`, `XDG_CACHE_HOME`
5. Platform defaults matching existing installs

For containers and agent sandboxes, prefer a single relocated root:

```bash
export YALIE_HOME=/srv/yalie
yalie-pp-cli doctor
```

Under `YALIE_HOME=/srv/yalie`, the four dirs resolve to `/srv/yalie/config`, `/srv/yalie/data`, `/srv/yalie/state`, and `/srv/yalie/cache`.

MCP servers do not receive CLI flags from the host. Put relocation in the host `env` block:

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

Precedence matters in fleets: an ambient per-kind variable such as `YALIE_DATA_DIR` overrides an explicit `--home` for that kind. Use `YALIE_HOME` or the per-kind variables for durable fleet relocation; treat `--home` as the weaker per-invocation lever.

Relocation is one-way. Unsetting `YALIE_HOME` does not move files back to platform defaults, and `doctor` cannot find credentials left under a former root. Move the files manually before unsetting relocation variables.

Existing installs keep working because the platform-default rung matches the legacy layout. On the first auth write, stored secrets leave `config.toml` and are consolidated into `credentials.toml` under the data directory. Run `yalie-pp-cli doctor --fail-on warn` to check path and credential-location warnings in automation.

## Commands

### courses

Manage courses


### files

Manage files

- **`yalie-pp-cli files <id>`** - Get metadata + download URL for one Canvas file by ID


### Self-learning loop

This CLI caches per-question discovery so repeat queries skip the walk and structurally similar queries get answered via entity substitution. The loop also self-captures: every invocation is journaled locally, and failed-flag corrections plus fresh teaches surface as candidates on the next `recall` for confirm/reject judgment. Agents call `recall` before discovery and fire `teach &` after answering. See the `## Automatic learning` section in `SKILL.md` for the full protocol.

- **`yalie-pp-cli recall <query>`** - Look up cached resources for a query before running discovery
- **`yalie-pp-cli teach`** - Record a query -> resource mapping (silent on success, safe to background with `&`)
- **`yalie-pp-cli learnings list`** - Inspect taught rows
- **`yalie-pp-cli learnings forget <query>`** - Undo a teach
- **`yalie-pp-cli learnings candidates`** - List auto-captured candidates awaiting confirm/reject
- **`yalie-pp-cli learnings stats`** - Local loop metrics: recall hit rate, teach-to-reuse, playbook resolution, candidate counts
- **`yalie-pp-cli teach-pattern`** - Install a query/resource template up front
- **`yalie-pp-cli teach-lookup`** - Add an entity mapping (e.g. country code, team alias) for pattern substitution

Pass `--no-learn` or set `YALIE_NO_LEARN=true` to disable the loop for deterministic flows.

The local store's schema version stamp is one-way: once this version of `yalie-pp-cli` opens the database, older binaries refuse it with a version error — upgrade the binary rather than downgrading.

## Output Formats

```bash
# Human-readable table (default in terminal, JSON when piped)
yalie-pp-cli files mock-value

# JSON for scripting and agents
yalie-pp-cli files mock-value --json
# Filter to specific fields
yalie-pp-cli files mock-value --json --select content-type,display_name,filename

# Dry run — show the request without sending
yalie-pp-cli files mock-value --dry-run

# Agent mode — JSON + compact + no prompts in one flag
yalie-pp-cli files mock-value --agent
```

## Agent Usage

This CLI is designed for AI agent consumption:

- **Non-interactive** - never prompts, every input is a flag
- **Pipeable** - `--json` output to stdout, errors to stderr
- **Filterable** - `--select <field>[,<field>...]` returns only fields you need
- **Previewable** - `--dry-run` shows the request without sending
- **Read-only by default** - this CLI does not create, update, delete, publish, send, or mutate remote resources
- **Offline-friendly** - sync/search commands can use the local SQLite store when available
- **Agent-safe by default** - no colors or formatting unless `--human-friendly` is set

Exit codes: `0` success, `2` usage error, `3` not found, `4` auth error, `5` API error, `7` rate limited, `10` config error.

## Health Check

```bash
yalie-pp-cli doctor
```

Verifies configuration, credentials, and connectivity to the API.

## Configuration

Run `yalie-pp-cli doctor` to see the resolved config, data, state, and cache directories. The platform-default config path is `~/.config/canvas-course-content-pp-cli/config.toml`; `--home`, `YALIE_HOME`, and per-kind env vars can relocate it.

Static request headers can be configured under `headers`; per-command header overrides take precedence.

Environment variables:

| Name | Kind | Required | Description |
| --- | --- | --- | --- |
| `YALIE_BEARER_AUTH` | per_call | Yes | Set to your API credential. |

### agentcookie (optional)

If you use agentcookie to sync secrets across machines, this CLI auto-adopts agentcookie-managed credentials with no extra setup. When the daemon writes to this CLI's config, `yalie-pp-cli doctor` reports `agentcookie: detected` and `auth-status` labels the source as `agentcookie`. Skip this section if you don't use agentcookie - the CLI works the same as any other.

## Troubleshooting
**Authentication errors (exit code 4)**
- Run `yalie-pp-cli doctor` to check credentials
- Verify the environment variable is set: `echo $YALIE_BEARER_AUTH`
**Not found errors (exit code 3)**
- Check the resource ID is correct
- Run the `list` command to see available items

### API-specific
- **Degree audit or worksheet commands fail with an auth error** — Your Yale CAS session cookie expired — re-copy `document.cookie` from a fresh logged-in tab on the relevant Yale site and set it again.
- **Canvas syllabus fetch fails even though other commands work** — Your Canvas cookie is separate from CourseTable/Degree Audit — copy it from a logged-in yale.instructure.com tab, or use a Bearer token if your Yale account has one.

## Sources & Inspiration

This CLI was built by studying these projects and resources:

- [**coursetable/ferry**](https://github.com/coursetable/ferry) — Python
- [**coursetable/coursetable**](https://github.com/coursetable/coursetable) — TypeScript
- [**filippo-fonseca/yale-degree-intelligence**](https://github.com/filippo-fonseca/yale-degree-intelligence) — TypeScript

Generated by [CLI Printing Press](https://github.com/mvanhorn/cli-printing-press)
