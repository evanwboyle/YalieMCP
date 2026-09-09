# Yalie Printed CLI Agent Guide

This directory is a generated `yalie-pp-cli` printed CLI. It was produced by [CLI Printing Press](https://github.com/mvanhorn/cli-printing-press), so treat systemic fixes as upstream Printing Press fixes first. Keep local edits narrow and document why a generated-tree patch belongs here.

## Local Operating Contract

Start by asking the generated CLI for current runtime truth:

```bash
yalie-pp-cli doctor --json
yalie-pp-cli agent-context --pretty
```

Use runtime discovery instead of relying on a copied command list:

```bash
yalie-pp-cli which "<capability>" --json
yalie-pp-cli <command> --help
```

Add `--agent` to command invocations for JSON, compact output, non-interactive defaults, and no color:

```bash
yalie-pp-cli <command> --agent
```

Before running an unfamiliar command that may mutate remote state, inspect its help and prefer a dry run:

```bash
yalie-pp-cli <command> --help
yalie-pp-cli <command> --dry-run --agent
```

When a command requires confirmation, pass `--yes` explicitly only after the target, arguments, and side effects are clear. `--agent` does not imply `--yes`.

## Novel Command Data Sources

Every hand-written novel command must declare its strategy in a Go line comment:

```go
// pp:data-source auto
```

Use exactly one of `auto`, `local`, `live`, or `computed`. Keep `auto` when the command honors `--data-source auto|local|live` by preferring live data with a local fallback; use `local` for local-only reads, `live` for remote-only reads, and `computed` for pure computation from embedded rules. Change a generated scaffold's `auto` default deliberately when its implementation has a narrower source, and reject incompatible `--data-source` requests with a clear error. TODO stubs still fail dogfood even when annotated.

## Self-Learning Loop

This CLI ships a self-capturing teach/recall loop backed by the local SQLite store. The CLI journals every invocation, derives `flag_alias` candidates from failed-flag + corrected-retry pairs, and synthesizes a playbook candidate when a family is taught without one - no manual failure bookkeeping. The agent's role is judgment:

1. On a new user question, call `yalie-pp-cli recall "<question>" --agent` FIRST. If `found=true` and the top result has `entity_match == "exact"` and `confidence >= 2`, skip discovery and go straight to the live fetch for the returned resource IDs. If the store is cold (recall finds nothing and `learnings list` and `learnings candidates` are both empty), skip recall for the rest of the session.
2. When the envelope carries a `candidates` section (warning `candidates_present`), candidates are try-then-confirm, never facts: follow each candidate's two-step `next_action` verbatim (trial command first, then `learnings confirm <id>` only after the trial verified the behavior), and reject wrong ones with `learnings reject <id>`. Never re-teach something recall surfaced as a candidate; confirm or reject it instead.
3. After answering, always fire `yalie-pp-cli teach --query "<question>" --resource <id> --resource-type <type> &` in the background - teaching is unconditional and is the anchor that triggers playbook synthesis. Teach the structural question with identifiers stripped (no names, emails, phone numbers, account ids); the CLI warns on obvious PII shapes but does not block.
4. Use `learnings list` to inspect taught rows, `learnings forget "<question>"` to undo a bad teach, `learnings candidates` for the full open candidate set, and `learnings stats` for the loop's local metrics. `teach-pattern` and `teach-lookup` install manual generalization rules when one teach should cover a whole family (e.g. one country alias unlocks every per-country query).
5. If `learnings confirm` is an unknown command, you are driving an older binary - ignore the candidates guidance and keep the rest of the flow.

Annotations: `recall`, `learnings list`, `learnings candidates`, and `learnings stats` carry `mcp:read-only=true`; `teach`, `teach-playbook`, `playbook amend`, `learnings confirm`, `teach-pattern`, and `teach-lookup` carry `mcp:local-write=true` (writes land only in the CLI's own local store); `learnings forget` and `learnings reject` keep honest may-write/destructive defaults.

### Success definition

Measurement is local-only: the `learn_events` table and `learnings stats`; nothing leaves this machine. Judge the loop on recall hit rate and teach-to-reuse at a minimum denominator of 50+ recall events. Near-zero rates at that denominator mean the loop is not earning its keep for this CLI - surface that in retros. An empty or thin events table means insufficient adoption, not failure.

The store's schema stamp is one-way: once this binary opens the database, an older binary refuses it (README.md carries the upgrade note).

Disable the loop with `--no-learn` per-invocation or `YALIE_NO_LEARN=true` for the whole session - useful for deterministic agent flows that don't want a learning row to silently change subsequent query results.

## Platform Credential References

Normal API authentication is separate from optional platform-source credential
resolution. If this CLI uses indirect references for a tenant-gated platform
source, add the downstream registration in a preserved hand-authored file
under `internal/cli/` and provide both `CredentialResolverFactory` and
`ValidateSourceProfile` on `platformSourceRegistration` for any selected source
that has references. A source with no references may omit both hooks and receives
an empty credential map. Keep reference values opaque to shared profile code,
validate only the selected source in the downstream hook, and never persist
resolved credential bytes. Do not edit generator-owned `internal/platform`
packages; a reprint refreshes those files while retaining the downstream
registration file.

For install, auth, examples, and longer product guidance, read `README.md` and `SKILL.md`. This file intentionally stays small so repo-local agents get invariant local guidance without duplicating the generated docs.

## Release Ledger

This CLI is **not** published to the public `mvanhorn/printing-press-library` — it lives directly in this repo (`YalieMCP/cli/`) and is versioned by this repo's own git history and tags, not the Printing Press library's release workflow. `CHANGELOG.md` still carries an unstamped `0.0.0-dev` version from the original print; bump it by hand here if this repo starts cutting releases, rather than waiting on an external publish step that won't happen.

## Local Customizations

This directory started as **generated output** from CLI Printing Press, but is now maintained directly in this repo — there is no reprint pipeline pointed at it, so hand-edits here are permanent, not at risk of being silently overwritten. The original generator's `.printing-press-patches/` convention (tracking edits so a reprint doesn't drop them) does not apply; ordinary git history is the record of what changed and why. `.printing-press.json` is kept as provenance (what generated this, when, from what manifest) but is no longer read by any active tooling in this repo.
