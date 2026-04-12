# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm install          # Install dependencies
npm run build        # Compile TypeScript → dist/
npm run dev:stdio    # Run stdio MCP server locally (Claude Desktop)
npm run dev:server   # Run HTTP OAuth server locally
npm start            # Run compiled stdio server
npm start:server     # Run compiled HTTP server
```

No test runner is configured. No linter is configured.

## Architecture

**YalieMCP** is a stateless MCP server that exposes 19 tools for Yale course/academic data. Two deployment modes:

- **Stdio mode** (`src/index.ts`) — for Claude Desktop; reads cookies from env vars (`COURSETABLE_COOKIE`, `CANVAS_COOKIE`, `AUDIT_COOKIE`)
- **HTTP mode** (`src/server.ts`) — OAuth 2.0 + PKCE server; cookies are encrypted into AES-256-GCM sealed tokens (no DB/Redis — all state travels in access tokens); deployed via `api/index.ts` on Vercel

### Key Files

| File | Role |
|------|------|
| `src/tools.ts` | All 19 MCP tool definitions and their handlers |
| `src/server.ts` | OAuth server, token sealing/unsealing, rate limiting |
| `src/index.ts` | Stdio entry point |
| `api/index.ts` | Vercel serverless entry point |

### Data Sources

- **CourseTable GraphQL** (`api.coursetable.com/ferry/v1/graphql`) — courses, evaluations, worksheets, friends
- **CourseTable REST** — user info, worksheet mutations, friends' worksheets
- **Canvas API** (`yale.instructure.com`) — syllabus content
- **Degree Audit API** (`degreeaudit.yale.edu`) — GPA, requirement blocks, course history
- **Yale Catalog scraping** (`catalog.yale.edu`) — major requirements

### Tool Registration Pattern

All tools live in `src/tools.ts`. Each tool is registered with:
1. A Zod schema for input validation
2. A handler that receives the parsed inputs + cookie strings
3. Returns formatted text or JSON as MCP content

Helper utilities: `gql<T>()` for GraphQL calls, `restApi<T>()` for REST, `buildWhere()` for constructing GraphQL `_and`/`_or` filter conditions, `seasonLabel()` / `decodeDays()` / `formatTime()` for formatting.

### OAuth Token Flow

Authorization → cookies validated by test requests → AES-256-GCM encrypted into code token (10 min) → exchanged for access (30 days) + refresh (60 days) tokens → decrypted per-request. No server state.

### Environment Variables

**HTTP server:** `TOKEN_SECRET` (required in prod), `BASE_URL`, `PORT`, `NODE_ENV`  
**Stdio mode:** `COURSETABLE_COOKIE` (required), `CANVAS_COOKIE`, `AUDIT_COOKIE`
