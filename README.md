# YalieMCP

An MCP (Model Context Protocol) server that gives AI assistants full access to Yale's course ecosystem — search courses, read evaluations, fetch syllabi, audit your degree, and manage your CourseTable worksheets, all from within Claude or any MCP-compatible client.

---

## Quick Start (Remote MCP)

The easiest way to connect is via the hosted server — no installation required.

**MCP URL:** `https://yalie-mcp.vercel.app/mcp`

### Claude.ai

1. Go to [claude.ai/customize/connectors](https://claude.ai/customize/connectors)
2. Click **+** → **Add a custom connection**
3. Enter the URL: `https://yalie-mcp.vercel.app/mcp`
4. Click **Connect** — you'll be redirected to the OAuth authorization page
5. Follow the instructions to connect your Yale services
6. Authorize — you're ready to go

### Claude Code (CLI)

```bash
claude mcp add --transport http yalie https://yalie-mcp.vercel.app/mcp
```

Then run `claude` — it will prompt you to authorize on first use.

---

## Authentication

YalieMCP uses OAuth 2.0 with PKCE. Your session cookies are **encrypted client-side** (AES-256-GCM) and sealed into the access token — no database, no server-side session storage.

### Getting Your Cookies

The OAuth page walks you through each service with specific instructions. The general flow for each:

1. Log in at the service's main page (link provided on the auth page)
2. Navigate to the provided check URL — verify you see your data
3. Open DevTools (`F12` / `Cmd ⌥ I`) → **Network** tab → reload the page
4. Right-click the request named after the last URL segment → **Copy** → **Copy as cURL**
5. Paste into the auth page and click **Test connection**

| Service | Required | Unlocks |
|---------|----------|---------|
| **CourseTable** | Yes | Course search, evaluations, worksheets, friends |
| **Canvas** | No | Syllabus content |
| **Degree Audit** | No | GPA, degree progress, requirement blocks |

---

## Tools

### Course Discovery

| Tool | Description | Auth Required |
|------|-------------|---------------|
| `list_seasons` | List all available academic seasons with codes (e.g. `202303` = Fall 2023) | CourseTable |
| `search_courses` | Search courses with rich filters: subject, title, professor, ratings, workload, areas, skills, credits | CourseTable |
| `get_course` | Full details for a course by ID: description, syllabus URL, all sections/CRNs, schedule with rooms, flags | CourseTable |
| `get_course_by_code` | Look up by subject + number (e.g. `CPSC 223`). Handles Yale's 3→4-digit course number migration automatically | CourseTable |
| `get_catalog_metadata` | Get the last time the CourseTable catalog was updated | None |

### Evaluations & Ratings

| Tool | Description | Auth Required |
|------|-------------|---------------|
| `get_course_evaluations` | AI-generated summaries + top student comments per evaluation question | CourseTable |
| `get_evaluation_ratings` | Quantitative rating distributions per question (how students spread across the scale) | CourseTable |
| `compare_courses` | Side-by-side comparison of 2–10 courses: ratings, workload, gut score, professor ratings, schedule | CourseTable |

### Professors

| Tool | Description | Auth Required |
|------|-------------|---------------|
| `search_professors` | Search by name, returns average rating and recent teaching history | CourseTable |

### Catalog & Majors

| Tool | Description | Auth Required |
|------|-------------|---------------|
| `list_majors` | All Yale majors and programs from catalog.yale.edu with URL slugs | None |
| `get_major_requirements` | Full requirements text for a major: prerequisites, core courses, distributional reqs, senior reqs | None |

### Personal Data

| Tool | Description | Auth Required |
|------|-------------|---------------|
| `get_user_info` | Your Yale profile: netId, name, email, class year, school, major, eval access | CourseTable |
| `get_degree_audit` | Full degree audit: GPA, requirement blocks with completion %, course history with grades | Degree Audit |
| `get_syllabus_content` | Fetch the full text of a Canvas syllabus for any course | Canvas |

### Worksheets & Wishlist

| Tool | Description | Auth Required |
|------|-------------|---------------|
| `get_worksheets` | Your CourseTable worksheets: all seasons, named lists, CRNs with color/hidden state | CourseTable |
| `get_wishlist` | Your CourseTable wishlist (season + CRN pairs) | CourseTable |
| `update_worksheet_course` | Add, remove, or update a course in a worksheet | CourseTable |
| `update_wishlist_course` | Add or remove a course from your wishlist | CourseTable |
| `update_worksheet_metadata` | Create, rename, or delete worksheets | CourseTable |
| `get_friends_worksheets` | Browse friends' worksheets — list friends or view a specific friend's courses | CourseTable |

---

## Search Filters Reference

`search_courses` supports the following filters:

| Filter | Type | Description |
|--------|------|-------------|
| `season_code` | string | **Required.** e.g. `202503` for Spring 2025. Use `list_seasons` to get valid values. |
| `subject` | string | Department code e.g. `CPSC`, `ENGL`, `MATH` |
| `title` | string | Partial case-insensitive title match |
| `professor` | string | Partial professor name match |
| `crn` | number | Exact CRN lookup |
| `crns` | number[] | Multiple CRNs at once (up to 50) |
| `min_rating` | 1–5 | Minimum average student rating |
| `max_workload` | 1–5 | Maximum workload rating (lower = easier) |
| `areas` | string[] | Distributional areas: `Hu`, `So`, `Sc` |
| `skills` | string[] | Course skills: `QR`, `WR`, `L` |
| `credits` | number | Credit count e.g. `1`, `0.5` |
| `limit` | 1–50 | Max results (default 20) |

---

## Example Prompts

```
What CS courses are available this spring with a rating above 4.0?

Compare CPSC 365 and CPSC 366 — which has better ratings and an easier workload?

What are the requirements for the Computer Science major?

Show me my degree audit and highlight what I still need to complete.

Fetch the syllabus for my ECON 115 course.

What courses is my friend abc123 taking this semester?
```

---

## Self-Hosting

### Prerequisites

- Node.js 18+
- A Vercel account (or any Node.js host)

### Local Development

```bash
git clone https://github.com/your-username/YalieMCP
cd YalieMCP
npm install
npm run build

# Run as stdio MCP (for Claude Desktop)
npm run dev:stdio

# Run as HTTP server (for remote MCP)
npm run dev:server
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `TOKEN_SECRET` | Secret key for sealing OAuth tokens (AES-256-GCM) | Insecure dev default — **must set in production** |
| `BASE_URL` | Public URL of your server | `http://localhost:3000` |
| `PORT` | Port to listen on | `3000` |

### Deploy to Vercel

```bash
vercel deploy
```

Set `TOKEN_SECRET` and `BASE_URL` in your Vercel project environment variables.

### Claude Desktop (stdio mode)

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "yaliemcp": {
      "command": "node",
      "args": ["/path/to/YalieMCP/dist/index.js"],
      "env": {
        "COURSETABLE_COOKIE": "YOUR_COURSETABLE_COOKIE_HERE"
      }
    }
  }
}
```

---

## Architecture

- **Stateless OAuth** — session cookies are AES-256-GCM encrypted and sealed into the access token. No database or Redis required.
- **CourseTable GraphQL** — course data, evaluations, and worksheets via the CourseTable API
- **Yale Catalog** — major requirements scraped from catalog.yale.edu
- **Canvas** — syllabus content fetched server-side with the user's session cookie
- **Degree Audit** — parsed from degreeaudit.yale.edu's REST API

---

## Data Sources

| Data | Source |
|------|--------|
| Courses, evaluations, worksheets | [CourseTable](https://coursetable.com) (api.coursetable.com) |
| Major requirements | [Yale Course Catalog](https://catalog.yale.edu) |
| Syllabi | [Yale Canvas](https://yale.instructure.com) |
| Degree audit | [Yale Degree Audit](https://degreeaudit.yale.edu) |
