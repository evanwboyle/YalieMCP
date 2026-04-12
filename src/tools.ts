import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

export const GRAPHQL_URL = "https://api.coursetable.com/ferry/v1/graphql";
const CATALOG_BASE = "https://catalog.yale.edu";

// ─── GraphQL helper ───────────────────────────────────────────────────────────

export async function gql<T>(
  cookie: string,
  query: string,
  variables?: Record<string, unknown>
): Promise<T> {
  const res = await fetch(GRAPHQL_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Origin": "https://coursetable.com",
      "User-Agent": "yalie-mcp/1.0",
      "Cookie": cookie,
    },
    body: JSON.stringify({ query, variables }),
  });

  if (!res.ok) {
    if (res.status === 405 || res.status === 401 || res.status === 403) {
      throw new Error(
        `Authentication required (HTTP ${res.status}). ` +
        "Your session cookie may have expired. Re-authenticate via the OAuth flow."
      );
    }
    throw new Error(`HTTP ${res.status}`);
  }

  const json = (await res.json()) as {
    data?: T;
    errors?: Array<{ message: string; extensions?: { code?: string } }>;
  };
  if (json.errors?.length) {
    const fieldNotFound = json.errors.some((e) => e.message.includes("not found in type"));
    if (fieldNotFound) {
      throw new Error(
        "Session expired or invalid — your CourseTable cookie no longer authenticates you. " +
        "Re-authenticate via the OAuth flow to refresh it."
      );
    }
    // Don't forward raw GraphQL error messages — they may leak schema details
    throw new Error("Course data request failed. Please try again.");
  }
  if (!json.data) throw new Error("Empty response from GraphQL");
  return json.data;
}

// ─── REST API helper ──────────────────────────────────────────────────────────

const API_BASE = "https://api.coursetable.com";

export async function restApi<T>(
  cookie: string,
  path: string,
  options?: { method?: string; body?: unknown }
): Promise<T> {
  const hasBody = options?.body !== undefined;
  const res = await fetch(`${API_BASE}${path}`, {
    method: options?.method ?? "GET",
    headers: {
      ...(hasBody ? { "Content-Type": "application/json" } : {}),
      "Cookie": cookie,
      "Origin": "https://coursetable.com",
      "User-Agent": "yalie-mcp/1.0",
    },
    body: hasBody ? JSON.stringify(options!.body) : undefined,
    signal: AbortSignal.timeout(15000),
  });

  if (!res.ok) {
    if (res.status === 401 || res.status === 403) {
      throw new Error(
        `Authentication required (HTTP ${res.status}). ` +
        "Your session cookie may have expired. Re-authenticate."
      );
    }
    throw new Error(`Request failed (HTTP ${res.status}).`);
  }

  const contentType = res.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    return res.json() as Promise<T>;
  }
  const text = await res.text();
  try {
    return JSON.parse(text) as T;
  } catch {
    return text as unknown as T;
  }
}

type FriendsData = {
  friends: Record<string, {
    name: string | null;
    worksheets: Record<string, Record<string, { name: string; courses: Array<{ crn: number; color: string; hidden: boolean | null }> }>>;
  }>;
};

async function getFriendsInCourse(cookie: string, season_code: string, crns: number[]): Promise<string[]> {
  try {
    const data = await restApi<FriendsData>(cookie, "/api/friends/worksheets");
    const crnSet = new Set(crns);
    const matches: string[] = [];
    for (const [, friend] of Object.entries(data.friends)) {
      const seasonWorksheets = friend.worksheets[season_code];
      if (!seasonWorksheets) continue;
      const inCourse = Object.values(seasonWorksheets).some((ws) =>
        ws.courses.some((c) => crnSet.has(c.crn))
      );
      if (inCourse) matches.push(friend.name ?? "Unknown");
    }
    return matches;
  } catch {
    return [];
  }
}

export async function validateCookie(cookie: string): Promise<boolean> {
  try {
    // Use the REST /api/user/info endpoint — requires a valid authenticated session.
    // The GraphQL seasons query works even for anonymous (unauthenticated) requests,
    // so it can't detect an invalid cookie.
    const res = await fetch("https://api.coursetable.com/api/user/info", {
      headers: {
        "Cookie": cookie,
        "Origin": "https://coursetable.com",
        "User-Agent": "yalie-mcp/1.0",
      },
      signal: AbortSignal.timeout(10000),
    });
    return res.ok;
  } catch {
    return false;
  }
}

// ─── Catalog HTML helper ──────────────────────────────────────────────────────

async function fetchCatalogText(url: string): Promise<string> {
  const res = await fetch(url, {
    headers: { "User-Agent": "Mozilla/5.0 (compatible; yalie-mcp/1.0)" },
    signal: AbortSignal.timeout(10000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} fetching ${url}`);
  const html = await res.text();
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&nbsp;/g, " ").replace(/&#\d+;/g, " ")
    .replace(/\s+/g, " ").trim();
}

// Extract subject-of-instruction href→text pairs from catalog index HTML
function extractCatalogLinks(html: string): Array<{ href: string; text: string }> {
  const results: Array<{ href: string; text: string }> = [];
  const re = /href="(\/ycps\/subjects-of-instruction\/[^"#?]+)"[^>]*>\s*([^<]{2,80})/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const text = m[2]!.trim().replace(/\s+/g, " ").replace(/&ndash;/g, "–").replace(/&amp;/g, "&");
    if (text) results.push({ href: m[1]!, text });
  }
  return results;
}

// ─── Degree audit helpers ─────────────────────────────────────────────────────

// letterGrade from the API truncates modifiers (A- → "A"). Reconstruct from numericGrade.
function resolveGrade(letterGrade: string | undefined, numericGrade: string | undefined, passfail: boolean, inProgress: boolean): string {
  if (inProgress) return "N/A";
  if (passfail) return letterGrade ?? "P/F";
  if (!numericGrade) return letterGrade ?? "";
  const n = Math.round(parseFloat(numericGrade) * 10) / 10;
  if (isNaN(n)) return letterGrade ?? "";
  const map: Record<number, string> = {
    4.0: "A", 3.7: "A-", 3.3: "B+", 3.0: "B", 2.7: "B-",
    2.3: "C+", 2.0: "C", 1.7: "C-", 1.3: "D+", 1.0: "D", 0.7: "D-", 0.0: "F",
  };
  return map[n] ?? letterGrade ?? "";
}

const ATTRIBUTE_LABELS: Record<string, string> = {
  // Yale distributional requirements
  YCQR: "Quantitative Reasoning",
  YCWR: "Writing",
  YCSH: "Science",
  YCSO: "Social Science",
  YCHU: "Humanities & Arts",
  YCLA: "Language",
  // Skills / equivalencies
  YCQE: "Quantitative Reasoning Equivalent",
  YCSC: "Science (no lab)",
};

function decodeAttributes(codes: string[]): string[] {
  return codes
    .map((c) => ATTRIBUTE_LABELS[c])
    .filter((v): v is string => v !== undefined);
}

// ─── Formatting helpers ───────────────────────────────────────────────────────

/** Returns the current season code based on today's date, e.g. "202601" for Spring 2026. */
function currentSeasonCode(): string {
  const now = new Date();
  const year = now.getFullYear();
  const month = now.getMonth() + 1; // 1-12
  // Yale seasons: 01=Spring (Jan-May), 02=Summer (Jun-Jul), 03=Fall (Aug-Dec)
  const term = month <= 5 ? "01" : month <= 7 ? "02" : "03";
  return `${year}${term}`;
}

export function seasonLabel(code: string): string {
  const year = code.slice(0, 4);
  const term = ({"01":"Spring","02":"Summer","03":"Fall"} as Record<string,string>)[code.slice(4)] ?? code.slice(4);
  return `${term} ${year}`;
}

function decodeDays(bits: number): string {
  const days = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];
  const result = days.filter((_, i) => bits & (1 << i));
  return result.length ? result.join("/") : "TBA";
}

function formatTime(t: string): string {
  const [h, m] = t.split(":").map(Number);
  if (h === undefined || m === undefined) return t;
  return `${h % 12 || 12}:${String(m).padStart(2,"0")} ${h >= 12 ? "PM" : "AM"}`;
}

function round1(n: number | null | undefined): number | null {
  return n != null ? Math.round(n * 10) / 10 : null;
}

function buildWhere(conditions: Array<Record<string,unknown>>): Record<string,unknown> {
  const truthy = conditions.filter((c) => Object.keys(c).length > 0);
  if (truthy.length === 0) return {};
  if (truthy.length === 1) return truthy[0]!;
  return { _and: truthy };
}

// ─── GraphQL queries ──────────────────────────────────────────────────────────

const SEARCH_QUERY = `
  query SearchCourses($where: courses_bool_exp!, $limit: Int!) {
    courses(where: $where, limit: $limit) {
      course_id title description credits average_rating average_workload areas skills colsem fysem
      listings(limit: 1, order_by: { crn: asc }) { course_code crn }
      course_professors { professor { name } }
      course_meetings { days_of_week start_time end_time }
    }
  }
`;

const GET_COURSE_QUERY = `
  query GetCourse($id: Int!) {
    courses_by_pk(course_id: $id) {
      course_id title description credits average_rating average_workload
      average_professor_rating average_gut_rating areas skills colsem fysem requirements
      syllabus_url
      season { season_code }
      listings { course_code section season_code crn }
      course_professors { professor { name average_rating } }
      course_meetings {
        days_of_week start_time end_time
        location { room building { code building_name } }
      }
      course_flags { flag { flag_text } }
    }
  }
`;

const GET_EVALS_QUERY = `
  query GetEvals($course_id: Int!, $limit: Int!) {
    evaluation_narrative_summaries(where: { course_id: { _eq: $course_id } }) {
      question_code summary
      evaluation_question { question_text }
    }
    evaluation_narratives(
      where: { course_id: { _eq: $course_id } }
      order_by: { comment_compound: desc }
      limit: $limit
    ) { question_code comment }
  }
`;

const GET_COURSE_BY_CODE_QUERY = `
  query GetCourseByCode($where: courses_bool_exp!, $limit: Int!) {
    courses(where: $where, limit: $limit, order_by: { listings_aggregate: { count: desc } }) {
      course_id title credits average_rating average_workload areas skills colsem fysem
      syllabus_url
      season { season_code }
      listings(order_by: { crn: asc }) { course_code section crn }
      course_professors { professor { name average_rating } }
      course_meetings {
        days_of_week start_time end_time
        location { room building { code building_name } }
      }
    }
  }
`;

const SEARCH_PROFESSORS_QUERY = `
  query SearchProfessors($name: String!, $limit: Int!) {
    professors(
      where: { name: { _ilike: $name } }
      limit: $limit
      order_by: { average_rating: desc_nulls_last }
    ) {
      professor_id name average_rating
      course_professors(order_by: { course: { season_code: desc } }, limit: 8) {
        course {
          course_id title
          season { season_code }
          listings(limit: 1, order_by: { crn: asc }) { course_code }
        }
      }
    }
  }
`;

const COMPARE_COURSES_QUERY = `
  query CompareCourses($ids: [Int!]!) {
    courses(where: { course_id: { _in: $ids } }) {
      course_id title credits
      average_rating average_workload average_gut_rating average_professor_rating
      areas skills colsem fysem
      syllabus_url
      listings(limit: 1, order_by: { crn: asc }) { course_code }
      course_professors { professor { name average_rating } }
      course_meetings { days_of_week start_time end_time }
    }
  }
`;

const GET_EVAL_RATINGS_QUERY = `
  query GetEvalRatings($course_id: Int!) {
    evaluation_ratings(where: { course_id: { _eq: $course_id } }) {
      question_code
      rating
      evaluation_question { question_text }
    }
  }
`;

// ─── Tool registration ────────────────────────────────────────────────────────

const NO_CT = "CourseTable not connected. Re-authenticate and connect CourseTable to use this tool.";

export function registerTools(
  server: McpServer,
  cookie: string | null,
  canvasCookie?: string | null,
  auditCookie?: string | null,
): void {

  // list_seasons
  server.registerTool("list_seasons", {
    description:
      "List all available academic seasons. Returns season codes (e.g. '202303' = Fall 2023) " +
      "and labels. Call this first to get valid season_code values for other tools.",
    inputSchema: z.object({}),
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async () => {
    if (!cookie) return { content: [{ type: "text" as const, text: NO_CT }] };
    const data = await gql<{ seasons: Array<{ season_code: string }> }>(
      cookie, `query { seasons(order_by: { season_code: desc }) { season_code } }`
    );
    const seasons = data.seasons.map((s) => ({ code: s.season_code, label: seasonLabel(s.season_code) }));
    return { content: [{ type: "text" as const, text: JSON.stringify(seasons) }] };
  });

  // search_courses
  server.registerTool("search_courses", {
    description:
      "Search CourseTable courses with filters. Returns a compact list of matching courses.\n\n" +
      "season_code is required — use list_seasons to get valid values.\n\n" +
      "TIP: Link directly to any course in the catalog with: " +
      "https://coursetable.com/catalog?course-modal={season}-{crn} " +
      "(e.g. https://coursetable.com/catalog?course-modal=202503-10529)\n\n" +
      "NOTE: Yale is migrating course numbers from 3-digit to 4-digit (e.g. CPSC 223 → CPSC 2230). " +
      "Some courses split into multiple new codes (e.g. CPSC 223 → CPSC 2231 + CPSC 2232). " +
      "For code-specific lookups, prefer get_course_by_code which handles this automatically.\n\n" +
      "Filters:\n" +
      "- subject: department code e.g. 'CPSC', 'ENGL', 'MATH' — NOTE: filtering by subject finds courses " +
      "listed under that code, but does NOT determine major eligibility. Not all CPSC courses count toward " +
      "the CS major, and courses cross-listed under other subjects may also count. Course number digits also " +
      "do NOT indicate region or category eligibility — only course flags (e.g. 'YC HIST Europe') and " +
      "major requirements text are authoritative. Always verify via get_major_requirements and get_course (flags field).\n" +
      "- crn: course registration number (exact match)\n" +
      "- crns: list of CRNs to look up multiple at once\n" +
      "- title: partial case-insensitive title match\n" +
      "- description: partial case-insensitive match against course description text (use keywords to find courses by topic)\n" +
      "- professor: partial professor name match\n" +
      "- min_rating: minimum average student rating (1–5)\n" +
      "- max_workload: maximum workload rating (1–5, lower = easier)\n" +
      "- areas: Yale distributional areas e.g. ['Hu','So','Sc']\n" +
      "- skills: course skills e.g. ['QR','WR','L']\n" +
      "- credits: number of credits e.g. 1, 0.5\n" +
      "- limit: max results (default 20, max 50)\n\n" +
      "Returns: course_id, course_code, title, credits, rating, workload, professors, schedule.",
    inputSchema: z.object({
      season_code: z.string().regex(/^\d{6}$/).describe("Season code e.g. '202303' for Fall 2023"),
      subject: z.string().max(10).optional().describe("Department code e.g. 'CPSC'"),
      crn: z.number().int().min(1).max(99999).optional().describe("Exact CRN to look up"),
      crns: z.array(z.number().int().min(1).max(99999)).max(50).optional().describe("List of CRNs to look up"),
      title: z.string().max(200).optional().describe("Partial title match"),
      description: z.string().max(500).optional().describe("Partial case-insensitive match against course description text"),
      professor: z.string().max(100).optional().describe("Partial professor name"),
      min_rating: z.number().min(1).max(5).optional(),
      max_workload: z.number().min(1).max(5).optional(),
      areas: z.array(z.string().max(10)).max(10).optional().describe("e.g. ['Hu','So']"),
      skills: z.array(z.string().max(10)).max(10).optional().describe("e.g. ['QR','WR']"),
      credits: z.number().min(0).max(10).optional(),
      limit: z.number().int().min(1).max(50).default(20),
    }),
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async ({ season_code, subject, crn, crns, title, description, professor, min_rating, max_workload, areas, skills, credits, limit }) => {
    if (!cookie) return { content: [{ type: "text" as const, text: NO_CT }] };
    const conditions: Array<Record<string,unknown>> = [{ season_code: { _eq: season_code } }];
    if (crn != null) conditions.push({ listings: { crn: { _eq: crn } } });
    if (crns?.length) conditions.push({ listings: { crn: { _in: crns } } });
    if (title) conditions.push({ title: { _ilike: `%${title}%` } });
    if (description) conditions.push({ description: { _ilike: `%${description}%` } });
    if (professor) conditions.push({ course_professors: { professor: { name: { _ilike: `%${professor}%` } } } });
    if (min_rating != null) conditions.push({ average_rating: { _gte: min_rating } });
    if (max_workload != null) conditions.push({ average_workload: { _lte: max_workload } });
    if (credits != null) conditions.push({ credits: { _eq: credits } });
    if (subject) conditions.push({ listings: { course_code: { _ilike: `${subject.toUpperCase()} %` } } });
    if (areas?.length) {
      conditions.push(areas.length === 1
        ? { areas: { _contains: [areas[0]] } }
        : { _or: areas.map((a) => ({ areas: { _contains: [a] } })) });
    }
    if (skills?.length) {
      conditions.push(skills.length === 1
        ? { skills: { _contains: [skills[0]] } }
        : { _or: skills.map((s) => ({ skills: { _contains: [s] } })) });
    }

    type SearchResult = { courses: Array<{
      course_id: number; title: string; description: string | null; credits: number | null;
      average_rating: number | null; average_workload: number | null;
      areas: string[] | null; skills: string[] | null; colsem: boolean; fysem: boolean;
      listings: Array<{ course_code: string; crn: number }>;
      course_professors: Array<{ professor: { name: string } }>;
      course_meetings: Array<{ days_of_week: number; start_time: string; end_time: string }>;
    }> };

    const data = await gql<SearchResult>(cookie, SEARCH_QUERY, { where: buildWhere(conditions), limit });

    const results = data.courses.map((c) => ({
      course_id: c.course_id,
      code: c.listings[0]?.course_code ?? "—",
      crn: c.listings[0]?.crn ?? null,
      title: c.title,
      description: c.description ?? null,
      credits: c.credits,
      rating: round1(c.average_rating),
      workload: round1(c.average_workload),
      professors: c.course_professors.map((p) => p.professor.name),
      schedule: c.course_meetings.map((m) => `${decodeDays(m.days_of_week)} ${formatTime(m.start_time)}–${formatTime(m.end_time)}`).join(", ") || null,
      areas: c.areas?.length ? c.areas : null,
      skills: c.skills?.length ? c.skills : null,
      flags: (c.colsem || c.fysem) ? [...(c.colsem ? ["ColSem"] : []), ...(c.fysem ? ["FrYrSem"] : [])] : null,
    }));

    return { content: [{ type: "text" as const, text: JSON.stringify({ count: results.length, courses: results }) }] };
  });

  // get_course
  server.registerTool("get_course", {
    description:
      "Get full details for a specific course by course_id. " +
      "Use search_courses or get_course_by_code first to find course_id values. " +
      "Returns: full description, professor ratings, meeting schedule with rooms, " +
      "cross-listings (CRNs), distributional areas/skills, flags, requirements, and syllabus URL.\n\n" +
      "TIP: Link to this course in the catalog with: " +
      "https://coursetable.com/catalog?course-modal={season}-{crn}\n\n" +
      "IMPORTANT — major eligibility: NEVER assume a course counts toward a major based solely on its " +
      "subject prefix or course number digits (e.g., not all CPSC courses count for the CS major, and non-CPSC " +
      "courses can count; course number patterns like x2xx do NOT reliably indicate geographic region or " +
      "category eligibility). Eligibility is determined by course `flags` (e.g. 'YC HIST Europe') and the " +
      "major requirements text — NOT by the course code alone. Course codes only matter if the major " +
      "requirements text explicitly says they do. Check `flags`, `description`, and `requirements` fields " +
      "returned here. When in doubt, use get_major_requirements to read the catalog's eligibility rules directly.",
    inputSchema: z.object({
      course_id: z.number().int().min(1).describe("Course ID from search_courses or get_course_by_code"),
    }),
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async ({ course_id }) => {
    if (!cookie) return { content: [{ type: "text" as const, text: NO_CT }] };
    type CourseDetail = { courses_by_pk: {
      course_id: number; title: string; description: string | null; credits: number | null;
      average_rating: number | null; average_workload: number | null;
      average_professor_rating: number | null; average_gut_rating: number | null;
      areas: string[] | null; skills: string[] | null; colsem: boolean; fysem: boolean;
      requirements: string | null; syllabus_url: string | null;
      season: { season_code: string };
      listings: Array<{ course_code: string; section: string; season_code: string; crn: number }>;
      course_professors: Array<{ professor: { name: string; average_rating: number | null } }>;
      course_meetings: Array<{ days_of_week: number; start_time: string; end_time: string;
        location: { room: string | null; building: { code: string; building_name: string | null } } | null }>;
      course_flags: Array<{ flag: { flag_text: string } }>;
    } | null };

    const data = await gql<CourseDetail>(cookie, GET_COURSE_QUERY, { id: course_id });
    if (!data.courses_by_pk) {
      return { content: [{ type: "text" as const, text: `No course found with ID ${course_id}` }] };
    }

    const c = data.courses_by_pk;
    const crns = c.listings.map((l) => l.crn);
    const friendsInCourse = await getFriendsInCourse(cookie, c.season.season_code, crns);
    const result = {
      course_id: c.course_id,
      season: seasonLabel(c.season.season_code),
      listings: c.listings.map((l) => ({ code: l.course_code, section: l.section, crn: l.crn })),
      title: c.title,
      description: c.description,
      credits: c.credits,
      syllabus_url: c.syllabus_url,
      ratings: {
        overall: round1(c.average_rating), workload: round1(c.average_workload),
        professor: round1(c.average_professor_rating), gut: round1(c.average_gut_rating),
      },
      areas: c.areas?.length ? c.areas : null,
      skills: c.skills?.length ? c.skills : null,
      flags: [...(c.colsem ? ["ColSem"] : []), ...(c.fysem ? ["FrYrSem"] : []), ...c.course_flags.map((f) => f.flag.flag_text)],
      requirements: c.requirements || null,
      friends_in_course: friendsInCourse,
      professors: c.course_professors.map((p) => ({ name: p.professor.name, avg_rating: round1(p.professor.average_rating) })),
      meetings: c.course_meetings.map((m) => ({
        days: decodeDays(m.days_of_week),
        time: `${formatTime(m.start_time)}–${formatTime(m.end_time)}`,
        location: m.location
          ? `${m.location.building.building_name ?? m.location.building.code}${m.location.room ? " " + m.location.room : ""}`.trim()
          : null,
      })),
    };
    return { content: [{ type: "text" as const, text: JSON.stringify(result) }] };
  });

  // get_course_evaluations
  server.registerTool("get_course_evaluations", {
    description:
      "Get student evaluation data for a course. " +
      "Returns AI-generated summaries and top individual comments per question. " +
      "Use course_id from search_courses or get_course.",
    inputSchema: z.object({
      course_id: z.number().int().min(1).describe("Course ID"),
      max_comments: z.number().int().min(1).max(20).default(5).describe("Max comments per question (default 5)"),
    }),
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async ({ course_id, max_comments }) => {
    if (!cookie) return { content: [{ type: "text" as const, text: NO_CT }] };
    type EvalsResult = {
      evaluation_narrative_summaries: Array<{
        question_code: string; summary: string;
        evaluation_question: { question_text: string };
      }>;
      evaluation_narratives: Array<{ question_code: string; comment: string }>;
    };

    const data = await gql<EvalsResult>(cookie, GET_EVALS_QUERY, { course_id, limit: max_comments * 6 });

    const byQuestion = new Map<string, string[]>();
    for (const n of data.evaluation_narratives) {
      const arr = byQuestion.get(n.question_code) ?? [];
      if (arr.length < max_comments) { arr.push(n.comment); byQuestion.set(n.question_code, arr); }
    }

    if (!data.evaluation_narrative_summaries.length && !byQuestion.size) {
      return { content: [{ type: "text" as const, text: "No evaluation data available for this course." }] };
    }

    // NOTE: evaluation_narrative_summaries is queried and the type includes `summary`, but
    // CourseTable has not yet populated this field — all values are "". The query and type are
    // intentionally kept so summaries will surface automatically once CourseTable provides data.
    const evaluations = data.evaluation_narrative_summaries.map((s) => ({
      question: s.evaluation_question.question_text, code: s.question_code,
      top_comments: byQuestion.get(s.question_code) ?? [],
    }));
    for (const [code, comments] of byQuestion.entries()) {
      if (!evaluations.find((e) => e.code === code)) {
        evaluations.push({ question: code, code, top_comments: comments });
      }
    }

    return { content: [{ type: "text" as const, text: JSON.stringify({ course_id, evaluations }) }] };
  });

  // get_course_by_code
  server.registerTool("get_course_by_code", {
    description:
      "Look up courses by subject + number code within a season. " +
      "Handles Yale's ongoing course number migration automatically: " +
      "searching 'CPSC 223' also matches 'CPSC 2230', 'CPSC 2231', 'CPSC 2232', etc. " +
      "(Yale is migrating from 3-digit to 4-digit course numbers; some courses split into " +
      "multiple new codes.) Use this instead of search_courses when you know the specific code.\n\n" +
      "Examples: 'CPSC 223', 'MATH 115', 'ECON 115', 'ENGL 114'. " +
      "Returns full course details including syllabus URL, all section CRNs, ratings, schedule.\n\n" +
      "TIP: Link to a course in the catalog with: " +
      "https://coursetable.com/catalog?course-modal={season}-{crn}",
    inputSchema: z.object({
      course_code: z.string().max(20).describe("Subject + number, e.g. 'CPSC 223' or 'MATH 115'"),
      season_code: z.string().regex(/^\d{6}$/).optional().describe("Season code e.g. '202503'. Defaults to the most recent season."),
      limit: z.number().int().min(1).max(20).default(10),
    }),
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async ({ course_code, season_code, limit }) => {
    if (!cookie) return { content: [{ type: "text" as const, text: NO_CT }] };

    // Resolve season: use provided value or fetch the latest
    let resolvedSeason = season_code;
    if (!resolvedSeason) {
      const sd = await gql<{ seasons: Array<{ season_code: string }> }>(
        cookie,
        `query ($max: String!) { seasons(where: { season_code: { _lte: $max } }, order_by: { season_code: desc }, limit: 1) { season_code } }`,
        { max: currentSeasonCode() }
      );
      resolvedSeason = sd.seasons[0]?.season_code;
      if (!resolvedSeason) return { content: [{ type: "text" as const, text: "Could not determine current season." }] };
    }

    // Normalize: "cpsc223" → "CPSC 223", "CPSC 223" → "CPSC 223"
    const normalized = course_code.trim().toUpperCase().replace(/([A-Z&]+)\s*(\d+)/, "$1 $2");
    // Append % so "CPSC 223" matches "CPSC 2230", "CPSC 2231", etc. (migration-aware)
    const pattern = `${normalized}%`;

    const conditions = [
      { season_code: { _eq: resolvedSeason } },
      { listings: { course_code: { _ilike: pattern } } },
    ];

    type CourseByCode = { courses: Array<{
      course_id: number; title: string; credits: number | null;
      average_rating: number | null; average_workload: number | null;
      areas: string[] | null; skills: string[] | null; colsem: boolean; fysem: boolean;
      syllabus_url: string | null;
      season: { season_code: string };
      listings: Array<{ course_code: string; section: string; crn: number }>;
      course_professors: Array<{ professor: { name: string; average_rating: number | null } }>;
      course_meetings: Array<{ days_of_week: number; start_time: string; end_time: string;
        location: { room: string | null; building: { code: string; building_name: string | null } } | null }>;
    }> };

    const data = await gql<CourseByCode>(cookie, GET_COURSE_BY_CODE_QUERY, {
      where: { _and: conditions },
      limit,
    });

    if (!data.courses.length) {
      return { content: [{ type: "text" as const, text: `No courses found matching '${normalized}' in season ${resolvedSeason}.` }] };
    }

    const friendsData = await Promise.all(
      data.courses.map((c) => getFriendsInCourse(cookie, c.season.season_code, c.listings.map((l) => l.crn)))
    );
    const results = data.courses.map((c, i) => ({
      course_id: c.course_id,
      season: seasonLabel(c.season.season_code),
      codes: [...new Set(c.listings.map((l) => l.course_code))],
      sections: c.listings.map((l) => ({ code: l.course_code, section: l.section, crn: l.crn })),
      title: c.title,
      credits: c.credits,
      syllabus_url: c.syllabus_url,
      rating: round1(c.average_rating),
      workload: round1(c.average_workload),
      areas: c.areas?.length ? c.areas : null,
      skills: c.skills?.length ? c.skills : null,
      flags: (c.colsem || c.fysem) ? [...(c.colsem ? ["ColSem"] : []), ...(c.fysem ? ["FrYrSem"] : [])] : null,
      friends_in_course: friendsData[i],
      professors: c.course_professors.map((p) => ({ name: p.professor.name, avg_rating: round1(p.professor.average_rating) })),
      meetings: c.course_meetings.map((m) => ({
        days: decodeDays(m.days_of_week),
        time: `${formatTime(m.start_time)}–${formatTime(m.end_time)}`,
        location: m.location
          ? `${m.location.building.building_name ?? m.location.building.code}${m.location.room ? " " + m.location.room : ""}`.trim()
          : null,
      })),
    }));

    return { content: [{ type: "text" as const, text: JSON.stringify({ count: results.length, courses: results }) }] };
  });

  // search_professors
  server.registerTool("search_professors", {
    description:
      "Search for professors by name. Returns professor rating and their recent courses. " +
      "Useful for finding which professor teaches a course, or exploring a professor's teaching history.",
    inputSchema: z.object({
      name: z.string().max(100).describe("Partial professor name, e.g. 'Spielman' or 'Dan Spi'"),
      limit: z.number().int().min(1).max(20).default(10),
    }),
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async ({ name, limit }) => {
    if (!cookie) return { content: [{ type: "text" as const, text: NO_CT }] };
    type ProfResult = { professors: Array<{
      professor_id: number; name: string; average_rating: number | null;
      course_professors: Array<{ course: {
        course_id: number; title: string;
        season: { season_code: string };
        listings: Array<{ course_code: string }>;
      } }>;
    }> };

    const data = await gql<ProfResult>(cookie, SEARCH_PROFESSORS_QUERY, {
      name: `%${name}%`,
      limit,
    });

    if (!data.professors.length) {
      return { content: [{ type: "text" as const, text: `No professors found matching '${name}'.` }] };
    }

    const results = data.professors.map((p) => ({
      professor_id: p.professor_id,
      name: p.name,
      avg_rating: round1(p.average_rating),
      recent_courses: p.course_professors.map((cp) => ({
        course_id: cp.course.course_id,
        code: cp.course.listings[0]?.course_code ?? "—",
        title: cp.course.title,
        season: seasonLabel(cp.course.season.season_code),
      })),
    }));

    return { content: [{ type: "text" as const, text: JSON.stringify({ count: results.length, professors: results }) }] };
  });

  // compare_courses
  server.registerTool("compare_courses", {
    description:
      "Compare multiple courses side-by-side. Takes a list of course_ids and returns " +
      "a structured comparison of ratings, workload, gut rating, professor ratings, " +
      "schedule, areas, skills, and syllabus URLs. " +
      "Use search_courses or get_course_by_code to find course_id values first.",
    inputSchema: z.object({
      course_ids: z.array(z.number().int().min(1)).min(2).max(10).describe("List of 2–10 course IDs to compare"),
    }),
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async ({ course_ids }) => {
    if (!cookie) return { content: [{ type: "text" as const, text: NO_CT }] };
    type CompareResult = { courses: Array<{
      course_id: number; title: string; credits: number | null;
      average_rating: number | null; average_workload: number | null;
      average_gut_rating: number | null; average_professor_rating: number | null;
      areas: string[] | null; skills: string[] | null; colsem: boolean; fysem: boolean;
      syllabus_url: string | null;
      listings: Array<{ course_code: string }>;
      course_professors: Array<{ professor: { name: string; average_rating: number | null } }>;
      course_meetings: Array<{ days_of_week: number; start_time: string; end_time: string }>;
    }> };

    const data = await gql<CompareResult>(cookie, COMPARE_COURSES_QUERY, { ids: course_ids });

    // Preserve requested order
    const byId = new Map(data.courses.map((c) => [c.course_id, c]));
    const results = course_ids
      .map((id) => byId.get(id))
      .filter(Boolean)
      .map((c) => ({
        course_id: c!.course_id,
        code: c!.listings[0]?.course_code ?? "—",
        title: c!.title,
        credits: c!.credits,
        ratings: {
          overall: round1(c!.average_rating),
          workload: round1(c!.average_workload),
          professor: round1(c!.average_professor_rating),
          gut: round1(c!.average_gut_rating),
        },
        areas: c!.areas?.length ? c!.areas : null,
        skills: c!.skills?.length ? c!.skills : null,
        flags: (c!.colsem || c!.fysem) ? [...(c!.colsem ? ["ColSem"] : []), ...(c!.fysem ? ["FrYrSem"] : [])] : null,
        syllabus_url: c!.syllabus_url,
        professors: c!.course_professors.map((p) => ({ name: p.professor.name, avg_rating: round1(p.professor.average_rating) })),
        schedule: c!.course_meetings.map((m) => `${decodeDays(m.days_of_week)} ${formatTime(m.start_time)}–${formatTime(m.end_time)}`).join(", ") || null,
      }));

    return { content: [{ type: "text" as const, text: JSON.stringify({ count: results.length, courses: results }) }] };
  });

  // list_majors
  server.registerTool("list_majors", {
    description:
      "List all Yale majors and programs from the official Yale course catalog (catalog.yale.edu). " +
      "Returns names and URL slugs. Use slugs with get_major_requirements to fetch requirements.",
    inputSchema: z.object({}),
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async () => {
    const res = await fetch(`${CATALOG_BASE}/ycps/azindex/`, {
      headers: { "User-Agent": "Mozilla/5.0 (compatible; yalie-mcp/1.0)" },
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} fetching catalog index`);
    const html = await res.text();
    const links = extractCatalogLinks(html);
    // Deduplicate by href
    const seen = new Set<string>();
    const majors = links
      .filter((l) => { if (seen.has(l.href)) return false; seen.add(l.href); return true; })
      .map((l) => ({ name: l.text, slug: l.href.replace(/^\/ycps\/subjects-of-instruction\//, "").replace(/\/$/, "") }));
    return { content: [{ type: "text" as const, text: JSON.stringify({ count: majors.length, majors }) }] };
  });

  // get_syllabus_content  (requires Canvas cookie)
  server.registerTool("get_syllabus_content", {
    description:
      "Fetch the full text of a Canvas syllabus for a Yale course. " +
      "Requires the user to have provided their Canvas session cookie during OAuth setup " +
      "(copy(document.cookie) on yale.instructure.com). " +
      "The syllabus_url comes from get_course or get_course_by_code (field: syllabus_url). " +
      "Returns the rendered syllabus as plain text, prefixed with the source URL. " +
      "IMPORTANT: Always cite the source URL when presenting syllabus information to the user. " +
      "Do NOT fetch from the URL yourself — it requires authentication cookies.",
    inputSchema: z.object({
      syllabus_url: z.string()
        .url()
        .max(512)
        .refine(
          (u) => { try { return new URL(u).hostname === "yale.instructure.com"; } catch { return false; } },
          { message: "syllabus_url must be a yale.instructure.com URL" }
        )
        .describe("Canvas syllabus URL from course data, e.g. https://yale.instructure.com/courses/89687/assignments/syllabus"),
    }),
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async ({ syllabus_url }) => {
    if (!canvasCookie) {
      return { content: [{ type: "text" as const, text: "Canvas cookie not provided. Re-authenticate and expand the optional Canvas section to paste your yale.instructure.com cookie." }] };
    }
    const res = await fetch(syllabus_url, {
      headers: {
        "Cookie": canvasCookie,
        "User-Agent": "Mozilla/5.0 (compatible; yalie-mcp/1.0)",
        "Accept": "text/html",
      },
      redirect: "manual",
      signal: AbortSignal.timeout(15000),
    });
    // Follow at most one redirect, but only within yale.instructure.com
    let finalRes = res;
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location");
      if (!location) {
        return { content: [{ type: "text" as const, text: "Failed to fetch syllabus: unexpected redirect with no Location header." }] };
      }
      let redirectUrl: URL;
      try { redirectUrl = new URL(location, syllabus_url); } catch {
        return { content: [{ type: "text" as const, text: "Failed to fetch syllabus: invalid redirect URL." }] };
      }
      if (redirectUrl.hostname !== "yale.instructure.com") {
        return { content: [{ type: "text" as const, text: "Failed to fetch syllabus: redirect outside yale.instructure.com is not permitted." }] };
      }
      finalRes = await fetch(redirectUrl.toString(), {
        headers: {
          "Cookie": canvasCookie,
          "User-Agent": "Mozilla/5.0 (compatible; yalie-mcp/1.0)",
          "Accept": "text/html",
        },
        redirect: "manual",
        signal: AbortSignal.timeout(15000),
      });
    }
    if (finalRes.status === 401 || finalRes.status === 403 || (finalRes.headers.get("location") ?? "").includes("/login")) {
      return { content: [{ type: "text" as const, text: "Canvas authentication failed. Your Canvas cookie may have expired or be missing HttpOnly session cookies — re-authenticate to refresh it." }] };
    }
    if (!finalRes.ok) {
      return { content: [{ type: "text" as const, text: "Failed to fetch syllabus." }] };
    }
    const html = await finalRes.text();
    // Extract syllabus body div if present, otherwise use full page
    const bodyMatch = /<div[^>]+id="syllabusBody"[^>]*>([\s\S]*?)<\/div>/i.exec(html)
                   ?? /<div[^>]+class="[^"]*syllabus[^"]*"[^>]*>([\s\S]*?)<\/div>/i.exec(html);
    const source = bodyMatch ? bodyMatch[1]! : html;
    const text = source
      .replace(/<script[\s\S]*?<\/script>/gi, "")
      .replace(/<style[\s\S]*?<\/style>/gi, "")
      .replace(/<br\s*\/?>/gi, "\n")
      .replace(/<\/p>/gi, "\n\n").replace(/<\/li>/gi, "\n")
      .replace(/<[^>]+>/g, "")
      .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
      .replace(/&nbsp;/g, " ").replace(/&#\d+;/g, " ")
      .replace(/\n{3,}/g, "\n\n").trim();
    if (text.length < 50) {
      return { content: [{ type: "text" as const, text: "Syllabus appears empty or could not be parsed. The course may not have a syllabus posted on Canvas." }] };
    }
    const truncated = text.length > 10000 ? text.slice(0, 10000) + "\n\n[truncated]" : text;
    const output = `Source: ${syllabus_url}\n\n${truncated}`;
    return { content: [{ type: "text" as const, text: output }] };
  });

  // get_degree_audit  (requires degree audit cookie)
  server.registerTool("get_degree_audit", {
    description:
      "Fetch the authenticated student's Yale degree audit — overall progress, GPA, " +
      "requirement blocks with completion percentages, and full course history with grades. " +
      "Also returns advisor info, degree/major, class year, and distributional attributes per course. " +
      "Requires the user to have provided their Degree Audit cookie during OAuth setup.",
    inputSchema: z.object({
      school: z.string().max(10).default("UG").describe("School code, default 'UG'"),
      degree: z.string().max(10).default("BA").describe("Degree code, default 'BA'"),
      include_courses: z.boolean().default(true).describe("Include full course history with grades"),
    }),
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async ({ school, degree, include_courses }) => {
    if (!auditCookie) {
      return { content: [{ type: "text" as const, text: "Degree audit cookie not provided. Re-authenticate and expand the optional Degree Audit section to paste your degreeaudit.yale.edu cookie." }] };
    }

    const headers = {
      "Cookie": auditCookie,
      "User-Agent": "Mozilla/5.0 (compatible; yalie-mcp/1.0)",
      "Accept": "application/json",
    };

    // Step 1: get student ID
    const meRes = await fetch("https://degreeaudit.yale.edu/responsive/api/users/myself", {
      headers,
      signal: AbortSignal.timeout(10000),
    });
    if (!meRes.ok) {
      if (meRes.status === 401 || meRes.status === 403 || meRes.status === 302) {
        return { content: [{ type: "text" as const, text: "Degree audit authentication failed. Your cookie may have expired — re-authenticate to update it." }] };
      }
      return { content: [{ type: "text" as const, text: `Failed to fetch user info: HTTP ${meRes.status}` }] };
    }
    const me = await meRes.json() as { id?: string; userId?: string; name?: string };
    const studentId = me.id ?? me.userId;
    if (!studentId) {
      return { content: [{ type: "text" as const, text: "Could not determine student ID from degree audit." }] };
    }

    // Step 2: fetch audit
    const auditUrl = `https://degreeaudit.yale.edu/responsive/api/audit?studentId=${encodeURIComponent(studentId)}&school=${encodeURIComponent(school)}&degree=${encodeURIComponent(degree)}&is-process-new=false&audit-type=AA&auditId=&include-inprogress=true&include-preregistered=true&aid-term=`;
    const auditRes = await fetch(auditUrl, {
      headers: {
        ...headers,
        "Accept": "application/vnd.net.hedtech.degreeworks.dashboard.audit.v1+json",
      },
      signal: AbortSignal.timeout(20000),
    });
    if (!auditRes.ok) {
      return { content: [{ type: "text" as const, text: `Failed to fetch degree audit: HTTP ${auditRes.status}` }] };
    }
    const audit = await auditRes.json() as Record<string, unknown>;

    // ── Parse ─────────────────────────────────────────────────────────────────

    type AuditHeader = {
      percentComplete?: string; studentSystemGpa?: string; degreeworksGpa?: string;
      residentApplied?: string; residentAppliedInProgress?: string;
      transferApplied?: string; examAppliedCredits?: string;
      dateYear?: string; dateMonth?: string; dateDay?: string;
    };
    type DegreeData = {
      degree?: string; degreeLiteral?: string; school?: string; schoolLiteral?: string;
      catalogYearLit?: string; activeTermLiteral?: string; degreeTerm?: string;
      studentLevelLiteral?: string; studentSystemCumulativeTotalCreditsEarned?: string;
    };
    type Goal = { code?: string; valueLiteral?: string; advisorName?: string; advisorEmail?: string; attachCode?: string };
    type Rule = { label?: string; percentComplete?: string; ruleType?: string; inProgressIncomplete?: string; requirement?: { ruleComplete?: string }; ruleArray?: Rule[] };
    type Block = { title?: string; percentComplete?: string; creditsApplied?: string; ruleArray?: Rule[] };
    type CourseClass = {
      discipline?: string; number?: string; courseTitle?: string; credits?: string;
      letterGrade?: string; numericGrade?: string; term?: string; termLiteral?: string;
      inProgress?: string; preregistered?: string; passfail?: string;
      attributeArray?: Array<{ code?: string; value?: string }>;
    };

    const header = (audit.auditHeader ?? {}) as AuditHeader;
    const degInfo = (audit.degreeInformation ?? {}) as { degreeDataArray?: DegreeData[]; goalArray?: Goal[] };
    const degData = degInfo.degreeDataArray?.[0] ?? {};
    const goals = degInfo.goalArray ?? [];

    const advisors = goals
      .filter((g) => g.code === "ADVISOR")
      .map((g) => ({ name: g.advisorName, email: g.advisorEmail, role: g.attachCode }));
    const major = goals.find((g) => g.code === "MAJOR")?.valueLiteral ?? "Undeclared";

    function ruleStatus(r: Rule): "complete" | "in_progress" | "incomplete" {
      if (r.requirement?.ruleComplete === "Y" || parseFloat(r.percentComplete ?? "0") >= 100) return "complete";
      if (r.inProgressIncomplete === "Y") return "in_progress";
      return "incomplete";
    }

    function blockStatus(pct: string | undefined): "complete" | "in_progress" | "incomplete" {
      const n = parseFloat(pct ?? "0");
      if (n >= 100) return "complete";
      if (n > 0) return "in_progress";
      return "incomplete";
    }

    function flattenRules(rules: Rule[], depth = 0): Array<{ indent: number; label: string; status: string }> {
      const out: Array<{ indent: number; label: string; status: string }> = [];
      for (const r of rules) {
        if (r.label) {
          out.push({ indent: depth, label: r.label, status: ruleStatus(r) });
        }
        if (r.ruleArray?.length) out.push(...flattenRules(r.ruleArray, depth + 1));
      }
      return out;
    }

    const blocks = ((audit.blockArray ?? []) as Block[]).map((b) => ({
      title: b.title,
      status: blockStatus(b.percentComplete),
      credits_applied: b.creditsApplied,
      rules: flattenRules(b.ruleArray ?? []),
    }));

    const classArray = ((audit.classInformation as { classArray?: CourseClass[] } | undefined)?.classArray ?? []);
    const courses = include_courses ? classArray.map((c) => ({
      code: `${c.discipline} ${c.number}`,
      title: c.courseTitle,
      credits: c.credits,
      grade: resolveGrade(c.letterGrade, c.numericGrade, c.passfail === "Y", c.inProgress === "Y" || c.preregistered === "Y"),
      term: c.termLiteral,
      in_progress: c.inProgress === "Y",
      preregistered: c.preregistered === "Y",
      pass_fail: c.passfail === "Y",
      attributes: decodeAttributes(
        (c.attributeArray ?? []).filter((a) => a.code === "ATTRIBUTE").map((a) => a.value ?? "")
      ),
    })) : undefined;

    const result = {
      student: {
        name: me.name,
        gpa: header.studentSystemGpa,
        dw_gpa: header.degreeworksGpa,
        overall_status: blockStatus(header.percentComplete),
        credits_applied: header.residentApplied,
        credits_in_progress: header.residentAppliedInProgress,
        transfer_credits: header.transferApplied,
        exam_credits: header.examAppliedCredits,
        audit_date: `${header.dateYear}-${header.dateMonth}-${header.dateDay}`,
      },
      degree: {
        degree: degData.degreeLiteral,
        school: degData.schoolLiteral,
        major,
        class_year: degData.studentLevelLiteral,
        catalog_year: degData.catalogYearLit,
        active_term: degData.activeTermLiteral,
        expected_graduation: degData.degreeTerm,
        total_credits_earned: degData.studentSystemCumulativeTotalCreditsEarned,
      },
      advisors,
      requirement_blocks: blocks,
      ...(include_courses ? { courses } : {}),
    };

    return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
  });

  // get_catalog_metadata
  server.registerTool("get_catalog_metadata", {
    description:
      "Get the last time the CourseTable course catalog was updated. " +
      "No authentication required. Returns an ISO date string.",
    inputSchema: z.object({}),
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async () => {
    const res = await fetch(`${API_BASE}/api/catalog/metadata`, {
      headers: { "Origin": "https://coursetable.com", "User-Agent": "yalie-mcp/1.0" },
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json() as { last_update: string };
    return { content: [{ type: "text" as const, text: JSON.stringify(data) }] };
  });

  // get_user_info
  server.registerTool("get_user_info", {
    description:
      "Get the authenticated user's Yale profile: netId, name, email, class year, school, major, " +
      "and whether they have evaluation access (hasEvals). Requires CourseTable cookie.",
    inputSchema: z.object({}),
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async () => {
    if (!cookie) return { content: [{ type: "text" as const, text: NO_CT }] };
    const data = await restApi<{
      netId: string; firstName: string | null; lastName: string | null;
      email: string | null; hasEvals: boolean; year: number | null;
      school: string | null; major: string | null;
    }>(cookie, "/api/user/info");
    return { content: [{ type: "text" as const, text: JSON.stringify(data) }] };
  });

  // get_worksheets
  server.registerTool("get_worksheets", {
    description:
      "Get the authenticated user's CourseTable worksheets. " +
      "Returns all seasons with worksheets, each containing named course lists " +
      "(CRN, color, hidden flag). Requires CourseTable cookie.\n\n" +
      "TIP: Link directly to a course in the worksheet view with: " +
      "https://coursetable.com/worksheet?course-modal={season}-{crn} " +
      "(e.g. https://coursetable.com/worksheet?course-modal=202503-10529)",
    inputSchema: z.object({}),
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async () => {
    if (!cookie) return { content: [{ type: "text" as const, text: NO_CT }] };
    const data = await restApi<{ data: Record<string, Record<string, { name: string; courses: Array<{ crn: number; color: string; hidden: boolean | null }> }>> }>(
      cookie, "/api/user/worksheets"
    );
    return { content: [{ type: "text" as const, text: JSON.stringify(data.data) }] };
  });

  // get_wishlist
  server.registerTool("get_wishlist", {
    description:
      "Get the authenticated user's CourseTable wishlist. " +
      "Returns a list of {season, crn} pairs. Requires CourseTable cookie.",
    inputSchema: z.object({}),
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async () => {
    if (!cookie) return { content: [{ type: "text" as const, text: NO_CT }] };
    const data = await restApi<{ data: Array<{ season: string; crn: number }> }>(
      cookie, "/api/user/wishlist"
    );
    return { content: [{ type: "text" as const, text: JSON.stringify(data.data) }] };
  });

  // update_worksheet_course
  server.registerTool("update_worksheet_course", {
    description:
      "Add, remove, or update a course in a CourseTable worksheet. " +
      "For 'add': color and hidden are required. For 'update': color/hidden are optional. " +
      "For 'remove': color/hidden are ignored. Requires CourseTable cookie.",
    inputSchema: z.object({
      action: z.enum(["add", "remove", "update"]),
      season: z.string().regex(/^\d{6}$/).describe("Season code e.g. '202503'"),
      crn: z.number().int().min(1).max(99999).describe("Course registration number"),
      worksheetNumber: z.number().int().min(0).max(999).default(0).describe("Worksheet number (0 = default)"),
      color: z.string().max(50).optional().describe("Color string (required for add, optional for update)"),
      hidden: z.boolean().optional().describe("Hidden flag (required for add, optional for update)"),
    }),
    annotations: { readOnlyHint: false, openWorldHint: false },
  }, async ({ action, season, crn, worksheetNumber, color, hidden }) => {
    if (!cookie) return { content: [{ type: "text" as const, text: NO_CT }] };
    await restApi<unknown>(cookie, "/api/user/updateWorksheetCourses", {
      method: "POST",
      body: { action, season, crn, worksheetNumber, color, hidden },
    });
    return { content: [{ type: "text" as const, text: `Course CRN ${crn} ${action === "add" ? "added to" : action === "remove" ? "removed from" : "updated in"} worksheet ${worksheetNumber} (${season}).` }] };
  });

  // update_wishlist_course
  server.registerTool("update_wishlist_course", {
    description:
      "Add or remove a course from the user's CourseTable wishlist. Requires CourseTable cookie.",
    inputSchema: z.object({
      action: z.enum(["add", "remove"]),
      season: z.string().regex(/^\d{6}$/).describe("Season code e.g. '202503'"),
      crn: z.number().int().min(1).max(99999).describe("Course registration number"),
    }),
    annotations: { readOnlyHint: false, openWorldHint: false },
  }, async ({ action, season, crn }) => {
    if (!cookie) return { content: [{ type: "text" as const, text: NO_CT }] };
    await restApi<unknown>(cookie, "/api/user/updateWishlistCourses", {
      method: "POST",
      body: { action, season, crn },
    });
    return { content: [{ type: "text" as const, text: `Course CRN ${crn} (${season}) ${action === "add" ? "added to" : "removed from"} wishlist.` }] };
  });

  // update_worksheet_metadata
  server.registerTool("update_worksheet_metadata", {
    description:
      "Create, delete, or rename a CourseTable worksheet. " +
      "add: creates a new worksheet with the given name, returns worksheetNumber. " +
      "delete: removes a worksheet by number. rename: renames a worksheet. " +
      "Requires CourseTable cookie.",
    inputSchema: z.object({
      action: z.enum(["add", "delete", "rename"]),
      season: z.string().regex(/^\d{6}$/).describe("Season code e.g. '202503'"),
      worksheetNumber: z.number().int().min(0).max(999).optional().describe("Required for delete/rename"),
      name: z.string().max(100).optional().describe("Required for add/rename"),
    }),
    annotations: { readOnlyHint: false, openWorldHint: false },
  }, async ({ action, season, worksheetNumber, name }) => {
    if (!cookie) return { content: [{ type: "text" as const, text: NO_CT }] };
    const body: Record<string, unknown> = { action, season };
    if (worksheetNumber !== undefined) body.worksheetNumber = worksheetNumber;
    if (name !== undefined) body.name = name;
    const result = await restApi<{ worksheetNumber?: number } | null>(
      cookie, "/api/user/updateWorksheetMetadata", { method: "POST", body }
    );
    if (action === "add" && result && typeof result === "object" && "worksheetNumber" in result) {
      return { content: [{ type: "text" as const, text: `Worksheet '${name}' created as worksheet #${result.worksheetNumber} in season ${season}.` }] };
    }
    return { content: [{ type: "text" as const, text: `Worksheet ${action} successful.` }] };
  });

  // get_friends_worksheets
  server.registerTool("get_friends_worksheets", {
    description:
      "Access friends' CourseTable worksheets. Two modes:\n" +
      "- list_friends: returns all friends' names and netIds\n" +
      "- get_courses: returns worksheet courses for a specific friend (net_id required, season optional)\n" +
      "Requires CourseTable cookie.\n\n" +
      "TIP: Link to a friend's worksheet course with: " +
      "https://coursetable.com/worksheet?course-modal={season}-{crn}",
    inputSchema: z.object({
      mode: z.enum(["list_friends", "get_courses"]),
      net_id: z.string().max(20).regex(/^[a-z0-9]+$/i).optional().describe("Required for get_courses mode"),
      season: z.string().regex(/^\d{6}$/).optional().describe("Filter by season code e.g. '202503' (get_courses only)"),
    }),
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async ({ mode, net_id, season }) => {
    if (!cookie) return { content: [{ type: "text" as const, text: NO_CT }] };

    const data = await restApi<FriendsData>(cookie, "/api/friends/worksheets");

    if (mode === "list_friends") {
      const friends = Object.entries(data.friends).map(([netId, f]) => ({
        net_id: netId,
        name: f.name,
      }));
      return { content: [{ type: "text" as const, text: JSON.stringify({ count: friends.length, friends }) }] };
    }

    // get_courses
    if (!net_id) {
      return { content: [{ type: "text" as const, text: "net_id is required for get_courses mode." }] };
    }
    const friend = data.friends[net_id];
    if (!friend) {
      return { content: [{ type: "text" as const, text: `No friend found with net_id '${net_id}'.` }] };
    }

    const seasons = season ? { [season]: friend.worksheets[season] } : friend.worksheets;
    const result: Array<{ season: string; worksheet: string; name: string; courses: Array<{ crn: number; color: string; hidden: boolean | null }> }> = [];
    for (const [seasonCode, worksheetMap] of Object.entries(seasons)) {
      if (!worksheetMap) continue;
      for (const [wsNum, ws] of Object.entries(worksheetMap)) {
        result.push({ season: seasonLabel(seasonCode), worksheet: wsNum, name: ws.name, courses: ws.courses });
      }
    }

    return { content: [{ type: "text" as const, text: JSON.stringify({ net_id, name: friend.name, worksheets: result }) }] };
  });

  // get_evaluation_ratings
  server.registerTool("get_evaluation_ratings", {
    description:
      "Get quantitative (numerical) evaluation rating distributions for a course. " +
      "Returns per-question rating arrays showing how students distributed their responses " +
      "across the scale. Complements get_course_evaluations which returns narrative comments. " +
      "Use course_id from search_courses or get_course.",
    inputSchema: z.object({
      course_id: z.number().int().describe("Course ID"),
    }),
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async ({ course_id }) => {
    if (!cookie) return { content: [{ type: "text" as const, text: NO_CT }] };
    type RatingsResult = {
      evaluation_ratings: Array<{
        question_code: string;
        rating: unknown;
        evaluation_question: { question_text: string };
      }>;
    };
    const data = await gql<RatingsResult>(cookie, GET_EVAL_RATINGS_QUERY, { course_id });
    if (!data.evaluation_ratings.length) {
      return { content: [{ type: "text" as const, text: "No quantitative rating data available for this course." }] };
    }
    const ratings = data.evaluation_ratings.map((r) => ({
      question: r.evaluation_question.question_text,
      code: r.question_code,
      distribution: r.rating,
    }));
    return { content: [{ type: "text" as const, text: JSON.stringify({ course_id, ratings }) }] };
  });

  // get_major_requirements
  server.registerTool("get_major_requirements", {
    description:
      "Fetch major or program requirements from the official Yale course catalog (catalog.yale.edu). " +
      "Use list_majors to find valid slugs (e.g. 'computer-science', 'mathematics', 'economics'). " +
      "Returns the full requirements text for the major including prerequisites, core courses, " +
      "distributional requirements, and senior requirements.\n\n" +
      "IMPORTANT — eligibility rules: The catalog text here is the authoritative source for which courses " +
      "count toward the major. Do NOT infer eligibility from a course's subject prefix alone — " +
      "cross-listed courses under other department codes may satisfy requirements, and many courses " +
      "with the major's own prefix do not count. Read this text carefully, then call get_course on " +
      "specific courses to check their `description` and `requirements` fields for confirmation.",
    inputSchema: z.object({
      slug: z.string().describe("Major slug from list_majors, e.g. 'computer-science' or 'mathematics'"),
    }),
    annotations: { readOnlyHint: true, openWorldHint: true },
  }, async ({ slug }) => {
    const clean = slug.trim().toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9-]/g, "");
    const url = `${CATALOG_BASE}/ycps/subjects-of-instruction/${clean}/`;
    const text = await fetchCatalogText(url);
    if (text.length < 100) {
      return { content: [{ type: "text" as const, text: `No content found at ${url}. Use list_majors to find the correct slug.` }] };
    }
    // Truncate to avoid context overflow — catalog pages can be large
    const truncated = text.length > 12000 ? text.slice(0, 12000) + "\n\n[truncated — content continues at " + url + "]" : text;
    return { content: [{ type: "text" as const, text: truncated }] };
  });
}
