#!/usr/bin/env npx tsx
/**
 * Smoke-tests get_syllabus_content logic against real Canvas URLs.
 * Reads COURSETABLE_COOKIE and CANVAS_COOKIE from env (same as stdio mode).
 *
 * Usage:
 *   COURSETABLE_COOKIE="..." CANVAS_COOKIE="..." npx tsx scripts/test-syllabus.ts
 *
 * Options (env vars):
 *   LIMIT=50          number of courses to sample (default 50)
 *   SEASON=202503     season code to pull from (default latest)
 *   CONCURRENCY=5     parallel fetches (default 5)
 */

const LIMIT = parseInt(process.env.LIMIT ?? "50", 10);
const CONCURRENCY = parseInt(process.env.CONCURRENCY ?? "5", 10);
const SEASON = process.env.SEASON ?? "202503";

const CT_COOKIE = process.env.COURSETABLE_COOKIE;
const CANVAS_COOKIE = process.env.CANVAS_COOKIE;

if (!CT_COOKIE) {
  console.error("ERROR: COURSETABLE_COOKIE not set");
  process.exit(1);
}
if (!CANVAS_COOKIE) {
  console.error("ERROR: CANVAS_COOKIE not set");
  process.exit(1);
}

// ── CourseTable GraphQL ──────────────────────────────────────────────────────

const GQL_URL = "https://api.coursetable.com/ferry/v1/graphql";

async function gql<T>(query: string, variables: Record<string, unknown>): Promise<T> {
  const res = await fetch(GQL_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: CT_COOKIE!,
    },
    body: JSON.stringify({ query, variables }),
    signal: AbortSignal.timeout(30000),
  });
  if (!res.ok) throw new Error(`CourseTable HTTP ${res.status}`);
  const json = (await res.json()) as { data?: T; errors?: unknown[] };
  if (json.errors?.length) throw new Error(`GQL errors: ${JSON.stringify(json.errors)}`);
  return json.data!;
}

const COURSES_QUERY = `
  query SyllabusTest($season: String!, $limit: Int!) {
    courses(
      where: {
        season_code: { _eq: $season }
        syllabus_url: { _is_null: false }
      }
      limit: $limit
      order_by: { course_id: asc }
    ) {
      course_id
      title
      syllabus_url
      listings(limit: 1, order_by: { crn: asc }) { course_code }
    }
  }
`;

// ── Syllabus fetch (mirrors tools.ts logic) ──────────────────────────────────

type Result =
  | { ok: true; course_id: number; code: string; title: string; syllabus_url: string; chars: number; pdfCount: number }
  | { ok: false; course_id: number; code: string; title: string; syllabus_url: string; error: string };

function extractDivContent(h: string, id: string): string | null {
  const pat = new RegExp(`<div[^>]*id=["']${id}["'][^>]*>`, "i");
  const m = pat.exec(h);
  if (!m) return null;
  let depth = 1,
    pos = m.index + m[0].length;
  const start = pos;
  function nextOpen(from: number): number {
    let p = from;
    while (p < h.length) {
      const idx = h.indexOf("<div", p);
      if (idx === -1) return -1;
      const c = h[idx + 4];
      if (c === ">" || c === " " || c === "\n" || c === "\t" || c === "\r") return idx;
      p = idx + 4;
    }
    return -1;
  }
  while (depth > 0 && pos < h.length) {
    const op = nextOpen(pos);
    const cl = h.indexOf("</div>", pos);
    if (cl === -1) break;
    if (op !== -1 && op < cl) {
      depth++;
      pos = op + 4;
    } else {
      depth--;
      if (depth === 0) return h.slice(start, cl);
      pos = cl + 6;
    }
  }
  return null;
}

async function testSyllabus(course: {
  course_id: number;
  title: string;
  syllabus_url: string;
  listings: Array<{ course_code: string }>;
}): Promise<Result> {
  const code = course.listings[0]?.course_code ?? "???";
  const base = { course_id: course.course_id, code, title: course.title, syllabus_url: course.syllabus_url };

  try {
    const res = await fetch(course.syllabus_url, {
      headers: {
        Cookie: CANVAS_COOKIE!,
        "User-Agent": "Mozilla/5.0 (compatible; yalie-mcp/1.0)",
        Accept: "text/html",
      },
      redirect: "manual",
      signal: AbortSignal.timeout(15000),
    });

    let finalRes = res;
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location");
      if (!location) return { ok: false, ...base, error: "redirect with no Location header" };
      let redirectUrl: URL;
      try {
        redirectUrl = new URL(location, course.syllabus_url);
      } catch {
        return { ok: false, ...base, error: "invalid redirect URL" };
      }
      if (redirectUrl.hostname !== "yale.instructure.com") {
        return { ok: false, ...base, error: `redirect outside yale.instructure.com → ${redirectUrl.hostname}` };
      }
      finalRes = await fetch(redirectUrl.toString(), {
        headers: {
          Cookie: CANVAS_COOKIE!,
          "User-Agent": "Mozilla/5.0 (compatible; yalie-mcp/1.0)",
          Accept: "text/html",
        },
        redirect: "manual",
        signal: AbortSignal.timeout(15000),
      });
    }

    if (
      finalRes.status === 401 ||
      finalRes.status === 403 ||
      (finalRes.headers.get("location") ?? "").includes("/login")
    ) {
      return { ok: false, ...base, error: `Canvas auth failed (HTTP ${finalRes.status})` };
    }
    if (!finalRes.ok) {
      return { ok: false, ...base, error: `HTTP ${finalRes.status}` };
    }

    const html = await finalRes.text();
    const syllabusHtml =
      extractDivContent(html, "content") ?? extractDivContent(html, "not_right_side");
    const source = syllabusHtml ?? html;

    // Count PDF links
    type PdfLink = { url: string; label: string; isCanvas: boolean };
    const pdfLinks: PdfLink[] = [];
    if (syllabusHtml) {
      const seenUrls = new Set<string>();
      const linkRe = /<a[^>]+href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
      let lm: RegExpExecArray | null;
      while ((lm = linkRe.exec(syllabusHtml)) !== null) {
        const rawHref = lm[1]!.trim();
        const label = lm[2]!.replace(/<[^>]+>/g, "").trim() || "attachment";
        const canvasMatch =
          /(?:https?:\/\/yale\.instructure\.com)?(\/courses\/(\d+)\/files\/(\d+))/i.exec(rawHref);
        if (canvasMatch) {
          const dlUrl = `https://yale.instructure.com/courses/${canvasMatch[2]}/files/${canvasMatch[3]}/download?download_frd=1`;
          if (!seenUrls.has(dlUrl)) {
            seenUrls.add(dlUrl);
            pdfLinks.push({ url: dlUrl, label, isCanvas: true });
          }
          continue;
        }
        if (/\.pdf(\?|#|$)/i.test(rawHref) && /^https?:\/\//i.test(rawHref)) {
          if (!seenUrls.has(rawHref)) {
            seenUrls.add(rawHref);
            pdfLinks.push({ url: rawHref, label, isCanvas: false });
          }
        }
      }
    }

    const text = source
      .replace(/<script[\s\S]*?<\/script>/gi, "")
      .replace(/<style[\s\S]*?<\/style>/gi, "")
      .replace(/<br\s*\/?>/gi, "\n")
      .replace(/<\/p>/gi, "\n\n")
      .replace(/<\/li>/gi, "\n")
      .replace(/<[^>]+>/g, "")
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&nbsp;/g, " ")
      .replace(/&#\d+;/g, " ")
      .replace(/\n{3,}/g, "\n\n")
      .trim();

    if (text.length < 50 && pdfLinks.length === 0) {
      return { ok: false, ...base, error: "empty syllabus (< 50 chars, no PDFs)" };
    }

    // Try fetching PDFs and parsing them
    let pdfErrors: string[] = [];
    for (const link of pdfLinks.slice(0, 2)) {
      try {
        const fetchHeaders: Record<string, string> = {
          "User-Agent": "Mozilla/5.0 (compatible; yalie-mcp/1.0)",
          Accept: "application/pdf,*/*",
        };
        if (link.isCanvas) fetchHeaders["Cookie"] = CANVAS_COOKIE!;
        const pdfRes = await fetch(link.url, {
          headers: fetchHeaders,
          redirect: "follow",
          signal: AbortSignal.timeout(10000),
        });
        if (!pdfRes.ok) {
          pdfErrors.push(`PDF HTTP ${pdfRes.status} (${link.label})`);
          continue;
        }
        const contentType = pdfRes.headers.get("content-type") ?? "";
        if (!contentType.includes("pdf") && !contentType.includes("octet-stream")) {
          pdfErrors.push(`PDF bad content-type ${contentType} (${link.label})`);
          continue;
        }
        const arrayBuf = await pdfRes.arrayBuffer();
        const { getDocumentProxy, extractText } = await import("unpdf");
        const pdf = await getDocumentProxy(new Uint8Array(arrayBuf));
        await extractText(pdf, { mergePages: true });
      } catch (err) {
        pdfErrors.push(`PDF parse error: ${err} (${link.label})`);
      }
    }

    if (pdfErrors.length > 0 && text.length < 50) {
      return { ok: false, ...base, error: pdfErrors.join("; ") };
    }

    // Treat PDF errors as warnings but still pass if we got HTML text
    return { ok: true, ...base, chars: text.length, pdfCount: pdfLinks.length };
  } catch (err) {
    return { ok: false, ...base, error: String(err) };
  }
}

// ── Concurrency pool ─────────────────────────────────────────────────────────

async function runPool<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T, i: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]!, i);
    }
  }
  await Promise.all(Array.from({ length: concurrency }, worker));
  return results;
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log(`Fetching up to ${LIMIT} courses with syllabus URLs from season ${SEASON}…`);

  type CoursesResp = {
    courses: Array<{
      course_id: number;
      title: string;
      syllabus_url: string;
      listings: Array<{ course_code: string }>;
    }>;
  };

  const data = await gql<CoursesResp>(COURSES_QUERY, { season: SEASON, limit: LIMIT });
  const courses = data.courses;
  console.log(`Got ${courses.length} courses. Testing syllabi with concurrency=${CONCURRENCY}…\n`);

  const results = await runPool(courses, CONCURRENCY, async (course, i) => {
    const result = await testSyllabus(course);
    const icon = result.ok ? "✓" : "✗";
    const detail = result.ok
      ? `${result.chars} chars, ${result.pdfCount} PDF(s)`
      : `ERROR: ${result.error}`;
    console.log(`[${String(i + 1).padStart(3)}/${courses.length}] ${icon} ${result.code.padEnd(12)} ${result.title.slice(0, 40).padEnd(40)} ${detail}`);
    return result;
  });

  const passed = results.filter((r) => r.ok);
  const failed = results.filter((r) => !r.ok) as Extract<Result, { ok: false }>[];

  console.log(`\n${"─".repeat(80)}`);
  console.log(`PASSED: ${passed.length}/${results.length}`);
  console.log(`FAILED: ${failed.length}/${results.length}`);

  if (failed.length > 0) {
    console.log(`\nFailed courses:`);
    for (const f of failed) {
      console.log(`  [${f.course_id}] ${f.code} "${f.title}"`);
      console.log(`    URL:   ${f.syllabus_url}`);
      console.log(`    Error: ${f.error}`);
    }
  }

  // Error breakdown by category
  if (failed.length > 0) {
    const categories = new Map<string, number>();
    for (const f of failed) {
      const key = f.error.replace(/\d{3,}/g, "NNN").split(":")[0]!.trim();
      categories.set(key, (categories.get(key) ?? 0) + 1);
    }
    console.log(`\nError breakdown:`);
    for (const [cat, count] of [...categories.entries()].sort((a, b) => b[1] - a[1])) {
      console.log(`  ${String(count).padStart(3)}x  ${cat}`);
    }
  }

  process.exit(failed.length > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(2);
});
