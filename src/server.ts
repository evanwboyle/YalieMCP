/**
 * YalieMCP remote server — compatible with Claude custom connectors.
 * Fully stateless: all state is sealed into encrypted tokens (no DB/Redis needed).
 *
 * Env vars:
 *   TOKEN_SECRET  — secret key for sealing tokens (required in production)
 *   BASE_URL      — public URL of this server (required in production)
 *   PORT          — port to listen on locally (default 3000)
 */
import express from "express";
import crypto from "crypto";
import { rateLimit } from "express-rate-limit";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import type { OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type {
  OAuthClientInformationFull,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type { Request, Response } from "express";
import { registerTools, validateCookie } from "./tools.js";

const PORT = parseInt(process.env.PORT ?? "3000", 10);
const BASE_URL = (process.env.BASE_URL ?? `http://localhost:${PORT}`).replace(/\/$/, "");
const DEFAULT_SECRET = "dev-secret-please-change-in-production";
const TOKEN_SECRET = process.env.TOKEN_SECRET ?? DEFAULT_SECRET;

if (TOKEN_SECRET === DEFAULT_SECRET) {
  if (process.env.NODE_ENV === "production") {
    console.error("Fatal: TOKEN_SECRET must be set in production. Exiting.");
    process.exit(1);
  } else {
    console.warn("Warning: TOKEN_SECRET not set — using insecure default. Never deploy this way.");
  }
}

// ─── Sealed token helpers (AES-256-GCM, stateless) ───────────────────────────

function getKey(): Buffer {
  return crypto.createHash("sha256").update(TOKEN_SECRET).digest();
}

function seal<T extends object>(payload: T): string {
  const json = JSON.stringify(payload);
  const key = getKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(json, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64url");
}

function unseal<T extends object>(token: string): T | null {
  try {
    const buf = Buffer.from(token, "base64url");
    // 12 bytes IV + 16 bytes GCM tag + at least 1 byte ciphertext
    if (buf.length < 29) return null;
    const key = getKey();
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, buf.subarray(0, 12));
    decipher.setAuthTag(buf.subarray(12, 28));
    const json = decipher.update(buf.subarray(28)).toString("utf8") + decipher.final("utf8");
    return JSON.parse(json) as T;
  } catch {
    return null;
  }
}

// HMAC-signed token for client IDs (client info is not sensitive, just needs integrity)
function signedToken(payload: object): string {
  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", TOKEN_SECRET).update(data).digest("base64url");
  return `${data}.${sig}`;
}

function verifySignedToken<T extends object>(token: string): T | null {
  try {
    const dot = token.lastIndexOf(".");
    const data = token.slice(0, dot);
    const sig = token.slice(dot + 1);
    const expected = crypto.createHmac("sha256", TOKEN_SECRET).update(data).digest("base64url");
    if (!crypto.timingSafeEqual(Buffer.from(sig, "base64url"), Buffer.from(expected, "base64url"))) return null;
    return JSON.parse(Buffer.from(data, "base64url").toString("utf8")) as T;
  } catch {
    return null;
  }
}

// ─── Token payloads ───────────────────────────────────────────────────────────

interface CodePayload {
  type: "code";
  coursetable_cookie?: string;
  canvas_cookie?: string;
  audit_cookie?: string;
  codeChallenge: string;
  redirectUri: string;
  clientId: string;
  exp: number;
}
interface AccessPayload {
  type: "access";
  coursetable_cookie?: string;
  canvas_cookie?: string;
  audit_cookie?: string;
  clientId: string;
  exp: number;
}
interface RefreshPayload {
  type: "refresh";
  coursetable_cookie?: string;
  canvas_cookie?: string;
  audit_cookie?: string;
  clientId: string;
  exp: number;
}

interface ExtraCookies {
  coursetable_cookie?: string;
  canvas_cookie?: string;
  audit_cookie?: string;
}

/**
 * Extract cookie string from either:
 *  - A plain cookie string (connect.sid=…; other=…)
 *  - A full "Copy as cURL" paste (-H 'cookie: …' or -H "Cookie: …")
 * Also strips accidental "Cookie: " header prefix.
 */
function normalizeCookie(raw: string): string {
  const trimmed = raw.trim();
  // cURL -H 'cookie: value' or -H "Cookie: value" (Chrome Copy as cURL)
  const headerMatch = trimmed.match(/-[Hh]\s+['"]cookie:\s*([^'"\\]+)['"]/i);
  if (headerMatch) return headerMatch[1]!.trim();
  // cURL -b 'value' or --cookie 'value' (Firefox / manual cURL)
  const bMatch = trimmed.match(/(?:-b|--cookie)\s+['"]([^'"]+)['"]/i);
  if (bMatch) return bMatch[1]!.trim();
  // Plain string — strip optional "Cookie: " prefix and normalize newlines
  return trimmed
    .replace(/^cookie:\s*/i, "")
    .replace(/[\r\n]+/g, "; ")
    .replace(/;\s*;+/g, ";")
    .trim();
}

function now(): number { return Math.floor(Date.now() / 1000); }

// ─── Hint cookie helpers (persists cookies across re-auth flows) ──────────────

interface HintPayload {
  type: "hint";
  coursetable_cookie?: string;
  canvas_cookie?: string;
  audit_cookie?: string;
  exp: number;
}

function sealHint(extra: ExtraCookies): string {
  return seal<HintPayload>({ type: "hint", ...extra, exp: now() + 60 * 86400 });
}

function parseRequestCookies(header: string | undefined): Record<string, string> {
  if (!header) return {};
  return Object.fromEntries(
    header.split(";")
      .map(s => s.trim())
      .filter(Boolean)
      .map(s => {
        const idx = s.indexOf("=");
        return idx === -1 ? [s, ""] : [s.slice(0, idx).trim(), s.slice(idx + 1).trim()];
      })
  );
}

// ─── CSRF token helpers (stateless, 10-minute window) ─────────────────────────

const CSRF_WINDOW = 600; // seconds

function csrfToken(clientId: string): string {
  const ts = Math.floor(now() / CSRF_WINDOW); // quantize to window
  const data = `${clientId}:${ts}`;
  const sig = crypto.createHmac("sha256", TOKEN_SECRET).update(data).digest("base64url");
  return `${ts}.${sig}`;
}

function verifyCsrf(clientId: string, token: string): boolean {
  const dot = token.indexOf(".");
  if (dot === -1) return false;
  const ts = parseInt(token.slice(0, dot), 10);
  if (isNaN(ts)) return false;
  const current = Math.floor(now() / CSRF_WINDOW);
  // Accept current window and the immediately preceding one (handles boundary edge)
  if (ts !== current && ts !== current - 1) return false;
  const data = `${clientId}:${ts}`;
  const expected = crypto.createHmac("sha256", TOKEN_SECRET).update(data).digest("base64url");
  const provided = token.slice(dot + 1);
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, "base64url"), Buffer.from(provided, "base64url"));
  } catch {
    return false;
  }
}

function issueCode(
  codeChallenge: string, redirectUri: string, clientId: string, extra: ExtraCookies
): string {
  return seal<CodePayload>({ type: "code", ...extra, codeChallenge, redirectUri, clientId, exp: now() + 600 });
}
function issueAccess(clientId: string, extra: ExtraCookies): string {
  return seal<AccessPayload>({ type: "access", ...extra, clientId, exp: now() + 30 * 86400 });
}
function issueRefresh(clientId: string, extra: ExtraCookies): string {
  return seal<RefreshPayload>({ type: "refresh", ...extra, clientId, exp: now() + 60 * 86400 });
}

// ─── OAuth clients store (self-contained signed client IDs) ───────────────────

const clientsStore: OAuthRegisteredClientsStore = {
  getClient(clientId) {
    const data = verifySignedToken<Omit<OAuthClientInformationFull, "client_id">>(clientId);
    if (!data) return undefined;
    return { ...data, client_id: clientId } as OAuthClientInformationFull;
  },
  registerClient(info) {
    const base: Omit<OAuthClientInformationFull, "client_id"> = {
      ...info,
      client_id_issued_at: now(),
    };
    const client_id = signedToken(base);
    return { ...base, client_id };
  },
};

// ─── OAuth provider ───────────────────────────────────────────────────────────

const provider: OAuthServerProvider = {
  get clientsStore() { return clientsStore; },

  async authorize(client: OAuthClientInformationFull, params, res: Response) {
    const req = res.req!;

    if (req.method === "POST") {
      const csrfFromForm = typeof req.body._csrf === "string" ? req.body._csrf : "";
      if (!verifyCsrf(client.client_id, csrfFromForm)) {
        res.status(403).send(renderAuthPage({
          clientName: client.client_name ?? "Claude",
          clientId: client.client_id,
          codeChallenge: params.codeChallenge,
          redirectUri: params.redirectUri,
          state: params.state,
          error: "Invalid or expired form submission — please reload the page and try again.",
        }));
        return;
      }

      const MAX_COOKIE_INPUT = 8192;
      const rawCT     = typeof req.body.coursetable_cookie === "string" ? req.body.coursetable_cookie.trim() : undefined;
      const rawCanvas = typeof req.body.canvas_cookie      === "string" ? req.body.canvas_cookie.trim()      : undefined;
      const rawAudit  = typeof req.body.audit_cookie       === "string" ? req.body.audit_cookie.trim()       : undefined;

      // Helper to re-render with a fresh CSRF token on error
      const rejectWithError = (status: number, error: string) => {
        res.status(status).send(renderAuthPage({
          clientName: client.client_name ?? "Claude",
          clientId: client.client_id,
          codeChallenge: params.codeChallenge,
          redirectUri: params.redirectUri,
          state: params.state,
          csrf: csrfToken(client.client_id),
          error,
        }));
      };

      if (
        (rawCT     && rawCT.length     > MAX_COOKIE_INPUT) ||
        (rawCanvas && rawCanvas.length > MAX_COOKIE_INPUT) ||
        (rawAudit  && rawAudit.length  > MAX_COOKIE_INPUT)
      ) {
        rejectWithError(400, "Input too large — paste only the cookie string, not the full page source.");
        return;
      }

      if (!rawCT && !rawCanvas && !rawAudit) {
        rejectWithError(400, "Connect at least one service before authorizing.");
        return;
      }

      const extra: ExtraCookies = {};

      if (rawCT) {
        const ctCookie = normalizeCookie(rawCT);
        const valid = await validateCookie(ctCookie);
        if (!valid) {
          rejectWithError(400, "CourseTable cookie invalid or expired — please try again.");
          return;
        }
        extra.coursetable_cookie = ctCookie;
      }
      if (rawCanvas) extra.canvas_cookie = normalizeCookie(rawCanvas);
      if (rawAudit)  extra.audit_cookie  = normalizeCookie(rawAudit);

      const code = issueCode(params.codeChallenge, params.redirectUri, client.client_id, extra);
      const url = new URL(params.redirectUri);
      url.searchParams.set("code", code);
      if (params.state) url.searchParams.set("state", params.state);
      // Persist cookies as a sealed hint for the next re-auth
      const isHttps = BASE_URL.startsWith("https://");
      res.setHeader("Set-Cookie",
        `yalie_hint=${sealHint(extra)}; HttpOnly; SameSite=Lax; Path=/authorize; Max-Age=${60 * 86400}${isHttps ? "; Secure" : ""}`
      );
      res.redirect(url.toString());
      return;
    }

    // Read sealed hint cookie to pre-fill the form on re-auth
    const cookies = parseRequestCookies(req.headers.cookie);
    let prefill: ExtraCookies | undefined;
    if (cookies["yalie_hint"]) {
      const hint = unseal<HintPayload>(cookies["yalie_hint"]);
      if (hint && hint.type === "hint" && hint.exp > now()) {
        prefill = {
          coursetable_cookie: hint.coursetable_cookie,
          canvas_cookie: hint.canvas_cookie,
          audit_cookie: hint.audit_cookie,
        };
      }
    }

    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Content-Security-Policy", "frame-ancestors 'none'");
    res.send(renderAuthPage({
      clientName: client.client_name ?? "Claude",
      clientId: client.client_id,
      codeChallenge: params.codeChallenge,
      redirectUri: params.redirectUri,
      state: params.state,
      csrf: csrfToken(client.client_id),
      prefill,
    }));
  },

  async challengeForAuthorizationCode(_client, code) {
    const p = unseal<CodePayload>(code);
    if (!p || p.type !== "code" || p.exp < now()) throw new Error("Invalid or expired code");
    return p.codeChallenge;
  },

  async exchangeAuthorizationCode(client, code) {
    const p = unseal<CodePayload>(code);
    if (!p || p.type !== "code" || p.exp < now()) throw new Error("Invalid or expired code");
    const extra: ExtraCookies = {};
    if (p.coursetable_cookie) extra.coursetable_cookie = p.coursetable_cookie;
    if (p.canvas_cookie)      extra.canvas_cookie      = p.canvas_cookie;
    if (p.audit_cookie)       extra.audit_cookie       = p.audit_cookie;
    return {
      access_token: issueAccess(client.client_id, extra),
      token_type: "bearer",
      expires_in: 30 * 86400,
      refresh_token: issueRefresh(client.client_id, extra),
    } satisfies OAuthTokens;
  },

  async exchangeRefreshToken(client, refreshToken) {
    const p = unseal<RefreshPayload>(refreshToken);
    if (!p || p.type !== "refresh" || p.exp < now()) throw new Error("Invalid or expired refresh token");
    const extra: ExtraCookies = {};
    if (p.coursetable_cookie) extra.coursetable_cookie = p.coursetable_cookie;
    if (p.canvas_cookie)      extra.canvas_cookie      = p.canvas_cookie;
    if (p.audit_cookie)       extra.audit_cookie       = p.audit_cookie;
    return {
      access_token: issueAccess(client.client_id, extra),
      token_type: "bearer",
      expires_in: 30 * 86400,
      refresh_token: issueRefresh(client.client_id, extra),
    } satisfies OAuthTokens;
  },

  async verifyAccessToken(token) {
    const p = unseal<AccessPayload>(token);
    if (!p || p.type !== "access" || p.exp < now()) throw new Error("Invalid or expired token");
    return {
      token,
      clientId: p.clientId,
      scopes: [],
      expiresAt: p.exp,
    } satisfies AuthInfo;
  },
};

// ─── Auth page ────────────────────────────────────────────────────────────────

function escapeHtml(s: string): string {
  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
          .replace(/"/g,"&quot;").replace(/'/g,"&#39;");
}

function curlSteps(): string {
  return `
    <ol>
      <li>Open DevTools — <code>F12</code> / <code>Cmd ⌥ I</code> → <strong>Network</strong> tab</li>
      <li>Reload the page so requests appear</li>
      <li>Right-click the <strong>first request at the top</strong> → <strong>Copy</strong> → <strong>Copy as cURL</strong></li>
      <li>Paste the entire output below — cookies are extracted automatically</li>
    </ol>
    <em style="font-size:.78rem;color:#888">
      Paste the full cURL command (Chrome <code>-H 'cookie: …'</code> or Firefox <code>-b '…'</code> format) or just a plain cookie string — all work.
    </em>`;
}

function renderAuthPage(opts: {
  clientName: string;
  clientId: string;
  codeChallenge: string;
  redirectUri: string;
  state?: string;
  error?: string;
  csrf?: string;
  prefill?: ExtraCookies;
}): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect YalieMCP</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f4f5f7;
     color:#1a1a2e;min-height:100vh;display:flex;align-items:center;
     justify-content:center;padding:1rem}
.card{background:#fff;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.1);
      padding:2.25rem;max-width:520px;width:100%}
h1{font-size:1.35rem;font-weight:700;margin-bottom:.25rem}
.sub{color:#666;font-size:.875rem;margin-bottom:1.25rem}
.security{background:#f0f7ff;border:1px solid #bdd7f5;border-radius:10px;
           padding:1rem 1.1rem;margin-bottom:1.5rem;font-size:.82rem;line-height:1.65;color:#1a3550}
.security strong{display:block;margin-bottom:.35rem;font-size:.88rem;color:#0d2d47}
.security ul{margin:.35rem 0 0 1.1rem}
.num{background:#286ee6;color:#fff;border-radius:50%;width:1.75rem;height:1.75rem;
     display:flex;align-items:center;justify-content:center;font-size:.8rem;
     font-weight:700;flex-shrink:0;margin-top:.1rem}
.num.opt{background:#6b7a99}
.step-title{font-weight:600;font-size:.95rem;margin-bottom:.35rem}
.step-desc{font-size:.84rem;color:#555;line-height:1.6}
.badge{display:inline-block;font-size:.7rem;font-weight:600;letter-spacing:.03em;
       padding:.1rem .45rem;border-radius:99px;vertical-align:middle;margin-left:.35rem}
.badge-opt{background:#eef1f7;color:#6b7a99}
.badge-unlocks{background:#e8f5e9;color:#2e7d32}
.btn{display:inline-flex;align-items:center;gap:.4rem;background:#286ee6;color:#fff;
     padding:.5rem 1.1rem;border-radius:8px;text-decoration:none;font-size:.875rem;
     font-weight:600;border:none;cursor:pointer;transition:background .15s}
.btn:hover{background:#1a5cc8}
code{background:#f0f3f8;padding:.1rem .35rem;border-radius:4px;
     font-size:.8rem;font-family:"SF Mono",Consolas,monospace}
ol{margin:.5rem 0 0 1.1rem;line-height:1.9}
textarea{width:100%;margin-top:.6rem;border:1.5px solid #d0d6e0;border-radius:8px;
         padding:.65rem .8rem;font-family:"SF Mono",Consolas,monospace;font-size:.78rem;
         resize:vertical;min-height:72px;color:#1a1a2e}
textarea:focus{outline:none;border-color:#286ee6}
.error{background:#fff0f0;border:1px solid #ffb3b3;color:#c0392b;
       border-radius:8px;padding:.65rem 1rem;margin-bottom:1.25rem;font-size:.875rem}
hr{border:none;border-top:1px solid #edf0f5;margin:1.375rem 0}
details{margin-bottom:.75rem}
details>summary{cursor:pointer;list-style:none;display:flex;align-items:center;
                gap:.875rem;padding:.5rem 0}
details>summary::-webkit-details-marker{display:none}
details>summary .chevron{font-size:.7rem;color:#6b7a99;transition:transform .15s}
details[open]>summary .chevron{transform:rotate(90deg)}
details .inner{padding-left:2.625rem;padding-bottom:.75rem}
.svc-status{font-size:.75rem;font-weight:700;padding:.2rem .55rem;border-radius:99px;
            white-space:nowrap;flex-shrink:0;background:#f0f3f8;color:#6b7a99}
.svc-status.ok{background:#e8f5e9;color:#2e7d32}
.svc-status.fail{background:#fff0f0;color:#c0392b}
.svc-status.busy{background:#fff8e1;color:#b45309}
.btn-test{margin-top:.6rem;padding:.42rem .95rem;font-size:.82rem;font-weight:600;
          background:#f0f3f8;color:#286ee6;border:1.5px solid #c8d6ec;border-radius:8px;cursor:pointer}
.btn-test:hover{background:#e2eaf7}
.btn-done{width:100%;justify-content:center;padding:.65rem;margin-top:1.25rem;font-size:.95rem}
.btn-done:disabled{background:#b0c4de;cursor:not-allowed;opacity:.7}
.req-hint{font-size:.78rem;color:#6b7a99;margin-bottom:1.25rem}
</style>
</head>
<body>
<div class="card">
  <h1>Connect YalieMCP</h1>
  <p class="sub">Authorizing <strong>${escapeHtml(opts.clientName)}</strong> to access Yale data.</p>

  <div class="security">
    <strong>🔒 Your credentials are safe — here's exactly why</strong>
    <ul>
      <li><strong>AES-256-GCM encryption</strong> — the same standard used by banks and governments. Your cookies are encrypted before leaving this page and can only be decrypted by your personal token.</li>
      <li><strong>Zero storage</strong> — this server has no database, no logs, no disk writes. Nothing is retained between requests. Your data exists only for the milliseconds your query is running.</li>
      <li><strong>Per-user isolation</strong> — each token is encrypted with a unique key derived from a secret only this server knows. It is cryptographically impossible for one user's data to appear in another user's session.</li>
      <li><strong>Stateless by design</strong> — even if the server were breached, there is nothing to steal. All secrets travel inside your encrypted token, which lives only in your browser.</li>
    </ul>
  </div>

  ${opts.error ? `<div class="error">${escapeHtml(opts.error)}</div>` : ""}

  <p class="req-hint">Connect at least one service. Each service you connect unlocks additional tools.</p>

  <form method="POST" id="authform">
    <input type="hidden" name="_csrf"                 value="${escapeHtml(opts.csrf ?? "")}">
    <input type="hidden" name="response_type"        value="code">
    <input type="hidden" name="client_id"             value="${escapeHtml(opts.clientId)}">
    <input type="hidden" name="code_challenge"        value="${escapeHtml(opts.codeChallenge)}">
    <input type="hidden" name="code_challenge_method" value="S256">
    <input type="hidden" name="redirect_uri"          value="${escapeHtml(opts.redirectUri)}">
    ${opts.state ? `<input type="hidden" name="state" value="${escapeHtml(opts.state)}">` : ""}

    <!-- CourseTable -->
    <details ${opts.prefill?.coursetable_cookie ? "open" : ""}>
      <summary>
        <div class="num opt">1</div>
        <div style="flex:1;display:flex;align-items:center;gap:.5rem">
          <span class="step-title" style="margin:0">CourseTable</span>
          <span class="badge badge-unlocks">course search &amp; ratings</span>
          <span class="svc-status" id="st-ct" style="margin-left:auto">○ skipped</span>
        </div>
        <span class="chevron" style="margin-left:.5rem">▶</span>
      </summary>
      <div class="inner">
        <div class="step-desc" style="margin-bottom:.5rem">
          <a class="btn" href="https://api.coursetable.com/api/auth/cas" target="_blank" rel="noopener" style="margin-bottom:.6rem;display:inline-flex">
            Open CourseTable ↗
          </a>
          ${curlSteps()}
        </div>
        <textarea id="ta-ct" name="coursetable_cookie"
          placeholder="curl 'https://coursetable.com/…' -H 'cookie: connect.sid=s%3A…' …"
          autocomplete="off" spellcheck="false" style="min-height:80px">${escapeHtml(opts.prefill?.coursetable_cookie ?? "")}</textarea>
        <button type="button" class="btn-test" onclick="testSvc('coursetable')">Test connection</button>
      </div>
    </details>

    <!-- Canvas -->
    <details ${opts.prefill?.canvas_cookie ? "open" : ""}>
      <summary>
        <div class="num opt">2</div>
        <div style="flex:1;display:flex;align-items:center;gap:.5rem">
          <span class="step-title" style="margin:0">Canvas</span>
          <span class="badge badge-unlocks">syllabus content</span>
          <span class="svc-status" id="st-canvas" style="margin-left:auto">○ skipped</span>
        </div>
        <span class="chevron" style="margin-left:.5rem">▶</span>
      </summary>
      <div class="inner">
        <div class="step-desc" style="margin-bottom:.5rem">
          <a class="btn" href="https://yale.instructure.com/" target="_blank" rel="noopener" style="margin-bottom:.6rem;display:inline-flex">
            Open Canvas ↗
          </a>
          ${curlSteps()}
        </div>
        <textarea id="ta-canvas" name="canvas_cookie"
          placeholder="curl 'https://yale.instructure.com/…' -H 'cookie: _canvas_session=…' …"
          autocomplete="off" spellcheck="false" style="min-height:80px">${escapeHtml(opts.prefill?.canvas_cookie ?? "")}</textarea>
        <button type="button" class="btn-test" onclick="testSvc('canvas')">Test connection</button>
      </div>
    </details>

    <!-- Degree Audit -->
    <details ${opts.prefill?.audit_cookie ? "open" : ""}>
      <summary>
        <div class="num opt">3</div>
        <div style="flex:1;display:flex;align-items:center;gap:.5rem">
          <span class="step-title" style="margin:0">Degree Audit</span>
          <span class="badge badge-unlocks">degree progress</span>
          <span class="svc-status" id="st-audit" style="margin-left:auto">○ skipped</span>
        </div>
        <span class="chevron" style="margin-left:.5rem">▶</span>
      </summary>
      <div class="inner">
        <div class="step-desc" style="margin-bottom:.5rem">
          <a class="btn" href="https://degreeaudit.yale.edu" target="_blank" rel="noopener" style="margin-bottom:.6rem;display:inline-flex">
            Open Degree Audit ↗
          </a>
          ${curlSteps()}
        </div>
        <textarea id="ta-audit" name="audit_cookie"
          placeholder="curl 'https://degreeaudit.yale.edu/…' -H 'cookie: JSESSIONID=…' …"
          autocomplete="off" spellcheck="false" style="min-height:80px">${escapeHtml(opts.prefill?.audit_cookie ?? "")}</textarea>
        <button type="button" class="btn-test" onclick="testSvc('audit')">Test connection</button>
      </div>
    </details>

    <button type="submit" id="done-btn" class="btn btn-done" disabled>All done →</button>
  </form>

<script>
function extractCookie(raw) {
  var t = raw.trim();
  var m = t.match(/-H\\s+['"]cookie:\\s*([^'"]+)['"]/i);
  if (m) return m[1].trim();
  var b = t.match(/(?:-b|--cookie)\\s+['"]([^'"]+)['"]/i);
  if (b) return b[1].trim();
  return t.replace(/^cookie:\\s*/i,'').replace(/[\\r\\n]+/g,'; ').trim();
}
function setStatus(id, state, msg) {
  var el = document.getElementById(id);
  el.textContent = msg;
  el.className = 'svc-status' + (state ? ' '+state : '');
}
var connected = {};
function updateDoneBtn() {
  var anyOk = Object.values(connected).some(function(v){ return v; });
  document.getElementById('done-btn').disabled = !anyOk;
}
async function testSvc(svc) {
  var ids = {coursetable:['ta-ct','st-ct'], canvas:['ta-canvas','st-canvas'], audit:['ta-audit','st-audit']};
  var taId = ids[svc][0], stId = ids[svc][1];
  var raw = document.getElementById(taId).value.trim();
  if (!raw) { alert('Paste the cURL output first.'); return; }
  var cookie = extractCookie(raw);
  setStatus(stId, 'busy', '⟳ testing…');
  try {
    var r = await fetch('/test-connection', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({service:svc, cookie:cookie})
    });
    var d = await r.json();
    setStatus(stId, d.ok ? 'ok' : 'fail', d.ok ? '✓ connected' : '✗ '+(d.message||'failed'));
    connected[svc] = d.ok;
    updateDoneBtn();
  } catch(e) {
    setStatus(stId, 'fail', '✗ network error');
  }
}
document.getElementById('authform').addEventListener('submit', function() {
  ['ta-ct','ta-canvas','ta-audit'].forEach(function(id) {
    var ta = document.getElementById(id);
    if (ta && ta.value.trim()) ta.value = extractCookie(ta.value);
  });
});
// Mark pre-filled services as connected so the done button is enabled
(function() {
  var pre = {coursetable:${opts.prefill?.coursetable_cookie ? "true" : "false"},canvas:${opts.prefill?.canvas_cookie ? "true" : "false"},audit:${opts.prefill?.audit_cookie ? "true" : "false"}};
  var stIds = {coursetable:'st-ct',canvas:'st-canvas',audit:'st-audit'};
  Object.keys(pre).forEach(function(svc) {
    if (pre[svc]) { setStatus(stIds[svc],'ok','↩ pre-filled'); connected[svc]=true; }
  });
  updateDoneBtn();
})();
</script>
</div>
</body>
</html>`;
}

// ─── Express app ──────────────────────────────────────────────────────────────

export const app = express();
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "64kb" }));

// Security headers on every response
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Permitted-Cross-Domain-Policies", "none");
  res.setHeader("Referrer-Policy", "no-referrer");
  if (BASE_URL.startsWith("https://")) {
    res.setHeader("Strict-Transport-Security", "max-age=63072000; includeSubDomains");
  }
  next();
});

// General rate limit — all endpoints
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "too_many_requests" },
}));

// Auth rate limit — 15 attempts per 15 min
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "too_many_requests" },
});
app.use("/authorize", authLimiter);
app.use("/token", authLimiter);
app.use("/register", authLimiter);
app.use("/test-connection", authLimiter);

// OAuth routes: /.well-known/*, /authorize, /token, /register
app.use(
  mcpAuthRouter({
    provider,
    issuerUrl: new URL(BASE_URL),
    serviceDocumentationUrl: new URL("https://github.com/coursetable/coursetable"),
    resourceName: "YalieMCP",
  })
);

app.get("/", (_req, res) => {
  const mcpUrl = `${BASE_URL}/mcp`;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>YalieMCP — Yale AI Tools for Claude</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f4f5f7;
     color:#1a1a2e;min-height:100vh;padding:2rem 1rem}
.wrap{max-width:680px;margin:0 auto}
h1{font-size:2rem;font-weight:800;margin-bottom:.4rem}
.tagline{color:#555;font-size:1rem;margin-bottom:2.5rem}
.card{background:#fff;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.08);
      padding:2rem;margin-bottom:1.5rem}
.card h2{font-size:1.1rem;font-weight:700;margin-bottom:1rem;display:flex;align-items:center;gap:.5rem}
.step{display:flex;gap:1rem;margin-bottom:1.25rem;align-items:flex-start}
.step:last-child{margin-bottom:0}
.num{background:#286ee6;color:#fff;border-radius:50%;width:2rem;height:2rem;
     display:flex;align-items:center;justify-content:center;font-size:.85rem;
     font-weight:700;flex-shrink:0;margin-top:.1rem}
.step-body{flex:1}
.step-title{font-weight:600;font-size:.95rem;margin-bottom:.25rem}
.step-desc{font-size:.855rem;color:#555;line-height:1.6}
.url-box{display:flex;align-items:center;gap:.5rem;margin-top:.75rem;
          background:#f0f3f8;border:1.5px solid #d0d6e0;border-radius:8px;padding:.6rem .8rem}
.url-text{font-family:"SF Mono",Consolas,monospace;font-size:.82rem;color:#1a1a2e;
           flex:1;word-break:break-all}
.copy-btn{background:#286ee6;color:#fff;border:none;border-radius:6px;padding:.35rem .75rem;
           font-size:.78rem;font-weight:600;cursor:pointer;flex-shrink:0;transition:background .15s}
.copy-btn:hover{background:#1a5cc8}
.copy-btn.copied{background:#2e7d32}
.tools{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:.6rem;margin-top:.25rem}
.tool-chip{background:#f0f3f8;border-radius:8px;padding:.45rem .75rem;font-size:.8rem;color:#333;line-height:1.4}
.tool-chip strong{display:block;font-size:.78rem;color:#286ee6}
a{color:#286ee6;text-decoration:none}
a:hover{text-decoration:underline}
.badge{display:inline-block;font-size:.72rem;font-weight:600;padding:.15rem .5rem;
       border-radius:99px;background:#e8f5e9;color:#2e7d32;margin-left:.4rem}
footer{text-align:center;font-size:.8rem;color:#888;margin-top:2rem}
</style>
</head>
<body>
<div class="wrap">
  <h1>YalieMCP</h1>
  <p class="tagline">Yale course search, evaluations, worksheets, and degree audit — right inside Claude.</p>

  <div class="card">
    <h2>⚡ Connect to Claude</h2>

    <div class="step">
      <div class="num">1</div>
      <div class="step-body">
        <div class="step-title">Open Claude.ai → Settings → Integrations</div>
        <div class="step-desc">Go to <a href="https://claude.ai" target="_blank" rel="noopener">claude.ai</a>, click your avatar → <strong>Settings</strong> → <strong>Integrations</strong> → <strong>Add integration</strong>.</div>
      </div>
    </div>

    <div class="step">
      <div class="num">2</div>
      <div class="step-body">
        <div class="step-title">Paste the MCP server URL</div>
        <div class="step-desc">Copy the URL below and paste it into the integration URL field.</div>
        <div class="url-box">
          <span class="url-text" id="mcp-url">${escapeHtml(mcpUrl)}</span>
          <button class="copy-btn" id="copy-btn" onclick="copyUrl()">Copy</button>
        </div>
      </div>
    </div>

    <div class="step">
      <div class="num">3</div>
      <div class="step-body">
        <div class="step-title">Authorize with your Yale cookies</div>
        <div class="step-desc">Claude will open an authorization window. Follow the steps to connect CourseTable (required), Canvas, and Degree Audit. Each service unlocks additional tools.</div>
      </div>
    </div>

    <div class="step">
      <div class="num">4</div>
      <div class="step-body">
        <div class="step-title">Start chatting</div>
        <div class="step-desc">Ask Claude to search for courses, compare professors, check your degree audit, view your worksheet, and more.</div>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>🛠 Available Tools <span class="badge">19 tools</span></h2>
    <div class="tools">
      <div class="tool-chip"><strong>CourseTable</strong>Search &amp; filter courses</div>
      <div class="tool-chip"><strong>CourseTable</strong>Course evaluations &amp; ratings</div>
      <div class="tool-chip"><strong>CourseTable</strong>Compare courses side-by-side</div>
      <div class="tool-chip"><strong>CourseTable</strong>Professor search</div>
      <div class="tool-chip"><strong>CourseTable</strong>Your worksheet</div>
      <div class="tool-chip"><strong>CourseTable</strong>Friends' worksheets</div>
      <div class="tool-chip"><strong>CourseTable</strong>Wishlist management</div>
      <div class="tool-chip"><strong>CourseTable</strong>Course catalog metadata</div>
      <div class="tool-chip"><strong>Canvas</strong>Syllabus content</div>
      <div class="tool-chip"><strong>Degree Audit</strong>GPA &amp; degree progress</div>
      <div class="tool-chip"><strong>Degree Audit</strong>Major requirements</div>
    </div>
  </div>

  <div class="card">
    <h2>🔒 Privacy &amp; Security</h2>
    <div class="step-desc" style="line-height:1.8">
      YalieMCP is <strong>fully stateless</strong> — no database, no logs, no cookies stored on any server.
      Your Yale session cookies are encrypted with <strong>AES-256-GCM</strong> and travel only inside your personal access token.
      The server never retains anything between requests. Source code is available on
      <a href="https://github.com/evanwboyle/YalieMCP" target="_blank" rel="noopener">GitHub</a>.
    </div>
  </div>

  <footer>YalieMCP is an independent project and is not affiliated with Yale University or CourseTable.</footer>
</div>
<script>
function copyUrl() {
  var url = document.getElementById('mcp-url').textContent;
  navigator.clipboard.writeText(url).then(function() {
    var btn = document.getElementById('copy-btn');
    btn.textContent = 'Copied!';
    btn.classList.add('copied');
    setTimeout(function() { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
  });
}
</script>
</body>
</html>`);
});

app.get("/health", (_req, res) => res.json({ ok: true }));

// ─── Connection test (used by the auth page "Test connection" buttons) ────────

const VALID_SERVICES = new Set(["coursetable", "canvas", "audit"]);
const MAX_COOKIE_LEN = 8192;

app.post("/test-connection", async (req, res) => {
  const { service, cookie } = req.body as { service?: unknown; cookie?: unknown };
  if (typeof service !== "string" || typeof cookie !== "string") {
    res.json({ ok: false, message: "missing parameters" }); return;
  }
  if (!VALID_SERVICES.has(service)) {
    res.json({ ok: false, message: "unknown service" }); return;
  }
  if (cookie.length > MAX_COOKIE_LEN) {
    res.json({ ok: false, message: "cookie value too large" }); return;
  }

  try {
    if (service === "coursetable") {
      const valid = await validateCookie(cookie);
      res.json({ ok: valid, message: valid ? "connected" : "cookie invalid or expired" });

    } else if (service === "canvas") {
      const r = await fetch("https://yale.instructure.com/api/v1/users/self", {
        headers: { "Cookie": cookie, "User-Agent": "yalie-mcp/1.0", "Accept": "application/json" },
        signal: AbortSignal.timeout(10000),
      });
      const ok = r.status === 200;
      res.json({ ok, message: ok ? "connected" : "canvas cookie invalid or expired" });

    } else if (service === "audit") {
      const r = await fetch("https://degreeaudit.yale.edu/responsive/api/users/myself", {
        headers: { "Cookie": cookie, "User-Agent": "Mozilla/5.0 (compatible; yalie-mcp/1.0)", "Accept": "application/json" },
        signal: AbortSignal.timeout(10000),
      });
      const ok = r.status === 200;
      res.json({ ok, message: ok ? "connected" : "degree audit cookie invalid or expired" });

    }
  } catch {
    res.json({ ok: false, message: "connection test failed" });
  }
});

// ─── MCP endpoint (stateless — works on Vercel serverless) ───────────────────

// Token-keyed rate limiter: 120 req/min per access token (keyed by token hash)
const mcpLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "too_many_requests" },
  keyGenerator: (req: Request) => {
    // Hash the bearer token so the key is fixed-length and doesn't log the secret
    const auth = req.headers.authorization ?? "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : auth;
    return crypto.createHash("sha256").update(token).digest("hex").slice(0, 16);
  },
});

app.all(
  "/mcp",
  mcpLimiter,
  requireBearerAuth({ verifier: provider }),
  async (req, res) => {
    const p = unseal<AccessPayload>(req.auth!.token);
    if (!p || p.type !== "access" || p.exp < now()) {
      res.status(401).json({ error: "invalid_token" });
      return;
    }

    // Stateless: new server per request (no session IDs)
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });
    const mcpServer = new McpServer({ name: "yalie", version: "1.0.0" });
    registerTools(mcpServer, p.coursetable_cookie ?? null, p.canvas_cookie, p.audit_cookie);
    await mcpServer.connect(transport);
    await transport.handleRequest(req, res, req.body);
  }
);

// ─── Local entry point ────────────────────────────────────────────────────────

// Only listen when run directly (not when imported by Vercel)
if (process.env.NODE_ENV !== "production" || process.env.START_SERVER === "1") {
  app.listen(PORT, () => {
    console.log(`YalieMCP listening on port ${PORT}`);
    console.log(`  MCP:    ${BASE_URL}/mcp`);
    console.log(`  OAuth:  ${BASE_URL}/authorize`);
  });
}
