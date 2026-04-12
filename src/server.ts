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
const BASE_URL = (process.env.BASE_URL ?? `http://localhost:${PORT}`).trim().replace(/\/$/, "");
const DEFAULT_SECRET = "dev-secret-please-change-in-production";
const TOKEN_SECRET = process.env.TOKEN_SECRET ?? DEFAULT_SECRET;

if (TOKEN_SECRET === DEFAULT_SECRET && process.env.NODE_ENV !== "production") {
  console.warn("Warning: TOKEN_SECRET not set — using insecure default. Never deploy this way.");
}
// In production, missing TOKEN_SECRET is caught at request time (below) so the
// module loads cleanly and Vercel can find the exported handler.
function assertSecretConfigured(): void {
  if (TOKEN_SECRET === DEFAULT_SECRET && process.env.NODE_ENV === "production") {
    throw new Error("TOKEN_SECRET env var must be set in production.");
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
    assertSecretConfigured();
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
      res.redirect(303, url.toString());
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
.step-desc{font-size:.84rem;color:#555;line-height:1.6}
.badge-unlocks{display:inline-block;font-size:.7rem;font-weight:600;letter-spacing:.03em;
               padding:.1rem .45rem;border-radius:99px;background:#e8f5e9;color:#2e7d32;
               vertical-align:middle}
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
.svc-tabs{display:flex;gap:.5rem;margin-bottom:.75rem}
.svc-tab{flex:1;padding:.45rem .5rem;border:1.5px solid #d0d6e0;border-radius:8px;
         background:#f8f9fb;color:#555;font-size:.8rem;font-weight:600;cursor:pointer;
         display:flex;flex-direction:column;align-items:center;gap:.2rem;
         transition:border-color .15s,color .15s}
.svc-tab:hover{border-color:#286ee6;color:#286ee6}
.svc-tab.active{background:#286ee6;color:#fff;border-color:#286ee6}
.tab-label{font-size:.8rem}
.tab-status{font-size:.68rem;font-weight:700;opacity:.8}
.svc-tab.active .tab-status{opacity:.9}
.svc-panel{border:1.5px solid #d0d6e0;border-radius:10px;padding:1rem 1.1rem;margin-bottom:.5rem}
.svc-panel-header{display:flex;align-items:center;gap:.5rem;margin-bottom:.75rem}
.svc-status{font-size:.75rem;font-weight:700;padding:.2rem .55rem;border-radius:99px;
            white-space:nowrap;background:#f0f3f8;color:#6b7a99}
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

  <p class="req-hint">Connect at least one service. Each one you add unlocks more tools.</p>

  <form method="POST" id="authform">
    <input type="hidden" name="_csrf"                 value="${escapeHtml(opts.csrf ?? "")}">
    <input type="hidden" name="response_type"        value="code">
    <input type="hidden" name="client_id"             value="${escapeHtml(opts.clientId)}">
    <input type="hidden" name="code_challenge"        value="${escapeHtml(opts.codeChallenge)}">
    <input type="hidden" name="code_challenge_method" value="S256">
    <input type="hidden" name="redirect_uri"          value="${escapeHtml(opts.redirectUri)}">
    ${opts.state ? `<input type="hidden" name="state" value="${escapeHtml(opts.state)}">` : ""}

    <!-- Service selector tabs -->
    <div class="svc-tabs">
      <button type="button" class="svc-tab active" data-svc="coursetable" onclick="selectSvc('coursetable')">
        <span class="tab-label">CourseTable</span>
        <span class="tab-status" id="ts-ct">○ skipped</span>
      </button>
      <button type="button" class="svc-tab" data-svc="canvas" onclick="selectSvc('canvas')">
        <span class="tab-label">Canvas</span>
        <span class="tab-status" id="ts-canvas">○ skipped</span>
      </button>
      <button type="button" class="svc-tab" data-svc="audit" onclick="selectSvc('audit')">
        <span class="tab-label">Degree Audit</span>
        <span class="tab-status" id="ts-audit">○ skipped</span>
      </button>
    </div>

    <!-- Shared instruction panel -->
    <div class="svc-panel">
      <div class="svc-panel-header">
        <span style="font-weight:600;font-size:.95rem" id="panel-title">CourseTable</span>
        <span class="badge-unlocks" id="panel-unlocks">course search &amp; ratings</span>
        <span class="svc-status" id="panel-status" style="margin-left:auto">○ skipped</span>
      </div>
      <ol class="step-desc">
        <li>Log in at <a id="inst-login" href="#" target="_blank" rel="noopener"></a></li>
        <li>Open <a id="inst-check" href="#" target="_blank" rel="noopener"></a> — <span id="inst-hint"></span></li>
        <li>Open DevTools <code>F12</code> / <code>Cmd ⌥ I</code> → <strong>Network</strong> tab → reload the page</li>
        <li>Right-click <code id="inst-req"></code> → <strong>Copy</strong> → <strong>Copy as cURL</strong></li>
        <li>Paste below and click <strong>Test connection</strong></li>
      </ol>
      <!-- One textarea per service; only the active one is visible -->
      <textarea id="ta-ct"     name="coursetable_cookie" autocomplete="off" spellcheck="false"
        placeholder="curl 'https://api.coursetable.com/api/auth/check' -H 'cookie: connect.sid=s%3A…' …"
        >${escapeHtml(opts.prefill?.coursetable_cookie ?? "")}</textarea>
      <textarea id="ta-canvas" name="canvas_cookie"      autocomplete="off" spellcheck="false" style="display:none"
        placeholder="curl 'https://yale.instructure.com/api/v1/conversations/unread_count' -H 'cookie: _canvas_session=…' …"
        >${escapeHtml(opts.prefill?.canvas_cookie ?? "")}</textarea>
      <textarea id="ta-audit"  name="audit_cookie"       autocomplete="off" spellcheck="false" style="display:none"
        placeholder="curl 'https://degreeaudit.yale.edu/responsive/api/users/myself' -H 'cookie: JSESSIONID=…' …"
        >${escapeHtml(opts.prefill?.audit_cookie ?? "")}</textarea>
      <button type="button" class="btn-test" onclick="testActiveSvc()">Test connection</button>
    </div>

    <button type="submit" id="done-btn" class="btn btn-done" disabled>All done →</button>
  </form>

<script>
var SVC = {
  coursetable: {
    title: 'CourseTable', unlocks: 'course search &amp; ratings',
    loginUrl: 'https://coursetable.com/worksheet', loginLabel: 'coursetable.com/worksheet',
    checkUrl: 'https://api.coursetable.com/api/auth/check', checkLabel: 'api.coursetable.com/api/auth/check',
    reqName: 'check', hint: 'shows your name when logged in',
    taId: 'ta-ct', tsId: 'ts-ct'
  },
  canvas: {
    title: 'Canvas', unlocks: 'syllabus content',
    loginUrl: 'https://yale.instructure.com/', loginLabel: 'yale.instructure.com',
    checkUrl: 'https://yale.instructure.com/api/v1/conversations/unread_count',
    checkLabel: 'yale.instructure.com/api/v1/conversations/unread_count',
    reqName: 'unread_count', hint: 'shows {"unread_count":"0"} when logged in',
    taId: 'ta-canvas', tsId: 'ts-canvas'
  },
  audit: {
    title: 'Degree Audit', unlocks: 'degree progress',
    loginUrl: 'https://degreeaudit.yale.edu/responsive/', loginLabel: 'degreeaudit.yale.edu/responsive',
    checkUrl: 'https://degreeaudit.yale.edu/responsive/api/users/myself',
    checkLabel: 'degreeaudit.yale.edu/responsive/api/users/myself',
    reqName: 'myself', hint: 'shows your name and student info',
    taId: 'ta-audit', tsId: 'ts-audit'
  }
};
var activeSvc = 'coursetable';
var connected = {};

function extractCookie(raw) {
  var t = raw.trim();
  var m = t.match(/-H\\s+['"]cookie:\\s*([^'"\\\\]+)['"]/i);
  if (m) return m[1].trim();
  var b = t.match(/(?:-b|--cookie)\\s+['"]([^'"]+)['"]/i);
  if (b) return b[1].trim();
  return t.replace(/^cookie:\\s*/i,'').replace(/[\\r\\n]+/g,'; ').trim();
}

function setTabStatus(svc, state, msg) {
  var el = document.getElementById(SVC[svc].tsId);
  el.textContent = msg;
  // also update panel status if this svc is active
  if (svc === activeSvc) {
    var ps = document.getElementById('panel-status');
    ps.textContent = msg;
    ps.className = 'svc-status' + (state ? ' '+state : '');
  }
}

function updateDoneBtn() {
  var anyOk = Object.values(connected).some(function(v){ return v; });
  document.getElementById('done-btn').disabled = !anyOk;
}

function selectSvc(svc) {
  activeSvc = svc;
  var d = SVC[svc];
  // update tabs
  document.querySelectorAll('.svc-tab').forEach(function(t) {
    t.classList.toggle('active', t.dataset.svc === svc);
  });
  // update panel header
  document.getElementById('panel-title').textContent = d.title;
  document.getElementById('panel-unlocks').innerHTML = d.unlocks;
  // update panel status from current connection state
  var ps = document.getElementById('panel-status');
  var tsEl = document.getElementById(d.tsId);
  ps.textContent = tsEl.textContent;
  ps.className = 'svc-status' + (connected[svc] === true ? ' ok' : connected[svc] === false ? ' fail' : '');
  // update instruction links
  document.getElementById('inst-login').href = d.loginUrl;
  document.getElementById('inst-login').textContent = d.loginLabel;
  document.getElementById('inst-check').href = d.checkUrl;
  document.getElementById('inst-check').textContent = d.checkLabel;
  document.getElementById('inst-hint').textContent = d.hint;
  document.getElementById('inst-req').textContent = d.reqName;
  // swap textarea visibility
  Object.values(SVC).forEach(function(s) {
    document.getElementById(s.taId).style.display = s.taId === d.taId ? '' : 'none';
  });
}

async function testActiveSvc() {
  var d = SVC[activeSvc];
  var raw = document.getElementById(d.taId).value.trim();
  if (!raw) { alert('Paste the cURL output first.'); return; }
  var cookie = extractCookie(raw);
  setTabStatus(activeSvc, 'busy', '⟳ testing…');
  try {
    var r = await fetch('/test-connection', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({service:activeSvc, cookie:cookie})
    });
    var dd = await r.json();
    var ok = dd.ok;
    connected[activeSvc] = ok;
    setTabStatus(activeSvc, ok ? 'ok' : 'fail', ok ? '✓ connected' : '✗ '+(dd.message||'failed'));
    updateDoneBtn();
  } catch(e) {
    connected[activeSvc] = false;
    setTabStatus(activeSvc, 'fail', '✗ network error');
  }
}

document.getElementById('authform').addEventListener('submit', function() {
  ['ta-ct','ta-canvas','ta-audit'].forEach(function(id) {
    var ta = document.getElementById(id);
    if (ta && ta.value.trim()) ta.value = extractCookie(ta.value);
  });
});

// Init: select first pre-filled service (or default to coursetable), mark pre-filled as connected
(function() {
  var pre = {coursetable:${opts.prefill?.coursetable_cookie ? "true" : "false"},canvas:${opts.prefill?.canvas_cookie ? "true" : "false"},audit:${opts.prefill?.audit_cookie ? "true" : "false"}};
  var firstPre = null;
  Object.keys(pre).forEach(function(svc) {
    if (pre[svc]) {
      connected[svc] = true;
      setTabStatus(svc, 'ok', '↩ pre-filled');
      if (!firstPre) firstPre = svc;
    }
  });
  selectSvc(firstPre || 'coursetable');
  updateDoneBtn();
})();
</script>
</div>
</body>
</html>`;
}

// ─── Express app ──────────────────────────────────────────────────────────────

export const app: ReturnType<typeof express> = express();
// Trust Vercel's reverse proxy so req.ip and rate-limit key correctly
app.set("trust proxy", 1);
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
.compat-strip{display:flex;align-items:center;gap:.6rem;margin-bottom:1rem;flex-wrap:wrap}
.compat-label{font-size:.78rem;color:#888;font-weight:500;margin-right:.2rem}
.compat-logo{width:20px;height:20px;border-radius:4px;opacity:.7;filter:grayscale(30%)}
.compat-more{font-size:.75rem;color:#aaa;font-style:italic}
.demo-pills{display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem}
.demo-pill{background:#fff;border:1.5px solid #d0d6e0;border-radius:99px;padding:.35rem .85rem;
           font-size:.8rem;font-weight:500;color:#444;cursor:pointer;transition:all .15s;white-space:nowrap}
.demo-pill:hover{border-color:#286ee6;color:#286ee6}
.demo-pill.active{background:#286ee6;border-color:#286ee6;color:#fff}
.chat-window{background:#f8f9fb;border:1.5px solid #e4e7ed;border-radius:12px;
             height:300px;overflow-y:auto;padding:1rem;display:flex;flex-direction:column;gap:.75rem}
.chat-msg{max-width:85%;line-height:1.55;font-size:.855rem;padding:.6rem .9rem;border-radius:14px;white-space:pre-wrap}
.chat-msg.user{align-self:flex-end;background:#286ee6;color:#fff;border-bottom-right-radius:4px}
.chat-msg.assistant{align-self:flex-start;background:#fff;border:1.5px solid #e4e7ed;
                    color:#1a1a2e;border-bottom-left-radius:4px}
.typing-dots{display:inline-flex;gap:4px;align-items:center;padding:.6rem .9rem}
.typing-dots span{width:7px;height:7px;background:#aaa;border-radius:50%;
                  animation:dot-bounce .9s infinite ease-in-out}
.typing-dots span:nth-child(2){animation-delay:.15s}
.typing-dots span:nth-child(3){animation-delay:.3s}
@keyframes dot-bounce{0%,80%,100%{transform:scale(.8);opacity:.5}40%{transform:scale(1.1);opacity:1}}
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
        <div class="step-title">Open Claude.ai Connectors</div>
        <div class="step-desc">Go to <a href="https://claude.ai/customize/connectors" target="_blank" rel="noopener">claude.ai/customize/connectors</a>, click <strong>+</strong> → <strong>Add a custom connection</strong>.</div>
      </div>
    </div>

    <div class="step">
      <div class="num">2</div>
      <div class="step-body">
        <div class="step-title">Paste the MCP server URL</div>
        <div class="step-desc">Copy the URL below and paste it into the connection URL field.</div>
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

  <div class="card" id="demo-card">
    <h2>💬 See It in Action</h2>
    <div class="compat-strip">
      <span class="compat-label">Works with</span>
      <img src="https://claude.ai/favicon.ico" class="compat-logo" title="Claude" alt="Claude">
      <img src="https://chat.openai.com/favicon.ico" class="compat-logo" title="ChatGPT" alt="ChatGPT">
      <img src="https://cursor.sh/favicon.ico" class="compat-logo" title="Cursor" alt="Cursor">
      <img src="https://codeium.com/favicon.ico" class="compat-logo" title="Windsurf" alt="Windsurf">
      <span class="compat-more">+ any MCP client</span>
    </div>
    <div class="demo-pills" id="demo-pills">
      <button class="demo-pill active" data-idx="0">Find gut CS courses</button>
      <button class="demo-pill" data-idx="1">Compare two courses</button>
      <button class="demo-pill" data-idx="2">Search a professor</button>
      <button class="demo-pill" data-idx="3">CS major requirements</button>
      <button class="demo-pill" data-idx="4">What tools do you have?</button>
    </div>
    <div class="chat-window" id="chat-window"></div>
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

// ── Demo chat ──────────────────────────────────────────────────────────────
var demoScenarios = [
  {
    prompt: "Find me some gut CS courses for spring 2025",
    response: "Here are some well-rated, lower-workload CS courses for Spring 2025:\\n\\n• CPSC 100 — Beyond Silicon: Tech & Society\\n  Rating: 4.3 · Workload: 1.8 · Prof: Joan Feigenbaum\\n\\n• CPSC 112 — Introduction to Programming\\n  Rating: 4.5 · Workload: 2.4 · Prof: Benedict Brown\\n\\n• CPSC 150 — Computing and the Arts\\n  Rating: 4.1 · Workload: 2.1 · Prof: Holly Rushmeier\\n\\nAll three satisfy the QR distributional requirement and have strong evaluations."
  },
  {
    prompt: "Compare CPSC 365 and CPSC 366",
    response: "Here's a side-by-side comparison:\\n\\n          CPSC 365       CPSC 366\\nRating    4.1 / 5        3.8 / 5\\nWorkload  3.9 / 5        4.2 / 5\\nProf      Dana Angluin   Yang Cai\\nCredits   1.0            1.0\\nSchedule  TTh 1:00pm     MW 2:30pm\\n\\nVerdict: CPSC 365 edges out on both rating and workload. CPSC 366 digs deeper into algorithmic game theory — worth it if that's your focus, but expect heavier problem sets."
  },
  {
    prompt: "Tell me about Professor Amin Karbasi",
    response: "Amin Karbasi — Associate Professor of Electrical Engineering\\n\\nAverage rating: 4.6 / 5\\nRecent courses:\\n• CPSC 474 — Computational Intelligence for Games (Sp 2025)\\n• CPSC 575 — Computational Vision and Biological Perception (Fa 2024)\\n• EENG 439 — Active Learning, Optimization & Bandits (Fa 2024)\\n\\nStudents praise his clear explanations and genuine enthusiasm. Workload is substantial but fair. Office hours are consistently helpful."
  },
  {
    prompt: "What are the requirements for the Computer Science major?",
    response: "Computer Science (B.S.) — Core Requirements:\\n\\n• CPSC 201 — Introduction to Computer Science\\n• CPSC 223 — Data Structures & Programming Techniques\\n• CPSC 323 — Systems Programming & Computer Organization\\n• CPSC 365 or 366 — Algorithms\\n• CPSC 468 or 469 — Computational Complexity or Randomized Algorithms\\n• Senior Requirement: CPSC 490 (Senior Project) or approved 400-level sequence\\n\\nDistributionals: 3 additional CPSC courses at 300+ level covering at least 2 of: Systems, Theory, AI/ML, Applications.\\n\\nGPA requirement: 2.0 in major courses."
  },
  {
    prompt: "What tools do you have?",
    response: "I have 19 tools across 5 categories:\\n\\nCourse Discovery\\n• search_courses — filter by subject, rating, workload, area\\n• get_course / get_course_by_code — full course details\\n• compare_courses — side-by-side comparison\\n• list_seasons — all available semesters\\n\\nEvaluations\\n• get_course_evaluations — AI summaries + student comments\\n• get_evaluation_ratings — quantitative score distributions\\n\\nProfessors\\n• search_professors — ratings & teaching history\\n\\nPersonal Data\\n• get_degree_audit — GPA & requirement progress\\n• get_syllabus_content — Canvas syllabus text\\n• get_worksheets / get_wishlist — your CourseTable lists\\n\\nMajors & Catalog\\n• list_majors / get_major_requirements\\n• list_certificates / get_curriculum_info"
  }
];

var streamTimer = null;
var pendingTimeout = null;

function runDemo(idx) {
  // Cancel any in-progress timers
  if (pendingTimeout) { clearTimeout(pendingTimeout); pendingTimeout = null; }
  if (streamTimer) { clearInterval(streamTimer); streamTimer = null; }

  // Update active pill
  var pills = document.querySelectorAll('.demo-pill');
  pills.forEach(function(p) { p.classList.remove('active'); });
  pills[idx].classList.add('active');

  var scenario = demoScenarios[idx];
  var chatWin = document.getElementById('chat-window');

  // Clear and add user bubble directly into chat-window (flex container)
  chatWin.innerHTML = '';
  var userBubble = document.createElement('div');
  userBubble.className = 'chat-msg user';
  userBubble.textContent = scenario.prompt;
  chatWin.appendChild(userBubble);

  // Show typing indicator
  var typingEl = document.createElement('div');
  typingEl.className = 'chat-msg assistant';
  typingEl.innerHTML = '<div class="typing-dots"><span></span><span></span><span></span></div>';
  chatWin.appendChild(typingEl);
  chatWin.scrollTop = chatWin.scrollHeight;

  // After short delay, stream response
  pendingTimeout = setTimeout(function() {
    pendingTimeout = null;
    if (typingEl.parentNode === chatWin) chatWin.removeChild(typingEl);
    var assistantBubble = document.createElement('div');
    assistantBubble.className = 'chat-msg assistant';
    assistantBubble.textContent = '';
    chatWin.appendChild(assistantBubble);

    var text = scenario.response;
    var i = 0;
    var chunkSize = 3;
    streamTimer = setInterval(function() {
      if (i >= text.length) {
        clearInterval(streamTimer);
        streamTimer = null;
        return;
      }
      assistantBubble.textContent += text.slice(i, i + chunkSize);
      i += chunkSize;
      chatWin.scrollTop = chatWin.scrollHeight;
    }, 18);
  }, 600);
}

// Wire up pills
document.querySelectorAll('.demo-pill').forEach(function(pill) {
  pill.addEventListener('click', function() {
    runDemo(parseInt(this.getAttribute('data-idx')));
  });
});

// Auto-run first scenario on load
runDemo(0);
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
  validate: { xForwardedForHeader: false, forwardedHeader: false },
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
  (req, res, next) => {
    if (!req.headers.authorization) {
      res.redirect(302, "/");
      return;
    }
    next();
  },
  requireBearerAuth({ verifier: provider }),
  async (req, res) => {
    assertSecretConfigured();
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

// Default export so Vercel's runtime validates this module as a valid
// serverless function entry regardless of how it resolves the import chain.
import type { IncomingMessage, ServerResponse } from "node:http";
export default function handler(req: IncomingMessage, res: ServerResponse): void {
  (app as unknown as (req: IncomingMessage, res: ServerResponse) => void)(req, res);
}
