#!/usr/bin/env node
/**
 * YalieMCP stdio entry point — for local use with Claude Desktop.
 * For remote/OAuth use, see src/server.ts.
 *
 * At least one of the following env vars is required:
 *   COURSETABLE_COOKIE — Cookie header from coursetable.com (unlocks course search/ratings)
 *   CANVAS_COOKIE      — Cookie header from yale.instructure.com (unlocks syllabus content)
 *   AUDIT_COOKIE       — Cookie header from degreeaudit.yale.edu (unlocks degree audit)
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerTools } from "./tools.js";

const coursetableCookie = process.env.COURSETABLE_COOKIE ?? null;
const canvasCookie      = process.env.CANVAS_COOKIE      ?? null;
const auditCookie       = process.env.AUDIT_COOKIE       ?? null;

if (!coursetableCookie && !canvasCookie && !auditCookie) {
  console.error(
    "Error: at least one cookie env var is required.\n" +
    "  COURSETABLE_COOKIE — from DevTools on coursetable.com\n" +
    "  CANVAS_COOKIE      — from DevTools on yale.instructure.com\n" +
    "  AUDIT_COOKIE       — from DevTools on degreeaudit.yale.edu"
  );
  process.exit(1);
}

const server = new McpServer({ name: "yalie", version: "1.0.0" });
registerTools(server, coursetableCookie, canvasCookie, auditCookie);

const transport = new StdioServerTransport();
await server.connect(transport);
console.error("YalieMCP server running on stdio");
