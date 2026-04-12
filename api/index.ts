// Vercel serverless entry point — wraps the Express app in an explicit handler
// so Vercel's runtime validator recognises it as a callable function.
import type { IncomingMessage, ServerResponse } from "node:http";
import { app } from "../src/server.js";

export default function handler(req: IncomingMessage, res: ServerResponse): void {
  app(req as any, res as any);
}
