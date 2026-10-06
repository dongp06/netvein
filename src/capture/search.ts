import * as fs from "node:fs";
import * as path from "node:path";
import type { SearchMatch } from "./types.js";

function makeSnippet(text: string, matchIdx: number, matchLen: number, contextRadius = 40): string {
  const start = Math.max(0, matchIdx - contextRadius);
  const end = Math.min(text.length, matchIdx + matchLen + contextRadius);
  const pre = start > 0 ? "..." : "";
  const post = end < text.length ? "..." : "";
  return pre + text.slice(start, end).replace(/[\r\n]+/g, " ") + post;
}

export function searchCaptures(options: {
  rootDir: string;
  query: string;
  sessionId?: string;
  limit?: number;
  isRegex?: boolean;
}): SearchMatch[] {
  const query = options.query.trim();
  if (!query) return [];

  const limit = Math.min(Math.max(options.limit ?? 30, 1), 200);
  const pattern = options.isRegex ? new RegExp(query, "i") : null;
  const lowerQuery = query.toLowerCase();

  const searchFiles: Array<{ sessionId: string; flowsPath: string }> = [];
  const baseDir = path.join(options.rootDir, ".netvein", "captures");
  const fallbackDir = path.join(options.rootDir, "captures");

  const candidatesDirs = [baseDir, fallbackDir];
  for (const cDir of candidatesDirs) {
    if (!fs.existsSync(cDir)) continue;
    try {
      const entries = fs.readdirSync(cDir);
      for (const entry of entries) {
        if (options.sessionId && entry !== options.sessionId) continue;
        const sub = path.join(cDir, entry);
        if (fs.statSync(sub).isDirectory()) {
          const flowsFile = path.join(sub, "flows.jsonl");
          if (fs.existsSync(flowsFile)) {
            searchFiles.push({ sessionId: entry, flowsPath: flowsFile });
          }
        }
      }
    } catch {}
  }

  // Also check direct .netvein/capture/ (standalone traffic flow files)
  const autoCaptureDir = path.join(options.rootDir, ".netvein", "capture");
  if (fs.existsSync(autoCaptureDir)) {
    try {
      const entries = fs.readdirSync(autoCaptureDir);
      for (const entry of entries) {
        if (entry.endsWith(".jsonl")) {
          searchFiles.push({ sessionId: "auto-capture", flowsPath: path.join(autoCaptureDir, entry) });
        }
      }
    } catch {}
  }

  const matches: SearchMatch[] = [];

  for (const sf of searchFiles) {
    if (matches.length >= limit) break;
    try {
      const content = fs.readFileSync(sf.flowsPath, "utf8");
      const lines = content.split(/\r?\n/);

      for (const line of lines) {
        if (!line.trim() || matches.length >= limit) continue;
        let flow: any;
        try {
          flow = JSON.parse(line);
        } catch {
          continue;
        }

        const flowId = flow.id || flow.summary?.id || "unknown";
        const method = flow.method || flow.summary?.method || "";
        const url = flow.url || flow.summary?.url || flow.request?.url || "";
        const status = flow.status_code || flow.summary?.status || flow.response?.status || null;

        // 1. Check URL
        const urlIdx = pattern ? url.search(pattern) : url.toLowerCase().indexOf(lowerQuery);
        if (urlIdx !== -1) {
          matches.push({
            sessionId: sf.sessionId,
            flowId,
            method,
            url,
            status,
            matchIn: "url",
            snippet: makeSnippet(url, urlIdx, query.length),
          });
          continue;
        }

        // 2. Check Request/Response Headers
        const headersStr = JSON.stringify({
          req: flow.headers || flow.request?.headers,
          res: flow.response?.headers,
        });
        const hIdx = pattern ? headersStr.search(pattern) : headersStr.toLowerCase().indexOf(lowerQuery);
        if (hIdx !== -1) {
          matches.push({
            sessionId: sf.sessionId,
            flowId,
            method,
            url,
            status,
            matchIn: "header",
            snippet: makeSnippet(headersStr, hIdx, query.length),
          });
          continue;
        }

        // 3. Check inline body
        const reqBody = flow.request?.body || flow.body?.sample?.text || "";
        const reqStr = typeof reqBody === "string" ? reqBody : JSON.stringify(reqBody);
        const reqIdx = pattern ? reqStr.search(pattern) : reqStr.toLowerCase().indexOf(lowerQuery);
        if (reqIdx !== -1) {
          matches.push({
            sessionId: sf.sessionId,
            flowId,
            method,
            url,
            status,
            matchIn: "request_body",
            snippet: makeSnippet(reqStr, reqIdx, query.length),
          });
          continue;
        }

        const resBody = flow.response?.body || "";
        const resStr = typeof resBody === "string" ? resBody : JSON.stringify(resBody);
        const resIdx = pattern ? resStr.search(pattern) : resStr.toLowerCase().indexOf(lowerQuery);
        if (resIdx !== -1) {
          matches.push({
            sessionId: sf.sessionId,
            flowId,
            method,
            url,
            status,
            matchIn: "response_body",
            snippet: makeSnippet(resStr, resIdx, query.length),
          });
        }
      }
    } catch {}
  }

  return matches;
}
