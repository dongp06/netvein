import { parse } from "acorn";
import * as walk from "acorn-walk";
import type { AnticrawlMatch, CryptoCandidate, CryptoMatch } from "./types.js";

export interface AstPattern {
  nodeType?: string;
  callee?: string;
  operator?: string;
  literal?: string;
  containsCalls?: string[];
  containsOperators?: string[];
}

export interface AstMatch {
  nodeType: string;
  start: number;
  end: number;
  line: number;
  column: number;
  snippet: string;
  callee?: string;
  operator?: string;
  literal?: unknown;
}

export interface AstSearchResult {
  matches: AstMatch[];
  parseError?: string;
}

export interface TextMatch {
  start: number;
  end: number;
  line: number;
  column: number;
  snippet: string;
}

function calleeName(node: any): string | undefined {
  if (!node) return undefined;
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression" || node.type === "OptionalMemberExpression") {
    if (!node.computed && node.property?.type === "Identifier") return node.property.name;
    if (node.computed && node.property?.type === "Literal") return String(node.property.value);
  }
  return undefined;
}

function isFunctionNode(node: any): boolean {
  return ["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression", "ObjectMethod", "ClassMethod"].includes(node.type);
}

function matchesNode(node: any, pattern: AstPattern, source: string): boolean {
  if (pattern.nodeType) {
    const wantsFunction = pattern.nodeType.toLowerCase() === "function";
    if (wantsFunction ? !isFunctionNode(node) : node.type !== pattern.nodeType) return false;
  }
  if (pattern.callee && calleeName(node.callee) !== pattern.callee) return false;
  if (pattern.operator && node.operator !== pattern.operator) return false;
  if (pattern.literal !== undefined) {
    if (node.type !== "Literal" || !String(node.value).includes(pattern.literal)) return false;
  }
  if (pattern.containsCalls?.length) {
    if (!isFunctionNode(node)) return false;
    const wanted = new Set(pattern.containsCalls);
    let found = false;
    walk.full(node, (child: any) => {
      if (child.type === "CallExpression" && wanted.has(calleeName(child.callee) ?? "")) found = true;
    });
    if (!found) return false;
  }
  if (pattern.containsOperators?.length) {
    if (!isFunctionNode(node)) return false;
    const wanted = new Set(pattern.containsOperators);
    let found = false;
    walk.full(node, (child: any) => {
      if ((child.type === "BinaryExpression" || child.type === "LogicalExpression" || child.type === "AssignmentExpression") && wanted.has(child.operator)) found = true;
    });
    if (!found) return false;
  }
  return Boolean(
    pattern.nodeType ||
    pattern.callee ||
    pattern.operator ||
    pattern.literal !== undefined ||
    pattern.containsCalls?.length ||
    pattern.containsOperators?.length ||
    source,
  );
}

export function searchAst(source: string, pattern: AstPattern, maxMatches = 100): AstSearchResult {
  let ast: any;
  try {
    try {
      ast = parse(source, { ecmaVersion: "latest", sourceType: "module", locations: true, allowHashBang: true });
    } catch (_) {
      ast = parse(source, { ecmaVersion: "latest", sourceType: "script", locations: true, allowHashBang: true });
    }
  } catch (error) {
    return { matches: [], parseError: error instanceof Error ? error.message : String(error) };
  }

  const matches: AstMatch[] = [];
  walk.full(ast, (node: any) => {
    if (matches.length >= maxMatches || !node?.type || node.start === undefined || node.end === undefined) return;
    if (!matchesNode(node, pattern, source)) return;
    matches.push({
      nodeType: node.type,
      start: node.start,
      end: node.end,
      line: (node.loc?.start.line ?? 1) - 1,
      column: node.loc?.start.column ?? 0,
      snippet: source.slice(node.start, Math.min(node.end, node.start + 1_500)),
      callee: calleeName(node.callee),
      operator: node.operator,
      literal: node.type === "Literal" ? node.value : undefined,
    });
  });
  return { matches, parseError: undefined };
}

export function findTextMatches(source: string, pattern: string, regex = false, maxMatches = 100): TextMatch[] {
  const matches: TextMatch[] = [];
  if (!regex) {
    let offset = 0;
    while (matches.length < maxMatches) {
      const start = source.indexOf(pattern, offset);
      if (start < 0) break;
      matches.push(makeTextMatch(source, start, start + pattern.length));
      offset = start + Math.max(pattern.length, 1);
    }
    return matches;
  }
  let expression: RegExp;
  try {
    expression = new RegExp(pattern, "g");
  } catch (error) {
    throw new Error(`Invalid search regex: ${error instanceof Error ? error.message : String(error)}`);
  }
  let match: RegExpExecArray | null;
  while (matches.length < maxMatches && (match = expression.exec(source)) !== null) {
    matches.push(makeTextMatch(source, match.index, match.index + Math.max(match[0].length, 1)));
    if (match[0].length === 0) expression.lastIndex += 1;
  }
  return matches;
}

function makeTextMatch(source: string, start: number, end: number): TextMatch {
  const lineStart = source.lastIndexOf("\n", Math.max(0, start - 1)) + 1;
  const line = source.slice(0, start).split("\n").length - 1;
  return {
    start,
    end,
    line,
    column: start - lineStart,
    snippet: source.slice(Math.max(0, start - 160), Math.min(source.length, end + 260)),
  };
}

export function textDiffSummary(before: string, after: string): Record<string, unknown> {
  const beforeLines = before.split("\n");
  const afterLines = after.split("\n");
  let changedLines = 0;
  const maxLines = Math.max(beforeLines.length, afterLines.length);
  for (let index = 0; index < maxLines; index += 1) {
    if (beforeLines[index] !== afterLines[index]) changedLines += 1;
  }
  const first = firstMismatch(before, after);
  return {
    beforeLength: before.length,
    afterLength: after.length,
    beforeLines: beforeLines.length,
    afterLines: afterLines.length,
    changedLines,
    firstMismatch: first,
    beforeSnippet: first === null ? undefined : before.slice(Math.max(0, first - 240), first + 500),
    afterSnippet: first === null ? undefined : after.slice(Math.max(0, first - 240), first + 500),
  };
}

function firstMismatch(left: string, right: string): number | null {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    if (left[index] !== right[index]) return index;
  }
  return left.length === right.length ? null : length;
}

export function beautifyJs(source: string, indentSize = 2): string {
  const indentStr = " ".repeat(indentSize);
  let output = "";
  let indentLevel = 0;
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inTemplateLiteral = false;
  let inLineComment = false;
  let inBlockComment = false;
  let isEscaped = false;
  let inForHeader = 0;

  const getIndent = () => indentStr.repeat(Math.max(0, indentLevel));
  const trimmed = source.trim();

  for (let i = 0; i < trimmed.length; i++) {
    const char = trimmed[i];
    const prevChar = i > 0 ? trimmed[i - 1] : "";
    const nextChar = i < trimmed.length - 1 ? trimmed[i + 1] : "";

    if (isEscaped) {
      output += char;
      isEscaped = false;
      continue;
    }
    if (char === "\\" && (inSingleQuote || inDoubleQuote || inTemplateLiteral)) {
      output += char;
      isEscaped = true;
      continue;
    }

    if (inLineComment) {
      output += char;
      if (char === "\n") {
        inLineComment = false;
        output += getIndent();
      }
      continue;
    }

    if (inBlockComment) {
      output += char;
      if (prevChar === "*" && char === "/") {
        inBlockComment = false;
      }
      continue;
    }

    if (!inSingleQuote && !inDoubleQuote && !inTemplateLiteral) {
      if (char === "/" && nextChar === "/") {
        inLineComment = true;
        output += char;
        continue;
      }
      if (char === "/" && nextChar === "*") {
        inBlockComment = true;
        output += char;
        continue;
      }
    }

    if (char === "'" && !inDoubleQuote && !inTemplateLiteral) {
      inSingleQuote = !inSingleQuote;
      output += char;
      continue;
    }
    if (char === '"' && !inSingleQuote && !inTemplateLiteral) {
      inDoubleQuote = !inDoubleQuote;
      output += char;
      continue;
    }
    if (char === "`" && !inSingleQuote && !inDoubleQuote) {
      inTemplateLiteral = !inTemplateLiteral;
      output += char;
      continue;
    }

    if (inSingleQuote || inDoubleQuote || inTemplateLiteral) {
      output += char;
      continue;
    }

    if (char === "(") {
      const recent = output.trimEnd().slice(-4);
      if (recent.endsWith("for") || recent.endsWith("for ")) {
        inForHeader++;
      }
      output += char;
      continue;
    } else if (char === ")" && inForHeader > 0) {
      inForHeader--;
      output += char;
      continue;
    }

    if (char === "{") {
      indentLevel++;
      output = output.trimEnd() + " {\n" + getIndent();
    } else if (char === "}") {
      indentLevel = Math.max(0, indentLevel - 1);
      output = output.trimEnd() + "\n" + getIndent() + "}";
      if (nextChar && nextChar !== ";" && nextChar !== "," && nextChar !== ")") {
        output += "\n" + getIndent();
      }
    } else if (char === ";" && inForHeader === 0) {
      output = output.trimEnd() + ";\n" + getIndent();
    } else if (char === "\n") {
      if (!output.endsWith("\n")) {
        output += "\n" + getIndent();
      }
    } else if (char === "," && inForHeader === 0) {
      output += ", ";
    } else {
      output += char;
    }
  }

  return output
    .split("\n")
    .map((line) => line.trimEnd())
    .join("\n")
    .replace(/\n{3,}/g, "\n\n");
}

export interface ExtractedInsights {
  endpoints: string[];
  urls: string[];
  websockets: string[];
  secrets: Array<{ type: string; value: string }>;
  parameters: string[];
}

export function extractEndpointsAndSecrets(source: string): ExtractedInsights {
  const endpoints = new Set<string>();
  const urls = new Set<string>();
  const websockets = new Set<string>();
  const secrets: Array<{ type: string; value: string }> = [];
  const parameters = new Set<string>();

  const urlRegex = /https?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+/g;
  let match: RegExpExecArray | null;
  while ((match = urlRegex.exec(source)) !== null) {
    const raw = match[0].replace(/['")\];,.]+$/, "");
    if (raw.length > 8) urls.add(raw);
  }

  const wsRegex = /wss?:\/\/[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]+/g;
  while ((match = wsRegex.exec(source)) !== null) {
    const raw = match[0].replace(/['")\];,.]+$/, "");
    if (raw.length > 6) websockets.add(raw);
  }

  const endpointRegex = /['"`]((?:\/(?:api|v[0-9]+|rest|graphql|auth|user|login|token|oauth|webhook|ws|data|admin)[a-zA-Z0-9\-._~/?#[\]!$&'*+,;=%]*))['"`]/gi;
  while ((match = endpointRegex.exec(source)) !== null) {
    if (match[1] && match[1].length > 2) endpoints.add(match[1]);
  }

  const jwtRegex = /\beyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\b/g;
  while ((match = jwtRegex.exec(source)) !== null) {
    secrets.push({ type: "JWT Token", value: match[0] });
  }

  const googleKeyRegex = /\bAIza[0-9A-Za-z-_]{35}\b/g;
  while ((match = googleKeyRegex.exec(source)) !== null) {
    secrets.push({ type: "Google API Key", value: match[0] });
  }

  const awsKeyRegex = /\bAKIA[0-9A-Z]{16}\b/g;
  while ((match = awsKeyRegex.exec(source)) !== null) {
    secrets.push({ type: "AWS Access Key", value: match[0] });
  }

  const stripeRegex = /\b(?:pk|sk)_(?:live|test)_[0-9a-zA-Z]{24,}\b/g;
  while ((match = stripeRegex.exec(source)) !== null) {
    secrets.push({ type: "Stripe Key", value: match[0] });
  }

  const genericSecretRegex = /(?:api_?key|secret|token|password|auth_?token|client_?secret)\s*[:=]\s*['"`]([a-zA-Z0-9_\-.~+]{8,100})['"`]/gi;
  while ((match = genericSecretRegex.exec(source)) !== null) {
    if (match[1] && !match[1].includes(" ") && !match[1].startsWith("http")) {
      secrets.push({ type: "Credential/Secret Assignment", value: match[1] });
    }
  }

  const paramRegex = /(?:params|searchParams|query)\.(?:get|set|has)\(['"`]([a-zA-Z0-9_-]+)['"`]\)/g;
  while ((match = paramRegex.exec(source)) !== null) {
    if (match[1]) parameters.add(match[1]);
  }

  return {
    endpoints: [...endpoints].sort(),
    urls: [...urls].sort(),
    websockets: [...websockets].sort(),
    secrets: secrets.slice(0, 50),
    parameters: [...parameters].sort(),
  };
}

export interface ParsedSourceMap {
  version?: number;
  file?: string;
  sourceRoot?: string;
  sources: Array<{ path: string; content?: string }>;
}

export function parseSourceMap(rawMap: string): ParsedSourceMap {
  const parsed = JSON.parse(rawMap);
  const sources = Array.isArray(parsed.sources) ? parsed.sources : [];
  const sourcesContent = Array.isArray(parsed.sourcesContent) ? parsed.sourcesContent : [];

  return {
    version: parsed.version,
    file: parsed.file,
    sourceRoot: parsed.sourceRoot,
    sources: sources.map((path: string, index: number) => ({
      path,
      content: typeof sourcesContent[index] === "string" ? sourcesContent[index] : undefined,
    })),
  };
}

export function identifyCrypto(source: string): CryptoMatch[] {
  const matches: CryptoMatch[] = [];

  const patterns: Array<{
    algorithm: string;
    category: CryptoMatch["category"];
    confidence: "high" | "medium" | "low";
    regex: RegExp;
    indicator: string;
  }> = [
    {
      algorithm: "MD5",
      category: "hash",
      confidence: "high",
      regex: /(?:0x67452301|1732584193)[\s\S]{0,100}(?:0xefcdab89|4023233417)/i,
      indicator: "MD5 Initial state constants (A=0x67452301, B=0xefcdab89)",
    },
    {
      algorithm: "MD5",
      category: "hash",
      confidence: "medium",
      regex: /\b(?:hex_md5|md5_vm_test|CryptoJS\.MD5|MD5\()\b/i,
      indicator: "MD5 API / function reference",
    },
    {
      algorithm: "SHA-1",
      category: "hash",
      confidence: "high",
      regex: /(?:0xc3d2e1f0|3285377520)[\s\S]{0,100}(?:0x67452301|1732584193)/i,
      indicator: "SHA-1 state constant (0xc3d2e1f0)",
    },
    {
      algorithm: "SHA-1",
      category: "hash",
      confidence: "medium",
      regex: /\b(?:CryptoJS\.SHA1|sha1\(|hex_sha1)\b/i,
      indicator: "SHA-1 API call",
    },
    {
      algorithm: "SHA-256",
      category: "hash",
      confidence: "high",
      regex: /(?:0x428a2f98|1116352408)[\s\S]{0,100}(?:0x71374491|1899200254)/i,
      indicator: "SHA-256 K constants (0x428a2f98, 0x71374491)",
    },
    {
      algorithm: "SHA-256",
      category: "hash",
      confidence: "medium",
      regex: /\b(?:CryptoJS\.SHA256|sha256\(|hex_sha256)\b/i,
      indicator: "SHA-256 API call",
    },
    {
      algorithm: "SHA-512",
      category: "hash",
      confidence: "high",
      regex: /(?:0x28ae22|0x5d9e98)[\s\S]{0,100}(?:0xdb0c2e|0x983e51)/i,
      indicator: "SHA-512 K constants",
    },
    {
      algorithm: "AES",
      category: "symmetric",
      confidence: "high",
      regex: /(?:0x63,\s*0x7c,\s*0x77,\s*0x7b|99,\s*124,\s*119,\s*123)/i,
      indicator: "AES Rijndael S-Box table (99, 124, 119, 123...)",
    },
    {
      algorithm: "AES",
      category: "symmetric",
      confidence: "medium",
      regex: /\b(?:CryptoJS\.AES|AES\.encrypt|AES\.decrypt|mode\.CBC|mode\.ECB|pad\.Pkcs7)\b/i,
      indicator: "AES API / cipher mode references",
    },
    {
      algorithm: "DES",
      category: "symmetric",
      confidence: "medium",
      regex: /(?:58,\s*50,\s*42,\s*34,\s*26,\s*18,\s*10,\s*2)/,
      indicator: "DES Initial Permutation (IP) table",
    },
    {
      algorithm: "DES",
      category: "symmetric",
      confidence: "medium",
      regex: /\b(?:CryptoJS\.DES|CryptoJS\.TripleDES)\b/i,
      indicator: "CryptoJS DES / TripleDES reference",
    },
    {
      algorithm: "RSA",
      category: "asymmetric",
      confidence: "high",
      regex: /-----BEGIN (?:RSA )?PUBLIC KEY-----|setPublicKey\s*\(|new\s+JSEncrypt/i,
      indicator: "RSA Public Key format or JSEncrypt instance",
    },
    {
      algorithm: "RSA",
      category: "asymmetric",
      confidence: "medium",
      regex: /\b(?:rsa\.encrypt|RSAKey|setPrivateKey|new\s+RSA)\b/i,
      indicator: "RSA encryption method call",
    },
    {
      algorithm: "SM3",
      category: "national_secret",
      confidence: "high",
      regex: /(?:0x7380166f|1937797743)[\s\S]{0,100}(?:0x4914b2b9|1226099385)/i,
      indicator: "SM3 Initial state IV constants (0x7380166f, 0x4914b2b9)",
    },
    {
      algorithm: "SM3",
      category: "national_secret",
      confidence: "medium",
      regex: /\b(?:sm3\(|sm-crypto.*sm3|sm3\.digest)\b/i,
      indicator: "SM3 digest API call",
    },
    {
      algorithm: "SM4",
      category: "national_secret",
      confidence: "high",
      regex: /(?:0xd6,\s*0x90,\s*0xe9,\s*0xfe|214,\s*144,\s*233,\s*254)/i,
      indicator: "SM4 S-Box table (214, 144, 233, 254...)",
    },
    {
      algorithm: "SM4",
      category: "national_secret",
      confidence: "medium",
      regex: /\b(?:sm4\.encrypt|sm-crypto.*sm4|sm4\()\b/i,
      indicator: "SM4 encryption method call",
    },
    {
      algorithm: "SM2",
      category: "national_secret",
      confidence: "medium",
      regex: /\b(?:sm2\.doEncrypt|sm2\.doSignature|sm-crypto.*sm2)\b/i,
      indicator: "SM2 asymmetric encryption / signature call",
    },
    {
      algorithm: "RC4",
      category: "symmetric",
      confidence: "medium",
      regex: /for\s*\(\s*(?:var|let)?\s*[a-z]\s*=\s*0\s*;\s*[a-z]\s*<\s*256\s*;\s*[a-z]\+\+\s*\)\s*\{[^}]{0,60}=\s*[a-z]\s*;/i,
      indicator: "RC4 Key-Scheduling Algorithm (KSA) 256-byte permutation initialization",
    },
    {
      algorithm: "Base64",
      category: "encoding",
      confidence: "high",
      regex: /ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+\//,
      indicator: "Standard Base64 alphabet constant",
    },
    {
      algorithm: "Base64-URL",
      category: "encoding",
      confidence: "high",
      regex: /ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_/,
      indicator: "URL-safe Base64 alphabet constant",
    },
    {
      algorithm: "CryptoJS",
      category: "library",
      confidence: "high",
      regex: /CryptoJS\.enc\.Utf8|CryptoJS\.lib\.WordArray|CryptoJS\.algo/i,
      indicator: "CryptoJS library internals found",
    },
    {
      algorithm: "JSEncrypt",
      category: "library",
      confidence: "high",
      regex: /JSEncrypt\.prototype\.setKey|JSEncrypt\.prototype\.encrypt/i,
      indicator: "JSEncrypt library internals found",
    },
    {
      algorithm: "Forge",
      category: "library",
      confidence: "high",
      regex: /forge\.util\.createBuffer|forge\.cipher\.createCipher/i,
      indicator: "Forge crypto library internals found",
    },
  ];

  for (const item of patterns) {
    const match = item.regex.exec(source);
    if (match) {
      const lineStart = source.lastIndexOf("\n", Math.max(0, match.index - 1)) + 1;
      const line = source.slice(0, match.index).split("\n").length;
      const column = match.index - lineStart;
      const snippet = source.slice(Math.max(0, match.index - 100), Math.min(source.length, match.index + 200));

      matches.push({
        algorithm: item.algorithm,
        category: item.category,
        confidence: item.confidence,
        indicator: item.indicator,
        line,
        column,
        snippet,
      });
    }
  }

  return matches;
}

export function findCryptoCandidates(
  source: string,
  parameterNames: string[],
  maxCandidates = 20
): CryptoCandidate[] {
  let ast: any;
  try {
    try {
      ast = parse(source, { ecmaVersion: "latest", sourceType: "module", locations: true });
    } catch (_) {
      ast = parse(source, { ecmaVersion: "latest", sourceType: "script", locations: true });
    }
  } catch (_) {
    return [];
  }

  const normalizedParams = parameterNames.map((p) => p.toLowerCase());
  const candidates: CryptoCandidate[] = [];

  const isFunction = (node: any) =>
    node &&
    (node.type === "FunctionDeclaration" ||
      node.type === "FunctionExpression" ||
      node.type === "ArrowFunctionExpression");

  walk.full(ast, (node: any) => {
    if (!isFunction(node)) return;
    if (!node.loc) return;

    let score = 0;
    const reasons: string[] = [];
    const matchedParams = new Set<string>();

    for (const param of node.params ?? []) {
      const pName = param.type === "Identifier" ? param.name.toLowerCase() : "";
      for (const target of normalizedParams) {
        if (pName.includes(target)) {
          matchedParams.add(target);
          score += 25;
          reasons.push(`Parameter named '${param.name}' matches target`);
        }
      }
    }

    let bitwiseCount = 0;
    let cryptoMethodCalls = 0;
    let toStringHex = false;
    let charCodeAtCalls = 0;

    walk.full(node.body, (child: any) => {
      if (child.type === "Identifier") {
        const idLower = child.name.toLowerCase();
        for (const target of normalizedParams) {
          if (idLower === target && !matchedParams.has(target)) {
            matchedParams.add(target);
            score += 15;
            reasons.push(`Accesses identifier '${child.name}'`);
          }
        }
      }

      if (
        child.type === "BinaryExpression" &&
        ["^", ">>>", "<<", ">>", "&", "|"].includes(child.operator)
      ) {
        bitwiseCount++;
      }

      if (child.type === "CallExpression") {
        const calleeProp = child.callee?.property?.name || child.callee?.name;
        if (calleeProp) {
          const calleeLower = String(calleeProp).toLowerCase();
          if (["encrypt", "decrypt", "digest", "md5", "sha256", "sha1", "encode", "btoa"].includes(calleeLower)) {
            cryptoMethodCalls++;
          }
          if (calleeLower === "charcodeat") charCodeAtCalls++;
          if (calleeLower === "tostring" && child.arguments?.[0]?.value === 16) {
            toStringHex = true;
          }
        }
      }
    });

    if (bitwiseCount > 0) {
      const bitScore = Math.min(bitwiseCount * 3, 30);
      score += bitScore;
      reasons.push(`Contains ${bitwiseCount} bitwise operations (^, >>>, <<, &)`);
    }

    if (cryptoMethodCalls > 0) {
      score += cryptoMethodCalls * 15;
      reasons.push(`Calls crypto methods (${cryptoMethodCalls} calls)`);
    }

    if (charCodeAtCalls > 0) {
      score += 10;
      reasons.push(`Reads character codes (charCodeAt)`);
    }

    if (toStringHex) {
      score += 15;
      reasons.push(`Converts result to hexadecimal (.toString(16))`);
    }

    if (score >= 20) {
      const funcName = node.id?.name || "(anonymous)";
      const startLine = node.loc.start.line;
      const startCol = node.loc.start.column;
      const snippet = source.slice(node.start, Math.min(node.end, node.start + 800));

      candidates.push({
        functionName: funcName,
        line: startLine,
        column: startCol,
        score,
        matchedParameters: [...matchedParams],
        reasons,
        snippet,
      });
    }
  });

  return candidates.sort((a, b) => b.score - a.score).slice(0, maxCandidates);
}

export function classifyAnticrawl(source: string, networkUrls: string[] = []): AnticrawlMatch[] {
  const matches: AnticrawlMatch[] = [];

  const checks: Array<{
    vendor: string;
    type: AnticrawlMatch["type"];
    confidence: "high" | "medium";
    regex: RegExp;
    evidence: string;
  }> = [
    {
      vendor: "Cloudflare Turnstile / Challenge",
      type: "bot_defense",
      confidence: "high",
      regex: /cf-ray|cf_chl_opt|challenges\.cloudflare\.com|turnstile/i,
      evidence: "Cloudflare Challenge / Turnstile tokens or scripts detected",
    },
    {
      vendor: "Akamai Bot Manager",
      type: "bot_defense",
      confidence: "high",
      regex: /_abck\b|bmak\.toElement|sensor_data|ak_bmsc/i,
      evidence: "Akamai Bot Manager sensor data (_abck, bmak, sensor_data) detected",
    },
    {
      vendor: "DataDome",
      type: "bot_defense",
      confidence: "high",
      regex: /datadome\.(?:js|net)|dd\.js|cid=|ddHost/i,
      evidence: "DataDome anti-bot script or domain signatures detected",
    },
    {
      vendor: "GeeTest",
      type: "captcha",
      confidence: "high",
      regex: /initGeetest|gt\.js|geetest_\w+/i,
      evidence: "GeeTest captcha initialization or SDK detected",
    },
    {
      vendor: "Tencent Captcha",
      type: "captcha",
      confidence: "high",
      regex: /TCaptcha|TencentCaptcha|ssl\.captcha\.qq\.com/i,
      evidence: "Tencent Waterproof Wall / TCaptcha detected",
    },
    {
      vendor: "JSVMP (Virtual Machine Protection)",
      type: "jsvmp",
      confidence: "high",
      regex: /while\s*\(\s*(?:true|1)\s*\)\s*\{\s*switch\s*\([a-zA-Z0-9_$.]+\)/,
      evidence: "JSVMP Opcode dispatcher loop (while(true) { switch(opcode) { ... } }) detected",
    },
    {
      vendor: "Anti-Debug Loop",
      type: "anti_debug",
      confidence: "high",
      regex: /setInterval\s*\([^)]*debugger[^)]*\)|new\s+Function\s*\(\s*['"]debugger['"]\s*\)|(?:\.constructor|\[\s*['"]constructor['"]\s*\])\s*\(\s*['"]debugger['"]\s*\)/i,
      evidence: "Infinite debugger loop or Function('debugger') anti-analysis construct detected",
    },
    {
      vendor: "Browser Fingerprinting (Canvas/Audio/WebGL)",
      type: "fingerprinting",
      confidence: "medium",
      regex: /toDataURL\s*\(\s*['"]image\/png['"]\s*\)|createOscillator|getParameter\(37445\)|UNMASKED_RENDERER_WEBGL/i,
      evidence: "Canvas / AudioContext / WebGL GPU renderer fingerprinting probes detected",
    },
  ];

  for (const c of checks) {
    if (c.regex.test(source)) {
      matches.push({
        vendor: c.vendor,
        type: c.type,
        confidence: c.confidence,
        evidence: c.evidence,
      });
    }
  }

  return matches;
}

export function generateJsrpcFiles(options: {
  actionName: string;
  targetExpression: string;
  port?: number;
}): { inPageStub: string; flaskProxy: string; burpDoc: string } {
  const port = options.port ?? 12080;
  const actionName = options.actionName;
  const targetExpr = options.targetExpression;

  const inPageStub = `
/**
 * JSRPC in-page client stub
 * Register into target page console or via evaluate_script
 */
(() => {
  window.__JSRPC_ACTIONS__ = window.__JSRPC_ACTIONS__ || {};
  
  // Register action
  window.__JSRPC_ACTIONS__[${JSON.stringify(actionName)}] = async (param) => {
    // Invoke the in-page target function
    return await (${targetExpr})(param);
  };

  if (!window.__JSRPC_INITIALIZED__) {
    window.__JSRPC_INITIALIZED__ = true;
    console.log("[JSRPC] Bridge ready. Available actions:", Object.keys(window.__JSRPC_ACTIONS__));
  }
})();
  `.trim();

  const flaskProxy = `
# Flask proxy for Burp Suite / Python automation
# Exposes http://127.0.0.1:${port}/go?action=${actionName}

from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route("/go", methods=["POST", "GET"])
def handle_action():
    action = request.args.get("action", ${JSON.stringify(actionName)})
    payload = request.get_json(silent=True) or request.form.to_dict() or request.data.decode("utf-8", errors="ignore")
    
    # Forward or format for CDP/JSRPC
    # When using netvein-mcp evaluate tool, evaluate in page:
    # window.__JSRPC_ACTIONS__[action](payload)
    return jsonify({
        "status": "success",
        "action": action,
        "input": payload,
        "note": "Connect to Chrome CDP or JSRPC WebSocket to fetch computed ciphertext"
    })

if __name__ == "__main__":
    print("[*] JSRPC Flask Proxy listening on port ${port}...")
    app.run(host="127.0.0.1", port=${port})
  `.trim();

  const burpDoc = `
# Burp Suite AutoDecoder Integration

1. In Burp Suite, open AutoDecoder extension.
2. Configure:
   - Target URL / Endpoint regex matching your encrypted API.
   - Mode: HTTP / JSRPC
   - URL: http://127.0.0.1:${port}/go?action=${actionName}
   - Request Body: $\{body\}
3. When sending requests in Repeater, AutoDecoder transparently calls this endpoint to encrypt plaintext payloads before transmission!
  `.trim();

  return { inPageStub, flaskProxy, burpDoc };
}


