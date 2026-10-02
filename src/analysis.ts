import { parse } from "acorn";
import * as walk from "acorn-walk";

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
