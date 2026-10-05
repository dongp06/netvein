export interface AxNode {
  nodeId: string;
  ignored?: boolean;
  role?: { value?: string };
  name?: { value?: string };
  value?: { value?: string };
  backendDOMNodeId?: number;
  childIds?: string[];
}

export interface SemanticNode {
  id: number;
  role: string;
  name: string;
  value?: string;
  depth: number;
}

export interface SemanticSnapshot {
  version: number;
  nodes: SemanticNode[];
  idMap: Map<number, number>;
  truncated: boolean;
}

export interface CompressOptions {
  version: number;
  interactiveOnly?: boolean;
  maxNodes?: number;
  nameMaxChars?: number;
}

const INTERACTIVE_ROLES = new Set([
  "button",
  "link",
  "textbox",
  "searchbox",
  "checkbox",
  "radio",
  "combobox",
  "listbox",
  "menuitem",
  "option",
  "slider",
  "spinbutton",
  "switch",
  "tab",
]);

const DROPPED_ROLES = new Set(["generic", "none", "presentational", "ignored", "InlineTextBox"]);

function roleOf(node: AxNode): string {
  return node.role?.value ?? "";
}

function isInteractive(node: AxNode): boolean {
  return INTERACTIVE_ROLES.has(roleOf(node));
}

function depthMap(nodes: AxNode[]): Map<string, number> {
  const byId = new Map(nodes.map((node) => [node.nodeId, node]));
  const depths = new Map<string, number>();

  const visit = (nodeId: string, depth: number): void => {
    const node = byId.get(nodeId);
    if (!node) return;
    depths.set(nodeId, depth);
    for (const childId of node.childIds ?? []) {
      const childDepth = DROPPED_ROLES.has(roleOf(byId.get(childId) ?? { nodeId: childId })) ? depth : depth + 1;
      visit(childId, childDepth);
    }
  };

  const roots = nodes.filter((node) => !nodes.some((other) => (other.childIds ?? []).includes(node.nodeId)));
  for (const root of roots) visit(root.nodeId, 0);
  return depths;
}

export function compressAxTree(nodes: AxNode[], options: CompressOptions): SemanticSnapshot {
  const depths = depthMap(nodes);
  const interactiveOnly = options.interactiveOnly ?? false;
  const maxNodes = options.maxNodes ?? 300;
  const nameMaxChars = options.nameMaxChars ?? 200;

  const kept = nodes.filter((node) => {
    if (node.ignored) return false;
    const role = roleOf(node);
    if (role.length === 0 || DROPPED_ROLES.has(role)) return false;
    if (interactiveOnly) return isInteractive(node);
    if (role === "RootWebArea") return true;
    const name = node.name?.value ?? "";
    return name.length > 0 || isInteractive(node);
  });

  const truncated = kept.length > maxNodes;
  const bounded = kept.slice(0, maxNodes);

  const semanticNodes: SemanticNode[] = bounded.map((node, index) => {
    const rawName = node.name?.value ?? "";
    const rawValue = node.value?.value;
    const name = rawName.length > nameMaxChars ? `${rawName.slice(0, nameMaxChars)}...` : rawName;
    const value =
      rawValue !== undefined && rawValue.length > nameMaxChars ? `${rawValue.slice(0, nameMaxChars)}...` : rawValue;
    return {
      id: index + 1,
      role: roleOf(node),
      name,
      ...(value !== undefined && value !== "" ? { value } : {}),
      depth: depths.get(node.nodeId) ?? 0,
    };
  });

  const idMap = new Map<number, number>();
  bounded.forEach((node, index) => {
    if (typeof node.backendDOMNodeId === "number") {
      idMap.set(index + 1, node.backendDOMNodeId);
    }
  });

  return { version: options.version, nodes: semanticNodes, idMap, truncated };
}

export function formatSemanticView(snapshot: SemanticSnapshot): string {
  const lines = [
    `#${snapshot.version}  semantic snapshot (${snapshot.nodes.length} nodes${snapshot.truncated ? ", truncated" : ""})`,
  ];
  for (const node of snapshot.nodes) {
    const indent = "  ".repeat(Math.max(node.depth - 1, 0));
    const value = node.value !== undefined && node.value !== "" ? `  value="${node.value}"` : "";
    lines.push(`${indent}[${node.id}] ${node.role} "${node.name}"${value}`);
  }
  return lines.join("\n");
}

export interface SnapshotDiff {
  added: SemanticNode[];
  removed: SemanticNode[];
  changed: SemanticNode[];
}

export function diffSnapshots(previous: SemanticSnapshot, current: SemanticSnapshot, maxChanges = 100): SnapshotDiff {
  const key = (node: SemanticNode): string => `${node.role}\u0000${node.name}`;
  const previousByKey = new Map(previous.nodes.map((node) => [key(node), node]));
  const currentByKey = new Map(current.nodes.map((node) => [key(node), node]));

  const added: SemanticNode[] = [];
  const removed: SemanticNode[] = [];
  const changed: SemanticNode[] = [];

  for (const [nodeKey, node] of currentByKey) {
    const before = previousByKey.get(nodeKey);
    if (!before) {
      added.push(node);
      continue;
    }
    if (before.value !== node.value) changed.push(node);
  }
  for (const [nodeKey, node] of previousByKey) {
    if (!currentByKey.has(nodeKey)) removed.push(node);
  }

  const bound = (list: SemanticNode[]): SemanticNode[] => list.slice(0, maxChanges);
  return { added: bound(added), removed: bound(removed), changed: bound(changed) };
}
