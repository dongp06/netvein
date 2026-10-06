import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

export interface AgentConfigTarget {
  id: string;
  name: string;
  configPath: string;
  type: "json" | "toml";
}

export interface TargetResult {
  target: string;
  path: string;
  action: "installed" | "updated" | "removed" | "already-configured" | "not-found" | "skipped";
  error?: string;
}

export interface InstallOptions {
  targets?: string[];
  force?: boolean;
}

export interface UninstallOptions {
  targets?: string[];
}

function getEntryPointPath(): string {
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const distIndex = path.resolve(here, "index.js");
    if (fs.existsSync(distIndex)) return distIndex;
    const parentDist = path.resolve(here, "..", "dist", "index.js");
    if (fs.existsSync(parentDist)) return parentDist;
    return path.resolve(here, "index.ts");
  } catch {
    return "netvein";
  }
}

function getSkillPath(): string {
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const cand1 = path.resolve(here, "..", "skills", "netvein", "SKILL.md");
    if (fs.existsSync(cand1)) return cand1;
    const cand2 = path.resolve(here, "skills", "netvein", "SKILL.md");
    if (fs.existsSync(cand2)) return cand2;
    const cand3 = path.resolve(here, "..", ".agents", "skills", "netvein", "SKILL.md");
    if (fs.existsSync(cand3)) return cand3;
    return "";
  } catch {
    return "";
  }
}

export function getKnownTargets(): AgentConfigTarget[] {
  const home = os.homedir();
  const isWin = process.platform === "win32";

  return [
    {
      id: "antigravity",
      name: "Antigravity / Gemini IDE",
      configPath: path.join(home, ".gemini", "config", "mcp_config.json"),
      type: "json",
    },
    {
      id: "claude",
      name: "Claude Code",
      configPath: path.join(home, ".claude.json"),
      type: "json",
    },
    {
      id: "cursor",
      name: "Cursor",
      configPath: path.join(home, ".cursor", "mcp.json"),
      type: "json",
    },
    {
      id: "codex",
      name: "Codex CLI",
      configPath: path.join(home, ".codex", "config.toml"),
      type: "toml",
    },
    {
      id: "opencode",
      name: "OpenCode",
      configPath: isWin
        ? path.join(process.env.APPDATA || path.join(home, "AppData", "Roaming"), "opencode", "opencode.json")
        : path.join(home, ".config", "opencode", "opencode.json"),
      type: "json",
    },
  ];
}

function resolveServerCommand(): { command: string; args: string[] } {
  // If entry point is on disk, point to node + entrypoint so it works immediately
  const entry = getEntryPointPath();
  if (fs.existsSync(entry) && entry.endsWith(".js")) {
    return {
      command: "node",
      args: [entry, "serve", "--mcp"],
    };
  }
  return {
    command: "netvein",
    args: ["serve", "--mcp"],
  };
}

export function installAgents(options: InstallOptions = {}): TargetResult[] {
  const targets = getKnownTargets();
  const selected = options.targets && options.targets.length > 0 && !options.targets.includes("all")
    ? targets.filter((t) => options.targets!.includes(t.id))
    : targets;

  const serverSpec = resolveServerCommand();
  const results: TargetResult[] = [];

  for (const target of selected) {
    try {
      const configDir = path.dirname(target.configPath);
      if (!fs.existsSync(configDir)) {
        // Parent folder doesn't exist; agent likely not installed
        results.push({
          target: target.name,
          path: target.configPath,
          action: "not-found",
        });
        continue;
      }

      if (target.type === "json") {
        let json: Record<string, any> = {};
        if (fs.existsSync(target.configPath)) {
          try {
            json = JSON.parse(fs.readFileSync(target.configPath, "utf8"));
          } catch {
            json = {};
          }
        }

        if (!json.mcpServers || typeof json.mcpServers !== "object") {
          json.mcpServers = {};
        }

        const existing = json.mcpServers["netvein"] || json.mcpServers["netvein-mcp"];
        if (existing && !options.force) {
          results.push({
            target: target.name,
            path: target.configPath,
            action: "already-configured",
          });
          continue;
        }

        json.mcpServers["netvein"] = {
          command: serverSpec.command,
          args: serverSpec.args,
          env: {
            CDP_HOST: "127.0.0.1",
            CDP_PORT: "9222",
          },
        };

        fs.writeFileSync(target.configPath, JSON.stringify(json, null, 2) + "\n", "utf8");

        if (target.id === "antigravity") {
          try {
            const skillSource = getSkillPath();
            if (skillSource && fs.existsSync(skillSource)) {
              const skillDir = path.join(path.dirname(target.configPath), "skills", "netvein");
              fs.mkdirSync(skillDir, { recursive: true });
              fs.copyFileSync(skillSource, path.join(skillDir, "SKILL.md"));
            }
          } catch {
            // non-fatal skill installation
          }
        }

        results.push({
          target: target.name,
          path: target.configPath,
          action: existing ? "updated" : "installed",
        });
      } else if (target.type === "toml") {
        let content = "";
        if (fs.existsSync(target.configPath)) {
          content = fs.readFileSync(target.configPath, "utf8");
        }

        if (content.includes("[mcp_servers.netvein]") && !options.force) {
          results.push({
            target: target.name,
            path: target.configPath,
            action: "already-configured",
          });
          continue;
        }

        const argsStr = JSON.stringify(serverSpec.args);
        const tomlBlock = `\n[mcp_servers.netvein]\ncommand = "${serverSpec.command.replace(/\\/g, "\\\\")}"\nargs = ${argsStr}\nstartup_timeout_sec = 60\n[mcp_servers.netvein.env]\nCDP_HOST = "127.0.0.1"\nCDP_PORT = "9222"\n`;

        fs.writeFileSync(target.configPath, content + tomlBlock, "utf8");
        results.push({
          target: target.name,
          path: target.configPath,
          action: "installed",
        });
      }
    } catch (err) {
      results.push({
        target: target.name,
        path: target.configPath,
        action: "skipped",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return results;
}

export function uninstallAgents(options: UninstallOptions = {}): TargetResult[] {
  const targets = getKnownTargets();
  const selected = options.targets && options.targets.length > 0 && !options.targets.includes("all")
    ? targets.filter((t) => options.targets!.includes(t.id))
    : targets;

  const results: TargetResult[] = [];

  for (const target of selected) {
    try {
      if (!fs.existsSync(target.configPath)) {
        results.push({
          target: target.name,
          path: target.configPath,
          action: "not-found",
        });
        continue;
      }

      if (target.type === "json") {
        const raw = fs.readFileSync(target.configPath, "utf8");
        let json: Record<string, any>;
        try {
          json = JSON.parse(raw);
        } catch {
          results.push({ target: target.name, path: target.configPath, action: "skipped", error: "Invalid JSON" });
          continue;
        }

        if (!json.mcpServers) {
          results.push({ target: target.name, path: target.configPath, action: "not-found" });
          continue;
        }

        let changed = false;
        for (const key of ["netvein", "netvein-mcp", "reverse-engineering"]) {
          if (json.mcpServers[key]) {
            delete json.mcpServers[key];
            changed = true;
          }
        }

        if (changed) {
          fs.writeFileSync(target.configPath, JSON.stringify(json, null, 2) + "\n", "utf8");
          results.push({ target: target.name, path: target.configPath, action: "removed" });
        } else {
          results.push({ target: target.name, path: target.configPath, action: "not-found" });
        }
      } else if (target.type === "toml") {
        const raw = fs.readFileSync(target.configPath, "utf8");
        const cleaned = raw
          .replace(/\[mcp_servers\.(netvein|reverse-engineering)\][\s\S]*?(?=\n\[|\Z)/g, "")
          .trim();
        if (cleaned !== raw.trim()) {
          fs.writeFileSync(target.configPath, cleaned + "\n", "utf8");
          results.push({ target: target.name, path: target.configPath, action: "removed" });
        } else {
          results.push({ target: target.name, path: target.configPath, action: "not-found" });
        }
      }
    } catch (err) {
      results.push({
        target: target.name,
        path: target.configPath,
        action: "skipped",
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return results;
}
