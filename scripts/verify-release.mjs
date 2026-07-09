#!/usr/bin/env node
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

const ROOT = process.cwd();
const CLI = path.join(ROOT, "dist", "cli", "index.js");
const NPM_CACHE = process.env.BOUNTYPILOT_NPM_CACHE ?? path.join(os.tmpdir(), "bountypilot-verify-release-npm-cache");
const NPM_ENV = {
  ...process.env,
  npm_config_cache: NPM_CACHE,
  NPM_CONFIG_CACHE: NPM_CACHE,
  npm_config_update_notifier: "false",
  // Suppress Node 22 ExperimentalWarning for SQLite and other built-in modules
  // that pollute stderr during test runs. Tests assert clean stderr/JSON.parse,
  // so we silence warnings at the process level rather than fixing every test.
  NODE_NO_WARNINGS: "1",
};
const BASE_DOCS_WITH_COMMANDS = ["README.md", "examples/safe-workflow.md"];
const GLOBAL_OPTIONS_WITH_VALUE = new Set(["-p", "--program", "--tool-registry"]);
const CLI_COMMAND_CACHE = new Map();

main();

function main() {
  npm(["run", "build"]);
  verifyDocumentedCommands();
  npm(["run", "typecheck"]);
  npm(["run", "test"]);
  npm(["run", "test:package-bin"]);
  npm(["run", "release:check"]);
  npm(["pack", "--dry-run"]);
  npm(["run", "release:check"]);
  console.log("\nverify:release passed");
}

function verifyDocumentedCommands() {
  if (!existsSync(CLI)) {
    throw new Error("dist/cli/index.js is missing; run npm run build before verifying docs.");
  }

  const packageJson = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8"));
  const npmScripts = new Set(Object.keys(packageJson.scripts ?? {}));
  const docsWithCommands = docsWithCommandSnippets();
  const snippets = docsWithCommands.flatMap((file) => extractCommandSnippets(file));
  const failures = [];
  const helpCommands = new Set();

  for (const snippet of snippets) {
    const tokens = shellWords(snippet.command);
    if (tokens.length === 0) continue;

    if (tokens[0] === "npm") {
      const scriptName = tokens[1] === "run" ? tokens[2] : undefined;
      if (scriptName && !npmScripts.has(scriptName)) {
        failures.push(`${snippet.file}:${snippet.line}: unknown npm script ${scriptName}`);
      }
      continue;
    }

    const commandTokens = cliCommandTokens(tokens);
    if (!commandTokens) continue;
    const result = documentedCliHelpCommand(commandTokens);
    if (result.error) {
      failures.push(`${snippet.file}:${snippet.line}: ${result.error}`);
      continue;
    }
    if (result.command.length > 0) helpCommands.add(result.command.join(" "));
  }

  for (const commandName of helpCommands) {
    const commandPath = commandName.split(" ");
    try {
      execFileSync(process.execPath, [CLI, ...commandPath, "--help"], { cwd: ROOT, stdio: "ignore" });
    } catch {
      failures.push(`bugbounty ${commandName} --help failed`);
    }
  }

  if (failures.length > 0) {
    throw new Error(`Documented command verification failed:\n${failures.map((item) => `- ${item}`).join("\n")}`);
  }

  console.log(`docs: verified ${snippets.length} command snippets across ${docsWithCommands.join(", ")}`);
}

function docsWithCommandSnippets() {
  const files = [...BASE_DOCS_WITH_COMMANDS];
  const docsDir = path.join(ROOT, "docs");
  if (!existsSync(docsDir)) return files;
  for (const entry of readdirSync(docsDir, { withFileTypes: true })) {
    if (entry.isFile() && entry.name.endsWith(".md")) {
      files.push(path.join("docs", entry.name));
    }
  }
  return files;
}

function readCliCommands(commandPath = []) {
  const cacheKey = commandPath.join("\0");
  const cached = CLI_COMMAND_CACHE.get(cacheKey);
  if (cached) return cached;

  const help = execFileSync(process.execPath, [CLI, ...commandPath, "--help"], { cwd: ROOT, encoding: "utf8" });
  const commands = new Set();
  let inCommands = false;
  for (const line of help.split(/\r?\n/)) {
    if (line.trim() === "Commands:") {
      inCommands = true;
      continue;
    }
    if (inCommands && line.trim() === "") break;
    const match = inCommands ? /^  ([a-z][a-z0-9-]*)\b/.exec(line) : undefined;
    if (match) commands.add(match[1]);
  }
  CLI_COMMAND_CACHE.set(cacheKey, commands);
  return commands;
}

function documentedCliHelpCommand(tokens) {
  const command = [];

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (GLOBAL_OPTIONS_WITH_VALUE.has(token)) {
      index += 1;
      continue;
    }
    if (token.startsWith("-")) continue;

    const commands = readCliCommands(command);
    if (commands.has(token)) {
      command.push(token);
      continue;
    }
    if (command.length === 0) {
      return token === "..." ? { command: [] } : { command: [], error: `unknown bounty command ${token}` };
    }
    if (commands.size > 0 && isLikelySubcommandTypo(token)) {
      return { command, error: `unknown bounty subcommand ${[...command, token].join(" ")}` };
    }
    break;
  }

  return { command };
}

function isLikelySubcommandTypo(token) {
  return /^[a-z][a-z0-9-]*$/.test(token) && !token.includes("-") && !token.includes(".") && !token.includes("=");
}

function extractCommandSnippets(file) {
  const text = readFileSync(path.join(ROOT, file), "utf8");
  const snippets = [];
  let inShellBlock = false;

  text.split(/\r?\n/).forEach((line, index) => {
    const lineNumber = index + 1;
    const trimmed = line.trim();
    const fence = /^```(\w+)?/.exec(trimmed);
    if (fence) {
      const language = (fence[1] ?? "").toLowerCase();
      inShellBlock = !inShellBlock && ["bash", "sh", "shell", "zsh"].includes(language);
      if (!inShellBlock && trimmed === "```") inShellBlock = false;
      return;
    }

    if (inShellBlock) {
      const command = normalizedCommandLine(trimmed);
      if (command) snippets.push({ file, line: lineNumber, command });
    }

    for (const match of line.matchAll(/`([^`]+)`/g)) {
      const command = normalizedCommandLine(match[1].trim());
      if (command) snippets.push({ file, line: lineNumber, command });
    }
  });

  return dedupeSnippets(snippets);
}

function normalizedCommandLine(line) {
  const withoutPrompt = line.replace(/^\$\s*/, "").trim();
  if (!withoutPrompt || withoutPrompt.startsWith("#")) return undefined;
  if (
    withoutPrompt.startsWith("bugbounty ") ||
    withoutPrompt === "bugbounty" ||
    withoutPrompt.startsWith("bounty ") ||
    withoutPrompt === "bounty" ||
    withoutPrompt.startsWith("node dist/cli/index.js") ||
    withoutPrompt.startsWith("npm run ") ||
    withoutPrompt === "npm run build" ||
    withoutPrompt === "npm pack --dry-run"
  ) {
    return withoutPrompt;
  }
  return undefined;
}

function cliCommandTokens(tokens) {
  if (tokens[0] === "bugbounty" || tokens[0] === "bounty") return tokens.slice(1);
  if (tokens[0] === "node" && tokens[1] === "dist/cli/index.js") return tokens.slice(2);
  return undefined;
}

function firstCliCommand(tokens) {
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (GLOBAL_OPTIONS_WITH_VALUE.has(token)) {
      index += 1;
      continue;
    }
    if (token.startsWith("-")) continue;
    return token;
  }
  return undefined;
}

function shellWords(command) {
  const words = [];
  let current = "";
  let quote;
  for (let index = 0; index < command.length; index += 1) {
    const char = command[index];
    if (quote) {
      if (char === quote) {
        quote = undefined;
      } else {
        current += char;
      }
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (/\s/.test(char)) {
      if (current) {
        words.push(current);
        current = "";
      }
      continue;
    }
    current += char;
  }
  if (current) words.push(current);
  return words;
}

function dedupeSnippets(snippets) {
  const seen = new Set();
  return snippets.filter((snippet) => {
    const key = `${snippet.file}:${snippet.line}:${snippet.command}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function npm(args) {
  const argsWithCache = ["--cache", NPM_CACHE, ...args];
  const npmExecPath = process.env.npm_execpath;
  if (npmExecPath && npmExecPath.endsWith(".js") && existsSync(npmExecPath)) {
    run("npm", process.execPath, [npmExecPath, ...argsWithCache]);
    return;
  }
  if (process.platform === "win32") {
    run("npm", "cmd.exe", ["/d", "/c", "npm.cmd", ...argsWithCache], { displayArgs: argsWithCache });
    return;
  }
  run("npm", "npm", argsWithCache);
}

function run(displayCommand, command, args, options = {}) {
  const { displayArgs = args, ...spawnOptions } = options;
  console.log(`\n> ${[displayCommand, ...displayArgs].join(" ")}`);
  const result = spawnSync(command, args, { cwd: ROOT, stdio: "inherit", env: NPM_ENV, ...spawnOptions });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    process.exitCode = result.status ?? 1;
    throw new Error(`${displayCommand} ${args.join(" ")} failed`);
  }
}
