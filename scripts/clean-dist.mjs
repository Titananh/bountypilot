import { rmSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const target = path.resolve(repoRoot, "dist");
const relativeTarget = path.relative(repoRoot, target);

if (relativeTarget.startsWith("..") || path.isAbsolute(relativeTarget) || path.basename(target) !== "dist") {
  throw new Error(`Refusing to clean unexpected path: ${target}`);
}

rmSync(target, { recursive: true, force: true });
