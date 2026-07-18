/**
 * Install the BountyPilot Hermes skills without replacing a user's profile.
 *
 * This intentionally does not use `hermes profile install`: Hermes 0.17 treats
 * whole distribution-owned directories as replaceable. This installer owns
 * nine category-qualified skill directories and one bundle file only.
 */

import { createHash, randomBytes } from "node:crypto";
import { constants as fsConstants, createReadStream } from "node:fs";
import {
  copyFile,
  lstat,
  mkdir,
  open,
  readFile,
  readdir,
  rename,
  rm,
  rmdir,
  unlink,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import YAML from "yaml";

const SCRIPT_PATH = fileURLToPath(import.meta.url);
const REPOSITORY_ROOT = path.resolve(path.dirname(SCRIPT_PATH), "..");

export const DEFAULT_SOURCE_ROOT = path.join(
  REPOSITORY_ROOT,
  "hermes",
  "bountypilot-agent",
);

export const MANAGED_SKILL_NAMES = Object.freeze([
  "bountypilot-duplicate-check",
  "bountypilot-evidence",
  "bountypilot-orchestrate",
  "bountypilot-program-intake",
  "bountypilot-recon",
  "bountypilot-report",
  "bountypilot-safety",
  "bountypilot-triage",
  "bountypilot-validate",
]);

export const MANAGED_BUNDLE_RELATIVE_PATH = "skill-bundles/bountypilot.yaml";
export const LEGACY_BUNDLE_RELATIVE_PATH = "skill-bundles/bountypilot.yml";

const EXPECTED_SOURCE_TOP_LEVEL = Object.freeze([
  "SOUL.md",
  "distribution.yaml",
  "skill-bundles",
  "skills",
]);

const EXPECTED_DISTRIBUTION_OWNED = Object.freeze([
  "SOUL.md",
  "distribution.yaml",
  "skill-bundles/bountypilot.yaml",
  ...MANAGED_SKILL_NAMES.map((skillName) => `skills/security/${skillName}`),
]);

const EXPECTED_BUNDLE_SKILLS = Object.freeze([
  "security/bountypilot-orchestrate",
  "security/bountypilot-safety",
]);

const FORBIDDEN_SOURCE_BASENAMES = new Set([
  ".aws",
  ".azure",
  ".git",
  ".hermes_history",
  ".ssh",
  "active_profile",
  "auth.json",
  "auth.lock",
  "audio_cache",
  "backups",
  "browser_screenshots",
  "cache",
  "checkpoints",
  "config.json",
  "config.toml",
  "config.yaml",
  "config.yml",
  "credentials",
  "credentials.json",
  "cron",
  "crontab",
  "document_cache",
  "errors.log",
  "gateway.pid",
  "gateway_state.json",
  "home",
  "hermes_state.db",
  "image_cache",
  "local",
  "logs",
  "mcp.json",
  "memories",
  "memory",
  "plans",
  "processes.json",
  "response_store.db",
  "response_store.db-shm",
  "response_store.db-wal",
  "sandboxes",
  "secrets",
  "secrets.json",
  "sessions",
  "state.db",
  "state.db-shm",
  "state.db-wal",
  "token.json",
  "workspace",
]);

const MAX_BUNDLE_METADATA_BYTES = 1024 * 1024;
const RESERVED_PROFILE_NAMES = new Set(["hermes", "root", "sudo", "test", "tmp"]);

export class InstallerError extends Error {
  constructor(message, options) {
    super(message, options);
    this.name = "InstallerError";
  }
}

function compareNames(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function isPathInside(boundary, candidate) {
  const relative = path.relative(path.resolve(boundary), path.resolve(candidate));
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

function assertPathInside(boundary, candidate, label) {
  if (!isPathInside(boundary, candidate)) {
    throw new InstallerError(`${label} escaped its permitted directory.`);
  }
}

async function lstatOrNull(filePath) {
  try {
    return await lstat(filePath);
  } catch (error) {
    if (error?.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

/**
 * Reject every existing symbolic-link or junction component in a path.
 * Missing tail components are allowed so callers can preflight future paths.
 */
export async function assertNoSymlinkAncestors(candidate, { includeLeaf = true } = {}) {
  const absolute = path.resolve(candidate);
  const parsed = path.parse(absolute);
  const relativeParts = absolute
    .slice(parsed.root.length)
    .split(path.sep)
    .filter(Boolean);
  const parts = includeLeaf ? relativeParts : relativeParts.slice(0, -1);

  let current = parsed.root;
  const rootStat = await lstatOrNull(current);
  if (rootStat?.isSymbolicLink()) {
    throw new InstallerError("A target ancestor is a symbolic link or junction.");
  }

  for (const part of parts) {
    current = path.join(current, part);
    const stat = await lstatOrNull(current);
    if (!stat) {
      continue;
    }
    if (stat.isSymbolicLink()) {
      throw new InstallerError("A target ancestor is a symbolic link or junction.");
    }
  }
}

function validateProfileName(profile) {
  const normalized = String(profile ?? "").trim().toLowerCase();
  if (normalized === "default") {
    return normalized;
  }
  if (!/^[a-z0-9][a-z0-9_-]{0,63}$/u.test(normalized)) {
    throw new InstallerError("The Hermes profile name is invalid.");
  }
  if (RESERVED_PROFILE_NAMES.has(normalized)) {
    throw new InstallerError("The Hermes profile name is reserved.");
  }
  return normalized;
}

function expandHome(input, homeDirectory) {
  const value = String(input).trim();
  if (value === "~") {
    return homeDirectory;
  }
  if (value.startsWith(`~${path.sep}`) || value.startsWith("~/") || value.startsWith("~\\")) {
    return path.join(homeDirectory, value.slice(2));
  }
  return value;
}

/**
 * Resolve a named profile from either a Hermes root or an HERMES_HOME that is
 * already `<root>/profiles/<name>`. No active-profile or config file is read.
 */
export function resolveHermesProfile({
  profile = "bugbounty",
  hermesHome,
  env = process.env,
  platform = process.platform,
  homeDirectory = os.homedir(),
} = {}) {
  const normalizedProfile = validateProfileName(profile);
  const providedHome = String(hermesHome ?? env.HERMES_HOME ?? "").trim();

  let candidate;
  if (providedHome) {
    candidate = path.resolve(expandHome(providedHome, homeDirectory));
  } else if (platform === "win32") {
    const localAppData = String(env.LOCALAPPDATA ?? "").trim();
    const base = localAppData
      ? path.resolve(localAppData)
      : path.join(homeDirectory, "AppData", "Local");
    candidate = path.join(base, "hermes");
  } else {
    candidate = path.join(homeDirectory, ".hermes");
  }

  const parentIsProfiles = path.basename(path.dirname(candidate)).toLowerCase() === "profiles";
  const candidateIsProfiles = path.basename(candidate).toLowerCase() === "profiles";

  let hermesRoot;
  let profileDir;
  if (parentIsProfiles) {
    hermesRoot = path.dirname(path.dirname(candidate));
    if (normalizedProfile === "default") {
      profileDir = hermesRoot;
    } else if (path.basename(candidate).toLowerCase() === normalizedProfile) {
      profileDir = candidate;
    } else {
      profileDir = path.join(hermesRoot, "profiles", normalizedProfile);
    }
  } else if (candidateIsProfiles) {
    hermesRoot = path.dirname(candidate);
    profileDir = normalizedProfile === "default"
      ? hermesRoot
      : path.join(candidate, normalizedProfile);
  } else {
    hermesRoot = candidate;
    profileDir = normalizedProfile === "default"
      ? candidate
      : path.join(candidate, "profiles", normalizedProfile);
  }

  return {
    hermesRoot: path.resolve(hermesRoot),
    profile: normalizedProfile,
    profileDir: path.resolve(profileDir),
  };
}

async function requireExistingProfile(profileDir) {
  await assertNoSymlinkAncestors(profileDir);
  const stat = await lstatOrNull(profileDir);
  if (!stat?.isDirectory() || stat.isSymbolicLink()) {
    throw new InstallerError("The selected Hermes profile does not exist as a real directory.");
  }
}

function parseYamlMapping(text, label, { tolerateInvalid = false } = {}) {
  let document;
  try {
    document = YAML.parseDocument(text, {
      maxAliasCount: 0,
      prettyErrors: false,
      strict: true,
    });
  } catch (error) {
    if (tolerateInvalid) {
      return null;
    }
    throw new InstallerError(`${label} is not valid YAML.`, { cause: error });
  }
  if (document.errors.length > 0) {
    if (tolerateInvalid) {
      return null;
    }
    throw new InstallerError(`${label} is not valid YAML.`);
  }
  let value;
  try {
    value = document.toJS({ maxAliasCount: 0 });
  } catch (error) {
    if (tolerateInvalid) {
      return null;
    }
    throw new InstallerError(`${label} cannot be safely decoded.`, { cause: error });
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    if (tolerateInvalid) {
      return null;
    }
    throw new InstallerError(`${label} must contain a YAML mapping.`);
  }
  return value;
}

async function inspectSourceNode(absolutePath, sourceRoot) {
  assertPathInside(sourceRoot, absolutePath, "A source entry");
  const stat = await lstat(absolutePath);
  if (stat.isSymbolicLink()) {
    throw new InstallerError("The distribution source contains a symbolic link or junction.");
  }
  const lowerName = path.basename(absolutePath).toLowerCase();
  if (lowerName.startsWith(".env") || FORBIDDEN_SOURCE_BASENAMES.has(lowerName)) {
    throw new InstallerError("The distribution source contains a forbidden profile or credential path.");
  }
  if (stat.isDirectory()) {
    const children = await readdir(absolutePath);
    children.sort(compareNames);
    for (const child of children) {
      await inspectSourceNode(path.join(absolutePath, child), sourceRoot);
    }
    return;
  }
  if (!stat.isFile()) {
    throw new InstallerError("The distribution source contains an unsupported filesystem entry.");
  }
}

/** Validate the complete, credential-free distribution before planning. */
export async function validateDistributionSource(sourceRoot = DEFAULT_SOURCE_ROOT) {
  const absoluteSource = path.resolve(sourceRoot);
  await assertNoSymlinkAncestors(absoluteSource);
  const rootStat = await lstatOrNull(absoluteSource);
  if (!rootStat?.isDirectory() || rootStat.isSymbolicLink()) {
    throw new InstallerError("The BountyPilot Hermes distribution source is missing.");
  }

  const topLevel = (await readdir(absoluteSource)).sort(compareNames);
  if (JSON.stringify(topLevel) !== JSON.stringify(EXPECTED_SOURCE_TOP_LEVEL)) {
    throw new InstallerError("The distribution source top level does not match its strict allowlist.");
  }
  for (const entry of topLevel) {
    await inspectSourceNode(path.join(absoluteSource, entry), absoluteSource);
  }

  const securityRoot = path.join(absoluteSource, "skills", "security");
  const skillsRootEntries = (await readdir(path.join(absoluteSource, "skills"))).sort(compareNames);
  if (JSON.stringify(skillsRootEntries) !== JSON.stringify(["security"])) {
    throw new InstallerError("The distribution may contain only the security skill category.");
  }
  const skillNames = (await readdir(securityRoot)).sort(compareNames);
  if (JSON.stringify(skillNames) !== JSON.stringify([...MANAGED_SKILL_NAMES].sort(compareNames))) {
    throw new InstallerError("The distribution must contain exactly the nine managed skills.");
  }
  for (const skillName of MANAGED_SKILL_NAMES) {
    const skillStat = await lstat(path.join(securityRoot, skillName));
    const skillFileStat = await lstat(path.join(securityRoot, skillName, "SKILL.md"));
    if (!skillStat.isDirectory() || skillStat.isSymbolicLink() || !skillFileStat.isFile() || skillFileStat.isSymbolicLink()) {
      throw new InstallerError("Every managed skill must be a real directory with a regular SKILL.md.");
    }
  }

  const bundleNames = (await readdir(path.join(absoluteSource, "skill-bundles"))).sort(compareNames);
  if (JSON.stringify(bundleNames) !== JSON.stringify(["bountypilot.yaml"])) {
    throw new InstallerError("The distribution must contain exactly one managed bundle.");
  }

  const manifest = parseYamlMapping(
    await readFile(path.join(absoluteSource, "distribution.yaml"), "utf8"),
    "distribution.yaml",
  );
  const distributionOwned = Array.isArray(manifest.distribution_owned)
    ? manifest.distribution_owned.map(String).sort(compareNames)
    : [];
  if (
    manifest.name !== "bountypilot-agent"
    || manifest.version !== "0.1.0"
    || manifest.hermes_requires !== ">=0.17.0"
    || manifest.license !== "MIT"
    || Object.hasOwn(manifest, "env_requires")
    || JSON.stringify(distributionOwned) !== JSON.stringify([...EXPECTED_DISTRIBUTION_OWNED].sort(compareNames))
  ) {
    throw new InstallerError("distribution.yaml violates the credential-free ownership contract.");
  }

  const bundle = parseYamlMapping(
    await readFile(path.join(absoluteSource, MANAGED_BUNDLE_RELATIVE_PATH), "utf8"),
    "bountypilot.yaml",
  );
  if (
    bundle.name !== "bountypilot"
    || !Array.isArray(bundle.skills)
    || JSON.stringify(bundle.skills.map(String)) !== JSON.stringify(EXPECTED_BUNDLE_SKILLS)
  ) {
    throw new InstallerError("The managed bundle must use the expected category-qualified skills.");
  }

  return absoluteSource;
}

async function feedFileToHash(hash, filePath) {
  for await (const chunk of createReadStream(filePath)) {
    hash.update(chunk);
  }
}

async function visitForHash(hash, absolutePath, relativePath) {
  const stat = await lstat(absolutePath);
  if (stat.isSymbolicLink()) {
    throw new InstallerError("A managed entry contains a symbolic link or junction.");
  }
  if (stat.isDirectory()) {
    hash.update(`D\0${relativePath}\0`);
    const children = (await readdir(absolutePath)).sort(compareNames);
    for (const child of children) {
      await visitForHash(
        hash,
        path.join(absolutePath, child),
        relativePath === "." ? child : `${relativePath}/${child}`,
      );
    }
    return;
  }
  if (!stat.isFile()) {
    throw new InstallerError("A managed entry contains an unsupported filesystem object.");
  }
  hash.update(`F\0${relativePath}\0${stat.size}\0`);
  await feedFileToHash(hash, absolutePath);
  hash.update("\0");
}

/** Return a stable SHA-256 over a file or directory tree. */
export async function hashManagedPath(absolutePath) {
  await assertNoSymlinkAncestors(absolutePath);
  const hash = createHash("sha256");
  hash.update("bountypilot-managed-tree-v1\0");
  await visitForHash(hash, absolutePath, ".");
  return hash.digest("hex");
}

function managedEntries(sourceRoot, profileDir) {
  const skills = MANAGED_SKILL_NAMES.map((skillName) => {
    const relativePath = `skills/security/${skillName}`;
    return {
      kind: "directory",
      relativePath,
      sourcePath: path.join(sourceRoot, ...relativePath.split("/")),
      targetPath: path.join(profileDir, ...relativePath.split("/")),
    };
  });
  return [
    ...skills,
    {
      kind: "file",
      relativePath: MANAGED_BUNDLE_RELATIVE_PATH,
      sourcePath: path.join(sourceRoot, ...MANAGED_BUNDLE_RELATIVE_PATH.split("/")),
      targetPath: path.join(profileDir, ...MANAGED_BUNDLE_RELATIVE_PATH.split("/")),
    },
  ];
}

function slugifyBundleName(name) {
  return String(name ?? "")
    .toLowerCase()
    .replaceAll(" ", "-")
    .replaceAll("_", "-")
    .replace(/[^a-z0-9-]/gu, "")
    .replace(/-{2,}/gu, "-")
    .replace(/^-|-$/gu, "");
}

/**
 * Perform the only narrow metadata scan outside managed paths: bundle names.
 * Contents and unrelated filenames are never returned or printed.
 */
async function assertNoOtherBundleSlugCollision(profileDir) {
  const bundlesDir = path.join(profileDir, "skill-bundles");
  assertPathInside(profileDir, bundlesDir, "The bundles directory");
  await assertNoSymlinkAncestors(bundlesDir);
  const dirStat = await lstatOrNull(bundlesDir);
  if (!dirStat) {
    return;
  }
  if (!dirStat.isDirectory() || dirStat.isSymbolicLink()) {
    throw new InstallerError("The Hermes bundle path is not a real directory.");
  }

  const entries = await readdir(bundlesDir);
  for (const entryName of entries) {
    const lowerName = entryName.toLowerCase();
    if (!lowerName.endsWith(".yaml") && !lowerName.endsWith(".yml")) {
      continue;
    }
    const isManagedName = process.platform === "win32"
      ? lowerName === "bountypilot.yaml" || lowerName === "bountypilot.yml"
      : entryName === "bountypilot.yaml" || entryName === "bountypilot.yml";
    if (isManagedName) {
      continue;
    }
    const entryPath = path.join(bundlesDir, entryName);
    const stat = await lstat(entryPath);
    if (stat.isSymbolicLink()) {
      throw new InstallerError("The bundle collision audit found an unsafe symbolic link.");
    }
    if (!stat.isFile()) {
      continue;
    }
    if (stat.size > MAX_BUNDLE_METADATA_BYTES) {
      throw new InstallerError("The bundle collision audit found oversized metadata.");
    }
    const metadata = parseYamlMapping(await readFile(entryPath, "utf8"), "A local bundle", {
      tolerateInvalid: true,
    });
    if (!metadata) {
      continue;
    }
    const fallbackName = path.basename(entryName, path.extname(entryName));
    if (slugifyBundleName(metadata.name ?? fallbackName) === "bountypilot") {
      throw new InstallerError("Another local bundle declares the reserved bountypilot slug.");
    }
  }
}

async function inspectTarget(targetPath, profileDir) {
  assertPathInside(profileDir, targetPath, "A managed target");
  await assertNoSymlinkAncestors(targetPath, { includeLeaf: false });
  const stat = await lstatOrNull(targetPath);
  if (!stat) {
    return { exists: false, sha256: null };
  }
  if (stat.isSymbolicLink()) {
    throw new InstallerError("A managed target is a symbolic link or junction.");
  }
  const kind = stat.isDirectory() ? "directory" : stat.isFile() ? "file" : "unsupported";
  if (kind === "unsupported") {
    throw new InstallerError("A managed target has an unsupported filesystem type.");
  }
  return { exists: true, kind, sha256: await hashManagedPath(targetPath) };
}

/** Build a read-only installation plan. */
export async function createInstallPlan({
  sourceRoot = DEFAULT_SOURCE_ROOT,
  profileDir,
  profile = "bugbounty",
} = {}) {
  if (!profileDir) {
    throw new InstallerError("createInstallPlan requires an explicit profile directory.");
  }
  const normalizedProfile = validateProfileName(profile);
  const absoluteProfile = path.resolve(profileDir);
  const absoluteSource = await validateDistributionSource(sourceRoot);
  await requireExistingProfile(absoluteProfile);
  await assertNoOtherBundleSlugCollision(absoluteProfile);

  const entries = [];
  for (const entry of managedEntries(absoluteSource, absoluteProfile)) {
    const sourceSha256 = await hashManagedPath(entry.sourcePath);
    const target = await inspectTarget(entry.targetPath, absoluteProfile);
    if (target.exists && target.kind !== entry.kind) {
      throw new InstallerError("A managed target has the wrong file or directory type.");
    }
    const action = !target.exists
      ? "install"
      : target.sha256 === sourceSha256
        ? "unchanged"
        : "update";
    entries.push({
      action,
      kind: entry.kind,
      relativePath: entry.relativePath,
      sourceSha256,
      targetSha256: target.sha256,
    });
  }

  const legacyPath = path.join(absoluteProfile, ...LEGACY_BUNDLE_RELATIVE_PATH.split("/"));
  const legacyTarget = await inspectTarget(legacyPath, absoluteProfile);
  if (legacyTarget.exists && legacyTarget.kind !== "file") {
    throw new InstallerError("The legacy managed bundle has the wrong filesystem type.");
  }
  const legacy = {
    action: legacyTarget.exists ? "backup-legacy" : "absent",
    relativePath: LEGACY_BUNDLE_RELATIVE_PATH,
    targetSha256: legacyTarget.sha256,
  };
  const changeCount = entries.filter((entry) => entry.action !== "unchanged").length
    + (legacy.action === "backup-legacy" ? 1 : 0);

  return {
    changeCount,
    entries,
    legacy,
    mode: "plan",
    ok: true,
    profile: normalizedProfile,
    profileDir: absoluteProfile,
    sourceRoot: absoluteSource,
  };
}

/** Verify only the ten managed target paths and the reserved bundle slug. */
export async function verifyInstallation({
  sourceRoot = DEFAULT_SOURCE_ROOT,
  profileDir,
  profile = "bugbounty",
} = {}) {
  if (!profileDir) {
    throw new InstallerError("verifyInstallation requires an explicit profile directory.");
  }
  const normalizedProfile = validateProfileName(profile);
  const absoluteProfile = path.resolve(profileDir);
  const absoluteSource = await validateDistributionSource(sourceRoot);
  await requireExistingProfile(absoluteProfile);
  await assertNoOtherBundleSlugCollision(absoluteProfile);

  const entries = [];
  for (const entry of managedEntries(absoluteSource, absoluteProfile)) {
    const expectedSha256 = await hashManagedPath(entry.sourcePath);
    const target = await inspectTarget(entry.targetPath, absoluteProfile);
    const status = !target.exists
      ? "missing"
      : target.kind !== entry.kind
        ? "type-mismatch"
        : target.sha256 === expectedSha256
        ? "verified"
        : "mismatch";
    entries.push({
      expectedSha256,
      relativePath: entry.relativePath,
      status,
      targetSha256: target.sha256,
    });
  }
  const legacyPath = path.join(absoluteProfile, ...LEGACY_BUNDLE_RELATIVE_PATH.split("/"));
  const legacyTarget = await inspectTarget(legacyPath, absoluteProfile);
  const legacyStatus = !legacyTarget.exists
    ? "absent"
    : legacyTarget.kind === "file"
      ? "present"
      : "type-mismatch";
  const ok = entries.every((entry) => entry.status === "verified") && legacyStatus === "absent";
  return {
    entries,
    legacy: {
      relativePath: LEGACY_BUNDLE_RELATIVE_PATH,
      status: legacyStatus,
      targetSha256: legacyTarget.sha256,
    },
    mode: "verify",
    ok,
    profile: normalizedProfile,
    profileDir: absoluteProfile,
  };
}

async function ensureDirectorySecure(directoryPath, boundary, createdDirectories) {
  const absoluteBoundary = path.resolve(boundary);
  const absoluteDirectory = path.resolve(directoryPath);
  assertPathInside(absoluteBoundary, absoluteDirectory, "A generated directory");
  await assertNoSymlinkAncestors(absoluteBoundary);
  const boundaryStat = await lstatOrNull(absoluteBoundary);
  if (!boundaryStat?.isDirectory() || boundaryStat.isSymbolicLink()) {
    throw new InstallerError("The selected Hermes profile directory became unsafe.");
  }
  const relative = path.relative(absoluteBoundary, absoluteDirectory);
  const parts = relative.split(path.sep).filter(Boolean);
  let current = absoluteBoundary;
  for (const part of parts) {
    current = path.join(current, part);
    const stat = await lstatOrNull(current);
    if (stat) {
      if (stat.isSymbolicLink() || !stat.isDirectory()) {
        throw new InstallerError("A generated directory ancestor is unsafe.");
      }
      continue;
    }
    await mkdir(current);
    createdDirectories.push(current);
  }
}

async function copyTreeSecure(sourcePath, destinationPath, sourceRoot, stagingRoot) {
  assertPathInside(sourceRoot, sourcePath, "A staged source");
  assertPathInside(stagingRoot, destinationPath, "A staging destination");
  await assertNoSymlinkAncestors(sourcePath);
  await assertNoSymlinkAncestors(destinationPath, { includeLeaf: false });
  const stat = await lstat(sourcePath);
  if (stat.isSymbolicLink()) {
    throw new InstallerError("The distribution changed to a symbolic link during staging.");
  }
  if (stat.isDirectory()) {
    await mkdir(destinationPath);
    const children = (await readdir(sourcePath)).sort(compareNames);
    for (const child of children) {
      await copyTreeSecure(
        path.join(sourcePath, child),
        path.join(destinationPath, child),
        sourceRoot,
        stagingRoot,
      );
    }
    return;
  }
  if (!stat.isFile()) {
    throw new InstallerError("The distribution changed to an unsupported entry during staging.");
  }
  await copyFile(sourcePath, destinationPath, fsConstants.COPYFILE_EXCL);
}

function makeRunId(now = new Date()) {
  const timestamp = now.toISOString().replace(/[-:.]/gu, "");
  return `${timestamp}-${randomBytes(6).toString("hex")}`;
}

function makeFaultCheckpoint(faultAfterOperations) {
  if (faultAfterOperations === undefined || faultAfterOperations === null) {
    return () => {};
  }
  if (!Number.isInteger(faultAfterOperations) || faultAfterOperations < 1) {
    throw new InstallerError("faultAfterOperations must be a positive integer.");
  }
  let completed = 0;
  return () => {
    completed += 1;
    if (completed === faultAfterOperations) {
      throw new InstallerError("Injected installer fault for rollback testing.");
    }
  };
}

async function assertTargetMatchesPlan(targetPath, expectedSha256, profileDir) {
  const current = await inspectTarget(targetPath, profileDir);
  if (expectedSha256 === null ? current.exists : current.sha256 !== expectedSha256) {
    throw new InstallerError("A managed target changed after planning; no further changes were made.");
  }
}

async function removeCreatedDirectories(createdDirectories) {
  const unique = [...new Set(createdDirectories)].sort((left, right) => right.length - left.length);
  for (const directoryPath of unique) {
    try {
      await rmdir(directoryPath);
    } catch (error) {
      if (!["ENOENT", "ENOTEMPTY", "EEXIST"].includes(error?.code)) {
        throw error;
      }
    }
  }
}

async function rollbackJournal(journal, stagingRoot, profileDir, createdDirectories) {
  const failures = [];
  for (const item of [...journal].reverse()) {
    try {
      if (item.installed) {
        const installed = await inspectTarget(item.targetPath, profileDir);
        if (!installed.exists || installed.sha256 !== item.installedSha256) {
          throw new InstallerError("A newly installed entry changed before rollback.");
        }
        const rollbackPath = path.join(stagingRoot, "rollback", ...item.relativePath.split("/"));
        await ensureDirectorySecure(path.dirname(rollbackPath), profileDir, createdDirectories);
        await rename(item.targetPath, rollbackPath);
      }
      if (item.originalMoved) {
        const occupied = await lstatOrNull(item.targetPath);
        if (occupied) {
          throw new InstallerError("A rollback target became occupied.");
        }
        await rename(item.backupPath, item.targetPath);
      }
    } catch (error) {
      failures.push(error);
    }
  }
  return failures;
}

/**
 * Apply a prepared safe merge. `faultAfterOperations` is deliberately exposed
 * only through this programmatic API for deterministic rollback tests.
 */
export async function applyManagedEntries({
  sourceRoot = DEFAULT_SOURCE_ROOT,
  profileDir,
  profile = "bugbounty",
  faultAfterOperations,
} = {}) {
  if (!profileDir) {
    throw new InstallerError("applyManagedEntries requires an explicit profile directory.");
  }
  const absoluteProfile = path.resolve(profileDir);
  let plan = await createInstallPlan({ sourceRoot, profileDir: absoluteProfile, profile });
  if (plan.changeCount === 0) {
    return {
      ...plan,
      changed: false,
      mode: "apply",
      verified: true,
    };
  }

  const createdDirectories = [];
  const agentLocalRoot = path.join(absoluteProfile, "local", "bountypilot-agent");
  await assertNoSymlinkAncestors(agentLocalRoot);
  await ensureDirectorySecure(agentLocalRoot, absoluteProfile, createdDirectories);

  const lockPath = path.join(agentLocalRoot, "install.lock");
  let lockHandle;
  try {
    lockHandle = await open(lockPath, "wx");
  } catch (error) {
    await removeCreatedDirectories(createdDirectories);
    if (error?.code === "EEXIST") {
      throw new InstallerError("Another BountyPilot Hermes installation is already running.");
    }
    throw error;
  }

  const runId = makeRunId();
  const stagingRoot = path.join(agentLocalRoot, "staging", runId);
  const backupRoot = path.join(agentLocalRoot, "backups", runId);
  const journal = [];
  let keepRecoveryArtifacts = false;
  const checkpoint = makeFaultCheckpoint(faultAfterOperations);

  try {
    plan = await createInstallPlan({ sourceRoot, profileDir: absoluteProfile, profile });
    if (plan.changeCount === 0) {
      return {
        ...plan,
        changed: false,
        mode: "apply",
        verified: true,
      };
    }

    await ensureDirectorySecure(stagingRoot, absoluteProfile, createdDirectories);
    const allEntries = managedEntries(plan.sourceRoot, absoluteProfile);
    const changingPlans = new Map(
      plan.entries
        .filter((entry) => entry.action !== "unchanged")
        .map((entry) => [entry.relativePath, entry]),
    );

    for (const entry of allEntries) {
      const entryPlan = changingPlans.get(entry.relativePath);
      if (!entryPlan) {
        continue;
      }
      const stagedPath = path.join(stagingRoot, ...entry.relativePath.split("/"));
      await ensureDirectorySecure(path.dirname(stagedPath), absoluteProfile, createdDirectories);
      await copyTreeSecure(entry.sourcePath, stagedPath, plan.sourceRoot, stagingRoot);
      const stagedSha256 = await hashManagedPath(stagedPath);
      if (stagedSha256 !== entryPlan.sourceSha256) {
        throw new InstallerError("A staged entry failed its SHA-256 integrity check.");
      }
    }

    for (const entry of allEntries) {
      const entryPlan = changingPlans.get(entry.relativePath);
      if (!entryPlan) {
        continue;
      }
      await assertTargetMatchesPlan(entry.targetPath, entryPlan.targetSha256, absoluteProfile);
      await ensureDirectorySecure(path.dirname(entry.targetPath), absoluteProfile, createdDirectories);
      const stagedPath = path.join(stagingRoot, ...entry.relativePath.split("/"));
      const backupPath = path.join(backupRoot, ...entry.relativePath.split("/"));
      const journalItem = {
        backupPath,
        installed: false,
        installedSha256: entryPlan.sourceSha256,
        originalMoved: false,
        relativePath: entry.relativePath,
        targetPath: entry.targetPath,
      };
      journal.push(journalItem);

      if (entryPlan.targetSha256 !== null) {
        await ensureDirectorySecure(path.dirname(backupPath), absoluteProfile, createdDirectories);
        await rename(entry.targetPath, backupPath);
        journalItem.originalMoved = true;
        checkpoint();
      }
      await rename(stagedPath, entry.targetPath);
      journalItem.installed = true;
      checkpoint();
    }

    if (plan.legacy.action === "backup-legacy") {
      const legacyTarget = path.join(absoluteProfile, ...LEGACY_BUNDLE_RELATIVE_PATH.split("/"));
      const legacyBackup = path.join(backupRoot, ...LEGACY_BUNDLE_RELATIVE_PATH.split("/"));
      await assertTargetMatchesPlan(legacyTarget, plan.legacy.targetSha256, absoluteProfile);
      await ensureDirectorySecure(path.dirname(legacyBackup), absoluteProfile, createdDirectories);
      const journalItem = {
        backupPath: legacyBackup,
        installed: false,
        installedSha256: null,
        originalMoved: false,
        relativePath: LEGACY_BUNDLE_RELATIVE_PATH,
        targetPath: legacyTarget,
      };
      journal.push(journalItem);
      await rename(legacyTarget, legacyBackup);
      journalItem.originalMoved = true;
      checkpoint();
    }

    const verification = await verifyInstallation({
      sourceRoot: plan.sourceRoot,
      profileDir: absoluteProfile,
      profile,
    });
    if (!verification.ok) {
      throw new InstallerError("Post-install verification failed.");
    }

    await rm(stagingRoot, { force: true, recursive: true });
    return {
      backupRoot: journal.some((item) => item.originalMoved) ? backupRoot : null,
      changed: true,
      changeCount: plan.changeCount,
      entries: verification.entries,
      legacy: verification.legacy,
      mode: "apply",
      ok: true,
      profile: plan.profile,
      profileDir: absoluteProfile,
      verified: true,
    };
  } catch (error) {
    const rollbackFailures = await rollbackJournal(
      journal,
      stagingRoot,
      absoluteProfile,
      createdDirectories,
    );
    if (rollbackFailures.length > 0) {
      keepRecoveryArtifacts = true;
      throw new InstallerError(
        "Installation failed and rollback was incomplete; managed recovery artifacts were preserved.",
        { cause: error },
      );
    }
    await rm(stagingRoot, { force: true, recursive: true });
    throw error;
  } finally {
    try {
      await lockHandle?.close();
    } finally {
      await unlink(lockPath).catch((error) => {
        if (error?.code !== "ENOENT") {
          throw error;
        }
      });
      if (!keepRecoveryArtifacts) {
        await removeCreatedDirectories(createdDirectories);
      }
    }
  }
}

function parseCliArguments(argv) {
  const result = {
    apply: false,
    dryRun: false,
    hermesHome: undefined,
    json: false,
    profile: "bugbounty",
    verify: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--apply") {
      result.apply = true;
    } else if (argument === "--dry-run") {
      result.dryRun = true;
    } else if (argument === "--verify") {
      result.verify = true;
    } else if (argument === "--json") {
      result.json = true;
    } else if (argument === "--help" || argument === "-h") {
      result.help = true;
    } else if (argument === "--profile" || argument === "--hermes-home") {
      const value = argv[index + 1];
      if (!value || value.startsWith("--")) {
        throw new InstallerError(`${argument} requires a value.`);
      }
      index += 1;
      if (argument === "--profile") {
        result.profile = value;
      } else {
        result.hermesHome = value;
      }
    } else if (argument.startsWith("--profile=")) {
      result.profile = argument.slice("--profile=".length);
    } else if (argument.startsWith("--hermes-home=")) {
      result.hermesHome = argument.slice("--hermes-home=".length);
    } else {
      throw new InstallerError("Unknown installer argument.");
    }
  }
  if ([result.apply, result.dryRun, result.verify].filter(Boolean).length > 1) {
    throw new InstallerError("--apply, --dry-run, and --verify are mutually exclusive.");
  }
  return result;
}

function helpText() {
  return [
    "BountyPilot Hermes safe-merge installer",
    "",
    "Usage:",
    "  node scripts/install-hermes-bountypilot.mjs [--dry-run] [--profile bugbounty] [--hermes-home PATH] [--json]",
    "  node scripts/install-hermes-bountypilot.mjs --apply [options]",
    "  node scripts/install-hermes-bountypilot.mjs --verify [options]",
    "",
    "The default mode and --dry-run are read-only plans. --apply is required to change the profile.",
  ].join("\n");
}

function renderHuman(result) {
  const lines = [
    `BountyPilot Hermes ${result.mode}`,
    `Profile: ${result.profile}`,
  ];
  if (result.mode === "plan") {
    lines.push(`Changes required: ${result.changeCount}`);
    for (const entry of result.entries) {
      lines.push(`${entry.action.toUpperCase()} ${entry.relativePath} sha256:${entry.sourceSha256}`);
    }
    lines.push(`${result.legacy.action.toUpperCase()} ${result.legacy.relativePath}`);
    lines.push("No profile files were changed. Re-run with --apply to install this exact managed set.");
  } else if (result.mode === "apply") {
    lines.push(result.changed ? `Applied and verified ${result.changeCount} change(s).` : "Already installed; zero changes made.");
    if (result.backupRelativePath) {
      lines.push(`Conflicting managed entries were backed up under: ${result.backupRelativePath}`);
    }
  } else {
    lines.push(result.ok ? "All managed entries are verified." : "Verification failed for one or more managed entries.");
    for (const entry of result.entries) {
      lines.push(`${entry.status.toUpperCase()} ${entry.relativePath} sha256:${entry.expectedSha256}`);
    }
    lines.push(`${result.legacy.status.toUpperCase()} ${result.legacy.relativePath}`);
  }
  return lines.join("\n");
}

function sanitizeCliResult(result) {
  const {
    backupRoot,
    profileDir,
    sourceRoot: _sourceRoot,
    ...publicResult
  } = result;
  if (backupRoot) {
    if (!profileDir || !isPathInside(profileDir, backupRoot)) {
      throw new InstallerError("The managed backup location failed output sanitization.");
    }
    const relativeBackup = path.relative(profileDir, backupRoot);
    publicResult.backupRelativePath = relativeBackup.split(path.sep).join("/");
  }
  return publicResult;
}

export async function runCli(argv = process.argv.slice(2), environment = process.env) {
  const options = parseCliArguments(argv);
  if (options.help) {
    return { exitCode: 0, help: helpText(), json: options.json };
  }
  const resolved = resolveHermesProfile({
    env: environment,
    hermesHome: options.hermesHome,
    profile: options.profile,
  });
  let result;
  if (options.verify) {
    result = await verifyInstallation({
      profile: resolved.profile,
      profileDir: resolved.profileDir,
    });
  } else if (options.apply) {
    result = await applyManagedEntries({
      profile: resolved.profile,
      profileDir: resolved.profileDir,
    });
  } else {
    result = await createInstallPlan({
      profile: resolved.profile,
      profileDir: resolved.profileDir,
    });
  }
  const publicResult = sanitizeCliResult(result);
  return {
    exitCode: options.verify && !result.ok ? 1 : 0,
    json: options.json,
    result: publicResult,
  };
}

async function main() {
  const jsonRequested = process.argv.slice(2).includes("--json");
  try {
    const outcome = await runCli();
    if (outcome.help) {
      process.stdout.write(`${outcome.help}\n`);
    } else if (outcome.json) {
      process.stdout.write(`${JSON.stringify(outcome.result, null, 2)}\n`);
    } else {
      process.stdout.write(`${renderHuman(outcome.result)}\n`);
    }
    process.exitCode = outcome.exitCode;
  } catch (error) {
    const message = error instanceof InstallerError
      ? error.message
      : "The installer failed safely because of an unexpected filesystem error.";
    if (jsonRequested) {
      process.stderr.write(`${JSON.stringify({ error: message, ok: false })}\n`);
    } else {
      process.stderr.write(`BountyPilot Hermes installer: ${message}\n`);
    }
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === SCRIPT_PATH) {
  await main();
}
