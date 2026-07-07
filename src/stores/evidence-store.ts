import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { BountyDatabase } from "./db/database.js";
import type { EvidenceArtifact } from "../types.js";
import { BountyPilotError } from "../utils/errors.js";
import { createId } from "../utils/ids.js";
import { maskSecrets } from "../utils/secrets.js";
import { nowIso } from "../utils/time.js";

export interface NewEvidenceInput extends Omit<EvidenceArtifact, "id" | "createdAt"> {
  id?: string;
  createdAt?: string;
}

export interface EvidenceManifestEntry extends EvidenceArtifact {
  relativePath?: string;
  bytes?: number;
  sha256?: string;
  readable: boolean;
}

export interface EvidenceManifest {
  generatedAt: string;
  evidenceRoot: string;
  findingId?: string;
  jobId?: string;
  artifactCount: number;
  artifacts: EvidenceManifestEntry[];
  safety: {
    contentsEmbedded: false;
    note: string;
  };
}

export interface EvidenceManifestInput {
  findingId?: string;
  jobId?: string;
  relativePath?: string;
  id?: string;
  createdAt?: string;
}

export interface EvidenceStoreOptions {
  maskSecrets?: boolean;
  trustedArtifactRoots?: string[];
}

export class EvidenceStore {
  constructor(
    private readonly db: BountyDatabase,
    private readonly evidenceRoot: string,
    private readonly options: EvidenceStoreOptions = {},
  ) {}

  writeTextArtifact(input: Omit<NewEvidenceInput, "path"> & { relativePath: string; content: string }): EvidenceArtifact {
    const artifactPath = this.resolveArtifactPath(input.relativePath);
    writeFileSync(artifactPath, this.maskText(input.content), "utf8");
    return this.create({
      id: input.id,
      findingId: input.findingId,
      jobId: input.jobId,
      adapterName: input.adapterName,
      kind: input.kind,
      sourceUrl: input.sourceUrl,
      path: artifactPath,
      createdAt: input.createdAt,
    });
  }

  copyFileArtifact(input: Omit<NewEvidenceInput, "path"> & { sourcePath: string; relativePath: string }): EvidenceArtifact {
    const sourcePath = path.resolve(input.sourcePath);
    const stats = statEvidenceSource(sourcePath);
    if (!stats.isFile()) {
      throw new BountyPilotError(`Evidence source is not a file: ${sourcePath}`, "EVIDENCE_SOURCE_NOT_FILE");
    }

    const artifactPath = this.resolveArtifactPath(input.relativePath);
    copyFileSync(sourcePath, artifactPath);
    return this.create({
      id: input.id,
      findingId: input.findingId,
      jobId: input.jobId,
      adapterName: input.adapterName,
      kind: input.kind,
      sourceUrl: input.sourceUrl,
      path: artifactPath,
      createdAt: input.createdAt,
    });
  }

  create(input: NewEvidenceInput): EvidenceArtifact {
    const artifactPath = this.resolveTrustedArtifactPath(input.path);
    const artifact: EvidenceArtifact = {
      id: input.id ?? createId("evidence"),
      findingId: input.findingId,
      jobId: input.jobId,
      adapterName: input.adapterName,
      kind: input.kind,
      sourceUrl: input.sourceUrl,
      path: artifactPath,
      createdAt: input.createdAt ?? nowIso(),
    };
    this.maskExistingTextArtifact(artifact.path, artifact.kind);

    this.db
      .prepare(
        `INSERT INTO evidence_artifacts (
          id, finding_id, job_id, adapter_name, kind, source_url, path, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        artifact.id,
        artifact.findingId ?? null,
        artifact.jobId ?? null,
        artifact.adapterName,
        artifact.kind,
        artifact.sourceUrl ?? null,
        artifact.path,
        artifact.createdAt,
      );

    return artifact;
  }

  list(findingId?: string): EvidenceArtifact[] {
    if (!findingId) {
      const rows = this.db.prepare("SELECT * FROM evidence_artifacts ORDER BY created_at DESC").all() as unknown as EvidenceRow[];
      return rows.map(rowToEvidence);
    }

    const directRows = this.db
      .prepare("SELECT * FROM evidence_artifacts WHERE finding_id = ? ORDER BY created_at DESC")
      .all(findingId) as unknown as EvidenceRow[];
    const pathRows = this.rowsForFindingEvidencePaths(findingId);
    return sortEvidenceRows(uniqueEvidenceRows([...directRows, ...pathRows])).map(rowToEvidence);
  }

  get(id: string): EvidenceArtifact | undefined {
    const row = this.db.prepare("SELECT * FROM evidence_artifacts WHERE id = ?").get(id) as EvidenceRow | undefined;
    return row ? rowToEvidence(row) : undefined;
  }

  linkToFinding(id: string, findingId: string): EvidenceArtifact | undefined {
    const artifact = this.get(id);
    if (!artifact) {
      return undefined;
    }
    this.db.prepare("UPDATE evidence_artifacts SET finding_id = ? WHERE id = ?").run(findingId, id);
    return { ...artifact, findingId };
  }

  buildManifest(input: Omit<EvidenceManifestInput, "relativePath" | "id" | "createdAt"> = {}): EvidenceManifest {
    const artifacts = this.list(input.findingId).filter((artifact) => !input.jobId || artifact.jobId === input.jobId);
    const entries = artifacts.map((artifact) => toManifestEntry(artifact, this.evidenceRoot, this.trustedRoots()));

    return {
      generatedAt: nowIso(),
      evidenceRoot: path.resolve(this.evidenceRoot),
      findingId: input.findingId,
      jobId: input.jobId,
      artifactCount: entries.length,
      artifacts: entries,
      safety: {
        contentsEmbedded: false,
        note:
          "Manifest records metadata, hashes, and local paths only. Review artifacts manually and redact sensitive data before attaching evidence to a third-party platform.",
      },
    };
  }

  buildManifestForArtifacts(
    artifacts: EvidenceArtifact[],
    input: Omit<EvidenceManifestInput, "relativePath" | "id" | "createdAt"> = {},
  ): EvidenceManifest {
    const filtered = artifacts.filter((artifact) => !input.jobId || artifact.jobId === input.jobId);
    const entries = filtered.map((artifact) => toManifestEntry(artifact, this.evidenceRoot, this.trustedRoots()));

    return {
      generatedAt: nowIso(),
      evidenceRoot: path.resolve(this.evidenceRoot),
      findingId: input.findingId,
      jobId: input.jobId,
      artifactCount: entries.length,
      artifacts: entries,
      safety: {
        contentsEmbedded: false,
        note:
          "Manifest records metadata, hashes, and local paths only. Review artifacts manually and redact sensitive data before attaching evidence to a third-party platform.",
      },
    };
  }

  writeManifest(input: EvidenceManifestInput = {}): EvidenceArtifact {
    const manifest = this.buildManifest({ findingId: input.findingId, jobId: input.jobId });
    const relativePath = input.relativePath ?? defaultManifestPath(input);
    return this.writeTextArtifact({
      id: input.id,
      findingId: input.findingId,
      jobId: input.jobId,
      adapterName: "evidence-store",
      kind: "tool_output",
      relativePath,
      createdAt: input.createdAt,
      content: `${JSON.stringify(manifest, null, 2)}\n`,
    });
  }

  private resolveArtifactPath(relativePath: string): string {
    if (path.isAbsolute(relativePath)) {
      throw new BountyPilotError(
        "Evidence artifact paths must be relative to the evidence directory.",
        "EVIDENCE_PATH_ABSOLUTE",
      );
    }

    const root = path.resolve(this.evidenceRoot);
    const artifactPath = path.resolve(root, relativePath);
    const pathFromRoot = path.relative(root, artifactPath);
    if (pathFromRoot.startsWith("..") || path.isAbsolute(pathFromRoot)) {
      throw new BountyPilotError("Evidence artifact path escapes the evidence directory.", "EVIDENCE_PATH_ESCAPES_ROOT");
    }

    this.ensureParentDirectoryInsideRoot(artifactPath, this.evidenceRootInfo());
    if (existsSync(artifactPath)) {
      assertExistingPathInTrustedRoots(artifactPath, [this.evidenceRootInfo()]);
    }
    return artifactPath;
  }

  private resolveTrustedArtifactPath(artifactPath: string): string {
    const resolvedPath = path.resolve(artifactPath);
    const roots = this.trustedRoots();
    if (existsSync(resolvedPath)) {
      assertExistingPathInTrustedRoots(resolvedPath, roots);
      return resolvedPath;
    }
    if (!roots.some((root) => isInsideRoot(root.rootPath, resolvedPath) || isInsideRoot(root.realPath, resolvedPath))) {
      throw new BountyPilotError("Evidence artifact path escapes trusted artifact roots.", "EVIDENCE_PATH_ESCAPES_ROOT");
    }
    return resolvedPath;
  }

  private ensureParentDirectoryInsideRoot(artifactPath: string, root: TrustedRoot): void {
    const parentPath = path.dirname(artifactPath);
    const relativeParent = path.relative(root.rootPath, parentPath);
    if (relativeParent.startsWith("..") || path.isAbsolute(relativeParent)) {
      throw new BountyPilotError("Evidence artifact path escapes the evidence directory.", "EVIDENCE_PATH_ESCAPES_ROOT");
    }

    let currentPath = root.rootPath;
    for (const segment of relativeParent.split(path.sep).filter(Boolean)) {
      currentPath = path.join(currentPath, segment);
      if (existsSync(currentPath)) {
        const stats = statSync(currentPath);
        if (!stats.isDirectory()) {
          throw new BountyPilotError(`Evidence artifact parent is not a directory: ${currentPath}`, "EVIDENCE_PATH_INVALID");
        }
        assertExistingPathInTrustedRoots(currentPath, [root]);
        continue;
      }
      mkdirSync(currentPath);
      assertExistingPathInTrustedRoots(currentPath, [root]);
    }
  }

  private evidenceRootInfo(): TrustedRoot {
    return trustedRootInfo(this.evidenceRoot);
  }

  private trustedRoots(): TrustedRoot[] {
    const roots = [this.evidenceRoot, ...(this.options.trustedArtifactRoots ?? [])].map(trustedRootInfo);
    const seen = new Set<string>();
    return roots.filter((root) => {
      if (seen.has(root.realPath)) {
        return false;
      }
      seen.add(root.realPath);
      return true;
    });
  }

  private maskText(content: string): string {
    return this.options.maskSecrets === false ? content : maskSecrets(content);
  }

  private maskExistingTextArtifact(filePath: string, kind: EvidenceArtifact["kind"]): void {
    if (this.options.maskSecrets === false || !isTextArtifactKind(kind) || !existsSync(filePath)) {
      return;
    }
    try {
      const content = readFileSync(filePath, "utf8");
      const masked = maskSecrets(content);
      if (masked !== content) {
        writeFileSync(filePath, masked, "utf8");
      }
    } catch {
      // Non-text artifacts are ignored; binary kinds are excluded before this point.
    }
  }

  private rowsForFindingEvidencePaths(findingId: string): EvidenceRow[] {
    const evidencePaths = this.findingEvidencePaths(findingId);
    if (evidencePaths.length === 0) {
      return [];
    }

    const placeholders = evidencePaths.map(() => "?").join(", ");
    return this.db
      .prepare(`SELECT * FROM evidence_artifacts WHERE path IN (${placeholders}) ORDER BY created_at DESC`)
      .all(...evidencePaths) as unknown as EvidenceRow[];
  }

  private findingEvidencePaths(findingId: string): string[] {
    const row = this.db.prepare("SELECT evidence_paths FROM findings WHERE id = ?").get(findingId) as
      | { evidence_paths: string }
      | undefined;
    if (!row) {
      return [];
    }

    try {
      const parsed = JSON.parse(row.evidence_paths) as unknown;
      return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string" && item.length > 0) : [];
    } catch {
      return [];
    }
  }
}

function statEvidenceSource(sourcePath: string) {
  try {
    return statSync(sourcePath);
  } catch (error) {
    if (isNodeError(error) && error.code === "ENOENT") {
      throw new BountyPilotError(`Evidence source not found: ${sourcePath}`, "EVIDENCE_SOURCE_NOT_FOUND");
    }
    const reason = error instanceof Error ? error.message : String(error);
    throw new BountyPilotError(`Could not read evidence source metadata: ${reason}`, "EVIDENCE_SOURCE_READ_FAILED");
  }
}

interface EvidenceRow {
  id: string;
  finding_id?: string | null;
  job_id?: string | null;
  adapter_name: string;
  kind: EvidenceArtifact["kind"];
  source_url?: string | null;
  path: string;
  created_at: string;
}

function rowToEvidence(row: EvidenceRow): EvidenceArtifact {
  return {
    id: row.id,
    findingId: row.finding_id ?? undefined,
    jobId: row.job_id ?? undefined,
    adapterName: row.adapter_name,
    kind: row.kind,
    sourceUrl: row.source_url ?? undefined,
    path: row.path,
    createdAt: row.created_at,
  };
}

function uniqueEvidenceRows(rows: EvidenceRow[]): EvidenceRow[] {
  const seen = new Set<string>();
  const uniqueRows: EvidenceRow[] = [];
  for (const row of rows) {
    if (seen.has(row.id)) {
      continue;
    }
    seen.add(row.id);
    uniqueRows.push(row);
  }
  return uniqueRows;
}

function sortEvidenceRows(rows: EvidenceRow[]): EvidenceRow[] {
  return [...rows].sort((left, right) => right.created_at.localeCompare(left.created_at));
}

interface TrustedRoot {
  rootPath: string;
  realPath: string;
}

function trustedRootInfo(rootPath: string): TrustedRoot {
  const resolvedRoot = path.resolve(rootPath);
  mkdirSync(resolvedRoot, { recursive: true });
  return {
    rootPath: resolvedRoot,
    realPath: realpathSync.native(resolvedRoot),
  };
}

function assertExistingPathInTrustedRoots(artifactPath: string, roots: TrustedRoot[]): void {
  const realPath = realpathSync.native(artifactPath);
  if (!roots.some((root) => isInsideRoot(root.realPath, realPath))) {
    throw new BountyPilotError("Evidence artifact path escapes trusted artifact roots.", "EVIDENCE_PATH_ESCAPES_ROOT");
  }
}

function isInsideRoot(rootPath: string, candidatePath: string): boolean {
  const relativePath = path.relative(rootPath, candidatePath);
  return relativePath === "" || (!relativePath.startsWith("..") && !path.isAbsolute(relativePath));
}

function toManifestEntry(artifact: EvidenceArtifact, evidenceRoot: string, trustedRoots: TrustedRoot[]): EvidenceManifestEntry {
  const fileMetadata = readArtifactFileMetadata(artifact.path, trustedRoots);
  const relativePath = relativePathFromRoot(evidenceRoot, artifact.path);
  return {
    ...artifact,
    ...(relativePath ? { relativePath } : {}),
    ...fileMetadata,
  };
}

function readArtifactFileMetadata(
  artifactPath: string,
  trustedRoots: TrustedRoot[],
): Pick<EvidenceManifestEntry, "bytes" | "sha256" | "readable"> {
  try {
    const realPath = realpathSync.native(artifactPath);
    if (!trustedRoots.some((root) => isInsideRoot(root.realPath, realPath))) {
      return { readable: false };
    }
    const stats = statSync(realPath);
    if (!stats.isFile()) {
      return { readable: false };
    }
    const content = readFileSync(realPath);
    return {
      bytes: stats.size,
      sha256: createHash("sha256").update(content).digest("hex"),
      readable: true,
    };
  } catch {
    return { readable: false };
  }
}

function relativePathFromRoot(rootPath: string, artifactPath: string): string | undefined {
  const root = path.resolve(rootPath);
  const resolvedArtifactPath = path.resolve(artifactPath);
  const relativePath = path.relative(root, resolvedArtifactPath);
  if (!relativePath || relativePath.startsWith("..") || path.isAbsolute(relativePath)) {
    return undefined;
  }
  return relativePath;
}

function isTextArtifactKind(kind: EvidenceArtifact["kind"]): boolean {
  return kind !== "screenshot" && kind !== "video" && kind !== "desktop_screenshot" && kind !== "browser_trace";
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

function defaultManifestPath(input: Pick<EvidenceManifestInput, "findingId" | "jobId">): string {
  return path.join(input.findingId ?? input.jobId ?? "workspace", "evidence-manifest.json");
}
