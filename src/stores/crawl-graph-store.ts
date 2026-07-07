import { createHash } from "node:crypto";
import type { BountyDatabase } from "./db/database.js";
import { createId } from "../utils/ids.js";
import { nowIso } from "../utils/time.js";

export interface CrawlPageRecord {
  url: string;
  title?: string;
  status?: number;
  contentHash?: string;
  firstSeenAt: string;
  lastSeenAt: string;
}

export interface CrawlEdgeRecord {
  id: string;
  fromUrl: string;
  toUrl: string;
  createdAt: string;
}

export class CrawlGraphStore {
  constructor(private readonly db: BountyDatabase) {}

  upsertPage(input: { url: string; title?: string; status?: number; content?: string }): CrawlPageRecord {
    const now = nowIso();
    const existing = this.getPage(input.url);
    const contentHash = input.content ? hashContent(input.content) : existing?.contentHash;

    if (existing) {
      this.db
        .prepare("UPDATE crawl_pages SET title = ?, status = ?, content_hash = ?, last_seen_at = ? WHERE url = ?")
        .run(input.title ?? existing.title ?? null, input.status ?? existing.status ?? null, contentHash ?? null, now, input.url);
      return {
        ...existing,
        title: input.title ?? existing.title,
        status: input.status ?? existing.status,
        contentHash,
        lastSeenAt: now,
      };
    }

    const record: CrawlPageRecord = {
      url: input.url,
      title: input.title,
      status: input.status,
      contentHash,
      firstSeenAt: now,
      lastSeenAt: now,
    };
    this.db
      .prepare(
        "INSERT INTO crawl_pages (url, title, status, content_hash, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)",
      )
      .run(record.url, record.title ?? null, record.status ?? null, record.contentHash ?? null, now, now);
    return record;
  }

  addEdge(fromUrl: string, toUrl: string): CrawlEdgeRecord {
    const record: CrawlEdgeRecord = {
      id: createId("edge"),
      fromUrl,
      toUrl,
      createdAt: nowIso(),
    };
    this.db
      .prepare("INSERT INTO crawl_edges (id, from_url, to_url, created_at) VALUES (?, ?, ?, ?)")
      .run(record.id, record.fromUrl, record.toUrl, record.createdAt);
    return record;
  }

  getPage(url: string): CrawlPageRecord | undefined {
    const row = this.db.prepare("SELECT * FROM crawl_pages WHERE url = ?").get(url) as unknown as CrawlPageRow | undefined;
    return row ? rowToPage(row) : undefined;
  }

  listPages(): CrawlPageRecord[] {
    const rows = this.db.prepare("SELECT * FROM crawl_pages ORDER BY last_seen_at DESC").all() as unknown as CrawlPageRow[];
    return rows.map(rowToPage);
  }
}

interface CrawlPageRow {
  url: string;
  title?: string | null;
  status?: number | null;
  content_hash?: string | null;
  first_seen_at: string;
  last_seen_at: string;
}

function rowToPage(row: CrawlPageRow): CrawlPageRecord {
  return {
    url: row.url,
    title: row.title ?? undefined,
    status: row.status ?? undefined,
    contentHash: row.content_hash ?? undefined,
    firstSeenAt: row.first_seen_at,
    lastSeenAt: row.last_seen_at,
  };
}

function hashContent(content: string): string {
  return createHash("sha256").update(content).digest("hex");
}
