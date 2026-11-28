/**
 * Unified metadata store (PRD §25) — durable by design.
 *
 * Drivers:
 * 1. DATABASE_URL (Postgres, e.g. Vercel Postgres / Neon) — PRODUCTION path.
 *    The metadata document lives in a jsonb row and is mutated under a row
 *    lock (`SELECT … FOR UPDATE`), so every serverless instance sees the same
 *    truth: sessions, users, verification tokens and branding survive cold
 *    starts. This is what makes sign-in stick.
 * 2. ./data/db.json — local development fallback. Never a silent production
 *    fallback: production deployments must provide DATABASE_URL.
 */
import { promises as fs } from "fs";
import os from "os";
import path from "path";
import { Pool, type PoolClient } from "pg";

export type UserStatus =
  | "unverified"
  | "pending"
  | "approved"
  | "rejected"
  | "suspended"
  | "deleted";

export type StoredUser = {
  id: string;
  role: "user" | "admin";
  mfaEnrolled: boolean;
  email: string; // normalised: trimmed + lowercase (AUTH-02)
  name: string;
  passwordHash: string;
  status: UserStatus;
  statusHistory: { status: string; at: string; by: string; reason?: string }[];
  emailVerifiedAt: string | null;
  lastSignInAt: string | null;
  failedSignInCount: number;
  lockedUntil: string | null;
  requestSubmittedAt: string | null;
  createdAt: string;
  requestText: string | null;
};

export type AccessRequest = {
  id: string;
  userId: string;
  fullName: string;
  organisation: string;
  dataTypes: string;
  jobRole: string;
  intendedUse: string;
  createdAt: string;
  status: "pending" | "approved" | "rejected";
  reasonCode?: string;
  reasonMessage?: string;
  decidedBy?: string;
  decidedAt?: string;
};

export type TokenRecord = {
  id: string;
  userId: string;
  tokenHash: string;
  kind: "verify_email" | "reset_password";
  expiresAt: string;
  usedAt: string | null;
  createdAt: string;
};

export type SessionRecord = {
  id: string;
  userId: string;
  role: "user" | "admin";
  createdAt: string;
  lastSeenAt: string;
  revokedAt: string | null;
};

export type AuditEvent = {
  id: string;
  adminId: string | null;
  action: string;
  targetType: "user" | "branding" | "request" | "admin" | "system";
  targetId: string | null;
  details: string;
  timestamp: string;
};

export type PlatformSettings = {
  platformName: string;
  logoReference: string | null;
  logoDarkReference: string | null;
  updatedBy: string;
  updatedAt: string;
};

export type Db = {
  users: StoredUser[];
  accessRequests: AccessRequest[];
  tokens: TokenRecord[];
  sessions: SessionRecord[];
  adminAuditEvents: AuditEvent[];
  platformSettings: PlatformSettings;
  brandVersions: (PlatformSettings & { id: string; changedAt: string })[];
};

export function emptyDb(): Db {
  return {
    users: [],
    accessRequests: [],
    tokens: [],
    sessions: [],
    adminAuditEvents: [],
    platformSettings: {
      platformName: "CleanCSV",
      logoReference: null,
      logoDarkReference: null,
      updatedBy: "default",
      updatedAt: new Date().toISOString(),
    },
    brandVersions: [],
  };
}

const onVercel = process.env.VERCEL === "1" || Boolean(process.env.NOW_REGION);

const usingPostgres = Boolean(process.env.DATABASE_URL);

const DATA_DIR =
  process.env.CLEANCSV_DATA_DIR ??
  (onVercel ? path.join(os.tmpdir(), "cleancsv-data") : path.join(process.cwd(), "data"));
const DB_PATH = path.join(DATA_DIR, "db.json");

/** Is durable metadata storage usable in this deployment? */
export function storeReady(): boolean {
  return usingPostgres || !onVercel; // Vercel without a DB is NOT durable
}

let pool: Pool | null = null;

function getPool(): Pool {
  if (!pool) {
    const connectionString = process.env.DATABASE_URL ?? "";
    const needsSsl = /neon|sslmode|render\.com|supabase/i.test(connectionString);
    pool = new Pool({
      connectionString,
      max: 3,
      ssl: needsSsl ? { rejectUnauthorized: false } : undefined,
    });
  }
  return pool;
}

async function ensureTable(client: PoolClient): Promise<void> {
  await client.query(`
    CREATE TABLE IF NOT EXISTS cleancsv_store (
      id TEXT PRIMARY KEY,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

async function postgresLoad(): Promise<Db> {
  const client = await getPool().connect();
  try {
    await ensureTable(client);
    const res = await client.query<{ data: Db }>(
      "SELECT data FROM cleancsv_store WHERE id = 'default'",
    );
    return res.rows.length ? res.rows[0].data : emptyDb();
  } finally {
    client.release();
  }
}

async function postgresPersist(mutate: (db: Db) => void | Promise<void>): Promise<void> {
  const client = await getPool().connect();
  try {
    await ensureTable(client);
    await client.query("BEGIN");
    const res = await client.query<{ data: Db }>(
      "SELECT data FROM cleancsv_store WHERE id = 'default' FOR UPDATE",
    );
    const db: Db = res.rows.length ? res.rows[0].data : emptyDb();
    await mutate(db);
    await client.query(
      `INSERT INTO cleancsv_store (id, data, updated_at) VALUES ('default', $1, now())
       ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`,
      [JSON.stringify(db)],
    );
    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK").catch(() => undefined);
    throw error;
  } finally {
    client.release();
  }
}

let current: Db | null = null;
let writeQueue: Promise<void> = Promise.resolve();

async function filePersist(): Promise<void> {
  if (!current) return;
  const snapshot = current;
  writeQueue = writeQueue.then(async () => {
    await fs.mkdir(DATA_DIR, { recursive: true });
    const tmp = DB_PATH + ".tmp";
    await fs.writeFile(tmp, JSON.stringify(snapshot, null, 2), "utf8");
    await fs.rename(tmp, DB_PATH);
  });
  return writeQueue;
}

export async function loadDb(): Promise<Db> {
  if (usingPostgres) return postgresLoad();

  if (current) return current;
  try {
    const raw = await fs.readFile(DB_PATH, "utf8");
    current = { ...emptyDb(), ...(JSON.parse(raw) as Partial<Db>) };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      current = emptyDb();
    } else {
      console.error("[cleancsv] store file unreadable — quarantining", error);
      await fs.copyFile(DB_PATH, `${DB_PATH}.corrupt-${Date.now()}`).catch(() => undefined);
      current = emptyDb();
    }
    (async () => await filePersist())();
  }
  return current;
}

/**
 * Sequence a read-modify-write against the durable store. Mutations receive a
 * plain mutable Db object; Postgres runs them inside a locked transaction so
 * concurrent serverless instances cannot lose one another's writes.
 */
export async function withDb<T>(mutate: (db: Db) => T | Promise<T>): Promise<T> {
  if (usingPostgres) {
    let result!: T;
    await postgresPersist(async (db) => {
      result = await mutate(db);
    });
    return result;
  }

  const db = await withFileDb(mutate);
  await filePersist();
  return db;

  async function withFileDb(fn: (db: Db) => T | Promise<T>): Promise<T> {
    const loaded = await loadDb();
    return fn(loaded);
  }
}
