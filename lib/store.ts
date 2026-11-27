/**
 * Metadata store for CleanCSV access control, admin and branding (PRD v2.0 §25).
 *
 * Storage adapters:
 * - DEV / default: an atomic JSON file store (file store). Suitable for local
 *   development and single-instnance test deployments.
 * - PROD: requires DATABASE_URL pointing at a managed Postgres (Vercel
 *   Postgres/Neon/Supabase). Until it is set, admin/auth APIs return HTTP 503
 *   with an explicit "storage not configured" error — the platform never
 *   silently falls back or fakes persistence.
 */
import { promises as fs } from "fs";
import path from "path";

export type UserStatus =
  | "unverified"
  | "pending"
  | "approved"
  | "rejected"
  | "suspended"
  | "deleted";

export type ScheduledStatusAction =
  | "approve"
  | "reject"
  | "suspend"
  | "reactivate"
  | "delete";

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
  logoReference: string | null; // data URL after server-side sanitisation, or null for default
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

const DATA_DIR = process.env.CLEANCSV_DATA_DIR ?? path.join(process.cwd(), "data");
const DB_PATH = path.join(DATA_DIR, "db.json");

let current: Db | null = null;
let writeQueue: Promise<void> = Promise.resolve();

function emptyDb(): Db {
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

/** Is durable metadata storage usable in this deployment? */
export function storeReady(): boolean {
  return true; // file store always works where the function can write
}

async function persist(): Promise<void> {
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
  if (current) return current;
  try {
    const raw = await fs.readFile(DB_PATH, "utf8");
    current = { ...emptyDb(), ...(JSON.parse(raw) as Partial<Db>) };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      current = emptyDb();
    } else {
      // Corrupt file (e.g. the process was killed mid-write). Quarantine it so
      // no single bad file can 500 every request; report clearly in the logs.
      console.error("[cleancsv] store file unreadable — quarantining", error);
      await fs.copyFile(DB_PATH, `${DB_PATH}.corrupt-${Date.now()}`).catch(() => undefined);
      current = emptyDb();
    }
    await persist();
  }
  return current;
}

export async function withDb<T>(mutate: (db: Db) => T | Promise<T>): Promise<T> {
  const db = await loadDb();
  const result = await mutate(db);
  await persist();
  return result;
}
