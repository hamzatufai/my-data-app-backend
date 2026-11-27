import { preflight } from "@/lib/cors";
/**
 * BRD-01/02/03: platform name + logo. Anyone can GET current branding
 * (needed by the header/sign-in pages); only the admin can publish.
 * POST validates: name 2–60 chars, no HTML; logo content-sniffed, ≤2 MB;
 * SVG is sanitised (scripts/external refs stripped).
 */
import {
  Forbidden, ValidationError, fail, handleError, json, readJsonBody,
} from "@/lib/api-helpers";
import { requireAdmin } from "@/lib/api-helpers";
import { loadDb, withDb, type PlatformSettings } from "@/lib/store";
import { newId } from "@/lib/auth";

const MAX_LOGO_BYTES = 2 * 1024 * 1024;
const VERSIONS_KEPT = 5;

const ALLOWED_IMAGE_START: Record<string, string> = {
  "89504e47": "image/png",
  "ffd8ff": "image/jpeg",
  "52494646": "image/webp", // RIFF....WEBP
  "3c737667": "image/svg", // <svg
  "3c3f786d": "image/svg", // <?xm
};

function sniffFile(buffer: Buffer): string | null {
  const hex = buffer.subarray(0, 8).toString("hex");
  for (const [sig, mime] of Object.entries(ALLOWED_IMAGE_START)) {
    if (hex.startsWith(sig)) return mime;
  }
  return null;
}

function sanitiseSvg(source: string): string {
  return source
    // Remove script blocks and inline event handlers.
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/\son\w+\s*=\s*"[^"]*"/gi, "")
    .replace(/\son\w+\s*=\s*'[^']*'/gi, "")
    // Remove external references (href/src to remote hosts).
    .replace(/\s(?:href|src|xlink:href)\s*=\s*["'](?:https?:|\/\/)[^"']*["']/gi, "")
    .replace(/javascript\s*:/gi, "");
}

function dataUrlFor(mime: string, buffer: Buffer): string {
  return `data:${mime};base64,${buffer.toString("base64")}`;
}

export async function GET(request: Request) {
  try {
    const db = await loadDb();
    const settings: PlatformSettings = db.platformSettings ?? {
      platformName: "CleanCSV",
      logoReference: null,
      logoDarkReference: null,
      updatedBy: "default",
      updatedAt: new Date().toISOString(),
    };
    return json(request, {
      platformName: settings.platformName,
      logoUrl: settings.logoReference,
      logoDarkUrl: settings.logoDarkReference,
      updatedAt: settings.updatedAt,
    });
  } catch (error) {
    return handleError(request, error);
  }
}

export async function PUT(request: Request) {
  try {
    const db = await loadDb();
    const { user: admin } = await requireAdmin(request, db);
    const body = await readJsonBody(request);

    let platformName = typeof body.platformName === "string" ? body.platformName.trim() : undefined;
    let logoDarkReference: string | null | undefined = undefined as never;
    void logoDarkReference;

    if (platformName !== undefined) {
      if (platformName.length < 2 || platformName.length > 60) {
        throw new ValidationError("Platform name must be 2–60 characters.");
      }
      if (/[<>]/.test(platformName)) {
        throw new ValidationError("HTML is not allowed in the platform name.");
      }
    }

    let logoReference: string | null | undefined;
    let logoDark: string | null | undefined;
    for (const key of ["logoDataUrl", "logoDarkDataUrl"] as const) {
      const value = typeof body[key] === "string" ? (body[key] as string) : undefined;
      if (value === undefined) continue;
      const match = /^data:([^;,]+);base64,(.+)$/.exec(value);
      if (!match) throw new ValidationError("Logo must be a base64 data URL.");
      const buffer = Buffer.from(match[2], "base64");
      if (buffer.length > MAX_LOGO_BYTES) {
        throw new ValidationError("Logo must be at most 2 MB (BRD-02).");
      }
      const mime = sniffFile(buffer);
      if (!mime) throw new ValidationError("Logo file type is not recognised. Use PNG, JPG, WebP or SVG.");
      if (mime === "image/svg") {
        const cleaned = sanitiseSvg(buffer.toString("utf8"));
        if (/<script/i.test(cleaned) || /on\w+\s=/i.test(cleaned)) {
          throw new ValidationError("This SVG contains script content and was rejected.");
        }
        const signed = dataUrlFor("image/svg+xml", Buffer.from(cleaned, "utf8"));
        if (key === "logoDataUrl") logoReference = signed;
        else logoDark = signed;
      } else {
        const signed = dataUrlFor(mime, buffer);
        if (key === "logoDataUrl") logoReference = signed;
        else logoDark = signed;
      }
    }
    if (body.resetLogo === true) logoReference = null;
    if (body.resetLogoDark === true) logoDark = null;

    const previous = { ...db.platformSettings };
    const now = new Date().toISOString();

    await withDb((store) => {
      const next: PlatformSettings = {
        platformName: platformName ?? previous.platformName,
        logoReference: logoReference !== undefined ? logoReference : previous.logoReference,
        logoDarkReference: logoDark !== undefined ? logoDark : previous.logoDarkReference,
        updatedBy: admin.email,
        updatedAt: now,
      };
      store.brandVersions.push({ ...previous, id: newId(), changedAt: now });
      while (store.brandVersions.length > VERSIONS_KEPT) store.brandVersions.shift();
      store.platformSettings = next;
      store.adminAuditEvents.push({
        id: newId(),
        adminId: admin.id,
        action: "branding.published",
        targetType: "branding",
        targetId: null,
        details: `Name: ${next.platformName}; logo: ${next.logoReference ? "custom" : "default"}`,
        timestamp: now,
      });
    });

    return json(request, { message: "Branding applied platform-wide.", updatedAt: now });
  } catch (error) {
    return handleError(request, error);
  }
}

export async function OPTIONS(request: Request) {
  return preflight(request);
}
