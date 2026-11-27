import { preflight } from "@/lib/cors";
/**
 * BRD-04 Branding History and Rollback (admin-only).
 * GET    /api/admin/branding           → last versions with who + when
 * POST   /api/admin/branding           → { brandVersionId } rollback
 */
import { ValidationError, fail, handleError, json, readJsonBody } from "@/lib/api-helpers";
import { requireAdmin } from "@/lib/api-helpers";
import { loadDb, withDb } from "@/lib/store";
import { newId } from "@/lib/auth";

export async function GET(request: Request) {
  try {
    const db = await loadDb();
    await requireAdmin(request, db);
    const versions = [...db.brandVersions]
      .sort((a, b) => Date.parse(b.changedAt) - Date.parse(a.changedAt))
      .map((v) => ({
        id: v.id,
        name: v.platformName,
        hasLogo: Boolean(v.logoReference),
        changedBy: v.updatedBy,
        changedAt: v.changedAt,
      }));
    return json(request, {
      current: {
        platformName: db.platformSettings?.platformName ?? "CleanCSV",
        hasLogo: Boolean(db.platformSettings?.logoReference),
        updatedBy: db.platformSettings?.updatedBy,
        updatedAt: db.platformSettings?.updatedAt,
      },
      versions,
    });
  } catch (error) {
    return handleError(request, error);
  }
}

export async function POST(request: Request) {
  try {
    const db = await loadDb();
    const { user: admin } = await requireAdmin(request, db);
    const body = await readJsonBody(request);
    const versionId = String(body.brandVersionId ?? "");
    if (!versionId) throw new ValidationError("brandVersionId is required.");

    const now = new Date().toISOString();
    const restored = await withDb((store) => {
      const version = store.brandVersions.find((v) => v.id === versionId);
      if (!version) return false;
      const previous = { ...store.platformSettings };
      const rollback: typeof previous = {
        platformName: version.platformName,
        logoReference: version.logoReference,
        logoDarkReference: version.logoDarkReference,
        updatedBy: admin.email,
        updatedAt: now,
      };
      store.brandVersions.push({ ...previous, id: newId(), changedAt: now });
      while (store.brandVersions.length > 5) store.brandVersions.shift();
      store.platformSettings = rollback;
      store.adminAuditEvents.push({
        id: newId(),
        adminId: admin.id,
        action: "branding.rollback",
        targetType: "branding",
        targetId: versionId,
        details: `Rolled back to version from ${version.changedAt}`,
        timestamp: now,
      });
      return true;
    });

    if (!restored) return fail(request, 404, "Brand version not found.");
    return json(request, { message: "Branding rolled back.", updatedAt: now });
  } catch (error) {
    return handleError(request, error);
  }
}

export async function OPTIONS(request: Request) {
  return preflight(request);
}
