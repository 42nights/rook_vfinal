// Tenant/branding env contract for Castle template deployments.
// All vars are optional; Rook works with zero of them set (local dev default).

export const tenant = {
  slug: process.env.ROOK_TENANT_SLUG ?? null,
  displayName: process.env.ROOK_TENANT_DISPLAY_NAME ?? "Rook",
  publicUrl: process.env.ROOK_TENANT_PUBLIC_URL ?? null,
  logoUrl: process.env.ROOK_LOGO_URL ?? null,
  primaryColor: process.env.ROOK_PRIMARY_COLOR ?? null,
} as const;

export type Tenant = typeof tenant;

// Throws listing missing required vars — but only when running in tenant mode.
// No-op in plain local dev (ROOK_TENANT_SLUG unset and TENANT_MODE !== "tenant").
export function requireTenantEnv(): void {
  const isTenantMode =
    !!process.env.ROOK_TENANT_SLUG || process.env.TENANT_MODE === "tenant";
  if (!isTenantMode) return;

  const required: Record<string, string | null | undefined> = {
    ROOK_TENANT_SLUG: process.env.ROOK_TENANT_SLUG,
    ROOK_TENANT_PUBLIC_URL: process.env.ROOK_TENANT_PUBLIC_URL,
    CASTLE_DEPLOYMENT_ID: process.env.CASTLE_DEPLOYMENT_ID,
    CASTLE_API_URL: process.env.CASTLE_API_URL,
  };
  const missing = Object.entries(required)
    .filter(([, v]) => !v)
    .map(([k]) => k);
  if (missing.length > 0) {
    throw new Error(
      `Rook tenant mode is active but required env vars are missing: ${missing.join(", ")}`,
    );
  }
}
