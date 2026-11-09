import type { AuthConfig } from "convex/server";

// Copy into your Convex project's convex/auth.config.ts; configure these server environment values.
const domain =
  process.env["TAPOK_BASE_ISSUER"] ?? "https://tapok.orria.space/oidc/base";
const applicationID = process.env["TAPOK_BASE_CLIENT_ID"];
if (!applicationID) throw new Error("TAPOK_BASE_CLIENT_ID is required");
export default { providers: [{ domain, applicationID }] } satisfies AuthConfig;
