import type { TapokMode } from "@tapokjs/core";
import { errors, jwtVerify } from "jose";
import type { JWTPayload } from "jose";
import { TapokAuthError } from "./errors.ts";
import type { remoteJwks } from "./jwks.ts";

export type VerifiedTokenClaims = JWTPayload & {
  sub: string;
  /** Always a single audience: multi-audience tokens are rejected. */
  aud: string;
  jti: string;
  iat: number;
  exp: number;
  /** Present in native Base and Connect tokens; Base OIDC tokens may omit it. */
  mode?: TapokMode;
};

/**
 * Which token family is expected. `base-oidc` is the separate Base OIDC
 * issuer: its ID tokens carry no `mode` claim, the issuer itself isolates
 * them, and a token that names another mode is still refused.
 */
export type TokenKind = TapokMode | "base-oidc";

function invalid(message: string): TapokAuthError {
  return new TapokAuthError("invalid_token", message);
}

/**
 * Verdicts of the JWT library that may be reported, each with fixed text.
 * The library's own error is never kept or quoted: `JWTExpired` and
 * `JWTClaimValidationFailed` carry the whole token payload, and their text is
 * not ours to vouch for.
 */
const verdicts: Readonly<Record<string, string>> = {
  ERR_JWT_EXPIRED: "JWT has expired",
  ERR_JWT_CLAIM_VALIDATION_FAILED: "JWT claim validation failed",
  ERR_JWT_INVALID: "JWT is malformed",
  ERR_JWS_INVALID: "JWT is malformed",
  ERR_JWS_SIGNATURE_VERIFICATION_FAILED: "JWT signature verification failed",
  ERR_JWKS_NO_MATCHING_KEY: "No Tapok signing key matches the JWT",
  ERR_JWKS_MULTIPLE_MATCHING_KEYS: "Several Tapok signing keys match the JWT",
  ERR_JOSE_ALG_NOT_ALLOWED: "JWT algorithm is not allowed",
  ERR_JOSE_NOT_SUPPORTED: "JWT algorithm or key is not supported",
  ERR_JWKS_TIMEOUT: "Tapok signing keys could not be loaded in time",
  ERR_JWKS_INVALID: "Tapok signing keys are malformed",
};
/** Claim names the library validates itself; safe to name in a message. */
const namedClaims = ["iss", "aud", "sub", "jti", "iat", "exp", "nbf"];

function describeVerdict(error: unknown): {
  message?: string;
  reason?: string;
} {
  if (!(error instanceof errors.JOSEError)) return {};
  const reason = error.code;
  if (!Object.hasOwn(verdicts, reason)) return {};
  let message = verdicts[reason] as string;
  if (error instanceof errors.JWTClaimValidationFailed) {
    const claim = error.claim;
    if (namedClaims.includes(claim)) message += `: ${claim}`;
  }
  return { message, reason };
}

function assertString(value: unknown, name: string): asserts value is string {
  if (typeof value !== "string" || value === "")
    throw invalid(`${name} must be a non-empty string`);
}

function assertNumericDate(
  value: unknown,
  name: string,
): asserts value is number {
  if (typeof value !== "number" || !Number.isFinite(value))
    throw invalid(`${name} must be a numeric date`);
}

const stringClaims = [
  "nonce",
  "sid",
  "email",
  "name",
  "preferred_username",
  "picture",
  "pairwise_sub",
] as const;

/**
 * A valid signature does not make a claim well typed. Check every claim the
 * published claim types promise, so the returned object matches its type.
 */
function assertClaimTypes(payload: JWTPayload, kind: TokenKind): void {
  for (const claim of stringClaims) {
    if (payload[claim] !== undefined) assertString(payload[claim], claim);
  }
  if (
    payload["email_verified"] !== undefined &&
    typeof payload["email_verified"] !== "boolean"
  )
    throw invalid("email_verified must be a boolean");
  if (
    payload["is_adult"] !== undefined &&
    payload["is_adult"] !== null &&
    typeof payload["is_adult"] !== "boolean"
  )
    throw invalid("is_adult must be a boolean or null");
  const authTime = payload["auth_time"];
  if (
    authTime !== undefined &&
    (!Number.isSafeInteger(authTime) || (authTime as number) < 0)
  )
    throw invalid("auth_time must be a nonnegative integer");
  if (kind === "base") {
    // Native Base identity tokens always carry both.
    assertString(payload["nonce"], "nonce");
    assertString(payload["pairwise_sub"], "pairwise_sub");
  }
}

/** Shared by browser Base OIDC and server flows; contains only public-key verification. */
export async function verifyToken(input: {
  token: string;
  expectedIssuer: string;
  expectedAudience: string;
  expectedNonce?: string;
  mode: TokenKind;
  maximumLifetime: number;
  maxClockSkewSeconds: number;
  jwks: ReturnType<typeof remoteJwks>;
}): Promise<VerifiedTokenClaims> {
  if (
    typeof input.maxClockSkewSeconds !== "number" ||
    !Number.isFinite(input.maxClockSkewSeconds) ||
    input.maxClockSkewSeconds < 0
  ) {
    throw new TypeError(
      "maxClockSkewSeconds must be a finite nonnegative number",
    );
  }
  let payload: JWTPayload;
  let keysRequested = false;
  try {
    ({ payload } = await jwtVerify(
      input.token,
      (protectedHeader, token) => {
        if (
          protectedHeader.typ !== "JWT" ||
          typeof protectedHeader.kid !== "string" ||
          protectedHeader.kid === ""
        ) {
          throw invalid("JWT header must have typ JWT and a kid");
        }
        keysRequested = true;
        return input.jwks(protectedHeader, token);
      },
      {
        issuer: input.expectedIssuer,
        audience: input.expectedAudience,
        algorithms: ["ES256", "RS256"],
        clockTolerance: input.maxClockSkewSeconds,
        requiredClaims: ["sub", "jti", "iat", "exp"],
      },
    ));
  } catch (error) {
    if (error instanceof TapokAuthError) throw error;
    const verdict = describeVerdict(error);
    // A token problem is final; a key-loading problem may pass on retry.
    // The library reports a failed JWKS download as JWKSTimeout, JWKSInvalid
    // or its generic error; a transport error passes through unwrapped.
    const keysUnavailable =
      error instanceof errors.JWKSTimeout ||
      error instanceof errors.JWKSInvalid ||
      (keysRequested &&
        (!(error instanceof errors.JOSEError) ||
          error.code === "ERR_JOSE_GENERIC"));
    // Nothing of `error` survives except an allowlisted verdict code.
    throw keysUnavailable
      ? new TapokAuthError(
          "jwks_unavailable",
          verdict.message ?? "Tapok signing keys could not be loaded",
          verdict.reason,
        )
      : new TapokAuthError(
          "invalid_token",
          verdict.message ?? "JWT verification failed",
          verdict.reason,
        );
  }
  if (Array.isArray(payload.aud)) {
    // jose already confirmed the expected audience is listed. The claim types
    // promise one audience, so anything wider is refused, not narrowed.
    if (payload.aud.length !== 1)
      throw invalid("JWT must have exactly one audience");
    payload.aud = payload.aud[0];
  }
  if (payload["azp"] !== undefined && payload["azp"] !== input.expectedAudience)
    throw invalid("JWT authorized party mismatch");
  assertString(payload.sub, "sub");
  assertString(payload.jti, "jti");
  assertNumericDate(payload.iat, "iat");
  assertNumericDate(payload.exp, "exp");
  const now = Math.floor(Date.now() / 1000);
  if (
    payload.iat > now + input.maxClockSkewSeconds ||
    payload.exp < now - input.maxClockSkewSeconds
  ) {
    throw invalid("JWT is outside its allowed clock skew");
  }
  if (
    payload.exp <= payload.iat ||
    payload.exp - payload.iat > input.maximumLifetime
  ) {
    throw invalid("JWT lifetime exceeds the Tapok limit");
  }
  const mode = payload["mode"];
  if (
    input.mode === "base-oidc"
      ? mode !== undefined && mode !== "base"
      : mode !== input.mode
  )
    throw invalid("JWT mode does not match this flow");
  if (
    input.expectedNonce !== undefined &&
    payload["nonce"] !== input.expectedNonce
  ) {
    throw invalid("JWT nonce does not match the authorization transaction");
  }
  assertClaimTypes(payload, input.mode);
  return payload as VerifiedTokenClaims;
}

/**
 * Base OIDC never releases the provider profile. `email` there is a synthetic
 * service address bound to the pairwise account, so `email_verified: true` is
 * expected and says nothing about a deliverable mailbox.
 */
export function assertBaseOidcClaims(
  value: unknown,
): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TapokAuthError("invalid_response", "Invalid Base OIDC claims");
  for (const claim of [
    "family_name",
    "given_name",
    "middle_name",
    "birthdate",
    "phone_number",
    "phone_number_verified",
    "address",
    "custom_fields",
  ]) {
    if (Object.hasOwn(value, claim))
      throw new TapokAuthError(
        "invalid_response",
        "Personal claim in Base OIDC",
      );
  }
}

export function assertAuthenticationAge(
  claims: Record<string, unknown>,
  maxAge?: number,
): void {
  if (maxAge === undefined) return;
  const authTime = claims["auth_time"];
  const now = Math.floor(Date.now() / 1000);
  if (
    !Number.isSafeInteger(maxAge) ||
    maxAge < 0 ||
    typeof authTime !== "number" ||
    !Number.isSafeInteger(authTime) ||
    authTime < 0 ||
    authTime > now + 60 ||
    now - authTime > maxAge + 60
  ) {
    throw invalid("ID token does not satisfy max_age");
  }
}
