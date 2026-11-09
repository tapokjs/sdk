import { TapokError } from "@tapokjs/core";
import type { TapokProtocolErrorBody } from "@tapokjs/core";

/**
 * Why an authorization could not be completed, apart from a rejected callback
 * (`TapokCallbackValidationError`) and an HTTP error answer (`TapokHttpError`).
 *
 * - `invalid_transaction`: the pending transaction is missing, expired, already
 *   used or belongs to another client configuration. Start the sign-in again.
 * - `binding_mismatch`: the callback arrived in a different browser session.
 * - `invalid_token`: the JWT failed signature, issuer, audience, lifetime,
 *   nonce, `max_age` or claim checks.
 * - `token_replayed`: the Base identity token `jti` was already consumed.
 * - `invalid_response`: Tapok answered with a body that breaks the protocol
 *   contract, widens the requested scopes or names another subject.
 * - `jwks_unavailable`: signing keys could not be loaded; retrying may help.
 * - `request_timeout`: a Tapok HTTP request exceeded `timeoutMs`.
 */
export type TapokAuthErrorCode =
  | "invalid_transaction"
  | "binding_mismatch"
  | "invalid_token"
  | "token_replayed"
  | "invalid_response"
  | "jwks_unavailable"
  | "request_timeout";

/**
 * The sign-in must not be treated as successful. Branch on `code`, never on
 * `message`.
 *
 * The error is safe to log whole. Its text is fixed per failure and it never
 * references the underlying JWT, JSON or transport error, because those can
 * contain token claims, response fragments or URLs. `reason`, when present, is
 * one of a fixed list of verifier verdict codes (for example
 * `ERR_JWT_EXPIRED`); it is a diagnostic hint, not a second code to branch on.
 */
export class TapokAuthError extends TapokError {
  override readonly name = "TapokAuthError";
  declare readonly code: TapokAuthErrorCode;
  readonly reason?: string;

  constructor(code: TapokAuthErrorCode, message: string, reason?: string) {
    super(code, message);
    if (reason !== undefined) this.reason = reason;
  }
}

/**
 * Tapok answered with a non-2xx status. `code` is the protocol error code when
 * the body was a valid protocol error, otherwise `http_error`. The response
 * body itself is never attached.
 */
export class TapokHttpError extends TapokError {
  override readonly name = "TapokHttpError";
  readonly status: number;
  readonly protocolError?: TapokProtocolErrorBody;

  constructor(status: number, protocolError?: TapokProtocolErrorBody) {
    super(
      protocolError?.error ?? "http_error",
      protocolError?.error_description ??
        protocolError?.error ??
        `Tapok request failed with HTTP ${status}`,
    );
    this.status = status;
    if (protocolError !== undefined) this.protocolError = protocolError;
  }
}
