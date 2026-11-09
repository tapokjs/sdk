import { parseProtocolError } from "@tapokjs/core";
import type { TapokProtocolErrorBody } from "@tapokjs/core";
import { TapokAuthError, TapokHttpError } from "./errors.ts";

export { TapokHttpError } from "./errors.ts";

/** Default limit for one Tapok HTTP request, including reading its body. */
export const DEFAULT_TIMEOUT_MS = 10_000;

const textDecoder = /* @__PURE__ */ new TextDecoder();

export function requireTimeout(value: number | undefined): number {
  if (value === undefined) return DEFAULT_TIMEOUT_MS;
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new TypeError("timeoutMs must be a positive finite number");
  }
  return value;
}

export async function parseJsonResponse(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  if (
    contentType.split(";", 1)[0]?.trim().toLowerCase() !== "application/json"
  ) {
    // A cloned response waits for its sibling to finish before cancellation settles.
    void response.body?.cancel().catch(() => undefined);
    throw new TapokAuthError(
      "invalid_response",
      "Tapok response must use application/json",
    );
  }
  try {
    return (await response.json()) as unknown;
  } catch {
    // The parser's own error may quote the body, which can hold tokens.
    throw new TapokAuthError(
      "invalid_response",
      "Tapok response is not valid JSON",
    );
  }
}

export async function throwHttpError(response: Response): Promise<never> {
  let protocolError: TapokProtocolErrorBody | undefined;
  try {
    protocolError = parseProtocolError(await parseJsonResponse(response));
  } catch {
    // Do not include a response body in an error. It may contain sensitive data.
  }
  throw new TapokHttpError(response.status, protocolError);
}

/**
 * Runs one request with a deadline that also covers reading the body. The
 * deadline wins even over a transport that ignores the abort signal.
 */
async function withDeadline<T>(
  timeoutMs: number,
  run: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(
        new TapokAuthError(
          "request_timeout",
          `Tapok request exceeded ${timeoutMs} ms`,
        ),
      );
      controller.abort();
    }, timeoutMs);
  });
  const work = run(controller.signal);
  // After the deadline the aborted request rejects on its own; that rejection
  // has no consumer left.
  work.catch(() => undefined);
  try {
    return await Promise.race([work, deadline]);
  } finally {
    clearTimeout(timer);
  }
}

/** Perform a redirect-free Tapok API request and turn failures into TapokHttpError. */
export async function fetchTapok(
  fetchImpl: typeof fetch | undefined,
  url: string,
  init: RequestInit,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<Response> {
  return withDeadline(timeoutMs, async (signal) => {
    const response = await (fetchImpl ?? globalThis.fetch)(url, {
      ...init,
      redirect: "error",
      signal,
    });
    if (!response.ok) await throwHttpError(response);
    return response;
  });
}

/**
 * Request a JSON document and validate it with a core parser. A body that
 * breaks the protocol contract becomes `invalid_response`; the body is never
 * attached to the error.
 */
export async function requestTapokJson<T>(
  fetchImpl: typeof fetch | undefined,
  url: string,
  init: RequestInit,
  timeoutMs: number,
  parse: (value: unknown) => T,
): Promise<T> {
  return withDeadline(timeoutMs, async (signal) => {
    const response = await (fetchImpl ?? globalThis.fetch)(url, {
      ...init,
      redirect: "error",
      signal,
    });
    if (!response.ok) await throwHttpError(response);
    const value = await parseJsonResponse(response);
    try {
      return parse(value);
    } catch (error) {
      if (error instanceof TapokAuthError) throw error;
      // Core parsers describe the broken field with fixed text and never quote
      // a value; anything else gets a generic description.
      throw new TapokAuthError(
        "invalid_response",
        error instanceof TypeError
          ? error.message
          : "Tapok response breaks the protocol contract",
      );
    }
  });
}

export function decodeJwtPayload(token: string): Record<string, unknown> {
  const invalid = (message: string) =>
    new TapokAuthError("invalid_token", message);
  const parts = typeof token === "string" ? token.split(".") : [];
  if (parts.length !== 3 || parts[1] === undefined || parts[1] === "") {
    throw invalid("identity_token must be a compact JWT");
  }

  const encoded = parts[1].replaceAll("-", "+").replaceAll("_", "/");
  const padded = encoded + "=".repeat((4 - (encoded.length % 4)) % 4);
  let payload: unknown;
  try {
    payload = JSON.parse(
      textDecoder.decode(
        Uint8Array.from(atob(padded), (character) => character.charCodeAt(0)),
      ),
    );
  } catch {
    // The decoder's error may quote the payload.
    throw invalid("identity_token has an invalid JWT payload");
  }
  if (
    payload === null ||
    typeof payload !== "object" ||
    Array.isArray(payload)
  ) {
    throw invalid("identity_token payload must be an object");
  }
  return payload as Record<string, unknown>;
}

export function requireExactNonce(token: string, nonce: string): void {
  const payload = decodeJwtPayload(token);
  if (payload["nonce"] !== nonce) {
    throw new TapokAuthError(
      "invalid_token",
      "identity_token nonce does not match the authorization transaction",
    );
  }
}
