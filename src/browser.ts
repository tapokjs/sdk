import { remoteJwks } from "./jwks.ts";
import {
  assertAuthenticationAge,
  assertBaseOidcClaims,
  verifyToken,
} from "./token-verification.ts";
import {
  TAPOK_ISSUER,
  TapokCallbackValidationError,
  buildBaseAuthorizeUrl,
  buildOidcBaseAuthorizeUrl,
  resolveTapokEndpoints,
  createConnectTokenBody,
  parseConnectTokenResponse,
  createAuthorizationSecrets,
  createBaseExchangeBody,
  deriveBaseClientId,
  parseAndValidateAuthorizationCallback,
  parseBaseExchangeResponse,
} from "@tapokjs/core";
import type {
  AuthorizationResponseErrorCode,
  BaseExchangeResponse,
  BaseOidcScope,
  BaseScope,
  OidcAuthorizationOptions,
  ParsedAuthorizationCallback,
} from "@tapokjs/core";
import { TapokAuthError } from "./errors.ts";
import {
  requestTapokJson,
  requireExactNonce,
  requireTimeout,
} from "./shared.ts";
import {
  DEFAULT_POPUP_FEATURES,
  exactOrigin,
  globalWindow,
  openAuthPopup,
  openBackendAuthPopup,
  type AuthPopupAttempt,
  type AuthPopupHostWindow,
  type BackendPopupStatus,
} from "./popup.ts";

export {
  DEFAULT_POPUP_FEATURES,
  notifyAuthPopupOpener,
  openAuthPopup,
  openBackendAuthPopup,
  shouldUsePopup,
} from "./popup.ts";
export type {
  AuthPopupAttempt,
  AuthPopupHostWindow,
  AuthPopupOptions,
  AuthPopupResult,
  BackendPopupStatus,
} from "./popup.ts";
export { TapokCallbackValidationError, TapokError } from "@tapokjs/core";
export { TapokAuthError, TapokHttpError } from "./errors.ts";
export type { TapokAuthErrorCode } from "./errors.ts";
export type { VerifiedTokenClaims } from "./token-verification.ts";
export type {
  AuthorizationResponseErrorCode,
  BaseExchangeResponse,
  BaseOidcScope,
  BaseScope,
  CallbackValidationErrorCode,
  OidcAuthorizationOptions,
  ParsedAuthorizationCallback,
  TapokProtocolErrorBody,
  TapokProtocolErrorCode,
} from "@tapokjs/core";

const transactionPrefix = "tapok.base.transaction.";
const TRANSACTION_TTL_MS = 300_000;
const callbackMessageType = "tapok:base:callback";
const callbackFields = [
  "code",
  "state",
  "iss",
  "error",
  "error_description",
] as const;

type BaseTransaction = {
  version: 1;
  redirectUri: string;
  /** Stored only for a non-default issuer, so default records keep their shape. */
  issuer?: string;
  state: string;
  nonce: string;
  verifier: string;
  expiresAt?: number;
};

export type BaseTransactionStorage = Pick<
  Storage,
  "getItem" | "setItem" | "removeItem"
>;

export type BaseBrowserClientOptions = {
  redirectUri: string;
  scopes?: readonly BaseScope[];
  /** Trusted Tapok issuer from application configuration. Defaults to production. */
  issuer?: string;
  /** Defaults to `sessionStorage`, resolved on first use. */
  storage?: BaseTransactionStorage;
  fetch?: typeof fetch;
  /** Limit for the exchange request. Default 10 000 ms. */
  timeoutMs?: number;
  /** Defaults to the global `window`, resolved on first use. */
  window?: Pick<
    Window,
    "location" | "history" | "open" | "addEventListener" | "removeEventListener"
  >;
};

export type BaseAuthorizationStart = {
  authorizationUrl: URL;
  state: string;
};

export type BaseAuthorizationError = {
  ok: false;
  error: AuthorizationResponseErrorCode;
  errorDescription?: string;
};

export type BaseAuthorizationSuccess = {
  ok: true;
  /** The exchange response as it is on the wire; send `identity_token` to your backend. */
  response: BaseExchangeResponse;
};

export type BaseAuthorizationResult =
  BaseAuthorizationSuccess | BaseAuthorizationError;

function invalidTransaction(message: string): TapokAuthError {
  return new TapokAuthError("invalid_transaction", message);
}

function browserWindow(
  options: BaseBrowserClientOptions,
): NonNullable<BaseBrowserClientOptions["window"]> {
  return options.window ?? globalWindow();
}

function transactionKey(redirectUri: string): string {
  return transactionPrefix + encodeURIComponent(redirectUri);
}

function browserStorage(options: {
  storage?: BaseTransactionStorage;
}): BaseTransactionStorage {
  if (options.storage !== undefined) return options.storage;
  if (typeof sessionStorage === "undefined") {
    throw new Error(
      "A transaction storage adapter must be provided outside a browser",
    );
  }
  return sessionStorage;
}

function loadTransaction(
  storage: BaseTransactionStorage,
  redirectUri: string,
  issuer: string,
): BaseTransaction {
  const raw = storage.getItem(transactionKey(redirectUri));
  if (raw === null)
    throw invalidTransaction(
      "No pending Tapok Base transaction exists for this redirect URI",
    );
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    // The parser's error may quote the record, which holds the PKCE verifier.
    throw invalidTransaction("The pending Tapok Base transaction is malformed");
  }
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    (value as Record<string, unknown>)["version"] !== 1 ||
    (value as Record<string, unknown>)["redirectUri"] !== redirectUri ||
    ((value as Record<string, unknown>)["issuer"] ?? TAPOK_ISSUER) !== issuer ||
    typeof (value as Record<string, unknown>)["state"] !== "string" ||
    typeof (value as Record<string, unknown>)["nonce"] !== "string" ||
    typeof (value as Record<string, unknown>)["verifier"] !== "string"
  ) {
    throw invalidTransaction("The pending Tapok Base transaction is malformed");
  }
  const expiry = (value as Record<string, unknown>)["expiresAt"];
  if (
    expiry !== undefined &&
    (typeof expiry !== "number" ||
      !Number.isFinite(expiry) ||
      expiry <= Date.now())
  )
    throw invalidTransaction("Base transaction expired");
  return value as BaseTransaction;
}

/**
 * Native Base in the browser: PKCE transaction in `sessionStorage`, redirect or
 * popup, callback validation and the CORS exchange. The identity token it
 * returns is **not** signature-checked here: send it to your backend, which
 * must call `verifyAndConsumeBaseIdentityToken()` before creating a session.
 *
 * Creating the client touches no browser global, so it is safe at module
 * scope during SSR; `window` and `sessionStorage` are resolved on first use.
 */
export function createBaseBrowserClient(options: BaseBrowserClientOptions) {
  const clientId = deriveBaseClientId(options.redirectUri);
  const issuer = options.issuer ?? TAPOK_ISSUER;
  // Validates the issuer the same way the server clients do.
  resolveTapokEndpoints({ issuer });
  const exchangeEndpoint = issuer + "/api/v1/base/exchange";
  const timeoutMs = requireTimeout(options.timeoutMs);
  const redirectUrl = new URL(options.redirectUri);

  async function beginAuthorization(): Promise<BaseAuthorizationStart> {
    const storage = browserStorage(options);
    const secrets = await createAuthorizationSecrets();
    const transaction: BaseTransaction = {
      version: 1,
      redirectUri: options.redirectUri,
      ...(issuer === TAPOK_ISSUER ? {} : { issuer }),
      state: secrets.state,
      nonce: secrets.nonce,
      verifier: secrets.pkce.verifier,
      expiresAt: Date.now() + TRANSACTION_TTL_MS,
    };
    storage.setItem(
      transactionKey(options.redirectUri),
      JSON.stringify(transaction),
    );
    return {
      authorizationUrl: buildBaseAuthorizeUrl({
        issuer,
        redirectUri: options.redirectUri,
        scopes: options.scopes,
        state: secrets.state,
        nonce: secrets.nonce,
        codeChallenge: secrets.pkce.challenge,
      }),
      state: secrets.state,
    };
  }

  async function redirect(): Promise<void> {
    const start = await beginAuthorization();
    browserWindow(options).location.assign(start.authorizationUrl.href);
  }

  async function completeCallback(
    callbackUrl?: string | URL,
  ): Promise<BaseAuthorizationResult> {
    const storage = browserStorage(options);
    // An explicit URL (popup message, tests) needs no window at all.
    const win = callbackUrl === undefined ? browserWindow(options) : undefined;
    const transaction = loadTransaction(storage, options.redirectUri, issuer);
    const callback = parseAndValidateAuthorizationCallback({
      callbackUrl: callbackUrl ?? (win as Window).location.href,
      expectedState: transaction.state,
      expectedIssuer: issuer,
      redirectUri: options.redirectUri,
    });
    // Drop the protocol parameters, keep the registered query of the page.
    win?.history.replaceState(
      null,
      "",
      win.location.pathname + redirectUrl.search + win.location.hash,
    );
    storage.removeItem(transactionKey(options.redirectUri));

    if (!callback.ok) {
      return {
        ok: false,
        error: callback.error,
        errorDescription: callback.errorDescription,
      };
    }

    const result = await requestTapokJson(
      options.fetch,
      exchangeEndpoint,
      {
        method: "POST",
        mode: "cors",
        credentials: "omit",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: createBaseExchangeBody({
          grant_type: "authorization_code",
          code: callback.code,
          client_id: clientId,
          redirect_uri: options.redirectUri,
          code_verifier: transaction.verifier,
        }),
      },
      timeoutMs,
      parseBaseExchangeResponse,
    );
    requireExactNonce(result.identity_token, transaction.nonce);
    return { ok: true, response: result };
  }

  async function completePopupMessage(
    event: MessageEvent<unknown>,
    popup: WindowProxy,
  ): Promise<BaseAuthorizationResult> {
    if (event.origin !== redirectUrl.origin || event.source !== popup) {
      throw new TypeError(
        "Tapok Base popup message has an unexpected source or origin",
      );
    }
    if (
      event.data === null ||
      typeof event.data !== "object" ||
      Array.isArray(event.data)
    ) {
      throw new TypeError("Tapok Base popup message must be an object");
    }
    const data = event.data as Record<string, unknown>;
    // The callback page saw a repeated or oversized protocol parameter. It
    // cannot be reduced to one value without guessing which the server meant.
    if (data["malformed"] === true)
      throw new TapokCallbackValidationError("malformed_callback");
    // Start from the registered URI so its own query is part of the callback.
    const callback = new URL(options.redirectUri);
    for (const name of callbackFields) {
      // Camel-case names are the message of the deprecated postBasePopupCallback().
      const alias =
        name === "iss"
          ? "issuer"
          : name === "error_description"
            ? "errorDescription"
            : name;
      if (
        data[name] !== undefined &&
        data[alias] !== undefined &&
        data[name] !== data[alias]
      ) {
        throw new TypeError(
          "Tapok Base popup message contains conflicting callback values",
        );
      }
      const value = data[name] !== undefined ? data[name] : data[alias];
      if (value !== undefined) {
        if (typeof value !== "string")
          throw new TypeError(
            "Tapok Base popup message contains an invalid callback value",
          );
        callback.searchParams.set(name, value);
      }
    }
    return completeCallback(callback);
  }

  async function openPopup(
    features = DEFAULT_POPUP_FEATURES,
  ): Promise<BaseAuthorizationStart | null> {
    const start = await beginAuthorization();
    const popup = browserWindow(options).open(
      start.authorizationUrl.href,
      "tapok-base",
      features,
    );
    return popup === null ? null : start;
  }

  function startPopup(
    popupOptions: {
      features?: string;
      timeoutMs?: number;
      window?: AuthPopupHostWindow;
    } = {},
  ): AuthPopupAttempt<BaseAuthorizationResult> {
    return openAuthPopup({
      url: async () => (await beginAuthorization()).authorizationUrl,
      messageOrigin: redirectUrl.origin,
      name: "tapok-base",
      features: popupOptions.features ?? DEFAULT_POPUP_FEATURES,
      ...(popupOptions.timeoutMs !== undefined
        ? { timeoutMs: popupOptions.timeoutMs }
        : {}),
      window: popupOptions.window ?? browserWindow(options),
      accept(event, popup) {
        const data = event.data as Record<string, unknown> | null;
        // Ignore unrelated same-origin messages: a callback is either the
        // relay message or, from the deprecated helper, an object with state.
        if (
          data === null ||
          typeof data !== "object" ||
          Array.isArray(data) ||
          (data["type"] !== callbackMessageType &&
            typeof data["state"] !== "string")
        )
          return undefined;
        return completePopupMessage(event, popup);
      },
    });
  }

  return {
    beginAuthorization,
    redirect,
    completeCallback,
    /**
     * Completes a callback relayed by the popup page. `startPopup()` calls it
     * for you; use it directly only with your own popup handling.
     */
    completePopupMessage,
    /**
     * @deprecated Use `startPopup()`. This method prepares PKCE before opening
     * the window, so browsers may treat the window as unsolicited and block it.
     */
    openPopup,
    /**
     * Opt-in popup flow with explicit states. The window opens synchronously in
     * the click handler; the PKCE transaction is prepared afterwards. A
     * `received` result still has to be sent to the application backend and
     * confirmed there before the user is treated as signed in; then call
     * `close()` on the attempt.
     */
    startPopup,
  };
}

export type ConnectBrowserNavigatorOptions = {
  /** Your backend route that starts Connect. Absolute, or relative to the current page. */
  startUrl: string;
  /** Defaults to the global `window`, resolved on first use. */
  window?: Pick<Window, "location" | "open">;
};

function requireHttp(url: URL): URL {
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new TypeError("startUrl must be an HTTP(S) URL");
  }
  return url;
}

/**
 * Browser-only navigation for Connect. It cannot access protocol secrets or
 * tokens. Safe to create at module scope during SSR.
 */
export function createConnectBrowserNavigator(
  options: ConnectBrowserNavigatorOptions,
) {
  let absolute: URL | undefined;
  try {
    absolute = new URL(options.startUrl);
  } catch {
    // Relative: resolved against the page when navigation starts.
  }
  // An absolute URL is checked now so a wrong scheme fails at start-up.
  if (absolute !== undefined) requireHttp(absolute);
  const hostWindow = () => options.window ?? globalWindow();
  const start = (): URL =>
    absolute ??
    requireHttp(new URL(options.startUrl, hostWindow().location.href));

  function startRedirect(): void {
    hostWindow().location.assign(start().href);
  }
  function startPopup(features = DEFAULT_POPUP_FEATURES): Window | null {
    return hostWindow().open(start().href, "tapok-connect", features);
  }
  function startPopupAttempt(
    popupOptions: {
      features?: string;
      timeoutMs?: number;
      /** Origin of the callback page; defaults to the start URL origin. */
      applicationOrigin?: string;
      window?: AuthPopupHostWindow;
    } = {},
  ): AuthPopupAttempt<{ status: BackendPopupStatus }> {
    const target = start();
    const win = hostWindow();
    return openBackendAuthPopup({
      url: target.href,
      messageOrigin: popupOptions.applicationOrigin ?? target.origin,
      name: "tapok-connect",
      features: popupOptions.features ?? DEFAULT_POPUP_FEATURES,
      ...(popupOptions.timeoutMs !== undefined
        ? { timeoutMs: popupOptions.timeoutMs }
        : {}),
      window:
        popupOptions.window ??
        ("addEventListener" in win
          ? (win as unknown as AuthPopupHostWindow)
          : globalWindow()),
    });
  }
  return {
    startRedirect,
    /**
     * @deprecated Use `startPopupAttempt()`, which reports blocked, closed,
     * cancelled, timeout and received states. This method only returns the
     * raw window, and has a different meaning from `startPopup()` of the Base
     * browser client.
     */
    startPopup,
    /**
     * Opt-in popup flow with explicit states. The backend callback page reports
     * through `notifyAuthPopupOpener`; the application must still confirm its
     * own session before showing success.
     */
    startPopupAttempt,
  };
}

/**
 * Notify a Connect popup opener after its backend callback has completed.
 *
 * @deprecated Use `notifyAuthPopupOpener()`, which also covers Base OIDC and
 * returns false instead of throwing when the page has no opener.
 */
export function postConnectPopupCompletion(input: {
  applicationOrigin: string;
  /** Optional hint for the opener; it never replaces the session check. */
  status?: BackendPopupStatus;
  window?: Pick<Window, "opener">;
}): void {
  const target = exactOrigin(input.applicationOrigin, "applicationOrigin");
  const opener = (input.window ?? globalWindow()).opener;
  if (opener === null) throw new Error("Tapok Connect popup has no opener");
  opener.postMessage(
    {
      type: "tapok:connect:complete",
      version: 1,
      ...(input.status ? { status: input.status } : {}),
    },
    target,
  );
}

/**
 * Base callback page inside a popup: forwards only the callback parameters
 * (code, state, iss, error) to the opener at the exact application origin and
 * removes them from the address bar. The opener validates state, issuer and
 * nonce in `completePopupMessage`, so the popup needs no transaction storage.
 * A repeated or oversized protocol parameter is reported as malformed and
 * fails the attempt; no value is chosen on the server's behalf.
 * Returns false when there is no opener; show a link back and a close button.
 */
export function relayBasePopupCallback(input: {
  applicationOrigin: string;
  window?: Pick<Window, "location" | "history" | "opener">;
}): boolean {
  const win = input.window ?? globalWindow();
  const target = exactOrigin(input.applicationOrigin, "applicationOrigin");
  const params = new URL(win.location.href).searchParams;
  let message: Record<string, string | number | boolean> = {
    type: callbackMessageType,
    version: 1,
  };
  for (const name of callbackFields) {
    const values = params.getAll(name);
    if (
      values.length > 1 ||
      (values[0] !== undefined && values[0].length > 4096)
    ) {
      message = { type: callbackMessageType, version: 1, malformed: true };
      break;
    }
    if (values[0] !== undefined) message[name] = values[0];
  }
  win.history.replaceState(null, "", win.location.pathname + win.location.hash);
  const opener = win.opener as WindowProxy | null;
  if (!opener || opener.closed) return false;
  opener.postMessage(message, target);
  return true;
}

/**
 * Validate a callback in the popup and return the protocol result to its opener.
 *
 * @deprecated Use `relayBasePopupCallback()` with `startPopup()`. This helper
 * needs the transaction state inside the popup, which the popup flow that
 * opens the window before preparing PKCE cannot provide.
 */
export function postBasePopupCallback(input: {
  callbackUrl?: string | URL;
  expectedState: string;
  applicationOrigin: string;
  /** Trusted issuer; defaults to production. */
  issuer?: string;
  /** Registered redirect URI, required when it has its own query. */
  redirectUri?: string;
  window?: Pick<Window, "location" | "history" | "opener">;
}): ParsedAuthorizationCallback {
  const win = input.window ?? globalWindow();
  const target = exactOrigin(input.applicationOrigin, "applicationOrigin");
  const callback = parseAndValidateAuthorizationCallback({
    callbackUrl: input.callbackUrl ?? win.location.href,
    expectedState: input.expectedState,
    expectedIssuer: input.issuer ?? TAPOK_ISSUER,
    ...(input.redirectUri !== undefined
      ? { redirectUri: input.redirectUri }
      : {}),
  });
  win.history.replaceState(null, "", win.location.pathname + win.location.hash);
  if (win.opener === null) throw new Error("Tapok Base popup has no opener");
  win.opener.postMessage(callback, target);
  return callback;
}

export type BaseOidcBrowserClientOptions = {
  clientId: string;
  redirectUri: string;
  /** Trusted Base OIDC issuer. Defaults to `https://tapok.orria.space/oidc/base`. */
  issuer?: string;
  scopes?: readonly BaseOidcScope[];
  /** Defaults to `sessionStorage`, resolved on first use. */
  storage?: BaseTransactionStorage;
  /** Used for the token request and for JWKS. */
  fetch?: typeof fetch;
  /** Limit for the token request. Default 10 000 ms. */
  timeoutMs?: number;
};

/**
 * Public PKCE client for the separate Base OIDC issuer. Unlike
 * `createBaseBrowserClient`, it verifies the ID token signature in the browser.
 * No refresh token is persisted. Safe to create at module scope during SSR.
 *
 * In its result `idToken` is the **compact JWT string** (what Convex and other
 * token consumers expect) and `claims` are the verified claims. The server
 * clients name the same things `rawIdToken` and `idToken`.
 */
export function createBaseOidcBrowserClient(
  options: BaseOidcBrowserClientOptions,
) {
  if (typeof options.clientId !== "string" || options.clientId === "")
    throw new TypeError("clientId must be a non-empty string");
  const scopes = options.scopes ?? ["openid"];
  const timeoutMs = requireTimeout(options.timeoutMs);
  const endpoints = resolveTapokEndpoints({
    issuer: options.issuer,
    mode: "base",
  });
  const key =
    "tapok.base.oidc." +
    encodeURIComponent(
      JSON.stringify([endpoints.issuer, options.clientId, options.redirectUri]),
    );
  const jwks = remoteJwks(endpoints.jwks_uri, options.fetch);
  async function beginAuthorization(
    authorizationOptions: OidcAuthorizationOptions = {},
  ) {
    const storage = browserStorage(options);
    const secrets = await createAuthorizationSecrets();
    const url = buildOidcBaseAuthorizeUrl({
      ...authorizationOptions,
      issuer: endpoints.issuer,
      clientId: options.clientId,
      redirectUri: options.redirectUri,
      scopes,
      state: secrets.state,
      nonce: secrets.nonce,
      codeChallenge: secrets.pkce.challenge,
    });
    storage.setItem(
      key,
      JSON.stringify({
        state: secrets.state,
        nonce: secrets.nonce,
        verifier: secrets.pkce.verifier,
        maxAge: authorizationOptions.maxAge,
        expiresAt: Date.now() + TRANSACTION_TTL_MS,
      }),
    );
    return { authorizationUrl: url, state: secrets.state };
  }
  async function completeCallback(callbackUrl: string | URL) {
    const storage = browserStorage(options);
    const raw = storage.getItem(key);
    if (!raw) throw invalidTransaction("No Base OIDC transaction");
    let transaction: Record<string, unknown> | null;
    try {
      transaction = JSON.parse(raw) as Record<string, unknown> | null;
    } catch {
      throw invalidTransaction("Invalid or expired Base OIDC transaction");
    }
    if (
      transaction === null ||
      typeof transaction !== "object" ||
      typeof transaction["state"] !== "string" ||
      typeof transaction["nonce"] !== "string" ||
      typeof transaction["verifier"] !== "string" ||
      typeof transaction["expiresAt"] !== "number" ||
      !Number.isFinite(transaction["expiresAt"]) ||
      transaction["expiresAt"] <= Date.now() ||
      (transaction["maxAge"] !== undefined &&
        typeof transaction["maxAge"] !== "number")
    )
      throw invalidTransaction("Invalid or expired Base OIDC transaction");
    const callback = parseAndValidateAuthorizationCallback({
      callbackUrl,
      expectedState: transaction["state"],
      expectedIssuer: endpoints.issuer,
      redirectUri: options.redirectUri,
    });
    storage.removeItem(key);
    if (!callback.ok) return { ok: false as const, callback };
    const body = createConnectTokenBody({
      grant_type: "authorization_code",
      code: callback.code,
      redirect_uri: options.redirectUri,
      code_verifier: transaction["verifier"],
    });
    body.set("client_id", options.clientId);
    const tokens = await requestTapokJson(
      options.fetch,
      endpoints.token_endpoint,
      {
        method: "POST",
        credentials: "omit",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body,
      },
      timeoutMs,
      parseConnectTokenResponse,
    );
    if (
      tokens.scope
        .split(" ")
        .some((scope) => !scopes.includes(scope as BaseOidcScope))
    )
      throw new TapokAuthError("invalid_response", "Base OIDC expanded scopes");
    const payload = await verifyToken({
      token: tokens.id_token,
      expectedIssuer: endpoints.issuer,
      expectedAudience: options.clientId,
      expectedNonce: transaction["nonce"],
      mode: "base-oidc",
      maximumLifetime: 900,
      maxClockSkewSeconds: 60,
      jwks,
    });
    assertAuthenticationAge(
      payload,
      transaction["maxAge"] as number | undefined,
    );
    assertBaseOidcClaims(payload);
    return {
      ok: true as const,
      /** The compact ID token (a JWT string), e.g. for Convex `setAuth`. */
      idToken: tokens.id_token,
      /** Verified claims of `idToken`. */
      claims: payload,
      /** Access token lifetime in seconds; the access token itself is discarded. */
      expiresIn: tokens.expires_in,
    };
  }
  return { beginAuthorization, completeCallback };
}
