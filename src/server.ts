import {
  TAPOK_ISSUER,
  buildConnectAuthorizeUrl,
  buildBaseAuthorizeUrl,
  buildOidcBaseAuthorizeUrl,
  buildLogoutUrl,
  resolveTapokEndpoints,
  validateOidcDiscovery,
  createBaseExchangeBody,
  parseBaseExchangeResponse,
  deriveBaseClientId,
  createConnectRefreshBody,
  parseConnectRefreshResponse,
  createAuthorizationSecrets,
  createConnectRevokeBody,
  createConnectTokenBody,
  parseAndValidateAuthorizationCallback,
  parseConnectTokenResponse,
  parseConnectUserInfo,
} from "@tapokjs/core";
import type {
  BaseIdentityTokenClaims,
  BaseScope,
  BaseOidcScope,
  OidcAuthorizationOptions,
  ConnectIdTokenClaims,
  ConnectScope,
  ConnectUserInfo,
  ParsedAuthorizationCallback,
} from "@tapokjs/core";
import { TapokAuthError } from "./errors.ts";
import { remoteJwks } from "./jwks.ts";
import {
  assertAuthenticationAge,
  assertBaseOidcClaims,
  verifyToken,
} from "./token-verification.ts";
import { fetchTapok, requestTapokJson, requireTimeout } from "./shared.ts";

export { TapokCallbackValidationError, TapokError } from "@tapokjs/core";
export { TapokAuthError, TapokHttpError } from "./errors.ts";
export type { TapokAuthErrorCode } from "./errors.ts";
export type { VerifiedTokenClaims } from "./token-verification.ts";
export type {
  AuthorizationResponseErrorCode,
  BaseIdentityTokenClaims,
  BaseOidcScope,
  BaseScope,
  CallbackValidationErrorCode,
  ConnectIdTokenClaims,
  ConnectRefreshResponse,
  ConnectScope,
  ConnectUserInfo,
  OidcAuthorizationOptions,
  ParsedAuthorizationCallback,
  TapokProtocolErrorBody,
  TapokProtocolErrorCode,
} from "@tapokjs/core";

export type ReplayStore = {
  /**
   * Atomically reserve `jti` until `expiresAt` and return false when it is
   * already reserved. `expiresAt` is in Unix **seconds** (a JWT NumericDate,
   * clock tolerance included), unlike transaction `expiresAt`, which is in
   * milliseconds.
   */
  consume(jti: string, expiresAt: number): Promise<boolean>;
};

export type ConnectAuthorizationTransaction = {
  state: string;
  /** SHA-256 of the browser binding. The raw value never reaches the store. */
  browserBinding: string;
  maxAge?: number;
  nonce: string;
  codeVerifier: string;
  redirectUri: string;
  scopes: readonly ConnectScope[];
  /**
   * Unix time in **milliseconds** (`Date.now()` scale), five minutes after
   * creation. The store must not return a record past this moment.
   */
  expiresAt: number;
};

export type ConnectTransactionStore = {
  save(transaction: ConnectAuthorizationTransaction): Promise<void>;
  /** Atomically return and delete the transaction for state. */
  consume(state: string): Promise<ConnectAuthorizationTransaction | null>;
};

export type ConnectServerClientOptions = {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: readonly ConnectScope[];
  transactions: ConnectTransactionStore;
  fetch?: typeof fetch;
  /** Optional transport for JWKS retrieval, useful behind controlled server egress. */
  jwksFetch?: typeof fetch;
  issuer?: string;
  /** Metadata fetched separately from a configured trusted issuer. */
  discovery?: unknown;
  allowedEndpointOrigins?: readonly string[];
  /** Limit for each token, UserInfo and revoke request. Default 10 000 ms. */
  timeoutMs?: number;
};

export type ConnectAuthorizationStart = {
  authorizationUrl: URL;
  state: string;
};

export type ConnectCallbackError = {
  ok: false;
  callback: Extract<ParsedAuthorizationCallback, { ok: false }>;
};

export type ConnectCallbackSuccess = {
  ok: true;
  /** Verified ID token **claims**. The compact JWT is `rawIdToken`. */
  idToken: ConnectIdTokenClaims;
  accessToken: string;
  grantedScopes: readonly ConnectScope[];
  userInfo: ConnectUserInfo;
  refreshToken?: string;
  /** The compact ID token, e.g. for `logout({ idTokenHint })`. */
  rawIdToken: string;
  /** Access token lifetime in seconds. */
  expiresIn: number;
};

export type ConnectCallbackResult =
  ConnectCallbackSuccess | ConnectCallbackError;

const TRANSACTION_TTL_MS = 5 * 60 * 1000;
/** A revoke after a failed validation must not hold the callback for long. */
const CLEANUP_TIMEOUT_MS = 5_000;

function readSingleState(callbackUrl: string | URL): string {
  let url: URL;
  try {
    url = callbackUrl instanceof URL ? callbackUrl : new URL(callbackUrl);
  } catch {
    throw new TypeError("callbackUrl must be an absolute URL");
  }
  const values = url.searchParams.getAll("state");
  if (values.length !== 1 || values[0] === undefined || values[0] === "") {
    throw new TypeError(
      "callback URL must contain exactly one state parameter",
    );
  }
  return values[0];
}

function requireClientId(clientId: unknown): asserts clientId is string {
  // The value becomes a form field or a Basic credential; whitespace and
  // control characters are never part of an issued identifier.
  // eslint-disable-next-line no-control-regex -- Reject control characters at the input boundary.
  if (typeof clientId !== "string" || !/^[^\u0000- \u007f]+$/u.test(clientId))
    throw new TypeError("clientId must be a non-empty string without spaces");
}

function basicAuthorization(clientId: string, clientSecret: string): string {
  if (
    typeof clientId !== "string" ||
    typeof clientSecret !== "string" ||
    clientId === "" ||
    clientSecret === ""
  )
    throw new TypeError("clientId and clientSecret must not be empty");
  const encoded = new URLSearchParams({ [clientId]: clientSecret }).toString();
  const separator = encoded.indexOf("=");
  const credentials = `${encoded.slice(0, separator)}:${encoded.slice(separator + 1)}`;
  // Form encoding is already ASCII, including non-ASCII client secrets.
  return `Basic ${btoa(credentials)}`;
}

function useDiscoveredEndpoint(url: URL, endpoint: string): URL {
  const configured = new URL(endpoint);
  for (const [name, value] of url.searchParams)
    configured.searchParams.set(name, value);
  return configured;
}

const textEncoder = /* @__PURE__ */ new TextEncoder();

async function hashBinding(value: string): Promise<string> {
  if (typeof value !== "string" || value.length < 32)
    throw new TypeError(
      "browserBinding must contain at least 32 random characters",
    );
  return Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", textEncoder.encode(value)),
    ),
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join("");
}

type StoredTransaction = {
  state: string;
  browserBinding?: string;
  redirectUri: string;
  expiresAt: number;
};

/**
 * One place for the rules every server flow shares: exactly one `state`, an
 * atomically consumed transaction that belongs to this client configuration
 * and has not expired, and the same browser that started the sign-in.
 */
async function consumeTransaction<T extends StoredTransaction>(
  label: string,
  store: { consume(state: string): Promise<T | null> },
  callbackUrl: string | URL,
  redirectUri: string,
  browserBinding: string,
): Promise<T> {
  const state = readSingleState(callbackUrl);
  const binding = await hashBinding(browserBinding);
  const transaction = await store.consume(state);
  if (transaction === null || transaction === undefined)
    throw new TapokAuthError(
      "invalid_transaction",
      `${label} transaction is missing, expired, or already consumed`,
    );
  if (transaction.state !== state || transaction.redirectUri !== redirectUri)
    throw new TapokAuthError(
      "invalid_transaction",
      `${label} transaction does not match this client configuration`,
    );
  if (
    typeof transaction.expiresAt !== "number" ||
    !Number.isFinite(transaction.expiresAt) ||
    transaction.expiresAt <= Date.now()
  )
    throw new TapokAuthError(
      "invalid_transaction",
      `${label} transaction has expired`,
    );
  // A record without a binding was written by a pre-1.0 SDK; it cannot prove
  // which browser started the sign-in, so it is refused like a mismatch.
  if (transaction.browserBinding !== binding)
    throw new TapokAuthError(
      "binding_mismatch",
      `${label} callback does not match the browser binding of its transaction`,
    );
  return transaction;
}

function scopeExpansion(message: string): TapokAuthError {
  return new TapokAuthError("invalid_response", message);
}

/**
 * Verifies a native Base identity token and reserves its `jti`. Resolves only
 * when the token is valid and was never accepted before; a repeated `jti`
 * rejects with `TapokAuthError` code `token_replayed`.
 */
export async function verifyAndConsumeBaseIdentityToken(input: {
  token: string;
  expectedIssuer: string;
  expectedAudience: `origin:${string}`;
  replayStore: ReplayStore;
  maxClockSkewSeconds?: number;
  expectedNonce?: string;
  jwksFetch?: typeof fetch;
}): Promise<{ claims: BaseIdentityTokenClaims; replayConsumed: true }> {
  const maxClockSkewSeconds = input.maxClockSkewSeconds ?? 300;
  const payload = await verifyToken({
    token: input.token,
    expectedIssuer: input.expectedIssuer,
    expectedAudience: input.expectedAudience,
    expectedNonce: input.expectedNonce,
    jwks: remoteJwks(
      resolveTapokEndpoints({ issuer: input.expectedIssuer }).jwks_uri,
      input.jwksFetch,
    ),
    mode: "base",
    maximumLifetime: 600,
    maxClockSkewSeconds,
  });
  if (payload["pairwise_sub"] !== payload.sub)
    throw new TapokAuthError(
      "invalid_token",
      "Base pairwise_sub must equal sub",
    );
  const consumed = await input.replayStore.consume(
    payload.jti,
    Math.ceil(payload.exp + maxClockSkewSeconds),
  );
  if (!consumed)
    throw new TapokAuthError(
      "token_replayed",
      "Base identity token has already been consumed",
    );
  return {
    claims: payload as unknown as BaseIdentityTokenClaims,
    replayConsumed: true,
  };
}

export async function verifyConnectIdToken(input: {
  token: string;
  expectedIssuer: string;
  expectedAudience: string;
  expectedNonce: string;
  maxClockSkewSeconds?: number;
  jwksFetch?: typeof fetch;
}): Promise<ConnectIdTokenClaims> {
  return (await verifyToken({
    token: input.token,
    expectedIssuer: input.expectedIssuer,
    expectedAudience: input.expectedAudience,
    expectedNonce: input.expectedNonce,
    mode: "connect",
    jwks: remoteJwks(
      resolveTapokEndpoints({ issuer: input.expectedIssuer }).jwks_uri,
      input.jwksFetch,
    ),
    maximumLifetime: 900,
    maxClockSkewSeconds: input.maxClockSkewSeconds ?? 300,
  })) as unknown as ConnectIdTokenClaims;
}

/**
 * Connect on the application backend. The same `browserBinding` — a random
 * value of at least 32 characters kept in a Secure HttpOnly SameSite=Lax
 * cookie or the server session — is required to start and to complete the
 * sign-in; never derive it from `state`, IP or User-Agent.
 */
export function createConnectServerClient(options: ConnectServerClientOptions) {
  const issuer = options.issuer ?? TAPOK_ISSUER;
  const endpoints =
    options.discovery === undefined
      ? resolveTapokEndpoints({ issuer })
      : validateOidcDiscovery(
          options.discovery,
          issuer,
          options.allowedEndpointOrigins,
        );
  if (
    typeof options.clientId !== "string" ||
    !/^tpk_client_[A-Za-z0-9_-]+$/u.test(options.clientId) ||
    typeof options.clientSecret !== "string" ||
    options.clientSecret === ""
  ) {
    throw new TypeError(
      "clientId must use the tpk_client_ prefix and clientSecret must not be empty",
    );
  }
  const timeoutMs = requireTimeout(options.timeoutMs);
  const clientJwks = remoteJwks(endpoints.jwks_uri, options.jwksFetch);
  const clientAuthorizationHeaders = {
    authorization: basicAuthorization(options.clientId, options.clientSecret),
    "content-type": "application/x-www-form-urlencoded",
  } as const;

  async function beginAuthorization(
    browserBinding: string,
    authorizationOptions: OidcAuthorizationOptions = {},
  ): Promise<ConnectAuthorizationStart> {
    const [binding, secrets] = await Promise.all([
      hashBinding(browserBinding),
      createAuthorizationSecrets(),
    ]);
    const authorizationUrl = useDiscoveredEndpoint(
      buildConnectAuthorizeUrl({
        ...authorizationOptions,
        issuer,
        clientId: options.clientId,
        redirectUri: options.redirectUri,
        scopes: options.scopes,
        state: secrets.state,
        nonce: secrets.nonce,
        codeChallenge: secrets.pkce.challenge,
      }),
      endpoints.authorization_endpoint,
    );
    await options.transactions.save({
      state: secrets.state,
      browserBinding: binding,
      ...(authorizationOptions.maxAge !== undefined
        ? { maxAge: authorizationOptions.maxAge }
        : {}),
      nonce: secrets.nonce,
      codeVerifier: secrets.pkce.verifier,
      redirectUri: options.redirectUri,
      scopes: [...options.scopes],
      expiresAt: Date.now() + TRANSACTION_TTL_MS,
    });
    return { authorizationUrl, state: secrets.state };
  }

  /** Best effort: the caller is already failing and must see its own error. */
  async function discard(tokens: {
    access_token: string;
    refresh_token?: string;
  }): Promise<void> {
    const timeout = Math.min(timeoutMs, CLEANUP_TIMEOUT_MS);
    await Promise.all([
      tokens.refresh_token === undefined
        ? undefined
        : sendRevoke(tokens.refresh_token, "refresh_token", timeout).catch(
            () => undefined,
          ),
      sendRevoke(tokens.access_token, "access_token", timeout).catch(
        () => undefined,
      ),
    ]);
  }

  async function completeCallback(
    callbackUrl: string | URL,
    browserBinding: string,
  ): Promise<ConnectCallbackResult> {
    const transaction = await consumeTransaction(
      "Tapok Connect",
      options.transactions,
      callbackUrl,
      options.redirectUri,
      browserBinding,
    );
    const callback = parseAndValidateAuthorizationCallback({
      callbackUrl,
      expectedState: transaction.state,
      expectedIssuer: issuer,
      redirectUri: options.redirectUri,
    });
    if (!callback.ok) return { ok: false, callback };

    const tokens = await requestTapokJson(
      options.fetch,
      endpoints.token_endpoint,
      {
        method: "POST",
        headers: clientAuthorizationHeaders,
        body: createConnectTokenBody({
          grant_type: "authorization_code",
          code: callback.code,
          redirect_uri: options.redirectUri,
          code_verifier: transaction.codeVerifier,
        }),
      },
      timeoutMs,
      parseConnectTokenResponse,
    );
    try {
      // parseConnectTokenResponse already validated the scope string: known values, no duplicates, openid granted.
      const grantedScopes = tokens.scope.split(" ") as ConnectScope[];
      if (grantedScopes.some((scope) => !transaction.scopes.includes(scope))) {
        throw scopeExpansion(
          "Token response grants a scope that was not requested",
        );
      }
      const idToken = (await verifyToken({
        token: tokens.id_token,
        expectedIssuer: issuer,
        expectedAudience: options.clientId,
        expectedNonce: transaction.nonce,
        mode: "connect",
        maximumLifetime: 900,
        maxClockSkewSeconds: 300,
        jwks: clientJwks,
      })) as unknown as ConnectIdTokenClaims;

      assertAuthenticationAge(
        idToken as unknown as Record<string, unknown>,
        transaction.maxAge,
      );
      const userInfo = await requestTapokJson(
        options.fetch,
        endpoints.userinfo_endpoint,
        {
          method: "GET",
          headers: { authorization: `Bearer ${tokens.access_token}` },
        },
        timeoutMs,
        (value) => parseConnectUserInfo(value, grantedScopes),
      );
      if (userInfo.sub !== idToken.sub) {
        throw new TapokAuthError(
          "invalid_response",
          "UserInfo sub does not match the verified ID token",
        );
      }
      return {
        ok: true,
        idToken,
        rawIdToken: tokens.id_token,
        expiresIn: tokens.expires_in,
        accessToken: tokens.access_token,
        ...(tokens.refresh_token !== undefined
          ? { refreshToken: tokens.refresh_token }
          : {}),
        grantedScopes,
        userInfo,
      };
    } catch (error) {
      // The tokens exist on the platform but will never reach the application.
      await discard(tokens);
      throw error;
    }
  }

  async function sendRevoke(
    token: string,
    tokenType: "access_token" | "refresh_token",
    timeout: number,
  ): Promise<void> {
    await fetchTapok(
      options.fetch,
      endpoints.revocation_endpoint,
      {
        method: "POST",
        headers: clientAuthorizationHeaders,
        body: createConnectRevokeBody({
          token,
          token_type_hint: tokenType,
        }),
      },
      timeout,
    );
  }

  /** Revokes an access token, or a refresh token with `tokenType: "refresh_token"`. */
  async function revoke(
    token: string,
    tokenType: "access_token" | "refresh_token" = "access_token",
  ): Promise<void> {
    await sendRevoke(token, tokenType, timeoutMs);
  }

  /**
   * Exchanges a refresh token. Returns the token endpoint response as it is on
   * the wire (`access_token`, `refresh_token`, …, snake_case) after checking
   * that scopes were not widened and a returned ID token names `expected.sub`.
   */
  async function refresh(
    refreshToken: string,
    expected: { sub: string; nonce?: string; scopes: readonly ConnectScope[] },
  ) {
    const tokens = await requestTapokJson(
      options.fetch,
      endpoints.token_endpoint,
      {
        method: "POST",
        headers: clientAuthorizationHeaders,
        body: createConnectRefreshBody({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          scope: expected.scopes.join(" "),
        }),
      },
      timeoutMs,
      parseConnectRefreshResponse,
    );
    try {
      if (
        tokens.scope
          .split(" ")
          .some((scope) => !expected.scopes.includes(scope as ConnectScope))
      )
        throw scopeExpansion("Refresh expanded scopes");
      if (tokens.id_token !== undefined) {
        const claims = await verifyToken({
          token: tokens.id_token,
          expectedIssuer: issuer,
          expectedAudience: options.clientId,
          expectedNonce: expected.nonce,
          mode: "connect",
          maximumLifetime: 900,
          maxClockSkewSeconds: 60,
          jwks: clientJwks,
        });
        if (claims.sub !== expected.sub)
          throw new TapokAuthError(
            "invalid_response",
            "Refresh subject mismatch",
          );
      }
    } catch (error) {
      await discard(tokens);
      throw error;
    }
    return tokens;
  }
  function logout(
    input: {
      idTokenHint?: string;
      postLogoutRedirectUri?: string;
      state?: string;
    } = {},
  ) {
    return useDiscoveredEndpoint(
      buildLogoutUrl({ ...input, issuer, clientId: options.clientId }),
      endpoints.end_session_endpoint,
    );
  }
  return { beginAuthorization, completeCallback, revoke, refresh, logout };
}

export type BaseServerTransaction = Omit<
  ConnectAuthorizationTransaction,
  "scopes"
> & { scopes: readonly BaseScope[] };
export type BaseServerClientOptions = {
  redirectUri: string;
  scopes?: readonly BaseScope[];
  issuer?: string;
  transactions: {
    save(transaction: BaseServerTransaction): Promise<void>;
    consume(state: string): Promise<BaseServerTransaction | null>;
  };
  replayStore: ReplayStore;
  fetch?: typeof fetch;
  jwksFetch?: typeof fetch;
  /** Limit for the exchange request. Default 10 000 ms. */
  timeoutMs?: number;
};

/** Store browserBinding in a Secure HttpOnly SameSite=Lax cookie/session, independently of state. */
export function createBaseServerClient(options: BaseServerClientOptions) {
  const issuer = options.issuer ?? TAPOK_ISSUER;
  const jwksUri = resolveTapokEndpoints({ issuer }).jwks_uri;
  const clientId = deriveBaseClientId(options.redirectUri);
  const timeoutMs = requireTimeout(options.timeoutMs);
  const jwks = remoteJwks(jwksUri, options.jwksFetch);
  async function beginAuthorization(browserBinding: string) {
    const [binding, secrets] = await Promise.all([
      hashBinding(browserBinding),
      createAuthorizationSecrets(),
    ]);
    const scopes = options.scopes ?? ["session"];
    const authorizationUrl = buildBaseAuthorizeUrl({
      issuer,
      redirectUri: options.redirectUri,
      scopes,
      state: secrets.state,
      nonce: secrets.nonce,
      codeChallenge: secrets.pkce.challenge,
    });
    await options.transactions.save({
      state: secrets.state,
      nonce: secrets.nonce,
      codeVerifier: secrets.pkce.verifier,
      redirectUri: options.redirectUri,
      scopes,
      browserBinding: binding,
      expiresAt: Date.now() + TRANSACTION_TTL_MS,
    });
    return { authorizationUrl, state: secrets.state };
  }
  async function completeCallback(
    callbackUrl: string | URL,
    browserBinding: string,
  ) {
    const transaction = await consumeTransaction(
      "Tapok Base",
      options.transactions,
      callbackUrl,
      options.redirectUri,
      browserBinding,
    );
    const callback = parseAndValidateAuthorizationCallback({
      callbackUrl,
      expectedState: transaction.state,
      expectedIssuer: issuer,
      redirectUri: options.redirectUri,
    });
    if (!callback.ok) return { ok: false as const, callback };
    const tokens = await requestTapokJson(
      options.fetch,
      issuer + "/api/v1/base/exchange",
      {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: createBaseExchangeBody({
          grant_type: "authorization_code",
          code: callback.code,
          client_id: clientId,
          redirect_uri: options.redirectUri,
          code_verifier: transaction.codeVerifier,
        }),
      },
      timeoutMs,
      parseBaseExchangeResponse,
    );
    if (
      tokens.scope.includes("age:18") &&
      !transaction.scopes.includes("age:18")
    )
      throw scopeExpansion("Base response expanded scopes");
    const claims = await verifyToken({
      token: tokens.identity_token,
      expectedIssuer: issuer,
      expectedAudience: clientId,
      expectedNonce: transaction.nonce,
      mode: "base",
      maximumLifetime: 600,
      maxClockSkewSeconds: 60,
      jwks,
    });
    if (claims["pairwise_sub"] !== claims.sub)
      throw new TapokAuthError(
        "invalid_token",
        "Base pairwise subject mismatch",
      );
    if (
      !(await options.replayStore.consume(
        claims.jti,
        Math.ceil(claims.exp + 60),
      ))
    )
      throw new TapokAuthError("token_replayed", "Base token already consumed");
    return {
      ok: true as const,
      claims: claims as unknown as BaseIdentityTokenClaims,
    };
  }
  return { beginAuthorization, completeCallback };
}

export type BaseOidcServerClientOptions = Omit<
  ConnectServerClientOptions,
  "clientSecret" | "scopes" | "transactions"
> & {
  /** Omit for a public client. An empty string is a configuration error. */
  clientSecret?: string;
  scopes: readonly BaseOidcScope[];
  transactions: ConnectTransactionStore;
};

/** Confidential or public PKCE Base OIDC. Personal Connect claims are rejected. */
export function createBaseOidcServerClient(
  options: BaseOidcServerClientOptions,
) {
  requireClientId(options.clientId);
  // An empty secret usually means an unset environment variable. Sending the
  // request as a public client instead would hide that misconfiguration.
  const authorization =
    options.clientSecret === undefined
      ? undefined
      : basicAuthorization(options.clientId, options.clientSecret);
  const timeoutMs = requireTimeout(options.timeoutMs);
  const defaults = resolveTapokEndpoints({
    issuer: options.issuer,
    mode: "base",
  });
  const endpoints =
    options.discovery === undefined
      ? defaults
      : validateOidcDiscovery(
          options.discovery,
          defaults.issuer,
          options.allowedEndpointOrigins,
        );
  const jwks = remoteJwks(endpoints.jwks_uri, options.jwksFetch);

  /** Form request authenticated as this client: Basic, or `client_id` for a public client. */
  function clientRequest(body: URLSearchParams): RequestInit {
    const headers: Record<string, string> = {
      "content-type": "application/x-www-form-urlencoded",
    };
    if (authorization !== undefined) headers["authorization"] = authorization;
    else body.set("client_id", options.clientId);
    return { method: "POST", headers, body };
  }

  async function beginAuthorization(
    browserBinding: string,
    authorizationOptions: OidcAuthorizationOptions = {},
  ) {
    const [binding, secrets] = await Promise.all([
      hashBinding(browserBinding),
      createAuthorizationSecrets(),
    ]);
    const authorizationUrl = useDiscoveredEndpoint(
      buildOidcBaseAuthorizeUrl({
        ...authorizationOptions,
        issuer: endpoints.issuer,
        clientId: options.clientId,
        redirectUri: options.redirectUri,
        scopes: options.scopes,
        state: secrets.state,
        nonce: secrets.nonce,
        codeChallenge: secrets.pkce.challenge,
      }),
      endpoints.authorization_endpoint,
    );
    await options.transactions.save({
      state: secrets.state,
      nonce: secrets.nonce,
      codeVerifier: secrets.pkce.verifier,
      redirectUri: options.redirectUri,
      scopes: [...options.scopes],
      browserBinding: binding,
      ...(authorizationOptions.maxAge !== undefined
        ? { maxAge: authorizationOptions.maxAge }
        : {}),
      expiresAt: Date.now() + TRANSACTION_TTL_MS,
    });
    return { authorizationUrl, state: secrets.state };
  }
  async function completeCallback(
    callbackUrl: string | URL,
    browserBinding: string,
  ) {
    const transaction = await consumeTransaction(
      "Tapok Base OIDC",
      options.transactions,
      callbackUrl,
      options.redirectUri,
      browserBinding,
    );
    const callback = parseAndValidateAuthorizationCallback({
      callbackUrl,
      expectedState: transaction.state,
      expectedIssuer: endpoints.issuer,
      redirectUri: options.redirectUri,
    });
    if (!callback.ok) return { ok: false as const, callback };
    const tokens = await requestTapokJson(
      options.fetch,
      endpoints.token_endpoint,
      clientRequest(
        createConnectTokenBody({
          grant_type: "authorization_code",
          code: callback.code,
          redirect_uri: options.redirectUri,
          code_verifier: transaction.codeVerifier,
        }),
      ),
      timeoutMs,
      parseConnectTokenResponse,
    );
    try {
      const grantedScopes = tokens.scope.split(" ") as BaseOidcScope[];
      if (
        grantedScopes.some(
          (scope) =>
            !transaction.scopes.includes(scope) ||
            !options.scopes.includes(scope),
        )
      )
        throw scopeExpansion("Base OIDC response expanded scopes");
      const claims = await verifyToken({
        token: tokens.id_token,
        expectedIssuer: endpoints.issuer,
        expectedAudience: options.clientId,
        expectedNonce: transaction.nonce,
        mode: "base-oidc",
        maximumLifetime: 900,
        maxClockSkewSeconds: 60,
        jwks,
      });
      assertAuthenticationAge(claims, transaction.maxAge);
      assertBaseOidcClaims(claims);
      const userInfo = await requestTapokJson(
        options.fetch,
        endpoints.userinfo_endpoint,
        {
          method: "GET",
          headers: { authorization: "Bearer " + tokens.access_token },
        },
        timeoutMs,
        (value) => {
          assertBaseOidcClaims(value);
          return parseConnectUserInfo(value, grantedScopes);
        },
      );
      if (userInfo.sub !== claims.sub)
        throw new TapokAuthError(
          "invalid_response",
          "Base OIDC UserInfo subject mismatch",
        );
      return {
        ok: true as const,
        /** Verified ID token **claims**. The compact JWT is `rawIdToken`. */
        idToken: claims,
        rawIdToken: tokens.id_token,
        accessToken: tokens.access_token,
        /** Access token lifetime in seconds. */
        expiresIn: tokens.expires_in,
        grantedScopes,
        userInfo,
      };
    } catch (error) {
      // Best effort: the access token will never reach the application.
      await fetchTapok(
        options.fetch,
        endpoints.revocation_endpoint,
        clientRequest(
          createConnectRevokeBody({
            token: tokens.access_token,
            token_type_hint: "access_token",
          }),
        ),
        Math.min(timeoutMs, CLEANUP_TIMEOUT_MS),
      ).catch(() => undefined);
      throw error;
    }
  }
  function logout(
    input: {
      idTokenHint?: string;
      postLogoutRedirectUri?: string;
      state?: string;
    } = {},
  ) {
    return useDiscoveredEndpoint(
      buildLogoutUrl({
        ...input,
        issuer: endpoints.issuer,
        mode: "base",
        clientId: options.clientId,
      }),
      endpoints.end_session_endpoint,
    );
  }
  return { beginAuthorization, completeCallback, logout };
}
