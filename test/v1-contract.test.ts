// Regression tests for the v1 contract: every case here failed, or could not be
// expressed, before the corresponding fix.
import { describe, expect, test } from "bun:test";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import * as browserEntry from "../src/browser.ts";
import * as rootEntry from "../src/index.ts";
import * as serverEntry from "../src/server.ts";
import {
  TapokAuthError,
  TapokCallbackValidationError,
  TapokError,
  TapokHttpError,
  createBaseBrowserClient,
  createBaseOidcBrowserClient,
  createConnectBrowserNavigator,
  notifyAuthPopupOpener,
  openAuthPopup,
  relayBasePopupCallback,
} from "../src/browser.ts";
import {
  createBaseOidcServerClient,
  createBaseServerClient,
  createConnectServerClient,
  verifyAndConsumeBaseIdentityToken,
  verifyConnectIdToken,
} from "../src/server.ts";
import type {
  BaseServerTransaction,
  ConnectAuthorizationTransaction,
} from "../src/server.ts";

const binding = "random-session-cookie-with-256-bits-of-entropy";
const otherBinding = "another-session-cookie-with-enough-entropy!";
const redirectUri = "https://app.example/callback";
const issuer = "https://id.example";
const baseIssuer = issuer + "/oidc/base";
const clientId = "tpk_client_test";

const keys = await generateKeyPair("RS256");
const jwk = {
  ...(await exportJWK(keys.publicKey)),
  kid: "test",
  alg: "RS256",
  use: "sig",
};
const json = (value: unknown, status = 200) => Response.json(value, { status });
const jwksFetch = (async () =>
  json({ keys: [jwk] })) as unknown as typeof fetch;

function sign(
  claims: Record<string, unknown>,
  header: Record<string, unknown> = {},
) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "test", typ: "JWT", ...header })
    .setIssuedAt()
    .setExpirationTime("5m")
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

function transactionStore<T extends { state: string }>() {
  const records = new Map<string, T>();
  return {
    records,
    async save(t: T) {
      records.set(t.state, t);
    },
    async consume(state: string) {
      const t = records.get(state);
      records.delete(state);
      return t ?? null;
    },
  };
}

function memoryStorage() {
  const data = new Map<string, string>();
  return {
    data,
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => {
      data.set(k, v);
    },
    removeItem: (k: string) => {
      data.delete(k);
    },
  };
}

function callback(state: string, iss: string, base = redirectUri) {
  const url = new URL(base);
  url.searchParams.set("code", "code");
  url.searchParams.set("state", state);
  url.searchParams.set("iss", iss);
  return url.href;
}

async function failure(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run();
  } catch (error) {
    return error;
  }
  throw new Error("Expected the call to reject");
}

type Call = { url: string; body: URLSearchParams; headers: Headers };

/** Connect client whose platform answers are scripted per test. */
function connect(input: {
  idToken?: (nonce: string) => Record<string, unknown>;
  tokenResponse?: Record<string, unknown>;
  userInfo?: () => Response | Promise<Response>;
  redirectUri?: string;
  timeoutMs?: number;
  transport?: typeof fetch;
}) {
  const calls: Call[] = [];
  const transactions = transactionStore<ConnectAuthorizationTransaction>();
  let nonce = "";
  const client = createConnectServerClient({
    issuer,
    clientId,
    clientSecret: "secret",
    redirectUri: input.redirectUri ?? redirectUri,
    scopes: ["openid", "email", "offline_access"],
    transactions,
    jwksFetch,
    ...(input.timeoutMs !== undefined ? { timeoutMs: input.timeoutMs } : {}),
    fetch:
      input.transport ??
      ((async (url: unknown, init?: RequestInit) => {
        const body = new URLSearchParams(String(init?.body ?? ""));
        calls.push({
          url: String(url),
          body,
          headers: new Headers(init?.headers),
        });
        if (String(url).endsWith("/revoke")) return new Response(null);
        if (String(url).endsWith("/userinfo"))
          return input.userInfo ? input.userInfo() : json({ sub: "user" });
        return json({
          access_token: "access",
          token_type: "Bearer",
          scope: "openid email",
          expires_in: 300,
          refresh_token: "refresh",
          id_token: await sign({
            iss: issuer,
            aud: clientId,
            sub: "user",
            mode: "connect",
            nonce,
            ...input.idToken?.(nonce),
          }),
          ...input.tokenResponse,
        });
      }) as unknown as typeof fetch),
  });
  return {
    client,
    calls,
    transactions,
    async begin(value = binding) {
      const start = await client.beginAuthorization(value);
      nonce = start.authorizationUrl.searchParams.get("nonce")!;
      return start;
    },
    revoked: () =>
      calls
        .filter((call) => call.url.endsWith("/revoke"))
        .map((call) => call.body.get("token"))
        .sort(),
  };
}

describe("error classes and codes", () => {
  test("every entry point exports the same error classes", () => {
    for (const entry of [browserEntry, serverEntry, rootEntry]) {
      expect(entry.TapokError).toBe(TapokError);
      expect(entry.TapokAuthError).toBe(TapokAuthError);
      expect(entry.TapokHttpError).toBe(TapokHttpError);
      expect(entry.TapokCallbackValidationError).toBe(
        TapokCallbackValidationError,
      );
    }
    expect(Object.keys(rootEntry).sort()).toEqual([
      "TapokAuthError",
      "TapokCallbackValidationError",
      "TapokError",
      "TapokHttpError",
    ]);
  });

  test("all three classes share the TapokError base and carry a code", () => {
    const http = new TapokHttpError(400, { error: "invalid_grant" });
    expect(http).toBeInstanceOf(TapokError);
    expect(http.code).toBe("invalid_grant");
    expect(http.status).toBe(400);
    expect(new TapokHttpError(502).code).toBe("http_error");
    const auth = new TapokAuthError("binding_mismatch", "text");
    expect(auth).toBeInstanceOf(TapokError);
    expect(auth).toBeInstanceOf(Error);
    expect(auth.name).toBe("TapokAuthError");
    expect(new TapokCallbackValidationError("state_mismatch")).toBeInstanceOf(
      TapokError,
    );
  });

  test("token failures are TapokAuthError invalid_token with an allowlisted reason", async () => {
    const verify = (token: string) =>
      verifyConnectIdToken({
        token,
        expectedIssuer: issuer,
        expectedAudience: clientId,
        expectedNonce: "n",
        jwksFetch,
      });
    const claims = { iss: issuer, aud: clientId, sub: "u", mode: "connect" };
    const cases = [
      await sign({ ...claims, nonce: "other" }),
      await sign({ ...claims, nonce: "n", aud: "someone-else" }),
      await sign({ ...claims, nonce: "n" }, { typ: "at+jwt" }),
      (await sign({ ...claims, nonce: "n" })).slice(0, -4) + "AAAA",
      "not-a-jwt",
    ];
    for (const token of cases) {
      const error = await failure(() => verify(token));
      expect(error).toBeInstanceOf(TapokAuthError);
      expect((error as TapokAuthError).code).toBe("invalid_token");
    }
    const malformed = (await failure(() => verify("a.b.c"))) as TapokAuthError;
    expect(malformed.reason).toBe("ERR_JWS_INVALID");
    expect(malformed.message).toBe("JWT is malformed");
    expect(malformed.cause).toBeUndefined();
    const forged = (await failure(() => verify(cases[3]!))) as TapokAuthError;
    expect(forged.reason).toBe("ERR_JWS_SIGNATURE_VERIFICATION_FAILED");
    const audience = (await failure(() => verify(cases[1]!))) as TapokAuthError;
    expect(audience.reason).toBe("ERR_JWT_CLAIM_VALIDATION_FAILED");
    expect(audience.message).toBe("JWT claim validation failed: aud");
    // Checks the SDK makes itself have fixed text and no library verdict.
    const nonce = (await failure(() => verify(cases[0]!))) as TapokAuthError;
    expect(nonce.reason).toBeUndefined();
    expect(nonce.message).toContain("nonce");
  });

  test("an unreachable JWKS is jwks_unavailable, not an invalid token", async () => {
    const token = await sign({
      iss: "https://down.example",
      aud: clientId,
      sub: "u",
      mode: "connect",
      nonce: "n",
    });
    for (const transport of [
      async () => {
        throw new TypeError("fetch failed");
      },
      async () => new Response("bad gateway", { status: 502 }),
    ]) {
      const error = await failure(() =>
        verifyConnectIdToken({
          token,
          expectedIssuer: "https://down.example",
          expectedAudience: clientId,
          expectedNonce: "n",
          jwksFetch: transport as unknown as typeof fetch,
        }),
      );
      expect(error).toBeInstanceOf(TapokAuthError);
      expect((error as TapokAuthError).code).toBe("jwks_unavailable");
    }
  });

  test("a replayed Base identity token is token_replayed", async () => {
    const token = await sign({
      iss: issuer,
      aud: "origin:https://app.example",
      sub: "p",
      pairwise_sub: "p",
      mode: "base",
      nonce: "n",
    });
    const seen = new Set<string>();
    const verify = () =>
      verifyAndConsumeBaseIdentityToken({
        token,
        expectedIssuer: issuer,
        expectedAudience: "origin:https://app.example",
        jwksFetch,
        replayStore: {
          async consume(jti) {
            if (seen.has(jti)) return false;
            seen.add(jti);
            return true;
          },
        },
      });
    expect((await verify()).claims.sub).toBe("p");
    const error = (await failure(verify)) as TapokAuthError;
    expect(error).toBeInstanceOf(TapokAuthError);
    expect(error.code).toBe("token_replayed");
  });

  test("a body that breaks the contract is invalid_response without the body", async () => {
    const flow = connect({ tokenResponse: { token_type: "MAC" } });
    const start = await flow.begin();
    const error = (await failure(() =>
      flow.client.completeCallback(callback(start.state, issuer), binding),
    )) as TapokAuthError;
    expect(error).toBeInstanceOf(TapokAuthError);
    expect(error.code).toBe("invalid_response");
    expect(error.message).not.toContain("access");
    expect(JSON.stringify(error)).not.toContain("refresh");
  });
});

describe("Connect browser binding is mandatory", () => {
  test("a sign-in cannot start without a binding", async () => {
    const flow = connect({});
    const begin = flow.client.beginAuthorization as (
      binding?: string,
    ) => Promise<unknown>;
    await expect(begin()).rejects.toThrow("browserBinding");
    await expect(begin("short")).rejects.toThrow("browserBinding");
    expect(flow.transactions.records.size).toBe(0);
  });

  test("the callback is refused in another browser before any token request", async () => {
    const flow = connect({});
    const start = await flow.begin();
    const error = (await failure(() =>
      flow.client.completeCallback(callback(start.state, issuer), otherBinding),
    )) as TapokAuthError;
    expect(error).toBeInstanceOf(TapokAuthError);
    expect(error.code).toBe("binding_mismatch");
    expect(flow.calls).toHaveLength(0);
    // The transaction is spent: the forged attempt cannot be retried.
    expect(flow.transactions.records.size).toBe(0);
  });

  test("a transaction stored without a binding by an older SDK is refused", async () => {
    const flow = connect({});
    const start = await flow.begin();
    const record = flow.transactions.records.get(start.state)!;
    delete (record as { browserBinding?: string }).browserBinding;
    const error = (await failure(() =>
      flow.client.completeCallback(callback(start.state, issuer), binding),
    )) as TapokAuthError;
    expect(error.code).toBe("binding_mismatch");
    expect(flow.calls).toHaveLength(0);
  });

  test("the same browser completes the sign-in", async () => {
    const flow = connect({});
    const start = await flow.begin();
    const result = await flow.client.completeCallback(
      callback(start.state, issuer),
      binding,
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.idToken.sub).toBe("user");
      expect(result.refreshToken).toBe("refresh");
      expect(typeof result.rawIdToken).toBe("string");
    }
    expect(flow.revoked()).toEqual([]);
  });

  test("transaction failures are invalid_transaction", async () => {
    const flow = connect({});
    const start = await flow.begin();
    flow.transactions.records.get(start.state)!.expiresAt = Date.now() - 1;
    const expired = (await failure(() =>
      flow.client.completeCallback(callback(start.state, issuer), binding),
    )) as TapokAuthError;
    expect(expired.code).toBe("invalid_transaction");
    const missing = (await failure(() =>
      flow.client.completeCallback(callback("unknown", issuer), binding),
    )) as TapokAuthError;
    expect(missing.code).toBe("invalid_transaction");
  });
});

describe("tokens are revoked when validation fails after issuance", () => {
  test.each([
    [
      "the ID token nonce is wrong",
      { idToken: () => ({ nonce: "forged" }) },
      "invalid_token",
    ],
    [
      "the response widens the scopes",
      { tokenResponse: { scope: "openid email profile" } },
      "invalid_response",
    ],
    [
      "UserInfo names another subject",
      { userInfo: () => json({ sub: "someone-else" }) },
      "invalid_response",
    ],
    [
      "UserInfo is not JSON",
      { userInfo: () => new Response("<html>", { status: 200 }) },
      "invalid_response",
    ],
    [
      "UserInfo carries a claim outside the granted scopes",
      { userInfo: () => json({ sub: "user", phone_number: "+70000000000" }) },
      "invalid_response",
    ],
  ])("when %s", async (_name, script, code) => {
    const flow = connect(script as Parameters<typeof connect>[0]);
    const start = await flow.begin();
    const error = (await failure(() =>
      flow.client.completeCallback(callback(start.state, issuer), binding),
    )) as TapokAuthError;
    expect(error).toBeInstanceOf(TapokAuthError);
    expect(error.code).toBe(code as TapokAuthError["code"]);
    expect(flow.revoked()).toEqual(["access", "refresh"]);
    const revoke = flow.calls.find((call) => call.url.endsWith("/revoke"))!;
    expect(revoke.headers.get("authorization")).toStartWith("Basic ");
  });

  test("a UserInfo HTTP error also revokes and keeps its own class", async () => {
    const flow = connect({
      userInfo: () => json({ error: "invalid_token" }, 401),
    });
    const start = await flow.begin();
    const error = await failure(() =>
      flow.client.completeCallback(callback(start.state, issuer), binding),
    );
    expect(error).toBeInstanceOf(TapokHttpError);
    expect(flow.revoked()).toEqual(["access", "refresh"]);
  });

  test("a failing revoke never hides the original error", async () => {
    const transactions = transactionStore<ConnectAuthorizationTransaction>();
    const client = createConnectServerClient({
      issuer,
      clientId,
      clientSecret: "secret",
      redirectUri,
      scopes: ["openid"],
      transactions,
      jwksFetch,
      fetch: (async (url: unknown) => {
        if (String(url).endsWith("/revoke")) throw new TypeError("offline");
        return json({
          access_token: "access",
          token_type: "Bearer",
          scope: "openid",
          expires_in: 300,
          id_token: await sign({
            iss: issuer,
            aud: clientId,
            sub: "user",
            mode: "connect",
            nonce: "forged",
          }),
        });
      }) as unknown as typeof fetch,
    });
    const start = await client.beginAuthorization(binding);
    const error = (await failure(() =>
      client.completeCallback(callback(start.state, issuer), binding),
    )) as TapokAuthError;
    expect(error.code).toBe("invalid_token");
    expect(error.message).toContain("nonce");
  });

  test("refresh revokes the rotated tokens when the subject changes", async () => {
    const calls: Call[] = [];
    const client = createConnectServerClient({
      issuer,
      clientId,
      clientSecret: "secret",
      redirectUri,
      scopes: ["openid"],
      transactions: transactionStore<ConnectAuthorizationTransaction>(),
      jwksFetch,
      fetch: (async (url: unknown, init?: RequestInit) => {
        calls.push({
          url: String(url),
          body: new URLSearchParams(String(init?.body ?? "")),
          headers: new Headers(init?.headers),
        });
        if (String(url).endsWith("/revoke")) return new Response(null);
        return json({
          access_token: "rotated-access",
          token_type: "bearer",
          scope: "openid",
          expires_in: 300,
          refresh_token: "rotated-refresh",
          id_token: await sign({
            iss: issuer,
            aud: clientId,
            sub: "other-user",
            mode: "connect",
          }),
        });
      }) as unknown as typeof fetch,
    });
    const error = (await failure(() =>
      client.refresh("old", { sub: "user", scopes: ["openid"] }),
    )) as TapokAuthError;
    expect(error.code).toBe("invalid_response");
    expect(
      calls
        .filter((call) => call.url.endsWith("/revoke"))
        .map((call) => call.body.get("token"))
        .sort(),
    ).toEqual(["rotated-access", "rotated-refresh"]);
  });
});

describe("claim types are checked at runtime", () => {
  test.each([
    ["is_adult as a string", { is_adult: "yes" }],
    ["email as a number", { email: 5 }],
    ["email_verified as a string", { email_verified: "true" }],
    ["name as an object", { name: { first: "A" } }],
    ["auth_time as a string", { auth_time: "1700000000" }],
    ["two audiences", { aud: [clientId, "other"], azp: clientId }],
    ["a foreign authorized party", { azp: "other" }],
  ])("Connect ID token with %s is refused", async (_name, claims) => {
    const flow = connect({ idToken: () => claims });
    const start = await flow.begin();
    const error = (await failure(() =>
      flow.client.completeCallback(callback(start.state, issuer), binding),
    )) as TapokAuthError;
    expect(error).toBeInstanceOf(TapokAuthError);
    expect(error.code).toBe("invalid_token");
  });

  test("a single-element audience array is returned as the promised string", async () => {
    const flow = connect({
      idToken: () => ({
        aud: [clientId],
        is_adult: null,
        email: "u@e.example",
      }),
    });
    const start = await flow.begin();
    const result = await flow.client.completeCallback(
      callback(start.state, issuer),
      binding,
    );
    expect(result.ok && result.idToken.aud).toBe(clientId);
    expect(result.ok && result.idToken.is_adult).toBeNull();
  });

  test("a native Base identity token must carry nonce and pairwise_sub", async () => {
    const replayStore = { consume: async () => true };
    for (const claims of [
      { pairwise_sub: "p" },
      { nonce: "n" },
      { nonce: "n", pairwise_sub: "p", is_adult: 1 },
    ]) {
      const token = await sign({
        iss: issuer,
        aud: "origin:https://app.example",
        sub: "p",
        mode: "base",
        ...claims,
      });
      const error = (await failure(() =>
        verifyAndConsumeBaseIdentityToken({
          token,
          expectedIssuer: issuer,
          expectedAudience: "origin:https://app.example",
          replayStore,
          jwksFetch,
        }),
      )) as TapokAuthError;
      expect(error.code).toBe("invalid_token");
    }
  });
});

describe("Base OIDC accepts the tokens the platform issues", () => {
  // The platform's Base OIDC ID token has no `mode` claim and, with the email
  // scope, a synthetic service address marked email_verified: true.
  const platformClaims = {
    email: "user-0123456789abcdef0123@tapok.orria.space",
    email_verified: true,
    auth_time: Math.floor(Date.now() / 1000),
    sid: "session-hash",
  };

  function server(input: {
    clientSecret?: string;
    idToken?: Record<string, unknown>;
    userInfo?: Record<string, unknown>;
  }) {
    const calls: Call[] = [];
    let nonce = "";
    const client = createBaseOidcServerClient({
      issuer: baseIssuer,
      clientId: "tpk_base_client",
      ...(input.clientSecret !== undefined
        ? { clientSecret: input.clientSecret }
        : {}),
      redirectUri,
      scopes: ["openid", "email"],
      transactions: transactionStore<ConnectAuthorizationTransaction>(),
      jwksFetch,
      fetch: (async (url: unknown, init?: RequestInit) => {
        calls.push({
          url: String(url),
          body: new URLSearchParams(String(init?.body ?? "")),
          headers: new Headers(init?.headers),
        });
        if (String(url).endsWith("/revoke")) return new Response(null);
        if (String(url).endsWith("/userinfo"))
          return json({
            sub: "pairwise",
            email: platformClaims.email,
            email_verified: true,
            ...input.userInfo,
          });
        return json({
          access_token: "access",
          token_type: "Bearer",
          scope: "openid email",
          expires_in: 600,
          id_token: await sign({
            iss: baseIssuer,
            aud: "tpk_base_client",
            sub: "pairwise",
            nonce,
            ...platformClaims,
            ...input.idToken,
          }),
        });
      }) as unknown as typeof fetch,
    });
    return {
      client,
      calls,
      async complete() {
        const start = await client.beginAuthorization(binding);
        nonce = start.authorizationUrl.searchParams.get("nonce")!;
        return client.completeCallback(
          callback(start.state, baseIssuer),
          binding,
        );
      },
    };
  }

  test("server client: no mode claim, verified service email", async () => {
    const flow = server({});
    const result = await flow.complete();
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.idToken.sub).toBe("pairwise");
      expect(result.idToken.mode).toBeUndefined();
      expect(result.userInfo.email_verified).toBe(true);
      expect(result.userInfo.email).toBe(platformClaims.email);
    }
    // Public client: client_id in the body, no Authorization header.
    const token = flow.calls.find((call) => call.url.endsWith("/token"))!;
    expect(token.body.get("client_id")).toBe("tpk_base_client");
    expect(token.headers.has("authorization")).toBe(false);
  });

  test("a token of the same issuer that claims mode base is accepted too", async () => {
    expect((await server({ idToken: { mode: "base" } }).complete()).ok).toBe(
      true,
    );
  });

  test("a token that names the Connect mode is refused and revoked", async () => {
    const flow = server({ idToken: { mode: "connect" } });
    const error = (await failure(() => flow.complete())) as TapokAuthError;
    expect(error.code).toBe("invalid_token");
    expect(error.message).toContain("mode");
    const revoke = flow.calls.find((call) => call.url.endsWith("/revoke"))!;
    expect(revoke.body.get("token")).toBe("access");
    expect(revoke.body.get("client_id")).toBe("tpk_base_client");
  });

  test.each([
    ["the ID token", { idToken: { phone_number: "+70000000000" } }],
    ["UserInfo", { userInfo: { birthdate: "1990-01-01" } }],
  ])("a personal claim in %s is still refused", async (_name, script) => {
    const flow = server(script);
    const error = (await failure(() => flow.complete())) as TapokAuthError;
    expect(error.code).toBe("invalid_response");
    expect(error.message).toContain("Personal claim");
    expect(flow.calls.some((call) => call.url.endsWith("/revoke"))).toBe(true);
  });

  test("a confidential client authenticates with Basic, also when revoking", async () => {
    const flow = server({
      clientSecret: "secret",
      idToken: { mode: "connect" },
    });
    await failure(() => flow.complete());
    for (const path of ["/token", "/revoke"]) {
      const call = flow.calls.find((item) => item.url.endsWith(path))!;
      expect(call.headers.get("authorization")).toStartWith("Basic ");
      expect(call.body.has("client_id")).toBe(false);
    }
  });

  test("an empty secret or client id is a configuration error", () => {
    const options = {
      issuer: baseIssuer,
      redirectUri,
      scopes: ["openid"] as const,
      transactions: transactionStore<ConnectAuthorizationTransaction>(),
    };
    expect(() =>
      createBaseOidcServerClient({
        ...options,
        clientId: "tpk_base_client",
        clientSecret: "",
      }),
    ).toThrow("clientSecret must not be empty");
    for (const id of ["", "has space", undefined]) {
      expect(() =>
        createBaseOidcServerClient({
          ...options,
          clientId: id as unknown as string,
        }),
      ).toThrow("clientId");
    }
  });

  test("browser client: no mode claim, verified service email", async () => {
    let nonce = "";
    const client = createBaseOidcBrowserClient({
      issuer: baseIssuer,
      clientId: "tpk_base_client",
      redirectUri,
      scopes: ["openid", "email"],
      storage: memoryStorage(),
      fetch: (async (url: unknown) => {
        if (String(url).endsWith("jwks.json")) return json({ keys: [jwk] });
        return json({
          access_token: "access",
          token_type: "Bearer",
          scope: "openid email",
          expires_in: 600,
          id_token: await sign({
            iss: baseIssuer,
            aud: "tpk_base_client",
            sub: "pairwise",
            nonce,
            ...platformClaims,
          }),
        });
      }) as unknown as typeof fetch,
    });
    const start = await client.beginAuthorization();
    nonce = start.authorizationUrl.searchParams.get("nonce")!;
    const result = await client.completeCallback(
      callback(start.state, baseIssuer),
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      // Documented contract: here idToken is the compact JWT, claims the object.
      expect(result.idToken.split(".")).toHaveLength(3);
      expect(result.claims.sub).toBe("pairwise");
      expect(result.claims["email_verified"]).toBe(true);
    }
  });
});

describe("redirect URI with its own query", () => {
  const registered = "https://app.example/callback?tenant=acme&flow=1";

  test("Connect completes on the registered URI and refuses a changed query", async () => {
    const flow = connect({ redirectUri: registered });
    const start = await flow.begin();
    expect(start.authorizationUrl.searchParams.get("redirect_uri")).toBe(
      registered,
    );
    const result = await flow.client.completeCallback(
      callback(start.state, issuer, registered),
      binding,
    );
    expect(result.ok).toBe(true);
    const token = flow.calls.find((call) => call.url.endsWith("/token"))!;
    expect(token.body.get("redirect_uri")).toBe(registered);

    const second = await flow.begin();
    const tampered = callback(
      second.state,
      issuer,
      "https://app.example/callback?tenant=evil&flow=1",
    );
    const error = await failure(() =>
      flow.client.completeCallback(tampered, binding),
    );
    expect(error).toBeInstanceOf(TapokCallbackValidationError);
    expect((error as TapokCallbackValidationError).code).toBe(
      "malformed_callback",
    );
  });

  test("Base browser redirect and popup message keep the registered query", async () => {
    const storage = memoryStorage();
    const replaced: string[] = [];
    let nonce = "";
    const location = {
      href: registered,
      pathname: "/callback",
      hash: "",
      assign() {},
    };
    const client = createBaseBrowserClient({
      redirectUri: registered,
      issuer,
      storage,
      window: {
        location,
        history: {
          replaceState: (_state: unknown, _title: string, url: string) => {
            replaced.push(url);
          },
        },
        open: () => null,
        addEventListener() {},
        removeEventListener() {},
      } as unknown as NonNullable<
        Parameters<typeof createBaseBrowserClient>[0]["window"]
      >,
      fetch: (async () =>
        json({
          identity_token: await sign({
            iss: issuer,
            aud: "origin:https://app.example",
            sub: "p",
            pairwise_sub: "p",
            mode: "base",
            nonce,
          }),
          expires_in: 600,
          scope: "session",
        })) as unknown as typeof fetch,
    });

    const start = await client.beginAuthorization();
    nonce = start.authorizationUrl.searchParams.get("nonce")!;
    location.href = callback(start.state, issuer, registered);
    expect((await client.completeCallback()).ok).toBe(true);
    // Protocol parameters are removed, the page's own query stays.
    expect(replaced).toEqual(["/callback?tenant=acme&flow=1"]);

    const popup = {} as WindowProxy;
    const again = await client.beginAuthorization();
    nonce = again.authorizationUrl.searchParams.get("nonce")!;
    const result = await client.completePopupMessage(
      {
        origin: "https://app.example",
        source: popup,
        data: {
          type: "tapok:base:callback",
          version: 1,
          code: "code",
          state: again.state,
          iss: issuer,
        },
      } as unknown as MessageEvent<unknown>,
      popup,
    );
    expect(result.ok).toBe(true);
  });
});

describe("Base browser client with a trusted custom issuer", () => {
  function client(
    storage = memoryStorage(),
    custom: string | undefined = issuer,
  ) {
    const requests: string[] = [];
    let nonce = "";
    const instance = createBaseBrowserClient({
      redirectUri,
      ...(custom !== undefined ? { issuer: custom } : {}),
      storage,
      fetch: (async (url: unknown) => {
        requests.push(String(url));
        return json({
          identity_token: await sign({ nonce }),
          expires_in: 300,
          scope: "session",
        });
      }) as unknown as typeof fetch,
    });
    return {
      instance,
      requests,
      async begin() {
        const start = await instance.beginAuthorization();
        nonce = start.authorizationUrl.searchParams.get("nonce")!;
        return start;
      },
    };
  }

  test("authorize, callback issuer and exchange all use the configured issuer", async () => {
    const flow = client();
    const start = await flow.begin();
    expect(start.authorizationUrl.href).toStartWith(
      `${issuer}/api/v1/base/authorize?`,
    );
    const result = await flow.instance.completeCallback(
      callback(start.state, issuer),
    );
    expect(result.ok && result.response.expires_in).toBe(300);
    expect(flow.requests).toEqual([`${issuer}/api/v1/base/exchange`]);
  });

  test("a callback from the production issuer is refused", async () => {
    const flow = client();
    const start = await flow.begin();
    await expect(
      flow.instance.completeCallback(
        callback(start.state, "https://tapok.orria.space"),
      ),
    ).rejects.toThrow("issuer_mismatch");
    expect(flow.requests).toHaveLength(0);
  });

  test("a transaction started for another issuer is not reused", async () => {
    const storage = memoryStorage();
    const first = client(storage, "https://id-a.example");
    const start = await first.begin();
    const second = client(storage, "https://id-b.example");
    const error = (await failure(() =>
      second.instance.completeCallback(
        callback(start.state, "https://id-b.example"),
      ),
    )) as TapokAuthError;
    expect(error).toBeInstanceOf(TapokAuthError);
    expect(error.code).toBe("invalid_transaction");
  });

  test("the issuer is validated like on the server", () => {
    for (const bad of ["https://id.example/", "http://id.example", "id"]) {
      expect(() =>
        createBaseBrowserClient({
          redirectUri,
          issuer: bad,
          storage: memoryStorage(),
        }),
      ).toThrow("issuer");
    }
  });
});

describe("clients are safe to create without browser globals", () => {
  test("no window and no storage are touched at creation", async () => {
    expect(typeof window).toBe("undefined");
    const base = createBaseBrowserClient({ redirectUri });
    const navigator = createConnectBrowserNavigator({
      startUrl: "/auth/tapok/start",
    });
    createBaseOidcBrowserClient({ clientId: "tpk_base_client", redirectUri });
    // First use reports the missing global with a clear error.
    expect(() => navigator.startRedirect()).toThrow(
      "A Window must be provided",
    );
    await expect(base.redirect()).rejects.toThrow("storage adapter");
    expect(() =>
      notifyAuthPopupOpener({
        applicationOrigin: "https://app.example",
        status: "complete",
      }),
    ).toThrow("A Window must be provided");
  });

  test("a relative start URL resolves against the page", () => {
    const assigned: string[] = [];
    const navigator = createConnectBrowserNavigator({
      startUrl: "/auth/tapok/start?next=%2Faccount",
      window: {
        location: {
          href: "https://app.example/login",
          assign: (url: string) => void assigned.push(url),
        },
        open: () => null,
      } as unknown as Pick<Window, "location" | "open">,
    });
    navigator.startRedirect();
    expect(assigned).toEqual([
      "https://app.example/auth/tapok/start?next=%2Faccount",
    ]);
  });

  test("a non-HTTP start URL fails at creation", () => {
    expect(() =>
      createConnectBrowserNavigator({ startUrl: "javascript:alert(1)" }),
    ).toThrow("HTTP");
  });
});

describe("request timeout", () => {
  test("a hanging token endpoint rejects with request_timeout", async () => {
    let aborted = false;
    const flow = connect({
      timeoutMs: 30,
      transport: ((_url: unknown, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            aborted = true;
            reject(new DOMException("aborted", "AbortError"));
          });
        })) as unknown as typeof fetch,
    });
    const start = await flow.begin();
    const started = Date.now();
    const error = (await failure(() =>
      flow.client.completeCallback(callback(start.state, issuer), binding),
    )) as TapokAuthError;
    expect(error).toBeInstanceOf(TapokAuthError);
    expect(error.code).toBe("request_timeout");
    expect(aborted).toBe(true);
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  test("the deadline wins over a transport that ignores the signal", async () => {
    const flow = connect({
      timeoutMs: 30,
      transport: (() =>
        new Promise<Response>(() => {})) as unknown as typeof fetch,
    });
    const start = await flow.begin();
    const error = (await failure(() =>
      flow.client.completeCallback(callback(start.state, issuer), binding),
    )) as TapokAuthError;
    expect(error.code).toBe("request_timeout");
  });

  test("timeoutMs must be a positive finite number", () => {
    for (const timeoutMs of [0, -1, Number.POSITIVE_INFINITY, Number.NaN]) {
      expect(() =>
        createBaseServerClient({
          redirectUri,
          transactions: transactionStore<BaseServerTransaction>(),
          replayStore: { consume: async () => true },
          timeoutMs,
        }),
      ).toThrow("timeoutMs");
    }
  });
});

describe("popup attempt and in-flight message handling", () => {
  function fakeHost() {
    const listeners = new Set<(event: MessageEvent<unknown>) => void>();
    const popup = {
      closed: false,
      close() {
        this.closed = true;
      },
      focus() {},
      location: { replace() {} },
    };
    return {
      popup,
      window: {
        open: () => popup,
        addEventListener: (_type: string, listener: unknown) =>
          void listeners.add(
            listener as (event: MessageEvent<unknown>) => void,
          ),
        removeEventListener: (_type: string, listener: unknown) =>
          void listeners.delete(
            listener as (event: MessageEvent<unknown>) => void,
          ),
      } as unknown as Parameters<typeof openAuthPopup>[0]["window"],
      post(data: unknown) {
        for (const listener of listeners)
          listener({
            source: popup,
            origin: "https://app.example",
            data,
          } as unknown as MessageEvent<unknown>);
      },
    };
  }
  const delay = (ms: number) => new Promise((done) => setTimeout(done, ms));

  test("a window closed during the code exchange still reports the result", async () => {
    const host = fakeHost();
    const attempt = openAuthPopup({
      url: "https://id.example/authorize",
      messageOrigin: "https://app.example",
      window: host.window,
      pollIntervalMs: 5,
      async accept() {
        await delay(80); // the network exchange
        return "identity-token";
      },
    });
    host.post({ state: "s", code: "c" });
    host.popup.closed = true; // the user closes the window straight away
    expect(await attempt.result).toEqual({
      status: "received",
      value: "identity-token",
    });
  });

  test("the timeout also waits for a message that is being processed", async () => {
    const host = fakeHost();
    const attempt = openAuthPopup({
      url: "https://id.example/authorize",
      messageOrigin: "https://app.example",
      window: host.window,
      timeoutMs: 20,
      async accept() {
        await delay(80);
        return "identity-token";
      },
    });
    host.post({ state: "s" });
    expect((await attempt.result).status).toBe("received");
    expect(host.popup.closed).toBe(true);
  });

  test("a failed exchange is reported as failed, not as closed", async () => {
    const host = fakeHost();
    const attempt = openAuthPopup({
      url: "https://id.example/authorize",
      messageOrigin: "https://app.example",
      window: host.window,
      pollIntervalMs: 5,
      async accept() {
        await delay(40);
        throw new TapokHttpError(400, { error: "invalid_grant" });
      },
    });
    host.post({ state: "s" });
    host.popup.closed = true;
    const result = await attempt.result;
    expect(result.status).toBe("failed");
    expect(result.status === "failed" && result.error).toBeInstanceOf(
      TapokHttpError,
    );
  });

  test("an ignored message does not swallow the closed state", async () => {
    const host = fakeHost();
    const attempt = openAuthPopup({
      url: "https://id.example/authorize",
      messageOrigin: "https://app.example",
      window: host.window,
      pollIntervalMs: 5,
      async accept() {
        await delay(40);
        return undefined; // unrelated message
      },
    });
    host.post({ unrelated: true });
    host.popup.closed = true;
    expect(await attempt.result).toEqual({ status: "closed" });
  });

  test("cancel stays immediate even while a message is processed", async () => {
    const host = fakeHost();
    const attempt = openAuthPopup({
      url: "https://id.example/authorize",
      messageOrigin: "https://app.example",
      window: host.window,
      accept: () => new Promise<string>(() => {}),
    });
    host.post({ state: "s" });
    attempt.cancel();
    expect(await attempt.result).toEqual({ status: "cancelled" });
  });

  function relay(search: string) {
    const posted: unknown[] = [];
    const sent = relayBasePopupCallback({
      applicationOrigin: "https://app.example",
      window: {
        location: {
          href: `https://app.example/callback${search}`,
          pathname: "/callback",
          hash: "",
        },
        history: { replaceState() {} },
        opener: {
          closed: false,
          postMessage: (message: unknown) => void posted.push(message),
        },
      } as unknown as Pick<Window, "location" | "history" | "opener">,
    });
    expect(sent).toBe(true);
    return posted[0] as Record<string, unknown>;
  }

  test("the relay reports duplicated or oversized protocol parameters as malformed", () => {
    expect(relay("?code=c&state=s&iss=i")).toEqual({
      type: "tapok:base:callback",
      version: 1,
      code: "c",
      state: "s",
      iss: "i",
    });
    for (const search of [
      "?code=attacker&code=victim&state=s&iss=i",
      "?code=c&state=s&state=s&iss=i",
      "?code=c&state=s&iss=i&iss=evil",
      `?code=${"c".repeat(4097)}&state=s&iss=i`,
    ]) {
      // No value is chosen on the server's behalf and none is forwarded.
      expect(relay(search)).toEqual({
        type: "tapok:base:callback",
        version: 1,
        malformed: true,
      });
    }
  });

  test("a malformed relay message fails the popup attempt without an exchange", async () => {
    const host = fakeHost();
    let exchanged = false;
    const client = createBaseBrowserClient({
      redirectUri,
      storage: memoryStorage(),
      window: host.window as unknown as NonNullable<
        Parameters<typeof createBaseBrowserClient>[0]["window"]
      >,
      fetch: (async () => {
        exchanged = true;
        return json({});
      }) as unknown as typeof fetch,
    });
    const attempt = client.startPopup({ timeoutMs: 2_000 });
    await delay(20); // PKCE is prepared after the window opened
    host.post(relay("?code=a&code=b&state=s&iss=i"));
    const result = await attempt.result;
    expect(result.status).toBe("failed");
    expect(result.status === "failed" && result.error).toBeInstanceOf(
      TapokCallbackValidationError,
    );
    expect(exchanged).toBe(false);
  });

  test("a relay message without state fails instead of waiting for a timeout", async () => {
    const host = fakeHost();
    const client = createBaseBrowserClient({
      redirectUri,
      storage: memoryStorage(),
      window: host.window as unknown as NonNullable<
        Parameters<typeof createBaseBrowserClient>[0]["window"]
      >,
    });
    const attempt = client.startPopup({ timeoutMs: 2_000 });
    await delay(20);
    host.post(relay("?code=c&iss=i"));
    const result = await attempt.result;
    expect(result.status).toBe("failed");
    expect(
      result.status === "failed" &&
        (result.error as TapokCallbackValidationError).code,
    ).toBe("missing_state");
  });
});
