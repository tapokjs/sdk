// An error object is logged whole: console.error(error), JSON.stringify,
// util.inspect, a crash reporter walking `cause`. None of that may reveal a
// token, a claim, a response fragment or a transport detail.
import { describe, expect, test } from "bun:test";
import { inspect } from "node:util";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import {
  TapokAuthError,
  createBaseBrowserClient,
  createBaseOidcBrowserClient,
} from "../src/browser.ts";
import {
  createConnectServerClient,
  verifyAndConsumeBaseIdentityToken,
  verifyConnectIdToken,
} from "../src/server.ts";
import type { ConnectAuthorizationTransaction } from "../src/server.ts";

const MARKER = "SECRET-MARKER-7f3a";
const email = `${MARKER}@mail.example`;
const issuer = "https://id.example";
const clientId = "tpk_client_test";
const redirectUri = "https://app.example/callback";
const binding = "random-session-cookie-with-256-bits-of-entropy";

const keys = await generateKeyPair("RS256");
const jwk = {
  ...(await exportJWK(keys.publicKey)),
  kid: "test",
  alg: "RS256",
  use: "sig",
};
const jwksFetch = (async () =>
  Response.json({ keys: [jwk] })) as unknown as typeof fetch;
const now = () => Math.floor(Date.now() / 1000);

function sign(claims: Record<string, unknown>, issuedAt = now(), ttl = 300) {
  return new SignJWT({
    iss: issuer,
    aud: clientId,
    sub: `subject-${MARKER}`,
    mode: "connect",
    nonce: "n",
    email,
    name: `Name ${MARKER}`,
    ...claims,
  })
    .setProtectedHeader({ alg: "RS256", kid: "test", typ: "JWT" })
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + ttl)
    .setJti(`jti-${MARKER}`)
    .sign(keys.privateKey);
}

async function failure(run: () => Promise<unknown>): Promise<TapokAuthError> {
  try {
    await run();
  } catch (error) {
    return error as TapokAuthError;
  }
  throw new Error("Expected the call to reject");
}

/** Everything a logger, serializer or crash reporter can reach from an error. */
function everythingReachable(error: unknown): string {
  const seen = new Set<unknown>();
  const parts: string[] = [];
  const visit = (value: unknown, depth: number) => {
    if (depth > 6 || seen.has(value)) return;
    if (typeof value === "string") return void parts.push(value);
    if (value === null || typeof value !== "object") {
      return void parts.push(String(value));
    }
    seen.add(value);
    for (const key of Reflect.ownKeys(value)) {
      parts.push(String(key));
      visit((value as Record<PropertyKey, unknown>)[key], depth + 1);
    }
    visit(Object.getPrototypeOf(value), depth + 1);
  };
  visit(error, 0);
  return [
    String(error),
    (error as Error).message,
    (error as Error).stack ?? "",
    JSON.stringify(error),
    JSON.stringify(error, Object.getOwnPropertyNames(error as object)),
    inspect(error, { depth: Infinity, showHidden: true, getters: true }),
    Bun.inspect(error),
    ...parts,
  ].join("\n");
}

function expectSafe(error: TapokAuthError, ...secrets: string[]) {
  expect(error).toBeInstanceOf(TapokAuthError);
  expect(error.cause).toBeUndefined();
  expect("payload" in error).toBe(false);
  const text = everythingReachable(error);
  for (const secret of [MARKER, email, ...secrets]) {
    expect(text).not.toContain(secret);
  }
}

const verify = (token: string, transport = jwksFetch) =>
  verifyConnectIdToken({
    token,
    expectedIssuer: issuer,
    expectedAudience: clientId,
    expectedNonce: "n",
    jwksFetch: transport,
  });

describe("token errors never carry the token or its claims", () => {
  test("an expired, correctly signed JWT", async () => {
    // jose's JWTExpired holds the whole decoded payload.
    const token = await sign({}, now() - 7200, 300);
    const error = await failure(() => verify(token));
    expect(error.code).toBe("invalid_token");
    expect(error.reason).toBe("ERR_JWT_EXPIRED");
    expect(error.message).toBe("JWT has expired");
    expectSafe(error, token, token.split(".")[1]!);
  });

  test("a JWT with a foreign audience or issuer", async () => {
    // jose's JWTClaimValidationFailed holds the payload too.
    for (const claims of [
      { aud: `aud-${MARKER}` },
      { iss: `https://${MARKER}.example` },
    ]) {
      const token = await sign(claims);
      const error = await failure(() => verify(token));
      expect(error.code).toBe("invalid_token");
      expect(error.reason).toBe("ERR_JWT_CLAIM_VALIDATION_FAILED");
      expectSafe(error, token, token.split(".")[1]!);
    }
  });

  test("a JWT whose signature or shape is broken", async () => {
    const valid = await sign({});
    for (const token of [
      valid.slice(0, -6) + "AAAAAA",
      `${valid.split(".")[0]}.${btoa(`{"email":"${email}"`)}.x`,
      `not-a-jwt-${MARKER}`,
    ]) {
      const error = await failure(() => verify(token));
      expect(error.code).toBe("invalid_token");
      expectSafe(error, token);
    }
  });

  test("claims the SDK checks itself: nonce, mode, types, lifetime", async () => {
    for (const claims of [
      { nonce: `nonce-${MARKER}` },
      { mode: `mode-${MARKER}` },
      { is_adult: `adult-${MARKER}` },
      { email: { address: email } },
      { azp: `azp-${MARKER}` },
    ]) {
      const token = await sign(claims);
      const error = await failure(() => verify(token));
      expect(error.code).toBe("invalid_token");
      expectSafe(error, token, token.split(".")[1]!);
    }
    const longLived = await sign({}, now(), 86_400);
    expectSafe(await failure(() => verify(longLived)), longLived);
  });

  test("a replayed Base identity token", async () => {
    const token = await sign({
      aud: "origin:https://app.example",
      mode: "base",
      sub: "p",
      pairwise_sub: "p",
    });
    const error = await failure(() =>
      verifyAndConsumeBaseIdentityToken({
        token,
        expectedIssuer: issuer,
        expectedAudience: "origin:https://app.example",
        replayStore: { consume: async () => false },
        jwksFetch,
      }),
    );
    expect(error.code).toBe("token_replayed");
    expectSafe(error, token);
  });
});

describe("key loading errors never carry transport details", () => {
  test("a custom jwksFetch that throws", async () => {
    const token = await sign({ iss: "https://down-a.example" });
    const transportError = Object.assign(
      new Error(`connect ECONNREFUSED https://proxy.internal/${MARKER}`),
      { url: `https://proxy.internal/${MARKER}`, token: MARKER },
    );
    const error = await failure(() =>
      verifyConnectIdToken({
        token,
        expectedIssuer: "https://down-a.example",
        expectedAudience: clientId,
        expectedNonce: "n",
        jwksFetch: (async () => {
          throw transportError;
        }) as unknown as typeof fetch,
      }),
    );
    expect(error.code).toBe("jwks_unavailable");
    expect(error.message).toBe("Tapok signing keys could not be loaded");
    expect(error.reason).toBeUndefined();
    expectSafe(error, token, "proxy.internal", "ECONNREFUSED");
  });

  test("a JWKS endpoint that answers with garbage", async () => {
    for (const [host, respond] of [
      ["down-b", () => new Response(`<html>${MARKER}</html>`, { status: 502 })],
      ["down-c", () => new Response(`{"keys":"${MARKER}"`, { status: 200 })],
      ["down-d", () => Response.json({ keys: MARKER })],
    ] as const) {
      const token = await sign({ iss: `https://${host}.example` });
      const error = await failure(() =>
        verifyConnectIdToken({
          token,
          expectedIssuer: `https://${host}.example`,
          expectedAudience: clientId,
          expectedNonce: "n",
          jwksFetch: (async () => respond()) as unknown as typeof fetch,
        }),
      );
      expect(error.code).toBe("jwks_unavailable");
      expectSafe(error, token);
    }
  });
});

describe("response errors never quote the response", () => {
  function connect(respond: () => Response) {
    const records = new Map<string, ConnectAuthorizationTransaction>();
    return createConnectServerClient({
      issuer,
      clientId,
      clientSecret: "secret",
      redirectUri,
      scopes: ["openid"],
      jwksFetch,
      transactions: {
        async save(t) {
          records.set(t.state, t);
        },
        async consume(state) {
          const t = records.get(state) ?? null;
          records.delete(state);
          return t;
        },
      },
      fetch: (async (url: unknown) =>
        String(url).endsWith("/revoke")
          ? new Response(null)
          : respond()) as unknown as typeof fetch,
    });
  }
  async function complete(respond: () => Response) {
    const client = connect(respond);
    const start = await client.beginAuthorization(binding);
    return failure(() =>
      client.completeCallback(
        `${redirectUri}?code=c&state=${start.state}&iss=${encodeURIComponent(issuer)}`,
        binding,
      ),
    );
  }
  const jsonBody = (body: string) =>
    new Response(body, { headers: { "content-type": "application/json" } });

  test("invalid JSON holding a token and an email", async () => {
    // Runtime JSON errors may quote the text around the failure position.
    for (const body of [
      `{"access_token":"${MARKER}","id_token":"${MARKER}", "email":"${email}"`,
      `${MARKER}`,
      `{"access_token":"${MARKER}"} trailing-${MARKER}`,
      `{"access_token":${MARKER}}`,
    ]) {
      const error = await complete(() => jsonBody(body));
      expect(error.code).toBe("invalid_response");
      expect(error.message).toBe("Tapok response is not valid JSON");
      expectSafe(error);
    }
  });

  test("a well-formed body that breaks the contract in any field", async () => {
    const valid = {
      access_token: `access-${MARKER}`,
      token_type: "Bearer",
      expires_in: 300,
      scope: "openid",
      id_token: `id-${MARKER}`,
    };
    for (const patch of [
      { token_type: `type-${MARKER}` },
      { expires_in: `ttl-${MARKER}` },
      { scope: `openid ${MARKER}` },
      { scope: [MARKER] },
      { access_token: { value: MARKER } },
      { id_token: 5 },
      { refresh_token: { value: MARKER } },
      { [`field-${MARKER}`]: MARKER, token_type: "MAC" },
    ]) {
      const error = await complete(() => Response.json({ ...valid, ...patch }));
      expect(error.code).toBe("invalid_response");
      expectSafe(error);
    }
  });

  test("a non-JSON body", async () => {
    const error = await complete(
      () => new Response(`<html>${MARKER}</html>`, { status: 200 }),
    );
    expect(error.code).toBe("invalid_response");
    expectSafe(error);
  });
});

describe("browser errors never quote tokens or stored transactions", () => {
  function memoryStorage() {
    const data = new Map<string, string>();
    return {
      data,
      getItem: (k: string) => data.get(k) ?? null,
      setItem: (k: string, v: string) => void data.set(k, v),
      removeItem: (k: string) => void data.delete(k),
    };
  }

  test("an identity token with an undecodable payload", async () => {
    for (const payload of [
      btoa(`{"nonce":"${MARKER}","email":"${email}"`),
      btoa(`"${MARKER}"`),
      `%%%${MARKER}`,
    ]) {
      const client = createBaseBrowserClient({
        redirectUri,
        issuer,
        storage: memoryStorage(),
        fetch: (async () =>
          Response.json({
            identity_token: `header.${payload}.signature`,
            expires_in: 600,
            scope: "session",
          })) as unknown as typeof fetch,
      });
      const start = await client.beginAuthorization();
      const error = await failure(() =>
        client.completeCallback(
          `${redirectUri}?code=c&state=${start.state}&iss=${encodeURIComponent(issuer)}`,
        ),
      );
      expect(error.code).toBe("invalid_token");
      expectSafe(error, payload);
    }
  });

  test("a corrupted stored transaction", async () => {
    // The record holds state, nonce and the PKCE verifier.
    const corrupted = `{"version":1,"verifier":"${MARKER}","state":"${MARKER}"`;
    const base = memoryStorage();
    const baseClient = createBaseBrowserClient({ redirectUri, storage: base });
    await baseClient.beginAuthorization();
    for (const key of base.data.keys()) base.data.set(key, corrupted);
    const first = await failure(() =>
      baseClient.completeCallback(`${redirectUri}?code=c&state=s&iss=i`),
    );
    expect(first.code).toBe("invalid_transaction");
    expectSafe(first);

    const oidc = memoryStorage();
    const oidcClient = createBaseOidcBrowserClient({
      clientId: "tpk_base_client",
      redirectUri,
      storage: oidc,
    });
    await oidcClient.beginAuthorization();
    for (const key of oidc.data.keys()) oidc.data.set(key, corrupted);
    const second = await failure(() =>
      oidcClient.completeCallback(`${redirectUri}?code=c&state=s&iss=i`),
    );
    expect(second.code).toBe("invalid_transaction");
    expectSafe(second);
  });
});
