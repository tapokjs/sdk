import { describe, expect, test } from "bun:test";
import { TAPOK_ISSUER, resolveTapokEndpoints } from "@tapokjs/core";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import {
  createBaseBrowserClient,
  createBaseOidcBrowserClient,
  postBasePopupCallback,
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
import {
  fetchTapok,
  parseJsonResponse,
  TapokHttpError,
} from "../src/shared.ts";

const issuer = "https://id.example";
const baseIssuer = issuer + "/oidc/base";
const redirectUri = "https://app.example/callback";
const clientId = "tpk_client_test";
const binding = "independent-browser-cookie-with-at-least-32-random-characters";
const keys = await generateKeyPair("ES256");
const jwk = {
  ...(await exportJWK(keys.publicKey)),
  alg: "ES256",
  kid: "test",
  use: "sig",
};
const jwksFetch = (async () =>
  Response.json({ keys: [jwk] })) as unknown as typeof fetch;

function storage() {
  const entries = new Map<string, string>();
  return {
    entries,
    getItem: (key: string) => entries.get(key) ?? null,
    setItem: (key: string, value: string) => {
      entries.set(key, value);
    },
    removeItem: (key: string) => {
      entries.delete(key);
    },
  };
}

function transactions<T extends { state: string }>() {
  const entries = new Map<string, T>();
  return {
    async save(value: T) {
      entries.set(value.state, value);
    },
    async consume(state: string) {
      const value = entries.get(state);
      entries.delete(state);
      return value ?? null;
    },
  };
}

function sign(
  claims: Record<string, unknown> = {},
  header: Record<string, unknown> = {},
) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iss: issuer,
    aud: clientId,
    sub: "pairwise",
    iat: now,
    exp: now + 300,
    jti: crypto.randomUUID(),
    mode: "connect",
    nonce: "nonce",
    ...claims,
  })
    .setProtectedHeader({ alg: "ES256", typ: "JWT", kid: "test", ...header })
    .sign(keys.privateKey);
}

function callback(state: string, expectedIssuer = issuer) {
  const url = new URL(redirectUri);
  url.search = new URLSearchParams({
    code: "code",
    state,
    iss: expectedIssuer,
  }).toString();
  return url;
}

describe("JWKS reuse", () => {
  test("rejects invalid token headers before fetching verification keys", async () => {
    let requests = 0;
    const fetchImpl = (async () => {
      requests += 1;
      return Response.json({ keys: [jwk] });
    }) as unknown as typeof fetch;
    for (const header of [{ typ: "at+jwt" }, { kid: undefined }]) {
      await expect(
        verifyConnectIdToken({
          token: await sign({}, header),
          expectedIssuer: issuer,
          expectedAudience: clientId,
          expectedNonce: "nonce",
          jwksFetch: fetchImpl,
        }),
      ).rejects.toThrow("typ JWT");
    }
    expect(requests).toBe(0);
  });

  test("coalesces concurrent standalone verifications and reuses cached keys", async () => {
    let requests = 0;
    const fetchImpl = (async () => {
      requests += 1;
      return Response.json({ keys: [jwk] });
    }) as unknown as typeof fetch;
    const token = await sign();
    const input = {
      token,
      expectedIssuer: issuer,
      expectedAudience: clientId,
      expectedNonce: "nonce",
      jwksFetch: fetchImpl,
    };
    await Promise.all(
      Array.from({ length: 12 }, () => verifyConnectIdToken(input)),
    );
    await verifyConnectIdToken(input);
    expect(requests).toBe(1);
    let separateTransportRequests = 0;
    await verifyConnectIdToken({
      ...input,
      jwksFetch: (async () => {
        separateTransportRequests += 1;
        return Response.json({ keys: [jwk] });
      }) as unknown as typeof fetch,
    });
    expect(separateTransportRequests).toBe(1);
  });

  test("bounds cached endpoints while retaining recently used issuers", async () => {
    const requests = new Map<string, number>();
    const fetchImpl = (async (url: string | URL | Request) => {
      const href = String(url);
      requests.set(href, (requests.get(href) ?? 0) + 1);
      return Response.json({ keys: [jwk] });
    }) as unknown as typeof fetch;
    async function verify(index: number) {
      const expectedIssuer = `https://id-${index}.example`;
      await verifyConnectIdToken({
        token: await sign({ iss: expectedIssuer }),
        expectedIssuer,
        expectedAudience: clientId,
        expectedNonce: "nonce",
        jwksFetch: fetchImpl,
      });
    }
    for (let index = 0; index < 32; index += 1) await verify(index);
    await verify(0);
    await verify(32);
    await verify(0);
    await verify(1);
    expect(requests.get("https://id-0.example/.well-known/jwks.json")).toBe(1);
    expect(requests.get("https://id-1.example/.well-known/jwks.json")).toBe(2);
  });
});

describe("Base replay protection", () => {
  test("retains a reservation throughout the accepted post-expiry clock tolerance", async () => {
    const now = Math.floor(Date.now() / 1000);
    const expiry = now - 30;
    const reservations = new Map<string, number>();
    const token = await sign({
      mode: "base",
      aud: "origin:https://app.example",
      pairwise_sub: "pairwise",
      iat: now - 300,
      exp: expiry,
    });
    const input = {
      token,
      expectedIssuer: issuer,
      expectedAudience: "origin:https://app.example" as const,
      jwksFetch,
      replayStore: {
        async consume(jti: string, expiresAt: number) {
          if ((reservations.get(jti) ?? 0) > Date.now() / 1000) return false;
          reservations.set(jti, expiresAt);
          return true;
        },
      },
    };
    await verifyAndConsumeBaseIdentityToken(input);
    expect([...reservations.values()]).toEqual([expiry + 300]);
    await expect(verifyAndConsumeBaseIdentityToken(input)).rejects.toThrow(
      "already been consumed",
    );
  });

  test("Base server callback also includes its clock tolerance in replay retention", async () => {
    const now = Math.floor(Date.now() / 1000);
    let nonce = "";
    let retainedUntil = 0;
    const client = createBaseServerClient({
      issuer,
      redirectUri,
      transactions: transactions<BaseServerTransaction>(),
      jwksFetch,
      replayStore: {
        async consume(_jti, expiresAt) {
          retainedUntil = expiresAt;
          return true;
        },
      },
      fetch: (async () =>
        Response.json({
          identity_token: await sign({
            nonce,
            mode: "base",
            aud: "origin:https://app.example",
            pairwise_sub: "pairwise",
            iat: now - 300,
            exp: now - 1,
          }),
          expires_in: 600,
          scope: "session",
        })) as unknown as typeof fetch,
    });
    const start = await client.beginAuthorization(binding);
    nonce = start.authorizationUrl.searchParams.get("nonce")!;
    expect(
      (await client.completeCallback(callback(start.state), binding)).ok,
    ).toBe(true);
    expect(retainedUntil).toBe(now + 59);
  });

  test.each([NaN, Infinity, -1])(
    "rejects invalid clock tolerance %s before consuming replay",
    async (maxClockSkewSeconds) => {
      let consumed = false;
      await expect(
        verifyAndConsumeBaseIdentityToken({
          token: await sign({
            mode: "base",
            aud: "origin:https://app.example",
            pairwise_sub: "pairwise",
          }),
          expectedIssuer: issuer,
          expectedAudience: "origin:https://app.example",
          jwksFetch,
          maxClockSkewSeconds,
          replayStore: {
            async consume() {
              consumed = true;
              return true;
            },
          },
        }),
      ).rejects.toThrow("maxClockSkewSeconds");
      expect(consumed).toBe(false);
    },
  );
});

describe("Base OIDC browser verification", () => {
  test.each([
    {
      name: "personal verification claim",
      claims: { phone_number_verified: false },
      header: {},
    },
    { name: "empty subject", claims: { sub: "" }, header: {} },
    { name: "missing jti", claims: { jti: undefined }, header: {} },
    { name: "wrong typ", claims: {}, header: { typ: "at+jwt" } },
    { name: "missing kid", claims: {}, header: { kid: undefined } },
  ])("rejects $name before returning the token", async ({ claims, header }) => {
    let nonce = "";
    const client = createBaseOidcBrowserClient({
      issuer: baseIssuer,
      clientId,
      redirectUri,
      storage: storage(),
      fetch: (async (url: string | URL | Request) =>
        String(url).endsWith("jwks.json")
          ? Response.json({ keys: [jwk] })
          : Response.json({
              token_type: "Bearer",
              access_token: "opaque",
              expires_in: 300,
              scope: "openid",
              id_token: await sign(
                { iss: baseIssuer, mode: "base", nonce, ...claims },
                header,
              ),
            })) as unknown as typeof fetch,
    });
    const start = await client.beginAuthorization();
    nonce = start.authorizationUrl.searchParams.get("nonce")!;
    await expect(
      client.completeCallback(callback(start.state, baseIssuer)),
    ).rejects.toThrow();
  });

  test("isolates transactions for clients with different trusted issuers", async () => {
    const store = storage();
    const tokenRequests: string[] = [];
    function clientFor(expectedIssuer: string) {
      let nonce = "";
      const client = createBaseOidcBrowserClient({
        issuer: expectedIssuer,
        clientId,
        redirectUri,
        storage: store,
        fetch: (async (url: string | URL | Request) => {
          if (String(url).endsWith("jwks.json"))
            return Response.json({ keys: [jwk] });
          tokenRequests.push(String(url));
          return Response.json({
            token_type: "Bearer",
            access_token: "opaque",
            expires_in: 300,
            scope: "openid",
            id_token: await sign({ iss: expectedIssuer, mode: "base", nonce }),
          });
        }) as unknown as typeof fetch,
      });
      return {
        client,
        async begin() {
          const start = await client.beginAuthorization();
          nonce = start.authorizationUrl.searchParams.get("nonce")!;
          return start;
        },
      };
    }
    const first = clientFor(baseIssuer);
    const secondIssuer = "https://other.example/oidc/base";
    const second = clientFor(secondIssuer);
    const startFirst = await first.begin();
    const startSecond = await second.begin();
    expect(store.entries.size).toBe(2);
    expect(
      (
        await first.client.completeCallback(
          callback(startFirst.state, baseIssuer),
        )
      ).ok,
    ).toBe(true);
    expect(
      (
        await second.client.completeCallback(
          callback(startSecond.state, secondIssuer),
        )
      ).ok,
    ).toBe(true);
    expect(tokenRequests).toEqual([
      baseIssuer + "/token",
      secondIssuer + "/token",
    ]);
    expect(store.entries.size).toBe(0);
  });
});

describe("discovered endpoints", () => {
  test.each(["base", "connect"] as const)(
    "uses configured %s authorization and logout URLs including fixed query parameters",
    async (mode) => {
      const expectedIssuer = mode === "base" ? baseIssuer : issuer;
      const discovery = {
        ...resolveTapokEndpoints({ issuer: expectedIssuer, mode }),
        authorization_endpoint:
          issuer + "/custom/authorize?tenant=example&client_id=stale",
        end_session_endpoint: issuer + "/custom/logout?tenant=example",
      };
      const options = {
        clientId,
        clientSecret: "secret",
        issuer: expectedIssuer,
        redirectUri,
        discovery,
        scopes: ["openid"] as const,
        transactions: transactions<ConnectAuthorizationTransaction>(),
      };
      const client =
        mode === "base"
          ? createBaseOidcServerClient(options)
          : createConnectServerClient(options);
      const start = await client.beginAuthorization(binding);
      expect(start.authorizationUrl.pathname).toBe("/custom/authorize");
      expect(start.authorizationUrl.searchParams.get("tenant")).toBe("example");
      expect(start.authorizationUrl.searchParams.getAll("client_id")).toEqual([
        clientId,
      ]);
      expect(start.authorizationUrl.searchParams.get("state")).toBe(
        start.state,
      );
      const logout = client.logout({
        postLogoutRedirectUri: redirectUri,
        state: "logout-state",
      });
      expect(logout.pathname).toBe("/custom/logout");
      expect(logout.searchParams.get("tenant")).toBe("example");
      expect(logout.searchParams.get("state")).toBe("logout-state");
    },
  );
});

describe("Base popup roundtrip", () => {
  test.each([true, false])(
    "consumes the callback helper's actual message (success: %s)",
    async (success) => {
      let message: unknown;
      let exchanges = 0;
      let nonce = "";
      const popup = {} as WindowProxy;
      const win = {
        location: { href: redirectUri, pathname: "/callback", hash: "" },
        history: { replaceState() {} },
        opener: {
          postMessage(data: unknown) {
            message = data;
          },
        },
      } as unknown as Pick<Window, "location" | "history" | "opener">;
      const client = createBaseBrowserClient({
        redirectUri,
        storage: storage(),
        window: win as unknown as Window,
        fetch: (async () => {
          exchanges += 1;
          return Response.json({
            identity_token: await sign({ nonce }),
            expires_in: 600,
            scope: "session",
          });
        }) as unknown as typeof fetch,
      });
      const start = await client.beginAuthorization();
      nonce = start.authorizationUrl.searchParams.get("nonce")!;
      const url = callback(start.state, TAPOK_ISSUER);
      if (!success) {
        url.searchParams.delete("code");
        url.searchParams.set("error", "access_denied");
        url.searchParams.set("error_description", "Consent was declined");
      }
      postBasePopupCallback({
        callbackUrl: url,
        expectedState: start.state,
        applicationOrigin: "https://app.example",
        window: win,
      });
      const result = await client.completePopupMessage(
        {
          origin: "https://app.example",
          source: popup,
          data: message,
        } as MessageEvent,
        popup,
      );
      expect(result.ok).toBe(success);
      expect(exchanges).toBe(success ? 1 : 0);
      if (!result.ok)
        expect(result.errorDescription).toBe("Consent was declined");
    },
  );
});

describe("HTTP response handling", () => {
  test("cancels non-JSON failure bodies and cannot enable redirects", async () => {
    let cancelled = false;
    const fetchImpl = (async (_url: unknown, init?: RequestInit) => {
      expect(init?.redirect).toBe("error");
      return new Response(
        new ReadableStream({
          cancel() {
            cancelled = true;
          },
        }),
        { status: 502, headers: { "content-type": "text/html" } },
      );
    }) as unknown as typeof fetch;
    await expect(
      fetchTapok(fetchImpl, issuer, { redirect: "follow" }),
    ).rejects.toBeInstanceOf(TapokHttpError);
    expect(cancelled).toBe(true);
  });

  test("rejects misleading JSON media types and releases their bodies", async () => {
    let cancelled = false;
    const response = new Response(
      new ReadableStream({
        cancel() {
          cancelled = true;
        },
      }),
      { headers: { "content-type": "application/jsonp" } },
    );
    await expect(parseJsonResponse(response)).rejects.toThrow(
      "application/json",
    );
    expect(cancelled).toBe(true);
  });

  test("rejects a cloned non-JSON response without waiting for its sibling stream", async () => {
    const original = new Response(new ReadableStream(), {
      headers: { "content-type": "text/html" },
    });
    const clone = original.clone();
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await expect(
        Promise.race([
          parseJsonResponse(clone),
          new Promise((_, reject) => {
            timer = setTimeout(
              () => reject(new Error("Cancellation stalled")),
              100,
            );
          }),
        ]),
      ).rejects.toThrow("application/json");
    } finally {
      clearTimeout(timer);
      await original.body?.cancel();
    }
  });
});
