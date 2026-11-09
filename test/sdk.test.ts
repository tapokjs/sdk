import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { TAPOK_ISSUER, tapokEndpoints } from "@tapokjs/core";
import type { ConnectScope } from "@tapokjs/core";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import {
  TapokHttpError,
  decodeJwtPayload,
  parseJsonResponse,
  requireExactNonce,
} from "../src/shared.ts";
import {
  createBaseBrowserClient,
  createConnectBrowserNavigator,
  postBasePopupCallback,
  postConnectPopupCompletion,
} from "../src/browser.ts";
import {
  createConnectServerClient,
  verifyAndConsumeBaseIdentityToken,
  verifyConnectIdToken,
} from "../src/server.ts";
import type {
  ConnectAuthorizationTransaction,
  ReplayStore,
} from "../src/server.ts";

const redirectUri = "https://app.example/auth/tapok/callback";
const applicationOrigin = "https://app.example";
const issuerParam = encodeURIComponent(TAPOK_ISSUER);
const kid = "test-key";

const { publicKey, privateKey } = await generateKeyPair("ES256", {
  extractable: true,
});
const publicJwk = {
  ...(await exportJWK(publicKey)),
  kid,
  alg: "ES256",
  use: "sig",
};

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function base64Url(value: string): string {
  return btoa(value)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

function unsignedJwt(payload: Record<string, unknown>): string {
  return `${base64Url(JSON.stringify({ alg: "none" }))}.${base64Url(JSON.stringify(payload))}.x`;
}

function signJwt(
  payload: Record<string, unknown>,
  header: Record<string, unknown> = {},
): Promise<string> {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "ES256", typ: "JWT", kid, ...header })
    .sign(privateKey);
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function baseClaims(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const now = nowSeconds();
  return {
    iss: TAPOK_ISSUER,
    sub: "pairwise-subject",
    aud: `origin:${applicationOrigin}`,
    exp: now + 600,
    iat: now,
    jti: crypto.randomUUID(),
    nonce: "nonce",
    mode: "base",
    pairwise_sub: "pairwise-subject",
    ...overrides,
  };
}

function connectClaims(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const now = nowSeconds();
  return {
    iss: TAPOK_ISSUER,
    sub: "connect-subject",
    aud: "tpk_client_example",
    exp: now + 900,
    iat: now,
    jti: crypto.randomUUID(),
    nonce: "nonce",
    mode: "connect",
    ...overrides,
  };
}

function memoryReplayStore(): ReplayStore & { used: Map<string, number> } {
  const used = new Map<string, number>();
  return {
    used,
    async consume(jti, expiresAt) {
      if (used.has(jti)) return false;
      used.set(jti, expiresAt);
      return true;
    },
  };
}

type StorageStub = {
  values: Map<string, string>;
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
};

function storage(): StorageStub {
  const values = new Map<string, string>();
  return {
    values,
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  };
}

type WindowStub = Pick<
  Window,
  "location" | "history" | "open" | "addEventListener" | "removeEventListener"
>;

function windowStub(
  overrides: Partial<Record<keyof WindowStub, unknown>> = {},
): WindowStub {
  return {
    location: {
      href: redirectUri,
      pathname: "/auth/tapok/callback",
      hash: "",
      assign() {},
    },
    history: { replaceState() {} },
    open() {
      return null;
    },
    addEventListener() {},
    removeEventListener() {},
    ...overrides,
  } as WindowStub;
}

const originalFetch = globalThis.fetch;

beforeAll(() => {
  // jose fetches the JWKS through the global fetch on first verification.
  globalThis.fetch = (async (url: unknown) => {
    if (String(url) === tapokEndpoints.jwks)
      return response({ keys: [publicJwk] });
    throw new Error("Unexpected network request in tests");
  }) as unknown as typeof fetch;
});

afterAll(() => {
  globalThis.fetch = originalFetch;
});

describe("shared helpers", () => {
  test("parses only application/json responses", async () => {
    await expect(parseJsonResponse(response({ ok: true }))).resolves.toEqual({
      ok: true,
    });
    await expect(
      parseJsonResponse(
        new Response("<html></html>", {
          headers: { "content-type": "text/html" },
        }),
      ),
    ).rejects.toThrow("application/json");
  });

  test("decodes JWT payloads and enforces exact nonce", () => {
    const token = unsignedJwt({ nonce: "expected" });
    expect(decodeJwtPayload(token)).toEqual({ nonce: "expected" });
    expect(() => decodeJwtPayload("not-a-jwt")).toThrow("compact JWT");
    expect(() => decodeJwtPayload("a..c")).toThrow("compact JWT");
    expect(() => decodeJwtPayload(`a.${base64Url("[1]")}.c`)).toThrow("object");
    expect(() => requireExactNonce(token, "expected")).not.toThrow();
    expect(() => requireExactNonce(token, "other")).toThrow("nonce");
  });

  test("keeps response bodies out of HTTP errors", () => {
    expect(new TapokHttpError(500).message).toBe(
      "Tapok request failed with HTTP 500",
    );
    expect(new TapokHttpError(400, { error: "invalid_grant" }).message).toBe(
      "invalid_grant",
    );
  });
});

describe("Base browser client", () => {
  test("stores fresh transaction material and exchanges only after callback validation", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const client = createBaseBrowserClient({
      redirectUri,
      storage: storage(),
      window: windowStub(),
      fetch: (async (url: unknown, init?: RequestInit) => {
        calls.push({ url: String(url), init });
        return response({
          identity_token: unsignedJwt({ nonce: "bad" }),
          expires_in: 600,
          scope: "session",
        });
      }) as unknown as typeof fetch,
    });
    const start = await client.beginAuthorization();
    expect(start.authorizationUrl.href).toContain(tapokEndpoints.baseAuthorize);
    await expect(
      client.completeCallback(
        `${redirectUri}?code=code&state=wrong&iss=${issuerParam}`,
      ),
    ).rejects.toThrow("state_mismatch");
    expect(calls).toHaveLength(0);
  });

  test("completes the redirect flow with CORS exchange and nonce verification", async () => {
    const store = storage();
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    let nonce = "";
    const client = createBaseBrowserClient({
      redirectUri,
      scopes: ["age:18"],
      storage: store,
      window: windowStub(),
      fetch: (async (url: unknown, init?: RequestInit) => {
        calls.push({ url: String(url), init });
        return response({
          identity_token: unsignedJwt({ nonce }),
          expires_in: 600,
          scope: "session age:18",
        });
      }) as unknown as typeof fetch,
    });

    const start = await client.beginAuthorization();
    expect(start.authorizationUrl.searchParams.get("scope")).toBe(
      "session age:18",
    );
    const [saved] = [...store.values.values()];
    const transaction = JSON.parse(saved as string) as Record<string, string>;
    nonce = transaction["nonce"] as string;

    const result = await client.completeCallback(
      `${redirectUri}?code=abc&state=${transaction["state"]}&iss=${issuerParam}`,
    );
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.response.scope).toBe("session age:18");

    expect(calls).toHaveLength(1);
    const call = calls[0] as { url: string; init?: RequestInit };
    expect(call.url).toBe(tapokEndpoints.baseExchange);
    expect(call.init).toMatchObject({
      method: "POST",
      mode: "cors",
      credentials: "omit",
    });
    const body = call.init?.body as URLSearchParams;
    expect(body.get("code")).toBe("abc");
    expect(body.get("client_id")).toBe(`origin:${applicationOrigin}`);
    expect(body.get("code_verifier")).toBe(transaction["verifier"] as string);
    expect(store.values.size).toBe(0);
  });

  test("rejects an identity token whose nonce does not match the transaction", async () => {
    const store = storage();
    const client = createBaseBrowserClient({
      redirectUri,
      storage: store,
      window: windowStub(),
      fetch: (async () =>
        response({
          identity_token: unsignedJwt({ nonce: "attacker" }),
          expires_in: 600,
          scope: "session",
        })) as unknown as typeof fetch,
    });
    await client.beginAuthorization();
    const transaction = JSON.parse(
      [...store.values.values()][0] as string,
    ) as Record<string, string>;
    await expect(
      client.completeCallback(
        `${redirectUri}?code=abc&state=${transaction["state"]}&iss=${issuerParam}`,
      ),
    ).rejects.toThrow("nonce");
  });

  test("returns protocol errors without exchanging and raises HTTP failures", async () => {
    const store = storage();
    let next: Response = response({ error: "invalid_grant" }, 400);
    const client = createBaseBrowserClient({
      redirectUri,
      storage: store,
      window: windowStub(),
      fetch: (async () => next) as unknown as typeof fetch,
    });

    await client.beginAuthorization();
    let transaction = JSON.parse(
      [...store.values.values()][0] as string,
    ) as Record<string, string>;
    const denied = await client.completeCallback(
      `${redirectUri}?error=access_denied&state=${transaction["state"]}&iss=${issuerParam}`,
    );
    expect(denied).toMatchObject({ ok: false, error: "access_denied" });

    await client.beginAuthorization();
    transaction = JSON.parse([...store.values.values()][0] as string) as Record<
      string,
      string
    >;
    await expect(
      client.completeCallback(
        `${redirectUri}?code=abc&state=${transaction["state"]}&iss=${issuerParam}`,
      ),
    ).rejects.toThrow(TapokHttpError);

    await client.beginAuthorization();
    transaction = JSON.parse([...store.values.values()][0] as string) as Record<
      string,
      string
    >;
    next = new Response("oops", {
      status: 500,
      headers: { "content-type": "text/plain" },
    });
    await expect(
      client.completeCallback(
        `${redirectUri}?code=abc&state=${transaction["state"]}&iss=${issuerParam}`,
      ),
    ).rejects.toThrow("Tapok request failed with HTTP 500");
  });

  test("accepts popup messages only from the expected source and origin", async () => {
    const store = storage();
    const popup = {} as WindowProxy;
    let nonce = "";
    const client = createBaseBrowserClient({
      redirectUri,
      storage: store,
      window: windowStub({ open: () => popup }),
      fetch: (async () =>
        response({
          identity_token: unsignedJwt({ nonce }),
          expires_in: 600,
          scope: "session",
        })) as unknown as typeof fetch,
    });

    const start = await client.openPopup();
    expect(start).not.toBeNull();
    const transaction = JSON.parse(
      [...store.values.values()][0] as string,
    ) as Record<string, string>;
    nonce = transaction["nonce"] as string;
    const data = {
      code: "abc",
      state: transaction["state"],
      iss: TAPOK_ISSUER,
    };

    await expect(
      client.completePopupMessage(
        {
          origin: "https://evil.example",
          source: popup,
          data,
        } as MessageEvent<unknown>,
        popup,
      ),
    ).rejects.toThrow("origin");
    await expect(
      client.completePopupMessage(
        {
          origin: applicationOrigin,
          source: {} as WindowProxy,
          data,
        } as MessageEvent<unknown>,
        popup,
      ),
    ).rejects.toThrow("source or origin");
    await expect(
      client.completePopupMessage(
        {
          origin: applicationOrigin,
          source: popup,
          data: { ...data, code: 5 },
        } as MessageEvent<unknown>,
        popup,
      ),
    ).rejects.toThrow("invalid callback value");
    await expect(
      client.completePopupMessage(
        {
          origin: applicationOrigin,
          source: popup,
          data: { ...data, code: null },
        } as MessageEvent<unknown>,
        popup,
      ),
    ).rejects.toThrow("invalid callback value");
    await expect(
      client.completePopupMessage(
        {
          origin: applicationOrigin,
          source: popup,
          data: { ...data, issuer: "https://other.example" },
        } as MessageEvent<unknown>,
        popup,
      ),
    ).rejects.toThrow("conflicting callback values");

    const result = await client.completePopupMessage(
      {
        origin: applicationOrigin,
        source: popup,
        data,
      } as MessageEvent<unknown>,
      popup,
    );
    expect(result.ok).toBe(true);
  });

  test("returns null when the popup is blocked", async () => {
    const client = createBaseBrowserClient({
      redirectUri,
      storage: storage(),
      window: windowStub({ open: () => null }),
    });
    expect(await client.openPopup()).toBeNull();
  });
});

describe("Base popup callback page", () => {
  test("posts the validated callback to the opener with an exact target origin", () => {
    const messages: Array<{ message: unknown; targetOrigin: string }> = [];
    const win = {
      location: {
        href: `${redirectUri}?code=abc&state=st&iss=${issuerParam}`,
        pathname: "/auth/tapok/callback",
        hash: "",
      },
      history: { replaceState() {} },
      opener: {
        postMessage(message: unknown, targetOrigin: string) {
          messages.push({ message, targetOrigin });
        },
      },
    } as unknown as Pick<Window, "location" | "history" | "opener">;

    const callback = postBasePopupCallback({
      expectedState: "st",
      applicationOrigin,
      window: win,
    });
    expect(callback).toMatchObject({ ok: true, code: "abc" });
    expect(messages).toEqual([
      { message: callback, targetOrigin: applicationOrigin },
    ]);

    expect(() =>
      postBasePopupCallback({
        expectedState: "st",
        applicationOrigin: `${applicationOrigin}/`,
        window: win,
      }),
    ).toThrow("exact origin");
    expect(() =>
      postBasePopupCallback({
        expectedState: "st",
        applicationOrigin,
        window: { ...win, opener: null } as unknown as typeof win,
      }),
    ).toThrow("opener");
  });
});

describe("Connect browser navigation", () => {
  test("navigates without touching protocol secrets", () => {
    const assigned: string[] = [];
    const opened: Array<[string, string]> = [];
    const navigator = createConnectBrowserNavigator({
      startUrl: "https://app.example/auth/tapok/start",
      window: {
        location: { assign: (href: string) => assigned.push(href) },
        open: (href?: string | URL, target?: string) => {
          opened.push([String(href), String(target)]);
          return null;
        },
      } as unknown as Pick<Window, "location" | "open">,
    });
    navigator.startRedirect();
    navigator.startPopup();
    expect(assigned).toEqual(["https://app.example/auth/tapok/start"]);
    expect(opened[0]).toEqual([
      "https://app.example/auth/tapok/start",
      "tapok-connect",
    ]);
    expect(() =>
      createConnectBrowserNavigator({ startUrl: "ftp://app.example/start" }),
    ).toThrow("HTTP");
  });

  test("notifies the opener about backend completion without protocol data", () => {
    const messages: Array<{ message: unknown; targetOrigin: string }> = [];
    postConnectPopupCompletion({
      applicationOrigin,
      window: {
        opener: {
          postMessage: (message: unknown, targetOrigin: string) =>
            void messages.push({ message, targetOrigin }),
        },
      } as unknown as Pick<Window, "opener">,
    });
    expect(messages).toEqual([
      {
        message: { type: "tapok:connect:complete", version: 1 },
        targetOrigin: applicationOrigin,
      },
    ]);
    expect(() =>
      postConnectPopupCompletion({
        applicationOrigin: `${applicationOrigin}/path`,
      }),
    ).toThrow("exact origin");
  });
});

describe("server-side token verification", () => {
  test("verifies a Base identity token and atomically consumes its jti", async () => {
    const claims = baseClaims();
    const replayStore = memoryReplayStore();
    const token = await signJwt(claims);

    const result = await verifyAndConsumeBaseIdentityToken({
      token,
      expectedIssuer: TAPOK_ISSUER,
      expectedAudience: `origin:${applicationOrigin}`,
      replayStore,
    });
    expect(result.replayConsumed).toBe(true);
    expect(result.claims.sub).toBe("pairwise-subject");
    expect(replayStore.used.get(claims["jti"] as string)).toBe(
      (claims["exp"] as number) + 300,
    );

    await expect(
      verifyAndConsumeBaseIdentityToken({
        token,
        expectedIssuer: TAPOK_ISSUER,
        expectedAudience: `origin:${applicationOrigin}`,
        replayStore,
      }),
    ).rejects.toThrow("already been consumed");
  });

  test("rejects Base tokens with a wrong audience, lifetime, mode, or pairwise binding", async () => {
    const replayStore = memoryReplayStore();
    const verify = (claims: Record<string, unknown>) =>
      signJwt(claims).then((token) =>
        verifyAndConsumeBaseIdentityToken({
          token,
          expectedIssuer: TAPOK_ISSUER,
          expectedAudience: `origin:${applicationOrigin}`,
          replayStore,
        }),
      );

    await expect(
      verify(baseClaims({ aud: "origin:https://evil.example" })),
    ).rejects.toThrow();
    await expect(
      verify(baseClaims({ exp: nowSeconds() + 601 })),
    ).rejects.toThrow("lifetime");
    await expect(verify(baseClaims({ mode: "connect" }))).rejects.toThrow(
      "mode",
    );
    await expect(verify(baseClaims({ pairwise_sub: "other" }))).rejects.toThrow(
      "pairwise_sub",
    );
    expect(replayStore.used.size).toBe(0);
  });

  test("verifies Connect ID tokens against issuer, audience, nonce, and lifetime", async () => {
    const verify = (claims: Record<string, unknown>) =>
      signJwt(claims).then((token) =>
        verifyConnectIdToken({
          token,
          expectedIssuer: TAPOK_ISSUER,
          expectedAudience: "tpk_client_example",
          expectedNonce: "nonce",
        }),
      );

    const claims = await verify(connectClaims());
    expect(claims.mode).toBe("connect");
    await expect(verify(connectClaims({ nonce: "other" }))).rejects.toThrow(
      "nonce",
    );
    await expect(
      verify(connectClaims({ exp: nowSeconds() + 901 })),
    ).rejects.toThrow("lifetime");
    await expect(verify(connectClaims({ mode: "base" }))).rejects.toThrow(
      "mode",
    );
  });
});

const connectBinding = "browser-session-secret-with-enough-entropy";
const connectBindingHash = Array.from(
  new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(connectBinding),
    ),
  ),
  (byte) => byte.toString(16).padStart(2, "0"),
).join("");

describe("Connect server client", () => {
  const clientId = "tpk_client_example";
  const clientSecret = "p@ss word/x";

  function transaction(
    overrides: Partial<ConnectAuthorizationTransaction> = {},
  ): ConnectAuthorizationTransaction {
    return {
      state: "st",
      browserBinding: connectBindingHash,
      nonce: "nonce",
      codeVerifier: "v".repeat(43),
      redirectUri,
      scopes: ["openid", "phone"] as readonly ConnectScope[],
      expiresAt: Date.now() + 60_000,
      ...overrides,
    };
  }

  function client(input: {
    consume?: (
      state: string,
    ) => Promise<ConnectAuthorizationTransaction | null>;
    fetch?: typeof fetch;
    scopes?: readonly ConnectScope[];
    save?: (value: ConnectAuthorizationTransaction) => Promise<void>;
  }) {
    return createConnectServerClient({
      clientId,
      clientSecret,
      redirectUri,
      scopes: input.scopes ?? ["openid", "phone"],
      transactions: {
        save: input.save ?? (async () => {}),
        consume: input.consume ?? (async () => null),
      },
      fetch: input.fetch,
    });
  }

  test("rejects invalid client credentials at construction", () => {
    expect(() =>
      createConnectServerClient({
        clientId: "client",
        clientSecret,
        redirectUri,
        scopes: ["openid"],
        transactions: {
          async save() {},
          async consume() {
            return null;
          },
        },
      }),
    ).toThrow("tpk_client_");
  });

  test("creates transaction server-side before redirect", async () => {
    const saved: ConnectAuthorizationTransaction[] = [];
    const start = await client({
      save: async (value) => void saved.push(value),
    }).beginAuthorization(connectBinding);
    expect(start.authorizationUrl.href).toContain(
      tapokEndpoints.connectAuthorize,
    );
    expect(saved).toHaveLength(1);
    const record = saved[0] as ConnectAuthorizationTransaction;
    expect(record.state).toBe(start.state);
    // Only the hash of the binding is stored, never the cookie value.
    expect(record.browserBinding).toBe(connectBindingHash);
    expect(JSON.stringify(record)).not.toContain(connectBinding);
    expect(record.codeVerifier).not.toBe("");
    expect(record.expiresAt).toBeLessThanOrEqual(Date.now() + 5 * 60 * 1000);
    expect(start.authorizationUrl.searchParams.get("code_verifier")).toBeNull();
    expect(start.authorizationUrl.href).not.toContain(clientSecret);
  });

  test("completes the full callback flow with client_secret_basic and sub binding", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const idToken = await signJwt(connectClaims({ sub: "subject" }));
    const result = await client({
      consume: async (state) => (state === "st" ? transaction() : null),
      fetch: (async (url: unknown, init?: RequestInit) => {
        calls.push({ url: String(url), init });
        if (String(url) === tapokEndpoints.connectToken) {
          return response({
            access_token: "opaque-token",
            token_type: "Bearer",
            expires_in: 900,
            scope: "openid phone",
            id_token: idToken,
          });
        }
        return response({ sub: "subject", phone_number: "+70000000000" });
      }) as unknown as typeof fetch,
    }).completeCallback(
      `${redirectUri}?code=code&state=st&iss=${issuerParam}`,
      connectBinding,
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.accessToken).toBe("opaque-token");
      expect(result.grantedScopes).toEqual(["openid", "phone"]);
      expect(result.idToken.sub).toBe("subject");
      expect(result.userInfo).toEqual({
        sub: "subject",
        phone_number: "+70000000000",
      });
    }

    const [tokenCall, userInfoCall] = calls as [
      { url: string; init?: RequestInit },
      { url: string; init?: RequestInit },
    ];
    // RFC 6749 §2.3.1: form-urlencode the credentials before Base64.
    const expectedBasic = `Basic ${btoa("tpk_client_example:p%40ss+word%2Fx")}`;
    expect(tokenCall.init?.headers).toMatchObject({
      authorization: expectedBasic,
    });
    const body = tokenCall.init?.body as URLSearchParams;
    expect(body.get("code_verifier")).toBe("v".repeat(43));
    expect(body.has("client_secret")).toBe(false);
    expect(userInfoCall.url).toBe(tapokEndpoints.connectUserInfo);
    expect(userInfoCall.init?.headers).toMatchObject({
      authorization: "Bearer opaque-token",
    });
  });

  test("returns protocol error callbacks without a token exchange", async () => {
    const result = await client({
      consume: async () => transaction(),
      fetch: (async () => {
        throw new Error("The token endpoint must not be called");
      }) as unknown as typeof fetch,
    }).completeCallback(
      `${redirectUri}?error=access_denied&state=st&iss=${issuerParam}`,
      connectBinding,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.callback.error).toBe("access_denied");
  });

  test("rejects missing, expired, or mismatched transactions", async () => {
    const url = `${redirectUri}?code=code&state=st&iss=${issuerParam}`;
    await expect(
      client({}).completeCallback(url, connectBinding),
    ).rejects.toThrow("missing");
    await expect(
      client({
        consume: async () => transaction({ expiresAt: Date.now() - 1 }),
      }).completeCallback(url, connectBinding),
    ).rejects.toThrow("expired");
    await expect(
      client({
        consume: async () =>
          transaction({ redirectUri: "https://other.example/cb" }),
      }).completeCallback(url, connectBinding),
    ).rejects.toThrow("client configuration");
    await expect(
      client({}).completeCallback(`${redirectUri}?code=code`, connectBinding),
    ).rejects.toThrow("state");
  });

  test("rejects granted scopes that were not requested", async () => {
    const idToken = await signJwt(connectClaims());
    await expect(
      client({
        consume: async () => transaction({ scopes: ["openid"] }),
        fetch: (async () =>
          response({
            access_token: "opaque-token",
            token_type: "Bearer",
            expires_in: 900,
            scope: "openid phone",
            id_token: idToken,
          })) as unknown as typeof fetch,
      }).completeCallback(
        `${redirectUri}?code=code&state=st&iss=${issuerParam}`,
        connectBinding,
      ),
    ).rejects.toThrow("not requested");
  });

  test("treats a UserInfo sub mismatch as token substitution and revokes", async () => {
    const calls: string[] = [];
    const idToken = await signJwt(connectClaims({ sub: "subject" }));
    await expect(
      client({
        consume: async () => transaction(),
        fetch: (async (url: unknown, init?: RequestInit) => {
          calls.push(String(url));
          if (String(url) === tapokEndpoints.connectToken) {
            return response({
              access_token: "opaque-token",
              token_type: "Bearer",
              expires_in: 900,
              scope: "openid phone",
              id_token: idToken,
            });
          }
          if (String(url) === tapokEndpoints.connectRevoke) {
            expect(
              (init?.body as URLSearchParams | undefined)?.get("token"),
            ).toBe("opaque-token");
            return new Response(null, { status: 200 });
          }
          return response({
            sub: "someone-else",
            phone_number: "+70000000000",
          });
        }) as unknown as typeof fetch,
      }).completeCallback(
        `${redirectUri}?code=code&state=st&iss=${issuerParam}`,
        connectBinding,
      ),
    ).rejects.toThrow("does not match the verified ID token");
    expect(calls).toContain(tapokEndpoints.connectRevoke);
  });

  test("surfaces protocol errors from the token endpoint via client_secret_basic only", async () => {
    let captured: RequestInit | undefined;
    await expect(
      client({
        consume: async () => transaction({ scopes: ["openid"] }),
        fetch: (async (_url: unknown, init?: RequestInit) => {
          captured = init;
          return response({ error: "invalid_grant" }, 400);
        }) as unknown as typeof fetch,
      }).completeCallback(
        `${redirectUri}?code=code&state=st&iss=${issuerParam}`,
        connectBinding,
      ),
    ).rejects.toThrow("invalid_grant");
    expect(captured?.headers).toMatchObject({
      authorization: expect.stringMatching(/^Basic /u),
    });
    expect(String(captured?.body)).not.toContain("client_secret");
  });

  test("revokes access tokens with client authentication", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    await client({
      fetch: (async (url: unknown, init?: RequestInit) => {
        calls.push({ url: String(url), init });
        return new Response(null, { status: 200 });
      }) as unknown as typeof fetch,
    }).revoke("opaque-token");
    const call = calls[0] as { url: string; init?: RequestInit };
    expect(call.url).toBe(tapokEndpoints.connectRevoke);
    expect(call.init?.headers).toMatchObject({
      authorization: expect.stringMatching(/^Basic /u),
    });
    const body = call.init?.body as URLSearchParams;
    expect(body.get("token")).toBe("opaque-token");
    expect(body.get("token_type_hint")).toBe("access_token");
  });
});
