import { expect, test } from "bun:test";
import { SignJWT, generateKeyPair, exportJWK } from "jose";
import {
  createBaseServerClient,
  createBaseOidcServerClient,
  createConnectServerClient,
} from "../src/server.ts";
import type {
  BaseServerTransaction,
  ConnectAuthorizationTransaction,
} from "../src/server.ts";
import { createBaseOidcBrowserClient } from "../src/browser.ts";

const binding = "random-session-cookie-with-256-bits-of-entropy";
const redirectUri = "https://app.example/callback";
const issuer = "https://id.example";
const baseIssuer = issuer + "/oidc/base";
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
const keys = await generateKeyPair("RS256");
const jwk = {
  ...(await exportJWK(keys.publicKey)),
  kid: "test",
  alg: "RS256",
  use: "sig",
};
const json = (value: unknown) => Response.json(value);
const jwksFetch = (async () =>
  json({ keys: [jwk] })) as unknown as typeof fetch;
async function sign(claims: Record<string, unknown>) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: "test", typ: "JWT" })
    .setIssuedAt()
    .setExpirationTime("5m")
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}
function callback(state: string, iss: string) {
  return (
    redirectUri +
    "?state=" +
    state +
    "&code=code&iss=" +
    encodeURIComponent(iss)
  );
}

test("backend Base binds browser, verifies nonce/signature and consumes replay atomically", async () => {
  const transactions = transactionStore<BaseServerTransaction>();
  let nonce = "";
  const replay = new Set<string>();
  const client = createBaseServerClient({
    issuer,
    redirectUri,
    transactions,
    replayStore: {
      async consume(jti) {
        if (replay.has(jti)) return false;
        replay.add(jti);
        return true;
      },
    },
    jwksFetch,
    fetch: (async (_url: unknown, init?: RequestInit) => {
      expect(new Headers(init?.headers).get("origin")).toBeNull();
      return json({
        identity_token: await sign({
          iss: issuer,
          aud: "origin:https://app.example",
          sub: "pairwise",
          pairwise_sub: "pairwise",
          mode: "base",
          nonce,
        }),
        expires_in: 600,
        scope: "session",
      });
    }) as unknown as typeof fetch,
  });
  const first = await client.beginAuthorization(binding);
  nonce = first.authorizationUrl.searchParams.get("nonce")!;
  await expect(
    client.completeCallback(
      callback(first.state, issuer),
      "different-browser-cookie-with-enough-entropy",
    ),
  ).rejects.toThrow("binding");
  const second = await client.beginAuthorization(binding);
  nonce = second.authorizationUrl.searchParams.get("nonce")!;
  const result = await client.completeCallback(
    callback(second.state, issuer),
    binding,
  );
  expect(result.ok).toBe(true);
  expect(replay.size).toBe(1);
  await expect(
    client.completeCallback(callback(second.state, issuer), binding),
  ).rejects.toThrow();
});

test("Base OIDC backend does not exchange a code from another browser", async () => {
  let fetched = false;
  const client = createBaseOidcServerClient({
    issuer: baseIssuer,
    clientId: "base_client",
    redirectUri,
    scopes: ["openid"],
    transactions: transactionStore(),
    jwksFetch,
    fetch: (async () => {
      fetched = true;
      return json({});
    }) as unknown as typeof fetch,
  });
  const start = await client.beginAuthorization(binding);
  await expect(
    client.completeCallback(
      callback(start.state, baseIssuer),
      "other-session-with-at-least-32-characters",
    ),
  ).rejects.toThrow("binding");
  expect(fetched).toBe(false);
});

test("Base OIDC browser verifies RS256 and returns token only from its isolated issuer", async () => {
  const data = new Map<string, string>();
  const storage = {
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => {
      data.set(k, v);
    },
    removeItem: (k: string) => {
      data.delete(k);
    },
  };
  let nonce = "";
  let leak = false;
  const client = createBaseOidcBrowserClient({
    issuer: baseIssuer,
    clientId: "base_client",
    redirectUri,
    storage,
    fetch: (async (url: unknown, init?: RequestInit) => {
      if (String(url).endsWith("jwks.json")) return json({ keys: [jwk] });
      const body = new URLSearchParams(String(init?.body));
      expect(body.get("client_id")).toBe("base_client");
      expect(body.has("client_secret")).toBe(false);
      return json({
        access_token: "opaque",
        token_type: "Bearer",
        scope: "openid",
        expires_in: 300,
        id_token: await sign({
          iss: baseIssuer,
          aud: "base_client",
          sub: "pairwise",
          mode: "base",
          nonce,
          ...(leak ? { phone_number: "+70000000000" } : {}),
        }),
      });
    }) as unknown as typeof fetch,
  });
  const first = await client.beginAuthorization();
  nonce = first.authorizationUrl.searchParams.get("nonce")!;
  expect(
    (await client.completeCallback(callback(first.state, baseIssuer))).ok,
  ).toBe(true);
  await expect(
    client.completeCallback(callback(first.state, baseIssuer)),
  ).rejects.toThrow("transaction");
  const second = await client.beginAuthorization();
  nonce = second.authorizationUrl.searchParams.get("nonce")!;
  leak = true;
  await expect(
    client.completeCallback(callback(second.state, baseIssuer)),
  ).rejects.toThrow("Personal claim");
});

test("Connect refresh verifies returned ID token subject and rejects widened scopes", async () => {
  let scope = "openid email";
  let subject = "same-user";
  const client = createConnectServerClient({
    issuer,
    clientId: "tpk_client_test",
    clientSecret: "secret",
    redirectUri,
    scopes: ["openid"],
    transactions: transactionStore<ConnectAuthorizationTransaction>(),
    jwksFetch,
    fetch: (async (_url: unknown, init?: RequestInit) => {
      expect(new URLSearchParams(String(init?.body)).get("grant_type")).toBe(
        "refresh_token",
      );
      return json({
        access_token: "rotated",
        token_type: "Bearer",
        scope,
        expires_in: 300,
        refresh_token: "new-refresh",
        id_token: await sign({
          iss: issuer,
          aud: "tpk_client_test",
          sub: subject,
          mode: "connect",
        }),
      });
    }) as unknown as typeof fetch,
  });
  const expected = { sub: "same-user", scopes: ["openid"] as const };
  await expect(client.refresh("old", expected)).rejects.toThrow(
    "expanded scopes",
  );
  scope = "openid";
  subject = "other-user";
  await expect(client.refresh("old", expected)).rejects.toThrow("subject");
  subject = "same-user";
  expect((await client.refresh("old", expected)).refresh_token).toBe(
    "new-refresh",
  );
});
