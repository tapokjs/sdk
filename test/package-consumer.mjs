import {
  TAPOK_ISSUER,
  createAuthorizationSecrets,
  tapokEndpoints,
} from "@tapokjs/core";
import { TapokHttpError } from "@tapokjs/sdk";
import { createBaseBrowserClient } from "@tapokjs/sdk/browser";
import {
  createConnectServerClient,
  verifyConnectIdToken,
  verifyAndConsumeBaseIdentityToken,
} from "@tapokjs/sdk/server";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}
const encode = (bytes) =>
  btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
const encodeJson = (value) =>
  encode(new TextEncoder().encode(JSON.stringify(value)));
assert(
  TAPOK_ISSUER === "https://tapok.orria.space",
  "Unexpected issuer export",
);
for (const entry of [
  TapokHttpError,
  createBaseBrowserClient,
  createConnectServerClient,
  verifyConnectIdToken,
  verifyAndConsumeBaseIdentityToken,
]) {
  assert(typeof entry === "function", "Missing public SDK export");
}
const secrets = await createAuthorizationSecrets();
const digest = await crypto.subtle.digest(
  "SHA-256",
  new TextEncoder().encode(secrets.pkce.verifier),
);
assert(
  secrets.pkce.method === "S256" && secrets.pkce.verifier.length === 43,
  "Invalid PKCE verifier",
);
assert(
  secrets.pkce.challenge === encode(new Uint8Array(digest)),
  "Invalid PKCE challenge",
);

const keys = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  true,
  ["sign", "verify"],
);
const jwk = {
  ...(await crypto.subtle.exportKey("jwk", keys.publicKey)),
  kid: "package-smoke",
  alg: "ES256",
  use: "sig",
};
const clientId = "tpk_client_package_smoke";
let transaction;
let activeTransaction;
let corruptSignature = false;
let jwksRequests = 0;
async function signToken() {
  const now = Math.floor(Date.now() / 1000);
  const data =
    encodeJson({ alg: "ES256", typ: "JWT", kid: jwk.kid }) +
    "." +
    encodeJson({
      iss: TAPOK_ISSUER,
      aud: clientId,
      sub: "smoke-subject",
      jti: crypto.randomUUID(),
      iat: now,
      exp: now + 300,
      mode: "connect",
      nonce: activeTransaction.nonce,
    });
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      keys.privateKey,
      new TextEncoder().encode(data),
    ),
  );
  if (corruptSignature) signature[0] ^= 1;
  return data + "." + encode(signature);
}
const client = createConnectServerClient({
  clientId,
  clientSecret: "package-smoke-only",
  redirectUri: "https://app.example/callback",
  scopes: ["openid"],
  transactions: {
    async save(value) {
      transaction = value;
    },
    async consume(state) {
      if (transaction?.state !== state) return null;
      const result = transaction;
      activeTransaction = result;
      transaction = undefined;
      return result;
    },
  },
  async jwksFetch(url) {
    assert(String(url) === tapokEndpoints.jwks, "Unexpected JWKS URL");
    jwksRequests++;
    return Response.json({ keys: [jwk] });
  },
  async fetch(url, init) {
    if (String(url) === tapokEndpoints.connectToken) {
      assert(
        new URLSearchParams(init.body).get("code_verifier") ===
          activeTransaction.codeVerifier,
        "Missing backend PKCE verifier",
      );
      return Response.json({
        access_token: "package-smoke-access",
        token_type: "Bearer",
        expires_in: 900,
        scope: "openid",
        id_token: await signToken(),
      });
    }
    assert(
      String(url) === tapokEndpoints.connectUserInfo,
      "Unexpected API URL",
    );
    return Response.json({ sub: "smoke-subject" });
  },
});
async function callback() {
  const binding = "package-smoke-browser-binding-256-bit-example";
  const start = await client.beginAuthorization(binding);
  const url = new URL("https://app.example/callback");
  url.search = new URLSearchParams({
    code: "package-smoke-code",
    state: start.state,
    iss: TAPOK_ISSUER,
  }).toString();
  return client.completeCallback(url, binding);
}
const result = await callback();
assert(
  result.ok &&
    result.idToken.sub === "smoke-subject" &&
    result.userInfo.sub === "smoke-subject",
  "SDK JWT verification failed",
);
assert(jwksRequests === 1, "SDK did not retrieve public signing keys");
const cached = await callback();
assert(cached.ok, "SDK failed the second login");
assert(jwksRequests === 1, "SDK failed to reuse cached JWKS");
corruptSignature = true;
let rejected = false;
try {
  await callback();
} catch (error) {
  rejected =
    error.code === "invalid_token" &&
    error.reason === "ERR_JWS_SIGNATURE_VERIFICATION_FAILED";
}
assert(rejected, "SDK accepted a corrupted JWT signature");
console.log("Published package exports, PKCE, and SDK JWT smoke passed");
