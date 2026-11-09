import * as oauth from "oauth4webapi";

/** Independent OIDC client. No Tapok Core or SDK imports. Configuration must be trusted. */
export async function createIndependentOidcClient(input: {
  issuer: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
  fetch?: typeof fetch;
}) {
  const issuer = new URL(input.issuer);
  if (
    issuer.protocol !== "https:" ||
    issuer.search ||
    issuer.hash ||
    issuer.username ||
    issuer.password
  )
    throw new TypeError("Configure an HTTPS issuer");
  const transport = { [oauth.customFetch]: input.fetch ?? fetch };
  const metadata = await oauth.processDiscoveryResponse(
    issuer,
    await oauth.discoveryRequest(issuer, transport),
  );
  for (const endpoint of [
    metadata.authorization_endpoint,
    metadata.token_endpoint,
    metadata.userinfo_endpoint,
    metadata.jwks_uri,
  ]) {
    if (!endpoint || new URL(endpoint).origin !== issuer.origin)
      throw new TypeError("Untrusted OIDC endpoint");
  }
  const client: oauth.Client = {
    client_id: input.clientId,
    id_token_signed_response_alg: "RS256",
  };
  const authentication = input.clientSecret
    ? oauth.ClientSecretBasic(input.clientSecret)
    : oauth.None();
  async function begin(scopes = ["openid", "profile", "email"]) {
    const verifier = oauth.generateRandomCodeVerifier();
    const state = oauth.generateRandomState();
    const nonce = oauth.generateRandomNonce();
    const authorizationUrl = new URL(metadata.authorization_endpoint!);
    authorizationUrl.search = new URLSearchParams({
      response_type: "code",
      client_id: input.clientId,
      redirect_uri: input.redirectUri,
      scope: scopes.join(" "),
      state,
      nonce,
      code_challenge: await oauth.calculatePKCECodeChallenge(verifier),
      code_challenge_method: "S256",
    }).toString();
    return { authorizationUrl, verifier, state, nonce };
  }
  async function complete(
    callback: URL,
    transaction: Awaited<ReturnType<typeof begin>>,
  ) {
    const parameters = oauth.validateAuthResponse(
      metadata,
      client,
      callback,
      transaction.state,
    );
    const response = await oauth.authorizationCodeGrantRequest(
      metadata,
      client,
      authentication,
      parameters,
      input.redirectUri,
      transaction.verifier,
      transport,
    );
    const tokens = await oauth.processAuthorizationCodeResponse(
      metadata,
      client,
      response,
      { expectedNonce: transaction.nonce, requireIdToken: true },
    );
    await oauth.validateApplicationLevelSignature(
      metadata,
      response,
      transport,
    );
    const claims = oauth.getValidatedIdTokenClaims(tokens)!;
    const profile = await oauth.processUserInfoResponse(
      metadata,
      client,
      claims.sub,
      await oauth.userInfoRequest(
        metadata,
        client,
        tokens.access_token,
        transport,
      ),
    );
    return { tokens, claims, profile };
  }
  return { metadata, begin, complete };
}
