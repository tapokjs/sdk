# @tapokjs/sdk

TypeScript SDK layer for Tapok integrations, built on `@tapokjs/core`.

## Scope

- Browser-facing Base and UI/navigation helpers: redirect, popup, transaction storage, callback handling and nonce checks.
- Server-facing Connect integration: backend transaction handling, `client_secret_basic`, token exchange, JWKS/JWT verification, UserInfo, revoke and replay-safe Base identity-token verification.
- Framework adapters may provide lifecycle, SSR guards, callback handlers and application-session integration.

## Constraints

- Connect is backend-only: browser code must never receive a client secret, PKCE verifier, authorization code, ID token or access token.
- Base browser flows validate `state`, exact issuer and nonce; popup messages use the exact application origin, never `*`.
- Do not log or expose codes, tokens, secrets, state, nonce, PKCE verifier, provider data or profile claims.
- Source is in `src/`; generated `.js`, `.mjs`, `.cjs` and `.d.ts` files belong in `dist/`.
