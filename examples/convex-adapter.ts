import { ConvexClient } from "convex/browser";
import { createBaseOidcBrowserClient } from "@tapokjs/sdk/browser";

/**
 * Base public client with silent PKCE renewal in a same-origin callback iframe.
 * If third-party session cookies are unavailable, show the explicit sign-in button.
 */
export function connectTapokToConvex(input: {
  convexUrl: string;
  clientId: string;
  redirectUri: string;
  issuer?: string;
  onInteractionRequired: () => void;
}) {
  const convex = new ConvexClient(input.convexUrl);
  const oidc = createBaseOidcBrowserClient({
    clientId: input.clientId,
    redirectUri: input.redirectUri,
    issuer: input.issuer,
    scopes: ["openid", "profile"],
  });
  let cached: { token: string; expiresAt: number } | undefined;
  let pending: Promise<string | null> | undefined;
  const origin = new URL(input.redirectUri).origin;
  if (origin !== location.origin)
    throw new Error("The callback must share the application origin");

  async function renew(): Promise<string | null> {
    const start = await oidc.beginAuthorization({ prompt: "none" });
    const frame = document.createElement("iframe");
    frame.hidden = true;
    let dispose = () => {};
    const callback = new Promise<string>((resolve, reject) => {
      const timeout = setTimeout(() => {
        dispose();
        reject(new Error("Silent login timed out"));
      }, 15_000);
      const receive = (event: MessageEvent<unknown>) => {
        if (
          event.origin !== origin ||
          event.source !== frame.contentWindow ||
          !event.data ||
          typeof event.data !== "object"
        )
          return;
        const data = event.data as Record<string, unknown>;
        if (data.type !== "tapok:base:renew" || typeof data.url !== "string")
          return;
        const url = new URL(data.url);
        if (
          url.origin !== origin ||
          url.pathname !== new URL(input.redirectUri).pathname ||
          url.searchParams.get("state") !== start.state
        )
          return;
        dispose();
        resolve(url.href);
      };
      dispose = () => {
        clearTimeout(timeout);
        window.removeEventListener("message", receive);
        frame.remove();
      };
      window.addEventListener("message", receive);
      frame.src = start.authorizationUrl.href;
      document.body.append(frame);
    });
    try {
      const result = await oidc.completeCallback(await callback);
      if (!result.ok) {
        cached = undefined;
        input.onInteractionRequired();
        return null;
      }
      cached = {
        token: result.idToken,
        expiresAt: Number(result.claims.exp) * 1000,
      };
      return cached.token;
    } catch {
      cached = undefined;
      input.onInteractionRequired();
      return null;
    } finally {
      dispose();
    }
  }
  const ready = new URL(location.href).searchParams.has("state")
    ? finishRedirect()
    : Promise.resolve(false);
  convex.setAuth(async ({ forceRefreshToken }) => {
    await ready;
    if (!forceRefreshToken && cached && cached.expiresAt > Date.now() + 60_000)
      return cached.token;
    pending ??= renew().finally(() => {
      pending = undefined;
    });
    return pending;
  });
  async function signIn() {
    await pending;
    const start = await oidc.beginAuthorization();
    location.assign(start.authorizationUrl.href);
  }
  async function finishRedirect() {
    const result = await oidc.completeCallback(location.href);
    history.replaceState(null, "", new URL(input.redirectUri).pathname);
    if (result.ok)
      cached = {
        token: result.idToken,
        expiresAt: Number(result.claims.exp) * 1000,
      };
    return result.ok;
  }
  return {
    convex,
    signIn,
    completeRedirect: () => ready,
    close: () => convex.close(),
  };
}

/** Invoke only on the registered callback page when loaded inside the renewal iframe. */
export function completeConvexRenewalFrame() {
  if (window.parent === window) return false;
  window.parent.postMessage(
    { type: "tapok:base:renew", url: location.href },
    location.origin,
  );
  history.replaceState(null, "", location.pathname);
  return true;
}
