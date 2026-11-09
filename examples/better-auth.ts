import { Database } from "bun:sqlite";
import { betterAuth } from "better-auth";
import { genericOAuth } from "better-auth/plugins";
import { getMigrations } from "better-auth/db/migration";

function env(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error("Missing " + name);
  return value;
}

/** Run with Bun; use a disposable local DB for this integration example. */
export async function createBetterAuthExample(input: {
  baseURL: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  secret: string;
  database?: Database;
}) {
  const { baseURL, issuer } = input;
  const auth = betterAuth({
    baseURL,
    secret: input.secret,
    database: input.database ?? new Database(":memory:"),
    account: { accountLinking: { enabled: false } },
    plugins: [
      genericOAuth({
        config: [
          {
            providerId: "tapok-base",
            clientId: input.clientId,
            clientSecret: input.clientSecret,
            discoveryUrl: issuer + "/.well-known/openid-configuration",
            scopes: ["openid", "profile", "email"],
            pkce: true,
            tokenEndpointAuth: { method: "client_secret_basic" },
          },
        ],
      }),
    ],
  });
  await (await getMigrations(auth.options)).runMigrations();
  return auth;
}

const pageHeaders = {
  "content-type": "text/html; charset=utf-8",
  "cache-control": "no-store",
  "referrer-policy": "no-referrer",
  "content-security-policy":
    "default-src 'self'; script-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  "x-content-type-options": "nosniff",
};

const styles = `body{margin:0;padding:24px 12px;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:#26362c;background:#fbfaf7}main{max-width:600px;margin:0 auto}h1{font-size:24px;margin:0 0 16px;color:#1b3a28}section{background:#fff;border:1px solid #dfe5dd;border-radius:10px;padding:20px}h2{font-size:18px;line-height:1.4;margin:0 0 8px;color:#1b3a28}p{color:#566a5c;margin:0 0 12px}.actions{display:flex;flex-wrap:wrap;gap:8px}button,a.button{font:inherit;font-weight:500;min-height:44px;padding:10px 14px;border-radius:7px;border:1px solid #dfe5dd;background:#fff;color:#1b3a28;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center}.primary{background:#1b6b3a;border-color:#1b6b3a;color:#fff}[hidden]{display:none!important}:focus-visible{outline:3px solid #5c9670;outline-offset:3px}@media(max-width:480px){.actions>*{width:100%;justify-content:center}}`;

function page(title: string, body: string): Response {
  return new Response(
    `<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>${styles}</style><script type="module" src="/example/client.js"></script></head><body><main>${body}</main></body></html>`,
    { headers: pageHeaders },
  );
}

/**
 * HTTP handler of the example application: Better Auth routes, the main page
 * with popup/redirect sign-in states and the popup completion page.
 * `clientScript` is the bundled `better-auth-client.ts`.
 */
export function createBetterAuthExampleHandler(input: {
  auth: { handler(request: Request): Promise<Response> };
  clientScript: string;
}) {
  return async (request: Request): Promise<Response> => {
    const { pathname } = new URL(request.url);
    if (pathname.startsWith("/api/auth/")) return input.auth.handler(request);
    if (pathname === "/example/client.js")
      return new Response(input.clientScript, {
        headers: {
          "content-type": "text/javascript; charset=utf-8",
          "cache-control": "no-store",
          "x-content-type-options": "nosniff",
        },
      });
    if (pathname === "/auth/popup-complete")
      return page(
        "Вход через Tapok",
        `<section data-tapok-example="popup-complete"><h2>Возврат на сайт</h2><p data-text role="status">Проверяем результат входа…</p><div class="actions"><a class="button primary" href="/" data-back hidden>Вернуться на сайт</a><button type="button" data-close>Закрыть окно</button></div></section>`,
      );
    if (pathname === "/")
      return page(
        "Tapok + Better Auth",
        `<h1>Tapok + Better Auth</h1><section data-tapok-example="main" data-state="idle" aria-live="polite"><h2 data-title>Проверяем сессию…</h2><p data-text></p><div class="actions"><button type="button" class="primary" data-login hidden>Войти через Tapok</button><button type="button" data-focus hidden>Перейти к окну</button><button type="button" data-same-tab hidden>Войти в этой вкладке</button></div></section>`,
      );
    return new Response("Not found", { status: 404 });
  };
}

/** Bundles the browser part with the SDK resolved from node_modules. */
export async function buildBetterAuthExampleClient(
  plugins: Bun.BunPlugin[] = [],
): Promise<string> {
  const result = await Bun.build({
    entrypoints: [import.meta.dir + "/better-auth-client.ts"],
    target: "browser",
    format: "esm",
    minify: true,
    plugins,
  });
  if (!result.success || !result.outputs[0])
    throw new Error("Example client build failed");
  return result.outputs[0].text();
}

export async function startBetterAuthExample() {
  const baseURL = process.env["BETTER_AUTH_URL"] ?? "http://localhost:4300";
  const auth = await createBetterAuthExample({
    baseURL,
    issuer:
      process.env["TAPOK_BASE_ISSUER"] ?? "https://tapok.orria.space/oidc/base",
    clientId: env("TAPOK_BASE_CLIENT_ID"),
    clientSecret: env("TAPOK_BASE_CLIENT_SECRET"),
    secret: env("BETTER_AUTH_SECRET"),
    database: new Database(process.env["EXAMPLE_DATABASE"] ?? ":memory:"),
  });
  const handler = createBetterAuthExampleHandler({
    auth,
    clientScript: await buildBetterAuthExampleClient(),
  });
  return Bun.serve({
    port: Number(new URL(baseURL).port || "4300"),
    fetch: handler,
  });
}

if (import.meta.main) await startBetterAuthExample();
