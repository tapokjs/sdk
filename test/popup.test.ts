import { describe, expect, test } from "bun:test";
import { TAPOK_ISSUER } from "@tapokjs/core";
import {
  createBaseBrowserClient,
  createConnectBrowserNavigator,
  notifyAuthPopupOpener,
  openAuthPopup,
  openBackendAuthPopup,
  postConnectPopupCompletion,
  relayBasePopupCallback,
  shouldUsePopup,
} from "../src/browser.ts";

const appOrigin = "https://app.example";
const redirectUri = `${appOrigin}/auth/tapok/callback`;

type FakePopup = {
  closed: boolean;
  replaced: string[];
  closeCalls: number;
  location: { replace(href: string): void };
  close(): void;
  focus(): void;
};

function fakePopup(): FakePopup {
  const popup: FakePopup = {
    closed: false,
    replaced: [],
    closeCalls: 0,
    location: { replace: (href) => void popup.replaced.push(href) },
    close() {
      popup.closeCalls += 1;
      popup.closed = true;
    },
    focus() {},
  };
  return popup;
}

function host(popup: FakePopup | null) {
  const listeners = new Set<(event: MessageEvent<unknown>) => void>();
  const opened: Array<[string, string, string]> = [];
  return {
    opened,
    listeners,
    window: {
      open(url?: string | URL, name?: string, features?: string) {
        opened.push([String(url), String(name), String(features)]);
        return popup as unknown as WindowProxy | null;
      },
      addEventListener(_type: string, listener: unknown) {
        listeners.add(listener as (event: MessageEvent<unknown>) => void);
      },
      removeEventListener(_type: string, listener: unknown) {
        listeners.delete(listener as (event: MessageEvent<unknown>) => void);
      },
      location: { href: appOrigin, pathname: "/", hash: "", assign() {} },
      history: { replaceState() {} },
    } as unknown as Window,
    dispatch(event: Partial<MessageEvent<unknown>>) {
      for (const listener of [...listeners])
        listener(event as MessageEvent<unknown>);
    },
  };
}

function storage() {
  const values = new Map<string, string>();
  return {
    values,
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => void values.set(key, value),
    removeItem: (key: string) => void values.delete(key),
  };
}

const tick = (ms = 0) => new Promise((resolve) => setTimeout(resolve, ms));

describe("openAuthPopup", () => {
  test("reports a blocked window without running the URL factory", async () => {
    const h = host(null);
    let prepared = false;
    const attempt = openAuthPopup({
      url: async () => {
        prepared = true;
        return "https://tapok.example/authorize";
      },
      messageOrigin: appOrigin,
      accept: () => "x",
      window: h.window,
    });
    expect(attempt.popup).toBeNull();
    expect(await attempt.result).toEqual({ status: "blocked" });
    expect(prepared).toBe(false);
  });

  test("opens about:blank synchronously and navigates once the URL is ready", async () => {
    const popup = fakePopup();
    const h = host(popup);
    const attempt = openAuthPopup({
      url: async () => {
        await tick(5);
        return "https://tapok.example/authorize?x=1";
      },
      messageOrigin: appOrigin,
      accept: () => "x",
      window: h.window,
    });
    expect(h.opened[0]).toEqual([
      "about:blank",
      "tapok-auth",
      "popup,width=480,height=720",
    ]);
    await tick(20);
    expect(popup.replaced).toEqual(["https://tapok.example/authorize?x=1"]);
    attempt.cancel();
    expect(await attempt.result).toEqual({ status: "cancelled" });
    expect(popup.closeCalls).toBe(1);
    expect(h.listeners.size).toBe(0);
  });

  test("closes the empty window when the URL cannot be prepared", async () => {
    const popup = fakePopup();
    const attempt = openAuthPopup({
      url: async () => {
        throw new Error("crypto unavailable");
      },
      messageOrigin: appOrigin,
      accept: () => "x",
      window: host(popup).window,
    });
    const result = await attempt.result;
    expect(result.status).toBe("failed");
    expect(popup.closed).toBe(true);
    for (const bad of ["javascript:alert(1)", "data:text/html,x"]) {
      const other = fakePopup();
      const failed = await openAuthPopup({
        url: () => bad,
        messageOrigin: appOrigin,
        accept: () => "x",
        window: host(other).window,
      }).result;
      expect(failed.status).toBe("failed");
      expect(other.replaced).toEqual([]);
    }
  });

  test("accepts only the exact source and origin; ignores unrelated messages", async () => {
    const popup = fakePopup();
    const h = host(popup);
    const attempt = openAuthPopup({
      url: "https://tapok.example/authorize",
      messageOrigin: appOrigin,
      accept: (event) =>
        (event.data as { type?: string })?.type === "done" ? "ok" : undefined,
      window: h.window,
    });
    h.dispatch({
      origin: "https://evil.example",
      source: popup as never,
      data: { type: "done" },
    });
    h.dispatch({
      origin: appOrigin,
      source: {} as never,
      data: { type: "done" },
    });
    h.dispatch({
      origin: appOrigin,
      source: popup as never,
      data: { type: "other" },
    });
    await tick();
    h.dispatch({
      origin: appOrigin,
      source: popup as never,
      data: { type: "done" },
    });
    expect(await attempt.result).toEqual({ status: "received", value: "ok" });
    // The popup is left open until the application confirms its session.
    expect(popup.closed).toBe(false);
    attempt.close();
    expect(popup.closed).toBe(true);
  });

  test("a closed window is reported as closed, never as success", async () => {
    const popup = fakePopup();
    const attempt = openAuthPopup({
      url: "https://tapok.example/authorize",
      messageOrigin: appOrigin,
      accept: () => "x",
      pollIntervalMs: 5,
      window: host(popup).window,
    });
    popup.closed = true;
    expect(await attempt.result).toEqual({ status: "closed" });
  });

  test("times out and closes the window", async () => {
    const popup = fakePopup();
    const attempt = openAuthPopup({
      url: "https://tapok.example/authorize",
      messageOrigin: appOrigin,
      accept: () => "x",
      timeoutMs: 10,
      window: host(popup).window,
    });
    expect(await attempt.result).toEqual({ status: "timeout" });
    expect(popup.closed).toBe(true);
  });

  test("requires an exact message origin", () => {
    for (const messageOrigin of [`${appOrigin}/`, "*", "null"])
      expect(() =>
        openAuthPopup({
          url: "https://tapok.example/",
          messageOrigin,
          accept: () => "x",
          window: host(fakePopup()).window,
        }),
      ).toThrow("exact origin");
  });
});

describe("Base startPopup", () => {
  test("prepares PKCE after opening and validates state through completePopupMessage", async () => {
    const popup = fakePopup();
    const h = host(popup);
    const store = storage();
    const client = createBaseBrowserClient({
      redirectUri,
      storage: store,
      window: h.window,
      fetch: (async () => {
        throw new Error("no exchange expected for a denied callback");
      }) as unknown as typeof fetch,
    });
    const attempt = client.startPopup();
    expect(h.opened[0]?.[0]).toBe("about:blank");
    await tick(20);
    const authorize = new URL(popup.replaced[0]!);
    expect(authorize.searchParams.get("code_challenge_method")).toBe("S256");
    const state = authorize.searchParams.get("state")!;
    // A same-origin message without state is unrelated and ignored.
    h.dispatch({
      origin: appOrigin,
      source: popup as never,
      data: { hello: 1 },
    });
    h.dispatch({
      origin: appOrigin,
      source: popup as never,
      data: {
        type: "tapok:base:callback",
        version: 1,
        error: "access_denied",
        state,
        iss: TAPOK_ISSUER,
      },
    });
    const result = await attempt.result;
    expect(result).toEqual({
      status: "received",
      value: { ok: false, error: "access_denied", errorDescription: undefined },
    });
    expect(store.values.size).toBe(0);
  });

  test("a forged state fails the attempt instead of succeeding", async () => {
    const popup = fakePopup();
    const h = host(popup);
    const client = createBaseBrowserClient({
      redirectUri,
      storage: storage(),
      window: h.window,
    });
    const attempt = client.startPopup();
    await tick(20);
    h.dispatch({
      origin: appOrigin,
      source: popup as never,
      data: { code: "c", state: "forged", iss: TAPOK_ISSUER },
    });
    expect((await attempt.result).status).toBe("failed");
  });
});

describe("popup callback pages", () => {
  test("relayBasePopupCallback forwards only callback fields to the exact origin", () => {
    const messages: Array<[unknown, string]> = [];
    let cleaned = "";
    const win = {
      location: {
        href: `${redirectUri}?code=c&state=s&iss=${encodeURIComponent(TAPOK_ISSUER)}&extra=secret`,
        pathname: "/auth/tapok/callback",
        hash: "",
      },
      history: {
        replaceState: (_s: unknown, _t: string, url: string) =>
          void (cleaned = url),
      },
      opener: {
        closed: false,
        postMessage: (message: unknown, target: string) =>
          void messages.push([message, target]),
      },
    } as unknown as Pick<Window, "location" | "history" | "opener">;
    expect(
      relayBasePopupCallback({ applicationOrigin: appOrigin, window: win }),
    ).toBe(true);
    expect(messages).toEqual([
      [
        {
          type: "tapok:base:callback",
          version: 1,
          code: "c",
          state: "s",
          iss: TAPOK_ISSUER,
        },
        appOrigin,
      ],
    ]);
    expect(cleaned).toBe("/auth/tapok/callback");
    expect(
      relayBasePopupCallback({
        applicationOrigin: appOrigin,
        window: { ...win, opener: null } as typeof win,
      }),
    ).toBe(false);
    expect(() =>
      relayBasePopupCallback({ applicationOrigin: "*", window: win }),
    ).toThrow();
  });

  test("notifyAuthPopupOpener sends only a status", () => {
    const messages: Array<[unknown, string]> = [];
    const opener = {
      closed: false,
      postMessage: (message: unknown, target: string) =>
        void messages.push([message, target]),
    };
    expect(
      notifyAuthPopupOpener({
        applicationOrigin: appOrigin,
        status: "complete",
        window: { opener } as unknown as Pick<Window, "opener">,
      }),
    ).toBe(true);
    expect(messages).toEqual([
      [
        { type: "tapok:popup:result", version: 1, status: "complete" },
        appOrigin,
      ],
    ]);
    expect(
      notifyAuthPopupOpener({
        applicationOrigin: appOrigin,
        status: "complete",
        window: { opener: null } as unknown as Pick<Window, "opener">,
      }),
    ).toBe(false);
  });

  test("backend popup accepts the new and legacy Connect completion messages", async () => {
    for (const data of [
      { type: "tapok:popup:result", version: 1, status: "denied" },
      { type: "tapok:connect:complete", version: 1 },
    ]) {
      const popup = fakePopup();
      const h = host(popup);
      const attempt = openBackendAuthPopup({
        url: `${appOrigin}/auth/start`,
        messageOrigin: appOrigin,
        window: h.window,
      });
      h.dispatch({
        origin: appOrigin,
        source: popup as never,
        data: { type: "tapok:popup:result", version: 1, status: "ok" },
      });
      h.dispatch({ origin: appOrigin, source: popup as never, data });
      const result = await attempt.result;
      expect(result.status).toBe("received");
    }
  });

  test("Connect navigator popup attempt keeps the backend-only boundary", async () => {
    const popup = fakePopup();
    const h = host(popup);
    const navigator = createConnectBrowserNavigator({
      startUrl: `${appOrigin}/auth/tapok/start`,
      window: h.window,
    });
    const attempt = navigator.startPopupAttempt();
    expect(h.opened[0]?.[0]).toBe(`${appOrigin}/auth/tapok/start`);
    const messages: Array<[unknown, string]> = [];
    postConnectPopupCompletion({
      applicationOrigin: appOrigin,
      status: "complete",
      window: {
        opener: {
          postMessage: (m: unknown, t: string) => void messages.push([m, t]),
        },
      } as unknown as Pick<Window, "opener">,
    });
    h.dispatch({
      origin: appOrigin,
      source: popup as never,
      data: messages[0]![0],
    });
    expect(await attempt.result).toEqual({
      status: "received",
      value: { status: "complete" },
    });
  });
});

test("shouldUsePopup uses media features, not the User-Agent", () => {
  const win = (coarse: boolean, width: number) =>
    ({
      innerWidth: width,
      matchMedia: (query: string) => ({
        matches: coarse && query.includes("coarse"),
      }),
    }) as unknown as Pick<Window, "matchMedia" | "innerWidth">;
  expect(shouldUsePopup(win(false, 1280))).toBe(true);
  expect(shouldUsePopup(win(true, 1280))).toBe(false);
  expect(shouldUsePopup(win(false, 390))).toBe(false);
  expect(shouldUsePopup(undefined)).toBe(false);
});

test("relative popup URLs resolve against the opener page", async () => {
  const popup = fakePopup();
  const h = host(popup);
  const original = globalThis.location;
  Object.defineProperty(globalThis, "location", {
    value: new URL(`${appOrigin}/page`),
    configurable: true,
  });
  try {
    const attempt = openAuthPopup({
      url: "/auth/start?popup=1",
      messageOrigin: appOrigin,
      accept: () => "x",
      window: h.window,
    });
    expect(h.opened[0]?.[0]).toBe(`${appOrigin}/auth/start?popup=1`);
    attempt.cancel();
  } finally {
    Object.defineProperty(globalThis, "location", {
      value: original,
      configurable: true,
    });
  }
});
