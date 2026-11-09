/**
 * Opt-in popup controller for the page that starts a Tapok sign-in.
 *
 * - The window is opened synchronously inside the user gesture (as
 *   `about:blank`), so async work such as PKCE generation or a backend
 *   sign-in request cannot make the browser treat it as an unsolicited popup.
 *   If preparing the URL fails, the empty window is closed.
 * - Messages are accepted only from that exact window and the exact expected
 *   origin, and only when `accept` recognises them.
 * - Closing the window is never a success: the controller reports `closed`,
 *   and the application must check its own session.
 * - A received message is not a success either: it only means the popup
 *   finished. The application confirms its own session and then calls
 *   `close()`. The popup page keeps a manual close button for the case
 *   where it has no opener.
 */

/** Resolved lazily so clients and helpers can be created during SSR. */
export function globalWindow(): Window {
  if (typeof window === "undefined") {
    throw new Error("A Window must be provided when running outside a browser");
  }
  return window;
}

export type AuthPopupResult<T> =
  | { status: "blocked" }
  | { status: "closed" }
  | { status: "cancelled" }
  | { status: "timeout" }
  | { status: "failed"; error: unknown }
  | { status: "received"; value: T };

export type AuthPopupAttempt<T> = {
  /** The opened window, or null when the browser blocked it. */
  readonly popup: WindowProxy | null;
  readonly result: Promise<AuthPopupResult<T>>;
  /** Brings the popup to the front if it is still open. */
  focus(): void;
  /** Stops waiting, closes the popup and resolves `cancelled`. */
  cancel(): void;
  /** Closes the popup, e.g. after the application confirmed its session. */
  close(): void;
};

export type AuthPopupHostWindow = Pick<
  Window,
  "open" | "addEventListener" | "removeEventListener"
>;

/**
 * How long a `closed` or `timeout` outcome waits for an `accept` that is still
 * running, so a slow handler cannot keep the attempt open for ever.
 */
const ACCEPT_GRACE_MS = 30_000;

export type AuthPopupOptions<T> = {
  /** Final popup URL, or an async factory evaluated after the window opened. */
  url: string | URL | (() => Promise<string | URL> | string | URL);
  /** Exact origin of the page that posts the result back to the opener. */
  messageOrigin: string;
  /**
   * Recognises a message from the popup. Return undefined to ignore it; throw
   * to fail the attempt. Origin and source are already checked. While it is
   * running, a closed window or the timeout does not end the attempt: its
   * result wins, because the work it does (exchanging a code) cannot be undone.
   */
  accept(
    event: MessageEvent<unknown>,
    popup: WindowProxy,
  ): T | undefined | Promise<T | undefined>;
  name?: string;
  features?: string;
  /** Default 10 minutes. The popup is closed when it elapses. */
  timeoutMs?: number;
  /** How often `popup.closed` is checked. Default 500 ms. */
  pollIntervalMs?: number;
  window?: AuthPopupHostWindow;
};

export const DEFAULT_POPUP_FEATURES = "popup,width=480,height=720";

export function exactOrigin(value: string, name: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError(`${name} must be an exact origin`);
  }
  if (
    url.origin !== value ||
    (url.protocol !== "https:" && url.protocol !== "http:")
  )
    throw new TypeError(`${name} must be an exact origin`);
  return value;
}

function httpUrl(value: string | URL): string {
  // Relative URLs resolve against the opener page, like window.open does.
  const url = new URL(String(value), globalThis.location?.href);
  if (url.protocol !== "https:" && url.protocol !== "http:")
    throw new TypeError("Popup URL must be an absolute HTTP URL");
  return url.href;
}

function hostWindow(options: { window?: AuthPopupHostWindow }) {
  return options.window ?? globalWindow();
}

export function openAuthPopup<T>(
  options: AuthPopupOptions<T>,
): AuthPopupAttempt<T> {
  const win = hostWindow(options);
  const messageOrigin = exactOrigin(options.messageOrigin, "messageOrigin");
  const deferred = typeof options.url === "function";
  const popup = win.open(
    deferred ? "about:blank" : httpUrl(options.url as string | URL),
    options.name ?? "tapok-auth",
    options.features ?? DEFAULT_POPUP_FEATURES,
  );
  if (popup === null) {
    return {
      popup: null,
      result: Promise.resolve({ status: "blocked" }),
      focus() {},
      cancel() {},
      close() {},
    };
  }
  let settled = false;
  let accepting = 0;
  // `closed` or `timeout` seen while a message is still being processed.
  let postponed: AuthPopupResult<T> | undefined;
  let grace: ReturnType<typeof setTimeout> | undefined;
  let resolve!: (result: AuthPopupResult<T>) => void;
  const result = new Promise<AuthPopupResult<T>>((done) => {
    resolve = done;
  });
  const closePopup = () => {
    try {
      if (!popup.closed) popup.close();
    } catch {
      // A severed or cross-origin window may refuse; the user can still close it.
    }
  };
  const onMessage = (event: MessageEvent<unknown>) => {
    if (settled || event.source !== popup || event.origin !== messageOrigin)
      return;
    accepting++;
    Promise.resolve()
      .then(() => options.accept(event, popup))
      .then(
        (value) => {
          accepting--;
          if (value !== undefined) finish({ status: "received", value });
          else if (accepting === 0 && postponed) finish(postponed);
        },
        (error: unknown) => {
          accepting--;
          finish({ status: "failed", error });
        },
      );
  };
  // The window going away or the deadline passing must not discard a message
  // that is already being processed: for Base that is the code exchange, and
  // reporting `closed` there would throw away a completed sign-in.
  const finishUnlessAccepting = (outcome: AuthPopupResult<T>) => {
    if (accepting === 0) return finish(outcome);
    if (postponed) return;
    postponed = outcome;
    grace = globalThis.setTimeout(() => finish(outcome), ACCEPT_GRACE_MS);
  };
  const poll = globalThis.setInterval(() => {
    let closed: boolean;
    try {
      closed = popup.closed;
    } catch {
      closed = true;
    }
    if (!closed) return;
    globalThis.clearInterval(poll);
    // Let a message queued just before closing win over `closed`.
    globalThis.setTimeout(() => finishUnlessAccepting({ status: "closed" }), 0);
  }, options.pollIntervalMs ?? 500);
  const timer = globalThis.setTimeout(() => {
    finishUnlessAccepting({ status: "timeout" });
    closePopup();
  }, options.timeoutMs ?? 600_000);
  function finish(outcome: AuthPopupResult<T>) {
    if (settled) return;
    settled = true;
    win.removeEventListener("message", onMessage as EventListener);
    globalThis.clearInterval(poll);
    globalThis.clearTimeout(timer);
    globalThis.clearTimeout(grace);
    resolve(outcome);
  }
  win.addEventListener("message", onMessage as EventListener);
  if (deferred) {
    Promise.resolve()
      .then(() => (options.url as () => Promise<string | URL> | string | URL)())
      .then((target) => {
        if (settled) return;
        const href = httpUrl(target);
        if (popup.closed) return finish({ status: "closed" });
        popup.location.replace(href);
      })
      .catch((error: unknown) => {
        closePopup();
        finish({ status: "failed", error });
      });
  }
  return {
    popup,
    result,
    focus() {
      try {
        if (!popup.closed) popup.focus();
      } catch {
        // Ignore: the window may be gone.
      }
    },
    cancel() {
      finish({ status: "cancelled" });
      closePopup();
    },
    close: closePopup,
  };
}

/** Status a backend-completed popup reports to its opener. Never protocol data. */
export type BackendPopupStatus = "complete" | "denied" | "failed";

const backendMessageType = "tapok:popup:result";

/**
 * For a popup whose sign-in is finished by the application backend (Connect,
 * Base OIDC through a server library). The opener must still confirm its own
 * session before treating the user as signed in.
 */
export function openBackendAuthPopup(
  options: Omit<AuthPopupOptions<{ status: BackendPopupStatus }>, "accept">,
): AuthPopupAttempt<{ status: BackendPopupStatus }> {
  return openAuthPopup({
    ...options,
    accept(event) {
      const data = event.data;
      if (data === null || typeof data !== "object" || Array.isArray(data))
        return undefined;
      const record = data as Record<string, unknown>;
      if (record["version"] !== 1) return undefined;
      // Message of the deprecated postConnectPopupCompletion().
      if (record["type"] === "tapok:connect:complete")
        return {
          status:
            record["status"] === "denied" || record["status"] === "failed"
              ? record["status"]
              : "complete",
        };
      if (record["type"] !== backendMessageType) return undefined;
      const status = record["status"];
      if (status !== "complete" && status !== "denied" && status !== "failed")
        return undefined;
      return { status };
    },
  });
}

/**
 * Runs on the application's own page inside the popup after its backend
 * finished. Returns false when there is no opener (the page should then show
 * a link back to the site and a manual close button).
 */
export function notifyAuthPopupOpener(input: {
  applicationOrigin: string;
  status: BackendPopupStatus;
  window?: Pick<Window, "opener">;
}): boolean {
  const target = exactOrigin(input.applicationOrigin, "applicationOrigin");
  const opener = (input.window ?? globalWindow()).opener as WindowProxy | null;
  if (!opener || opener.closed) return false;
  opener.postMessage(
    { type: backendMessageType, version: 1, status: input.status },
    target,
  );
  return true;
}

/**
 * Prefer a same-tab redirect on touch-first or narrow screens; popups are an
 * optional desktop enhancement. Uses media features, not User-Agent sniffing.
 */
export function shouldUsePopup(
  win: Pick<Window, "matchMedia" | "innerWidth"> | undefined = typeof window ===
  "undefined"
    ? undefined
    : window,
): boolean {
  if (!win || typeof win.matchMedia !== "function") return false;
  if (win.matchMedia("(hover: none) and (pointer: coarse)").matches)
    return false;
  return win.innerWidth >= 640;
}
