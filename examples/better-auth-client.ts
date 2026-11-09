/**
 * Browser part of the Better Auth example. Bundle it for the browser (the
 * example server does this with Bun.build) and load it as a module script.
 * Inside this repository tsconfig `paths` resolve "@tapokjs/sdk/browser" to
 * the source; in an application it is the installed package.
 *
 * - Desktop: optional popup. The window opens synchronously in the click
 *   handler; the sign-in URL is requested from Better Auth afterwards.
 * - Touch-first or narrow screens: redirect in the current tab by default.
 * - Success is shown only after /api/auth/get-session confirms the session.
 *   A closed window or a popup message alone is never treated as success.
 */
import {
  notifyAuthPopupOpener,
  openBackendAuthPopup,
  shouldUsePopup,
  type AuthPopupAttempt,
  type BackendPopupStatus,
} from "@tapokjs/sdk/browser";

type State =
  | "idle"
  | "waiting"
  | "blocked"
  | "closed"
  | "denied"
  | "timeout"
  | "error"
  | "success";

const copy: Record<State, [string, string]> = {
  idle: ["Вы не вошли", "Войдите через Tapok, чтобы продолжить."],
  waiting: [
    "Подтвердите вход в открывшемся окне",
    "Здесь появится результат, когда сайт проверит вход.",
  ],
  blocked: [
    "Браузер не открыл окно",
    "Можно продолжить в этой вкладке. Ничего настраивать в браузере не нужно.",
  ],
  closed: [
    "Окно закрыто, подтверждение не получено",
    "Сайт проверил свою сессию: вход не завершён. Начните вход заново.",
  ],
  denied: [
    "Вы отменили вход",
    "Можно остаться на сайте без входа или попробовать снова.",
  ],
  timeout: [
    "Время ожидания истекло",
    "Окно входа закрыто. Начните вход заново.",
  ],
  error: [
    "Не удалось завершить вход",
    "Сайт не подтвердил сессию. Попробуйте ещё раз или войдите в этой вкладке.",
  ],
  success: [
    "Вы вошли в приложение",
    "Сессия подтверждена сайтом. Окно Tapok закрыто.",
  ],
};

async function hasSession(): Promise<boolean> {
  const response = await fetch("/api/auth/get-session", {
    credentials: "same-origin",
    cache: "no-store",
  });
  if (!response.ok) return false;
  const session = (await response.json()) as { user?: { id?: unknown } } | null;
  return typeof session?.user?.id === "string";
}

async function signInUrl(mode: "popup" | "redirect"): Promise<string> {
  const target = mode === "popup" ? "/auth/popup-complete" : "/";
  const response = await fetch("/api/auth/sign-in/social", {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      provider: "tapok-base",
      disableRedirect: true,
      callbackURL: target,
      errorCallbackURL: mode === "popup" ? target : "/?login=failed",
    }),
  });
  const body = (await response.json().catch(() => null)) as {
    url?: unknown;
  } | null;
  if (!response.ok || typeof body?.url !== "string")
    throw new Error("Sign-in could not be started");
  return body.url;
}

function mainPage(root: HTMLElement) {
  const title = root.querySelector<HTMLElement>("[data-title]")!;
  const text = root.querySelector<HTMLElement>("[data-text]")!;
  const login = root.querySelector<HTMLButtonElement>("[data-login]")!;
  const sameTab = root.querySelector<HTMLButtonElement>("[data-same-tab]")!;
  const focus = root.querySelector<HTMLButtonElement>("[data-focus]")!;
  let attempt: AuthPopupAttempt<{ status: BackendPopupStatus }> | undefined;

  const show = (state: State) => {
    root.dataset.state = state;
    [title.textContent, text.textContent] = copy[state];
    login.hidden = state === "success" || state === "waiting";
    login.textContent =
      state === "idle" ? "Войти через Tapok" : "Начать вход заново";
    focus.hidden = state !== "waiting";
    // Same-tab sign-in stays available as the popup fallback; on touch or
    // narrow screens the primary button already signs in in this tab.
    sameTab.hidden = state === "success" || !shouldUsePopup();
  };

  const redirect = async () => {
    attempt?.cancel();
    try {
      location.assign(await signInUrl("redirect"));
    } catch {
      show("error");
    }
  };

  const popup = async () => {
    attempt?.cancel();
    attempt = openBackendAuthPopup({
      url: () => signInUrl("popup"),
      messageOrigin: location.origin,
    });
    const current = attempt;
    if (current.popup) show("waiting");
    const result = await current.result;
    if (attempt !== current) return;
    switch (result.status) {
      case "blocked":
        return show("blocked");
      case "cancelled":
        return;
      case "timeout":
        return show("timeout");
      case "failed":
        current.close();
        return show("error");
      case "closed":
        // The window may have finished just before closing; ask the site.
        return show((await hasSession()) ? "success" : "closed");
      case "received": {
        const confirmed = await hasSession();
        // Close only after the opener has its answer.
        current.close();
        if (confirmed) return show("success");
        return show(result.value.status === "denied" ? "denied" : "error");
      }
    }
  };

  login.addEventListener("click", () => {
    // Decide synchronously inside the click so the popup is not blocked.
    if (shouldUsePopup()) void popup();
    else void redirect();
  });
  sameTab.addEventListener("click", () => void redirect());
  focus.addEventListener("click", () => attempt?.focus());

  const params = new URLSearchParams(location.search);
  const error = params.get("error");
  const failed = params.has("login") || error !== null;
  if (failed) history.replaceState(null, "", location.pathname);
  void hasSession().then((signedIn) =>
    show(
      signedIn
        ? "success"
        : error === "access_denied"
          ? "denied"
          : failed
            ? "error"
            : "idle",
    ),
  );
}

/** Runs inside the popup after Better Auth handled the Tapok callback. */
function popupCompletePage(root: HTMLElement) {
  const params = new URLSearchParams(location.search);
  const error = params.get("error");
  history.replaceState(null, "", location.pathname);
  const status: BackendPopupStatus =
    error === null
      ? "complete"
      : error === "access_denied"
        ? "denied"
        : "failed";
  const delivered = notifyAuthPopupOpener({
    applicationOrigin: location.origin,
    status,
  });
  root.querySelector<HTMLElement>("[data-text]")!.textContent = delivered
    ? "Вход проверяется в исходной вкладке. Это окно закроется автоматически."
    : "Исходная вкладка недоступна. Вернитесь на сайт, чтобы продолжить.";
  root.querySelector<HTMLElement>("[data-back]")!.hidden = delivered;
  root
    .querySelector<HTMLButtonElement>("[data-close]")!
    .addEventListener("click", () => window.close());
}

const root = document.querySelector<HTMLElement>("[data-tapok-example]");
if (root?.dataset.tapokExample === "main") mainPage(root);
if (root?.dataset.tapokExample === "popup-complete") popupCompletePage(root);
