# @tapokjs/sdk

Готовый TypeScript SDK для Tapok. Пакет построен на `@tapokjs/core` и публикует два ESM entry point:

- `@tapokjs/sdk/browser` — Base в браузере, public Base OIDC, popup и навигация Connect;
- `@tapokjs/sdk/server` — Connect, Base и Base OIDC на backend, проверка токенов.

Работает в Bun 1.4+, Node.js 22+ и Deno 2+; `/browser` — ещё и в браузерах с поддержкой ES2022. Пакет только ESM.

Полное руководство: [tapok.orria.space/docs/sdk](https://tapok.orria.space/docs/sdk).

## Установка

```sh
bun add @tapokjs/sdk
```

Импортируйте `/browser` или `/server`. Корневой entry point содержит только классы ошибок; те же классы экспортируют оба entry point.

## Какой клиент нужен

| Задача                                                                | Клиент                                                          | Entry                  |
| --------------------------------------------------------------------- | --------------------------------------------------------------- | ---------------------- |
| Вход без профиля, сессию создаёт ваш backend                          | `createBaseBrowserClient` + `verifyAndConsumeBaseIdentityToken` | `/browser` + `/server` |
| Тот же Base, но весь flow на backend                                  | `createBaseServerClient`                                        | `/server`              |
| Base как стандартный OIDC, токен нужен в браузере (Convex и подобные) | `createBaseOidcBrowserClient`                                   | `/browser`             |
| Base как стандартный OIDC на backend                                  | `createBaseOidcServerClient`                                    | `/server`              |
| Профиль, телефон, email с согласия пользователя                       | `createConnectServerClient`                                     | `/server`              |
| Кнопка и popup для backend-входа                                      | `createConnectBrowserNavigator`, `openBackendAuthPopup`         | `/browser`             |

Сначала выберите режим в [обзоре](https://tapok.orria.space/docs/overview).

## Base в браузере

Сначала разместите Base manifest на production origin: [Base manifest](https://tapok.orria.space/docs/base-manifest).

```ts
import { createBaseBrowserClient } from "@tapokjs/sdk/browser";

const tapok = createBaseBrowserClient({
  redirectUri: "https://app.example/auth/tapok/callback",
  scopes: ["session", "age:18"],
});

// Страница входа.
await tapok.redirect();

// Страница callback.
const result = await tapok.completeCallback();
if (result.ok) {
  await fetch("/api/session/tapok", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "content-type": "application/json",
      "x-csrf-token": csrfToken,
    },
    body: JSON.stringify({ identityToken: result.response.identity_token }),
  });
}
```

Клиент хранит transaction в `sessionStorage`, проверяет `state`, exact `iss` и nonce, затем удаляет параметры callback из адресной строки до exchange. **Подпись identity token в браузере не проверяется.** Отправьте токен своему серверу same-origin POST с CSRF-защитой; сессию создаёт только сервер.

На сервере проверьте JWT и атомарно погасите `jti`:

```ts
import { TAPOK_ISSUER } from "@tapokjs/core";
import { verifyAndConsumeBaseIdentityToken } from "@tapokjs/sdk/server";

const verified = await verifyAndConsumeBaseIdentityToken({
  token: body.identityToken,
  expectedIssuer: TAPOK_ISSUER,
  expectedAudience: "origin:https://app.example",
  replayStore: {
    async consume(jti, expiresAt) {
      // expiresAt — Unix-секунды. Вставьте jti с unique constraint и TTL до expiresAt.
      return await reserveJtiOnce(jti, expiresAt);
    },
  },
});

await createApplicationSession(verified.claims.sub);
```

Функция проверяет `typ`, `kid`, подпись ES256/RS256, issuer, audience, сроки, mode, `pairwise_sub` и типы claims. Токен живёт не дольше 10 минут. Повторный `jti` завершается ошибкой `TapokAuthError` с кодом `token_replayed`.

### Popup с явными состояниями

`startPopup()` открывает окно синхронно в обработчике клика и только потом готовит PKCE, поэтому браузер не считает окно непрошеным. Результат — одно из состояний: `blocked`, `closed`, `cancelled`, `timeout`, `failed` или `received`.

```ts
import { createBaseBrowserClient, shouldUsePopup } from "@tapokjs/sdk/browser";

const tapok = createBaseBrowserClient({ redirectUri });
button.onclick = async () => {
  if (!shouldUsePopup()) return tapok.redirect(); // mobile: redirect по умолчанию
  const attempt = tapok.startPopup();
  showWaiting(attempt.popup !== null);
  const result = await attempt.result;
  if (result.status === "received" && result.value.ok) {
    // Вход считается успешным только после проверки на вашем backend.
    const confirmed = await createSessionOnBackend(
      result.value.response.identity_token,
    );
    attempt.close();
    return confirmed ? showSignedIn() : showError();
  }
  attempt.close();
  showState(result); // blocked → кнопка «Войти в этой вкладке»
};
```

На странице callback в popup вызовите `relayBasePopupCallback({ applicationOrigin })`. Она передаёт opener только `code`, `state`, `iss` и `error`. Если opener нет, функция вернёт false: покажите ссылку на сайт и кнопку закрытия окна.

Поведение, на которое можно опираться:

- Сообщения принимаются только от открытого окна и точного origin. `targetOrigin` всегда равен exact origin приложения, не `*`.
- Закрытие окна само по себе не означает вход. Но если сообщение от окна уже обрабатывается (идёт обмен code), закрытие окна или таймаут не отменяют его: попытка дождётся результата и вернёт `received` либо `failed`. Отменить ожидание немедленно можно через `attempt.cancel()`.
- Повторяющийся или слишком длинный параметр callback страница popup не «выбирает» сама: попытка завершается `failed` с `TapokCallbackValidationError` (`malformed_callback`).
- Если ваш сайт отдаёт `Cross-Origin-Opener-Policy: same-origin`, окно потеряет связь с исходной вкладкой сразу после перехода на Tapok. Для popup нужен `same-origin-allow-popups`; redirect работает при любой политике.

Если вход завершает ваш backend (Connect, Base OIDC через серверную библиотеку), используйте `openBackendAuthPopup()` или `createConnectBrowserNavigator().startPopupAttempt()`. Страница после callback вызывает `notifyAuthPopupOpener({ applicationOrigin, status })`. Сообщение содержит только статус, исходная вкладка проверяет собственную сессию. Полный пример — `examples/better-auth.ts`.

## Connect на сервере

Connect требует backend. Не передавайте в браузер client secret, PKCE verifier, authorization code, ID token или access token. Перед началом зарегистрируйте приложение, callback URI, цели scopes и получите secret в [Developer portal](https://tapok.orria.space/developer).

```ts
import { createConnectServerClient } from "@tapokjs/sdk/server";

const tapok = createConnectServerClient({
  clientId: process.env.TAPOK_CLIENT_ID!,
  clientSecret: process.env.TAPOK_CLIENT_SECRET!,
  redirectUri: "https://app.example/auth/tapok/callback",
  scopes: ["openid", "email"],
  transactions: transactionStore,
});

// GET /auth/tapok/start
// browserBinding — случайное значение не короче 32 символов из Secure HttpOnly
// SameSite=Lax cookie. Создайте cookie до redirect.
const { authorizationUrl } = await tapok.beginAuthorization(browserBinding);
return Response.redirect(authorizationUrl, 302);

// GET /auth/tapok/callback — прочитайте то же значение cookie.
const completed = await tapok.completeCallback(request.url, browserBinding);
if (!completed.ok) {
  return Response.redirect(
    "https://app.example/login?error=access_denied",
    303,
  );
}

await createApplicationSession(completed.userInfo.sub);
// Для связи используйте только контактный email с email_verified: true.
return Response.redirect("https://app.example/account", 303);
```

`browserBinding` обязателен в обоих вызовах. Он привязывает callback к браузеру, начавшему вход: без него атакующий мог бы подставить жертве свой callback и войти в её сессии под своим аккаунтом. Не используйте вместо него `state`, IP, User-Agent или значение из query. SDK хранит в транзакции только SHA-256 от binding и сверяет его до обмена code.

`transactions` должен реализовать контракт:

```ts
import type { ConnectTransactionStore } from "@tapokjs/sdk/server";

const transactionStore: ConnectTransactionStore = {
  async save(transaction) {
    // Server-side encrypted storage. transaction.expiresAt — Unix-МИЛЛИСЕКУНДЫ
    // (шкала Date.now()), TTL записи не больше этого момента.
  },
  async consume(state) {
    // Одной атомарной операцией верните и удалите непросроченную transaction.
    return null;
  },
};
```

В production store общий для всех backend replicas. SDK формирует `client_secret_basic`, обменивает code, проверяет ID token через Tapok JWKS, сверяет nonce, загружает UserInfo и сравнивает его `sub` с `sub` ID token. Если проверка проваливается уже после выдачи токенов, SDK отзывает их (best effort) и бросает исходную ошибку. После callback перенаправьте пользователя на allowlisted локальный URL без OAuth query.

`createConnectBrowserNavigator()` открывает ваш `/auth/tapok/start` из браузера (адрес может быть относительным). Он не реализует Connect protocol и не получает секреты или tokens.

### Refresh, revoke и logout

```ts
const tokens = await tapok.refresh(refreshToken, { sub, nonce, scopes });
await tapok.revoke(accessToken);
await tapok.revoke(refreshToken, "refresh_token");
const logoutUrl = tapok.logout({ idTokenHint, postLogoutRedirectUri, state });
```

`refresh()` проверяет, что ответ не расширяет scopes и что новый ID token относится к прежнему пользователю; иначе отзывает выданные токены и бросает ошибку. Передавайте nonce первоначального входа, если новый ID token его содержит. Сохраняйте ротированный refresh token атомарно, исключая параллельное обновление одного семейства. Не возвращайте результат браузеру.

## Base на backend

`createBaseServerClient()` выполняет нативный Base flow целиком на backend. Секрет клиента не нужен.

```ts
import { createBaseServerClient } from "@tapokjs/sdk/server";

const base = createBaseServerClient({
  redirectUri: "https://app.example/auth/base/callback",
  scopes: ["session"],
  transactions: baseTransactionStore,
  replayStore,
});

// Оба обработчика читают browserBinding из одной защищённой cookie/session.
const start = await base.beginAuthorization(browserBinding);
const completed = await base.completeCallback(request.url, browserBinding);
if (completed.ok) await createApplicationSession(completed.claims.sub);
```

## Base OIDC и внешние клиенты

Issuer Base OIDC: `https://tapok.orria.space/oidc/base`.
Discovery: `https://tapok.orria.space/oidc/base/.well-known/openid-configuration`.
Разрешены `openid`, `profile`, `email`, `age:18`. Profile и email синтетические, отдельные для площадки; контактная почта и профиль Сбера недоступны. Email — сервисный адрес `@tapok.orria.space` с `email_verified: true`: подтверждена привязка к аккаунту, а не почтовый ящик. Не используйте его для писем, восстановления доступа и связывания аккаунтов.

`createBaseOidcServerClient()` принимает client ID, redirect URI, scopes, transaction store и необязательный client secret. Confidential client использует Basic authentication, public client отправляет client ID и PKCE. Пустая строка в `clientSecret` — ошибка конфигурации; для public client не передавайте поле вовсе. Методы: `beginAuthorization(binding, { prompt, maxAge })`, `completeCallback(url, binding)`, `logout(...)`.

`createBaseOidcBrowserClient()` — только для public Base OIDC. Он проверяет подпись ID token по JWKS и возвращает `idToken` (JWT-строка), `claims` и `expiresIn`. Токен храните в памяти. После истечения начните новый authorize с `prompt: "none"`; `login_required` и `interaction_required` требуют видимого входа. Браузерный клиент не выдаёт refresh token. Для Convex передайте `idToken` его auth adapter, настроив тот же issuer и client ID как audience на backend (пример — `examples/convex-adapter.ts`).

Better Auth и другие серверные OIDC-клиенты подключаются напрямую через Base discovery, зарегистрированный callback, PKCE S256 и разрешённые scopes.

## Контракт результатов

Имена полей стабильны в 1.x. У клиентов они сложились по-разному; ниже — точный смысл каждого.

| Клиент                        | Успех (`ok: true`)                                                                                                | Отказ протокола (`ok: false`) |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------- | ----------------------------- |
| `createBaseBrowserClient`     | `response` — ответ exchange как в протоколе: `identity_token`, `expires_in`, `scope`                              | `error`, `errorDescription`   |
| `createBaseServerClient`      | `claims` — проверенные claims identity token                                                                      | `callback`                    |
| `createBaseOidcBrowserClient` | `idToken` — **JWT-строка**, `claims` — объект, `expiresIn`                                                        | `callback`                    |
| `createBaseOidcServerClient`  | `idToken` — **объект claims**, `rawIdToken` — JWT-строка, `accessToken`, `expiresIn`, `grantedScopes`, `userInfo` | `callback`                    |
| `createConnectServerClient`   | то же, плюс `refreshToken`, если выдан                                                                            | `callback`                    |

- `idToken` в браузерном Base OIDC клиенте — строка, в серверных клиентах — объект claims. Строку на сервере берите из `rawIdToken`.
- `callback` — разобранный ответ авторизации: `{ ok: false, error, errorDescription?, state, issuer }`.
- `refresh()` возвращает ответ token endpoint как в протоколе, в snake_case: `access_token`, `token_type`, `expires_in`, `scope`, необязательные `id_token` и `refresh_token`.
- `expiresIn` и `expires_in` — секунды. `expiresAt` транзакции — миллисекунды; `expiresAt` в `ReplayStore.consume` — секунды.
- `ok: false` означает, что пользователь или Tapok отказали (например, `access_denied`). Любая другая неудача — исключение.

## Ошибки

Все ошибки неудавшегося входа наследуют `TapokError` и имеют стабильное поле `code`. Ветвитесь по `code`, текст `message` предназначен только для диагностики.

```ts
import {
  TapokAuthError,
  TapokCallbackValidationError,
  TapokHttpError,
} from "@tapokjs/sdk/server"; // те же классы есть в /browser

try {
  await tapok.completeCallback(request.url, browserBinding);
} catch (error) {
  if (error instanceof TapokAuthError && error.code === "request_timeout") {
    return retryLater();
  }
  return restartSignIn();
}
```

| Класс                          | `code`                                                                                       | Что произошло                                                                              |
| ------------------------------ | -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `TapokCallbackValidationError` | `missing_state`, `state_mismatch`, `missing_issuer`, `issuer_mismatch`, `malformed_callback` | Ответ авторизации не прошёл проверку; `code` из него использовать нельзя                   |
| `TapokHttpError`               | код протокола (`invalid_grant`, …) или `http_error`                                          | Tapok ответил не-2xx; есть `status` и `protocolError`                                      |
| `TapokAuthError`               | `invalid_transaction`                                                                        | Транзакция отсутствует, просрочена, уже использована или от другой конфигурации            |
|                                | `binding_mismatch`                                                                           | Callback пришёл не в том браузере, который начал вход                                      |
|                                | `invalid_token`                                                                              | JWT не прошёл проверку подписи, issuer, audience, срока, nonce, `max_age` или типов claims |
|                                | `token_replayed`                                                                             | `jti` Base identity token уже использован                                                  |
|                                | `invalid_response`                                                                           | Ответ Tapok нарушает контракт, расширяет scopes или называет другого пользователя          |
|                                | `jwks_unavailable`                                                                           | Не удалось загрузить ключи подписи; повтор может помочь                                    |
|                                | `request_timeout`                                                                            | Запрос к Tapok не уложился в `timeoutMs`                                                   |

Ошибки SDK безопасно логировать целиком. Текст каждой ошибки фиксирован; исходные ошибки JWT-библиотеки, JSON-парсера и транспорта к ним не прикладываются (`cause` всегда отсутствует), потому что те могут содержать claims токена, фрагмент ответа или адреса. У `TapokAuthError` может быть поле `reason` — код вердикта проверки из фиксированного списка (`ERR_JWT_EXPIRED`, `ERR_JWS_SIGNATURE_VERIFICATION_FAILED`, `ERR_JWT_CLAIM_VALIDATION_FAILED` и подобные). Это подсказка для диагностики, а не второй код для ветвления.

Исключение — `TapokHttpError.protocolError.error_description`: это текст, который прислал Tapok по протоколу, он передаётся как есть. Неверные аргументы и конфигурация по-прежнему бросают `TypeError`; сетевой сбой вашего транспорта при запросе token, UserInfo или revoke — ошибку самого `fetch` без изменений.

## Надёжность и окружения

- **Таймаут.** Каждый запрос к Tapok (token, exchange, UserInfo, revoke) ограничен `timeoutMs`, по умолчанию 10 секунд, включая чтение тела. Загрузку JWKS ограничивает jose (5 секунд).
- **Свой issuer.** Все клиенты принимают `issuer` — для staging или собственного развёртывания. Он задаётся доверенной конфигурацией приложения; не берите его из запроса пользователя. Серверные клиенты Connect и Base OIDC дополнительно принимают `discovery` и `allowedEndpointOrigins` (точные origins); SDK сверяет issuer и origins до сетевого обращения. HTTP redirects при запросах запрещены.
- **Redirect URI с query.** Зарегистрированный `redirectUri` может содержать собственные параметры (`…/callback?tenant=acme`). Они должны вернуться в callback без изменений и в том же порядке; параметры `code`, `state`, `iss`, `error`, `error_description` в redirect URI запрещены.
- **Reverse proxy.** Серверные клиенты не сравнивают origin и путь `request.url` с redirect URI: за прокси сервер часто видит внутренний адрес. Точное совпадение redirect URI проверяет Tapok при authorize и обмене code.
- **SSR.** Создание любого браузерного клиента не обращается к `window` и `sessionStorage`; их можно создавать на уровне модуля. Глобальные объекты берутся при первом вызове метода. Вне браузера передайте `storage` и `window` явно.
- **Часы.** Допуск расхождения часов: 300 секунд у `verifyAndConsumeBaseIdentityToken`, `verifyConnectIdToken` (настраивается через `maxClockSkewSeconds`) и у callback Connect; 60 секунд у остальных клиентов и у `refresh()`.

## Устаревшие API

Работают в 1.x, но не развиваются; редакторы показывают их зачёркнутыми.

| Устарело                                               | Замена                     | Причина                                                                                           |
| ------------------------------------------------------ | -------------------------- | ------------------------------------------------------------------------------------------------- |
| `createBaseBrowserClient().openPopup()`                | `startPopup()`             | Готовит PKCE до открытия окна, браузер может окно заблокировать                                   |
| `createConnectBrowserNavigator().startPopup(features)` | `startPopupAttempt()`      | Возвращает сырое окно без состояний; имя совпадает с другим по смыслу `startPopup()` Base-клиента |
| `postBasePopupCallback()`                              | `relayBasePopupCallback()` | Требует `state` транзакции внутри popup                                                           |
| `postConnectPopupCompletion()`                         | `notifyAuthPopupOpener()`  | Бросает исключение без opener; не покрывает Base OIDC                                             |

## Смена режима и управление доступом

Аккаунты связывайте по `(iss, sub)`. Email можно сменить, технический адрес может быть недоставляемым, а `email_verified` может быть false. Совпадение email не является основанием объединить аккаунты.

Перед переходом Base → Connect подтвердите контроль площадки и получите одобрение Connect-приложения. Сохраняйте старую привязку аккаунта сайта до завершения подтверждённой миграции пользователя. Backend должен принять одноразовое сопоставление Base subject и Connect subject от Platform, проверить соответствие своей площадке и связать обе identity с прежним локальным аккаунтом в одной транзакции. Не принимайте эти subjects как доказательство из тела запроса браузера.

Новый issuer меняет OIDC identity даже при совпадающем sub. После миграции сохраните прежние issuer/subject как подтверждённую связь. Дополнительные Connect scopes требуют согласия пользователя.

Отзыв токена прекращает доступ этим токеном; отзыв consent прекращает разрешённый доступ приложения. При logout удалите текущую сессию приложения и завершите сессию Tapok через end-session endpoint. Возврат разрешён только на зарегистрированный post-logout URI; приложение проверяет сохранённый logout state. Back-channel logout пока не является частью SDK.

«Забыть связь» в кабинете Tapok — отдельное действие. После него прежняя привязка Base может стать недоступной. Не вызывайте его как часть обычного logout или отзыва токена.

## Полезные ссылки

- [Выбор режима](https://tapok.orria.space/docs/overview)
- [Public API](https://tapok.orria.space/docs/api)
- [Scopes и consent](https://tapok.orria.space/docs/scopes)
- [Metadata и JWKS](https://tapok.orria.space/docs/metadata)
- [Требования безопасности](https://tapok.orria.space/docs/security)

## Разработка

```sh
bun install
bun run typecheck
bun test
bun run build
```

Исходники проверяются без глобальных типов Bun и Node.js; тесты и примеры используют отдельный `tsconfig.test.json`. Изменения и инструкция перехода с 0.1 описаны в [CHANGELOG](./CHANGELOG.md), выпуск — в [RELEASING](./RELEASING.md).
