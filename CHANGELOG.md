# История изменений

## 1.0.0 — 2026-11-10

Первый стабильный контракт v1. Требуется `@tapokjs/core` `^1.0.0`; Core 0.1.0 не подходит. Инструкция перехода с 0.1.0 приведена ниже.

### Исправления

- **Base OIDC работает с токенами платформы.** `createBaseOidcBrowserClient()` и `createBaseOidcServerClient()` отклоняли любой ID token Base OIDC: требовали claim `mode`, которого платформа в этих токенах не выдаёт. Теперь отсутствие `mode` допустимо, а токен с другим режимом по-прежнему отклоняется. Со scope `email` вход больше не падает на `email_verified: true` сервисного адреса. Запрет персональных claims сохранён.
- **Popup не теряет завершённый вход.** Если окно закрывали (или истекал таймаут), пока исходная вкладка обменивала code, попытка завершалась `closed`, хотя code уже был погашен. Теперь попытка дожидается идущей обработки и возвращает `received` или `failed`; `cancel()` по-прежнему срабатывает сразу.
- **Отзыв токенов при провале проверки.** Connect `completeCallback()` и `refresh()`, а также Base OIDC `completeCallback()` на сервере отзывают уже выданные access и refresh token, если после выдачи не прошла проверка ID token, scopes, `max_age` или UserInfo. Раньше это делалось только при несовпадении `sub`. Сбой отзыва не скрывает исходную ошибку.
- **Проверка типов claims.** Проверенный токен больше не возвращается с claims неверного типа: `is_adult`, `email`, `email_verified`, `name`, `auth_time`, `nonce` и другие проверяются; токен с несколькими audience отклоняется, одноэлементный массив `aud` приводится к строке.
- **Повторяющиеся параметры в popup callback.** `relayBasePopupCallback()` раньше брал первое из повторяющихся значений `code`, `state` или `iss`. Теперь такой callback помечается некорректным и попытка завершается `malformed_callback` без обмена code.
- **Redirect URI с собственным query.** URI вида `…/callback?tenant=acme` принимался при старте, но callback на него всегда отклонялся. Теперь зарегистрированные параметры должны вернуться без изменений, а параметры протокола в redirect URI запрещены сразу.
- **Пустой `clientSecret` в Base OIDC** — ошибка конфигурации, а не молчаливый переход в public client. Пустой или содержащий пробелы `clientId` отклоняется.

### Новое

- **Классы ошибок из обоих entry point.** `/browser`, `/server` и корень экспортируют `TapokError`, `TapokAuthError`, `TapokHttpError`, `TapokCallbackValidationError`. У всех есть стабильное поле `code`; у `TapokAuthError` это `invalid_transaction`, `binding_mismatch`, `invalid_token`, `token_replayed`, `invalid_response`, `jwks_unavailable` или `request_timeout`.
- **Ошибки безопасно логировать целиком.** Текст фиксирован, исходные ошибки jose, JSON-парсера и транспорта не прикладываются: `JWTExpired` и `JWTClaimValidationFailed` из jose содержат весь payload токена, а ошибка разбора JSON может цитировать тело ответа. Для диагностики у `TapokAuthError` есть необязательное поле `reason` с кодом вердикта из фиксированного списка.
- **`timeoutMs`** у всех клиентов, выполняющих запросы: предел на каждый запрос к Tapok, по умолчанию 10 секунд.
- **`issuer` у `createBaseBrowserClient()`** для staging и собственного развёртывания; транзакция, начатая для другого issuer, не переиспользуется.
- **Создание клиентов без браузерных глобальных объектов.** `createBaseBrowserClient()`, `createBaseOidcBrowserClient()` и `createConnectBrowserNavigator()` можно создавать на уровне модуля при SSR; `window` и `sessionStorage` берутся при первом вызове метода. `startUrl` навигатора может быть относительным.
- Entry points реэкспортируют типы Core, встречающиеся в их сигнатурах (`ConnectScope`, `ConnectUserInfo`, `BaseScope`, `BaseOidcScope` и другие), и тип `VerifiedTokenClaims`. Добавлен тип `BaseOidcBrowserClientOptions`.
- Opt-in popup-контроллер с явными состояниями: `openAuthPopup()`, `openBackendAuthPopup()`, `createBaseBrowserClient().startPopup()` и `createConnectBrowserNavigator().startPopupAttempt()`; для страниц callback — `relayBasePopupCallback()` и `notifyAuthPopupOpener()`; `shouldUsePopup()` выбирает redirect на сенсорных и узких экранах. URL popup может быть относительным.
- Клиенты `createBaseServerClient()`, `createBaseOidcServerClient()`, `createBaseOidcBrowserClient()`, методы Connect `refresh()` и `logout()`.

### Несовместимые изменения

- **Connect: `browserBinding` обязателен.** `beginAuthorization(browserBinding, options?)` и `completeCallback(url, browserBinding)` требуют одно и то же значение не короче 32 символов. Транзакция, сохранённая без binding, отклоняется.
- **Классы ошибок.** Провалы проверки транзакции, токена и ответа были `Error`/`TypeError`, теперь это `TapokAuthError`. Ошибки jose (`JWTExpired` и другие) больше не выходят наружу ни напрямую, ни через `cause`; их код, если он в разрешённом списке, доступен как `reason`. Тексты проверок, которые делает сам SDK, сохранены, тексты вердиктов jose заменены фиксированными; ветвиться следует по `code`.
- **`expiresAt` транзакции — миллисекунды, `ReplayStore.consume(jti, expiresAt)` — Unix-секунды** с учётом допуска часов. Единицы не менялись относительно репозитория, но теперь зафиксированы в типах; в опубликованной 0.1.0 `ReplayStore` получал срок без допуска.
- `verifyAndConsumeBaseIdentityToken()` требует в токене `nonce` и `pairwise_sub` строками (платформа выдаёт их всегда).
- `createConnectBrowserNavigator()` сообщает о недопустимой схеме `startUrl` текстом `startUrl must be an HTTP(S) URL`; относительный адрес больше не ошибка.
- `createBaseBrowserClient()` вне браузера без `storage` бросает ошибку при первом вызове метода, а не при создании.

### Устарело

Работают в 1.x; замены и причины — в README, раздел «Устаревшие API»: `openPopup()`, `createConnectBrowserNavigator().startPopup(features)`, `postBasePopupCallback()`, `postConnectPopupCompletion()`.

### Переход с 0.1.0

1. Обновите оба пакета вместе; SDK требует `@tapokjs/core` ^1.0.0.
2. **Connect.** Перед redirect создайте случайное значение (например, `crypto.randomUUID() + crypto.randomUUID()`), положите его в Secure HttpOnly SameSite=Lax cookie и передайте в `beginAuthorization(binding)`. В callback прочитайте cookie и передайте в `completeCallback(request.url, binding)`. Входы, начатые до обновления, завершатся `binding_mismatch` — пользователь начнёт вход заново.
3. **Обработка ошибок.** Замените проверки `instanceof TypeError`, классов и кодов jose и сравнение текста сообщений на `instanceof TapokAuthError` и `error.code`; прежний код jose — в `error.reason`. Импортируйте классы из `@tapokjs/sdk/server` или `@tapokjs/sdk/browser`.
4. **`ReplayStore`.** Убедитесь, что TTL записи считается из `expiresAt` в секундах, а TTL транзакции — из `expiresAt` в миллисекундах.
5. **Popup.** Замените `openPopup()` на `startPopup()`, на странице callback — `postBasePopupCallback()` на `relayBasePopupCallback()`. Старые вызовы продолжают работать.
6. Если сервер стоит за медленным прокси, задайте `timeoutMs` больше 10 секунд.

Формы результатов клиентов не менялись и зафиксированы на 1.x; их точный смысл — в README, раздел «Контракт результатов».

### Ранее в этом разделе

- Пример Better Auth показывает ожидание, блокировку окна, закрытие, отказ, таймаут и подтверждённый сессией вход; на mobile используется redirect.
- Новые сценарии проверены в настоящем Chromium: разрешение и отказ в доступе, закрытие окна, проверка серверной сессии и мобильный redirect. Состояние блокировки popup проверено имитацией; настоящий Сбер ID и Safari/iOS не проверены.

## 0.1.1, не публиковалась

- Защита Base identity token от replay сохраняет `jti` до `exp + clockTolerance`. `ReplayStore.consume` получает срок в Unix seconds.
- JWT-проверки браузера и сервера используют общий модуль. Standalone verifier переиспользует JWKS для настроенного issuer и fetch, кеш ограничен 32 адресами на transport.
- Исправлен обмен сообщениями Base popup и применение discovery endpoints для authorization и logout.
- Browser Base OIDC включает issuer в ключ транзакции. После обновления SDK незавершённый вход нужно начать заново.
- Зависимость от `@tapokjs/core` использует диапазон `^0.1.1`, доступный обычным npm-клиентам и отдельному репозиторию SDK.
- Исходники проверяются с ES2023 и стандартными Web API. Типы Bun подключаются отдельно для тестов и примеров.
- `prepack` пересобирает ESM и декларации перед созданием архива.
- Проверка релиза устанавливает архив во внешний проект, выполняет Connect flow с проверкой JWT в Bun, Node.js и Deno, проверяет декларации в NodeNext и Bundler и собирает browser entry без серверных экспортов.

Версия 0.1.1 в npm не публиковалась; её изменения входят в следующий выпуск.
