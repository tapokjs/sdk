# Примеры OIDC Base

Зависимости примеров закреплены в devDependencies SDK. Выполните `bun install`
в каталоге пакета. Примеры не входят в npm package.

## Better Auth

Зарегистрируйте confidential Base client и callback
`http://localhost:4300/api/auth/callback/tapok-base` для разрешённого локального
окружения. Для production используйте HTTPS callback своего приложения.

```sh
TAPOK_BASE_CLIENT_ID='ваш-client-id' \
TAPOK_BASE_CLIENT_SECRET='ваш-client-secret' \
BETTER_AUTH_SECRET='случайная-строка-не-менее-32-символов' \
bun examples/better-auth.ts
```

Откройте `http://localhost:4300`. Сервер запускает стандартный Generic OAuth
с discovery, PKCE и Basic authentication. На desktop кнопка открывает popup:
окно открывается сразу, URL входа запрашивается после. Страница показывает
ожидание, блокировку окна, закрытие без входа, отказ, таймаут и успешный вход
только после проверки `/api/auth/get-session`. После проверки исходная вкладка
закрывает окно; на странице в popup остаётся кнопка закрытия. На сенсорных
и узких экранах вход идёт redirect в текущей вкладке. Браузерная часть —
`better-auth-client.ts`; сервер собирает её через `Bun.build`. Подпись ID token, issuer, audience
и nonce проверяет Better Auth. SQLite по умолчанию в памяти и исчезает после
остановки. Переменная `EXAMPLE_DATABASE` задаёт путь к отдельной базе примера.

Автоматическая привязка аккаунтов по email выключена. Base email — сервисный
адрес `@tapok.orria.space` только для этого сайта. Это несуществующий почтовый
ящик: письма не доставляются. `emailVerified` равен true, потому что адрес
закреплён за аккаунтом, а не потому что ящик проверен. Не используйте его
для писем, восстановления доступа или связывания аккаунтов по email.

## Convex

Скопируйте `convex-auth.config.ts` в `convex/auth.config.ts` своего проекта.
Задайте в окружении Convex `TAPOK_BASE_CLIENT_ID`, соответствующий public
Base client. Issuer по умолчанию `https://tapok.orria.space/oidc/base`.
Для иного окружения задайте одинаковый `TAPOK_BASE_ISSUER` на клиенте и сервере.

В браузерной точке входа подключите адаптер:

```ts
import {
  connectTapokToConvex,
  completeConvexRenewalFrame,
} from "./convex-adapter";

if (!completeConvexRenewalFrame()) {
  const auth = connectTapokToConvex({
    convexUrl: "https://YOUR_DEPLOYMENT.convex.cloud",
    clientId: "YOUR_PUBLIC_BASE_CLIENT_ID",
    redirectUri: location.origin + "/auth/tapok/callback",
    onInteractionRequired() {
      document.querySelector<HTMLButtonElement>("#login")!.hidden = false;
    },
  });
  document.querySelector<HTMLButtonElement>("#login")!.onclick = () =>
    auth.signIn();
  // Используйте auth.convex для запросов приложения.
}
```

Callback должен обслуживать ту же точку входа и иметь тот же origin. На callback
адаптер завершает pending login до подключения auth fetcher к Convex.
ID token хранится только в памяти. `forceRefreshToken` вызывает новый PKCE flow
с `prompt=none`; параллельные обновления объединяются в один запрос.

Обновление использует iframe. При недоступности Tapok-session в стороннем iframe,
запрете встраивания или отсутствии согласия адаптер возвращает null и показывает
кнопку полноценного redirect-входа. SDK не подменяет ошибку старым токеном.
Convex повторно проверяет issuer, audience, срок действия и подпись токена
по опубликованному JWKS.

## Проверки

```sh
bun run typecheck
bun test
```

`typecheck` проверяет и примеры: они импортируют `@tapokjs/sdk/browser` так же,
как приложение, а внутри репозитория это имя разрешается в исходники через
`paths` в `tsconfig.json`.

Что проверено автоматически и что нет:

- Клиенты Base OIDC из SDK проверяются сквозным контрактным тестом против
  настоящего Base OIDC роутера Tapok: authorize, согласие, token, JWKS, UserInfo
  и revoke без подмены протокола. Тест живёт в закрытом репозитории платформы и
  запускается перед выпуском SDK.
- Better Auth Generic OAuth и независимый клиент на `oauth4webapi` проверяются
  там же: discovery, code flow, подпись, UserInfo, отказ при подделке подписи.
- Popup и redirect примера Better Auth проверены в Chromium на синтетическом
  стенде: разрешение и отказ, закрытие окна, возврат на сайт. Safari, iOS и
  настоящий Сбер ID автоматически не проверяются.
- Convex adapter проверяется только TypeScript с установленным Convex SDK. Для
  проверки передачи токена до облачного Convex нужно ваше развёртывание и
  зарегистрированный Base client; этот сценарий автоматически не запускался.

Основания конфигурации:
[Better Auth Generic OAuth](https://better-auth.com/docs/plugins/generic-oauth),
[Convex Custom OIDC](https://docs.convex.dev/auth/advanced/custom-auth),
[oauth4webapi OIDC example](https://github.com/panva/oauth4webapi/blob/main/examples/oidc.ts).
