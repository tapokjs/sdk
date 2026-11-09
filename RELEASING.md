# Разработка и выпуск SDK

Исходники: [tapokjs/sdk](https://github.com/tapokjs/sdk). Пакет публикуется как `@tapokjs/sdk` и использует `@tapokjs/core` по обычному npm-диапазону `^1.0.0`. Версии пакетов независимы.

## Проверки

Нужны Node.js 22+, Deno 2+ и версия Bun из `.bun-version`:

```sh
npm install --global "bun@$(cat .bun-version)"
bun install --frozen-lockfile
bun run check
bun lint --no-script --max-warnings 0
bun fmt --no-script --check
bun audit
```

`check` проверяет типы исходников, тестов и примеров, запускает тесты и собирает ESM с декларациями. CI `package` дополнительно устанавливает npm-архив вне checkout и проверяет JWT, PKCE, кеш JWKS и отказ поддельной подписи на Node 22/26, Bun и Deno. `prepack` пересобирает `dist`; в npm не попадают тесты и зависимости разработки.

## Выпуск

Сначала убедитесь, что минимальная версия Core опубликована: `npm view @tapokjs/core version`. При использовании нового API Core поднимите нижнюю границу диапазона SDK до первой версии с этим API. Совместимые исправления повышают patch, новый API — minor; несовместимые изменения после 1.0 требуют major и инструкции миграции.

Обновите `package.json`, `CHANGELOG.md`, lockfile и проверьте архив. Использованный npm-номер нельзя публиковать повторно. Для самостоятельной публикации workflow `publish.yml` использует GitHub environment `npm` и provenance. Настройте trusted publisher в npm: owner `tapokjs`, repository `sdk`, workflow `publish.yml`, environment `npm`. Если trusted publisher ещё не настроен, требуется разрешённый npm publish token в environment secret `NPM_PUBLISH_TOKEN`; секреты никогда не добавляются в Git.

После публикации проверьте npm dist-tag и создайте тег `v<version>` с GitHub Release на том же коммите. Опишите обязательные изменения интеграции в CHANGELOG; список различий контрактов клиентов зафиксирован в README.

Проверка архива не заменяет браузерные тесты popup, callback и storage. Отдельно проверяйте реальные браузеры и провайдера перед включением новых сценариев входа. Connect code, verifier, client secret и tokens всегда остаются на backend.
