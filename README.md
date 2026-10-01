# multi-tenant-oauth2

Внутренний Spring Boot starter для resource server'а, который принимает JWT от нескольких
независимых Keycloak-инстансов (или любых других OIDC IdP), плюс демонстрационное приложение,
доказывающее, что всё работает end-to-end без внешней инфраструктуры.

## Модули

- **multi-tenant-oauth2-autoconfigure** — вся логика: `@ConfigurationProperties` со списком
  tenant'ов (`issuer-uri`, `audience`, опциональный `jwks-uri`, `roles-claim-path`), кастомный
  `AudienceValidator` (проверка `aud`, которую Spring не делает по умолчанию), `ClaimPathRoleConverter`
  (маппинг ролей по произвольному пути в claims — у разных Keycloak-realm'ов структура ролей может
  отличаться), и `MultiTenantOAuth2AutoConfiguration`, которая собирает `JwtIssuerAuthenticationManagerResolver`
  — по одному `AuthenticationManager` на каждый tenant, резолвится по `iss` claim токена.
- **multi-tenant-oauth2-spring-boot-starter** — тонкий модуль, тянет автоконфигурацию.
- **demo-app** — runnable Spring Boot приложение, которое подключает стартер и доказывает его
  работоспособность:
  - встроенный **mock IdP** (`/mock-idp/{tenant}/jwks`, `/mock-idp/{tenant}/token`) — генерирует
    RSA-ключи и подписывает тестовые JWT для `tenant-a` и `tenant-b`, без обращения к реальному
    Keycloak;
  - `tenant-a` использует плоский claim `roles`, `tenant-b` — вложенный `realm_access.roles`
    (как в реальном Keycloak) — специально, чтобы показать per-tenant `roles-claim-path`;
  - защищённый эндпоинт `GET /api/hello`, возвращающий issuer/subject/roles аутентифицированного
    пользователя;
  - интеграционный тест `HelloControllerIT`, который реально минтит токены через mock IdP и
    вызывает `/api/hello` по HTTP — успешные случаи для обоих tenant'ов, негативные кейсы
    (неверный `aud`, подделка `iss` чужим ключом) и отказ без токена.
- **client-demo-app** — демонстрирует роль OAuth2 **Client** в одном модуле с двумя сценариями,
  в зависимости от того, кто инициатор исходящего запроса:
  - `GET /gateway/hello` — защищён как resource server (переиспользует наш же стартер); если
    запрос пришёл с валидным токеном пользователя, `DownstreamClient` находит его в
    `SecurityContextHolder` (`JwtAuthenticationToken`) и **релеит** этот же токен в `demo-app`, не
    запрашивая новый;
  - `POST /internal/sync` — открытый эндпоинт, инициатор — сам сервис; аутентификации в контексте
    нет, поэтому `DownstreamClient` получает собственный токен через **client_credentials**
    (`internal-service`/`internal-secret`, зарегистрирован в mock IdP на tenant-a);
  - mock IdP в demo-app получил настоящий `POST /mock-idp/{tenant}/token` с проверкой client_id/secret
    через HTTP Basic — именно против него Spring Security и получает client_credentials токен;
  - `ClientDemoIT` поднимает реальный `DemoApplication` вторым контекстом в том же JVM (порт 8080)
    и гоняет оба сценария по-настоящему, плюс проверяет 401 без токена.

## Ключевые технические решения

- Если для tenant'а задан `jwks-uri`, декодер строится через `NimbusJwtDecoder.withJwkSetUri(...)`
  вместо `JwtDecoders.fromIssuerLocation(...)` — это избегает блокирующего OIDC discovery запроса
  при старте контекста: если Keycloak временно недоступен при деплое, приложение всё равно
  поднимется.
- `aud` не проверяется Spring по умолчанию — добавлен `AudienceValidator`, подключаемый на каждый
  декодер индивидуально (у разных tenant'ов свой ожидаемый audience).
- Резолюция tenant'а идёт по `iss` claim внутри уже провалидированного JWT
  (`JwtIssuerAuthenticationManagerResolver`), а не по клиентскому заголовку — обсуждали, что если
  запросы приходят от внешних клиентов напрямую (без доверенного gateway), заголовок не даёт
  ничего, кроме лишней точки отказа.

## Версии

- Java 21 (как обсуждали), Spring Boot **4.1.1** — это тоже актуальная стабильная версия на Maven
  Central на момент сборки (4.2.0 существует только как милестоун M1); при первой сборке в этом
  окружении обнаружилось, что офлайн-кэш Gradle на машине был наполнен через корпоративный
  Artifactory, а не публичный Maven Central, из-за чего пришлось сверяться с реальными версиями
  на repo.maven.apache.org.
- Gradle 9.7.1 (враппер уже настроен, `distributionUrl` указывает на публичный дистрибутив).

## Сборка и запуск

```bash
./gradlew build                     # компиляция + все тесты (8/8 проходят)
./gradlew :demo-app:bootRun         # resource server + mock IdP на localhost:8080
./gradlew :client-demo-app:bootRun  # client-демо на localhost:8082 (нужен запущенный demo-app)
```

Проверка вручную после `bootRun` demo-app:

```bash
# без токена -> 401
curl -i http://localhost:8080/api/hello

# получить токен от tenant-a и вызвать защищённый эндпоинт
TOKEN=$(curl -s "http://localhost:8080/mock-idp/tenant-a/token?subject=alice&roles=USER,ADMIN" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
curl -s http://localhost:8080/api/hello -H "Authorization: Bearer $TOKEN"

# токен с неверным audience -> 401
BAD=$(curl -s "http://localhost:8080/mock-idp/tenant-a/token?subject=eve&roles=USER&audience=wrong-api" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
curl -i http://localhost:8080/api/hello -H "Authorization: Bearer $BAD"
```

Проверка client-demo-app (нужны оба `bootRun` одновременно):

```bash
# сценарий 1 - relay: получаем токен пользователя у demo-app и зовём gateway client-demo-app
TOKEN=$(curl -s "http://localhost:8080/mock-idp/tenant-a/token?subject=alice&roles=USER" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
curl -s http://localhost:8082/gateway/hello -H "Authorization: Bearer $TOKEN"
# -> {"issuer":"...","subject":"alice",...} - токен пользователя реально пробросился в demo-app

# gateway без токена -> 401
curl -i http://localhost:8082/gateway/hello

# сценарий 2 - self-initiated: client-demo-app сам получает client_credentials токен
curl -s -X POST http://localhost:8082/internal/sync
# -> {"issuer":"...","subject":"internal-service",...} - это уже токен самого сервиса, не alice
```

Всё это уже проверено при сборке проекта: `./gradlew clean build` проходит полностью
(BUILD SUCCESSFUL, 8/8 тестов — 5 в demo-app, 3 в client-demo-app), и все три сценария (resource
server, relay, client_credentials) реально запускались и отвечали на эти запросы во время сборки.

## Что такое `FACTOR_BEARER` в ответе `/api/hello`

В списке ролей вы увидите не только `ROLE_*`, но и `FACTOR_BEARER` — это не баг маппинга ролей.
Spring Security 7 сам добавляет authority, обозначающий "фактор аутентификации" (bearer-токен),
поверх того, что возвращает `ClaimPathRoleConverter`. Роли из claims — это отдельные `ROLE_*`
записи, `FACTOR_BEARER` можно игнорировать.

## Подключение к реальному Keycloak

Замените `application.yml` в demo-app (или в вашем сервисе, подключающем стартер) на:

```yaml
app:
  security:
    multi-tenant:
      tenants:
        - issuer-uri: https://keycloak-1.example.com/realms/realm-a
          audience: my-api
          roles-claim-path: realm_access.roles
        - issuer-uri: https://keycloak-2.example.com/realms/realm-b
          audience: my-api-service
          roles-claim-path: resource_access.my-api-service.roles
```

`jwks-uri` можно не указывать — тогда используется OIDC discovery по `issuer-uri` (проще, но
блокирующий сетевой вызов при старте). Не забудьте добавить в Keycloak protocol mapper
"Audience" с client audience вашего API — по умолчанию Keycloak не кладёт client_id в `aud`.
