# Universal Audio Stream Proxy (Go)

Минималистичный production-ready MVP сервис для прозрачного проксирования бесконечных аудиопотоков по HTTP.

`universal audio stream proxy` принимает URL upstream-потока и отдает клиенту непрерывный stream без транскодирования и без записи на диск.

## Что делает сервис

- endpoint: `GET /stream?url=<encoded_upstream_url>`
- тянет upstream-поток (`http/https`) и сразу релеит клиенту
- не буферизует поток целиком в память
- поддерживает долгоживущие/chunked ответы
- умеет multi-user Basic Auth через `users.yaml`
- применяет SSRF protection и лимиты

## Что сервис НЕ делает

- не медиасервер
- не использует ffmpeg
- не делает transcoding/перекодирование
- не сохраняет stream на диск

## Безопасность

Сервис **не является open proxy**:

- разрешены только `http` и `https`
- блокируются `localhost`, `127.0.0.1`, `::1`
- блокируются private IP и link-local адреса
- блокируются неразрешенные схемы (`file://` и др.)
- есть лимит длины URL
- URL проверяется после DNS resolve
- при dial выполняется повторная проверка resolve (снижение риска DNS rebinding)
- есть host allowlist/denylist через ENV

## API

### `GET /health`

- без auth
- ответ: `200 OK`, body: `ok`

### `GET /metrics`

- требует Basic Auth
- JSON метрики:
  - `total_requests`
  - `active_streams`
  - `failed_streams`
  - `bytes_transferred`

### `GET /stream?url=<encoded_upstream_url>`

- требует Basic Auth
- валидирует URL
- применяет SSRF и лимиты
- проксирует upstream stream клиенту

Пример:

```bash
curl -u user1:password1 \
"http://localhost:8080/stream?url=https%3A%2F%2Fexample.com%2Flive.mp3"
```

## Basic Auth users.yaml

Формат:

```yaml
users:
  - username: user1
    password_hash: "$2a$10$ayUWAGy/41hJqxxo6TMZTec3NGwawi9eGp2shoMM3gO0qINAIsIfG"
    enabled: true
    max_streams: 2

  - username: user2
    password_hash: "$2a$10$kHnfgLLhVlciweEkyXxFQeKk/8pGeybOhQE53Dk82.XMWBDl2bF6u"
    enabled: true
    max_streams: 1
```

Важно:

- хранить только bcrypt hash
- plaintext passwords запрещены
- `enabled: false` -> доступ запрещен
- при превышении `max_streams` -> `429`

Пример генерации bcrypt hash:

```bash
# встроенная команда приложения (без внешних зависимостей)
stream-proxy hash-password --stdin
# затем введите пароль и нажмите Enter
```

Non-interactive встроенный вариант:

```bash
stream-proxy hash-password --password "MyStrongPassword"
```

Альтернатива через `htpasswd` (если установлен):

```bash
htpasswd -nbBC 10 "" "MyStrongPassword" | tr -d ':\n'
```

### Как добавить пользователя

1. Сгенерируйте bcrypt hash для нового пароля.
2. Добавьте запись в `users.yaml`:

```yaml
users:
  - username: new-user
    password_hash: "$2y$10$...."
    enabled: true
    max_streams: 2
```

3. Перечитайте конфиг без рестарта процесса:

```bash
kill -HUP <pid_stream-proxy>
```

Если сервис запущен через `systemd`:

```bash
sudo systemctl reload stream-proxy
```

## Конфигурация (ENV)

| Variable | Default | Описание |
|---|---|---|
| `PORT` | `8080` | Порт HTTP-сервера |
| `USER_AGENT` | `UniversalStreamProxy/1.0` | User-Agent для upstream |
| `CONNECT_TIMEOUT_SECONDS` | `10` | Таймаут подключения upstream |
| `RESPONSE_HEADER_TIMEOUT_SECONDS` | `15` | Таймаут ожидания заголовков upstream |
| `MAX_REDIRECTS` | `5` | Максимум redirect upstream |
| `MAX_CONCURRENT_STREAMS` | `100` | Глобальный лимит активных stream |
| `MAX_STREAMS_PER_IP` | `5` | Лимит активных stream на клиентский IP |
| `MAX_STREAMS_PER_USER` | `0` | Глобальный лимит активных stream на пользователя (`0` = только лимит из `users.yaml`) |
| `USERS_FILE` | `./users.yaml` | Путь к users config |
| `ALLOWED_HOSTS` | `` | CSV allowlist хостов (опционально) |
| `DENIED_HOSTS` | `` | CSV denylist хостов (опционально) |
| `LOG_LEVEL` | `info` | `debug/info/warn/error` |
| `MAX_URL_LENGTH` | `2048` | Максимальная длина `url` query |

`ALLOWED_HOSTS`/`DENIED_HOSTS` поддерживают:

- точное совпадение (`example.com`)
- wildcard (`*.example.com`)

## Локальный запуск

```bash
go mod tidy
go run ./cmd/stream-proxy
```

Проверка:

```bash
curl http://localhost:8080/health
curl -u user1:password1 http://localhost:8080/metrics
```

## Docker

Build:

```bash
docker build -t universal-stream-proxy:local .
```

Run:

```bash
docker run --rm -p 8080:8080 \
  -e PORT=8080 \
  -e USERS_FILE=/app/users.yaml \
  universal-stream-proxy:local
```

Если нужен свой `users.yaml`, смонтируйте его:

```bash
docker run --rm -p 8080:8080 \
  -v $(pwd)/users.yaml:/app/users.yaml:ro \
  -e USERS_FILE=/app/users.yaml \
  universal-stream-proxy:local
```

## Debian Package + systemd

`.deb` пакет кладет файлы в:

- бинарник: `/usr/bin/stream-proxy`
- users config: `/etc/stream-proxy/users.yaml`
- env overrides: `/etc/default/stream-proxy`
- unit: `/lib/systemd/system/stream-proxy.service`

После установки пакета:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now stream-proxy
```

Перечитать `users.yaml` на лету:

```bash
sudo systemctl reload stream-proxy
```

## Логирование

Structured JSON logs включают:

- request start/end
- username
- client IP
- upstream host
- stream start/end
- duration
- bytes transferred
- errors

Логи не содержат пароль и не содержат `Authorization` header.

## Graceful shutdown

Сервис корректно завершает работу по `SIGINT`/`SIGTERM`:

- завершает HTTP server через context timeout
- закрывает idle upstream connections
- корректно освобождает активные stream лимиты
