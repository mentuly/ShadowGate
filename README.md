# Async Reverse Proxy with Security Controls

> Ukrainian / English
>
> [Українська](#-українська) · [English](#-english)

## 🇺🇦 Українська

### Огляд
Цей проєкт — демонстраційний сервіс для маршрутизації HTTP-запитів через reverse proxy з базовими механізмами безпеки. Він підходить для навчання, тестування або як простий приклад архітектури з проксі, WAF, обмеженням частоти запитів і адміністративною панеллю.

### Основні можливості
- приймає вхідні HTTP-запити від клієнтів;
- пересилає їх на обраний бекенд-сервіс;
- застосовує правила WAF для блокування підозрілих запитів;
- обмежує кількість запитів від одного джерела;
- відстежує репутацію IP-адрес;
- веде журнали подій і дозволяє керувати правилами через admin UI.

### Як це працює
1. Клієнт надсилає запит на проксі.
2. Проксі перевіряє запит на підозрілі шаблони.
3. Якщо запит допустимий, він пересилається на бекенд.
4. Під час обробки фіксуються події, а правила можна змінювати без перезапуску сервісу.

### Захист сервісу
Проєкт має кілька рівнів захисту:
- WAF — перевіряє вхідні дані та блокує небажані шаблони;
- rate limiting — зменшує навантаження від надмірної активності з одного джерела;
- IP reputation — дозволяє відстежувати повторювану підозрілу поведінку;
- логування — зберігає інформацію про події для аналізу;
- адміністративна панель — дає змогу керувати правилами в процесі роботи.

### Технології
- Python
- FastAPI
- Redis
- Docker / Docker Compose

### Швидкий старт
```bash
docker compose build
docker compose up
```

Відкрийте:
- Proxy: http://localhost:8000
- Admin UI: http://localhost:8080

### Конфігурація
Налаштування зберігаються у файлі config.yaml. Там можна змінити цільовий бекенд, правила WAF і параметри обмеження запитів.

### Безпека
- Адмін-панель вимагає токен доступу. Встановіть змінну середовища ADMIN_AUTH_TOKEN перед запуском сервісу, наприклад: ADMIN_AUTH_TOKEN='ваш-сильний-секрет'.
- Для Docker Compose зручно використовувати файл .env або запускати команду з `--env-file`.
- Для доступу до admin UI використовуйте заголовок X-Admin-Token або Authorization: Bearer <token>.
- Проксі блокує спроби відправити запит на довільний зовнішній хост, а WAF перевіряє шлях, query, body і заголовки.

### Security checklist
- [x] Proxy blocks absolute URL targets to avoid SSRF/open-proxy behavior.
- [x] WAF output escapes attacker-controlled content to prevent reflected XSS.
- [x] Admin routes require authentication via token.
- [x] Admin service is exposed only on localhost in Docker Compose.
- [x] Environment-based secrets are documented via .env and .env.example.
- [x] Generated artifacts such as logs, pickle models, and caches are ignored by Git.

### Безпечний запуск у Docker
```bash
cp .env.example .env
# заповніть ADMIN_AUTH_TOKEN у .env
docker compose --env-file .env up --build
```

### Примітки
- Серсіс розроблено як безпечний навчальний приклад для роботи з проксі та правилами доступу.
- Проксі обробляє запити асинхронно і не зберігає великі тіла запитів у пам’яті.

---

## 🇬🇧 English

### Overview
This project is a demonstration service for routing HTTP traffic through a reverse proxy with basic security controls. It is suitable for learning, testing, or as a simple example of an architecture that includes a proxy, WAF, rate limiting, and an administrative interface.

### Key features
- accepts incoming HTTP requests from clients;
- forwards them to a selected backend service;
- applies WAF rules to block suspicious requests;
- limits the number of requests coming from a single source;
- tracks IP reputation;
- records events and allows rules to be managed through the admin UI.

### How it works
1. A client sends a request to the proxy.
2. The proxy checks the request for suspicious patterns.
3. If the request is allowed, it is forwarded to the backend.
4. Events are logged during processing, and rules can be changed without restarting the service.

### Security model
The project includes several layers of protection:
- WAF — inspects incoming traffic and blocks suspicious patterns;
- rate limiting — reduces pressure from excessive activity from a single source;
- IP reputation — helps track repeated suspicious behavior;
- logging — stores event information for review and analysis;
- admin panel — allows rule management while the service is running.

### Technologies
- Python
- FastAPI
- Redis
- Docker / Docker Compose

### Quick start
```bash
docker compose build
docker compose up
```

Open the services at:
- Proxy: http://localhost:8000
- Admin UI: http://localhost:8080

### Configuration
Settings are stored in config.yaml. You can change the target backend, WAF rules, and request limiting parameters there.

### Security notes
- The admin panel requires an access token. Set the ADMIN_AUTH_TOKEN environment variable before starting the services, for example: ADMIN_AUTH_TOKEN='your-strong-secret'.
- For Docker Compose, it is convenient to use a .env file or run the command with `--env-file`.
- Access the admin UI by sending the X-Admin-Token header or an Authorization: Bearer <token> header.
- The proxy blocks attempts to forward requests to arbitrary external hosts, and the WAF inspects paths, query strings, bodies, and headers.

### Security checklist
- [x] Proxy blocks absolute URL targets to avoid SSRF/open-proxy behavior.
- [x] WAF output escapes attacker-controlled content to prevent reflected XSS.
- [x] Admin routes require authentication via token.
- [x] Admin service is exposed only on localhost in Docker Compose.
- [x] Environment-based secrets are documented via .env and .env.example.
- [x] Generated artifacts such as logs, pickle models, and caches are ignored by Git.

### Secure Docker run
```bash
cp .env.example .env
# fill in ADMIN_AUTH_TOKEN in .env
docker compose --env-file .env up --build
```

### Notes
- The service is designed as a safe learning example for working with proxies and access rules.
- The proxy handles requests asynchronously and does not buffer large request bodies in memory.
