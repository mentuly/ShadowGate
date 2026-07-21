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

### Notes
- The service is designed as a safe learning example for working with proxies and access rules.
- The proxy handles requests asynchronously and does not buffer large request bodies in memory.
