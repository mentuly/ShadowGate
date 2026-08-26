# Testing Guide

Детальний гайд по запуску та розумінню тестів для Async Reverse Proxy.

## Швидкий Старт

```bash
# Всі тести
./run_tests.sh all

# Тільки unit тести
./run_tests.sh unit

# Тільки E2E тести
./run_tests.sh integration

# Бенчмарки (latency)
./run_tests.sh benchmark

# Load тести (Locust web UI)
./run_tests.sh locust

# Stress тест
./run_tests.sh stress
```

## 1️⃣ Unit Tests

Тестування окремих компонентів та функцій.

### Запуск

```bash
./run_tests.sh unit
# або
pytest tests/test_proxy.py tests/test_admin_csrf.py tests/test_admin_nonascii.py tests/test_security_dynamic.py -v
```

### Покриття

| Файл | Що тестує |
|------|----------|
| `test_proxy.py` | Forwarding, WAF, SSRF protection, rate limit, anomaly detection |
| `test_admin_csrf.py` | Admin auth, CSRF token validation |
| `test_admin_nonascii.py` | Unicode/non-ASCII request handling |
| `test_security_dynamic.py` | Runtime config updates, dynamic rule changes |

### Приклад результату

```
tests/test_proxy.py::test_proxy_forwards_http_requests PASSED [  5%]
tests/test_proxy.py::test_proxy_blocks_malicious_requests_with_waf PASSED [ 10%]
tests/test_proxy.py::test_proxy_rejects_absolute_url_targets PASSED [ 15%]
...
======================== 25 passed in 2.45s ========================
```

## 2️⃣ Integration Tests (E2E)

Тестування повних потоків користувача через систему.

### Запуск

```bash
./run_tests.sh integration
# або
pytest tests/test_integration_e2e.py -v
```

### Сценарії

#### TestProxyBasicFlow (6 тестів)
- ✅ Простий GET запит через proxy
- ✅ Послідовні запити (5 рядків)
- ✅ POST з payload
- ✅ DELETE запит
- ✅ Запит з custom headers
- ✅ Query параметри

```bash
pytest tests/test_integration_e2e.py::TestProxyBasicFlow -v
```

#### TestWAFIntegration (5 тестів)
- ✅ Блокування SQL injection
- ✅ Блокування XSS
- ✅ Блокування path traversal
- ✅ Дозвіл безпечних запитів
- ✅ Блокування закодованої XSS

```bash
pytest tests/test_integration_e2e.py::TestWAFIntegration -v
```

#### TestSSRFProtection (2 тести)
- ✅ Відхилення абсолютної URL у path
- ✅ Відхилення не-дозволених бекендів

```bash
pytest tests/test_integration_e2e.py::TestSSRFProtection -v
```

#### TestRateLimiting (2 тести)
- ✅ Дозвіл запитів у межах ліміту
- ✅ Блокування надлишкових запитів

```bash
pytest tests/test_integration_e2e.py::TestRateLimiting -v
```

#### TestAdminPanel (4 тести)
- ✅ Вимога аутентифікації
- ✅ Доступ з валідним токеном
- ✅ Отримання конфігурації
- ✅ Toggle WAF правил

```bash
pytest tests/test_integration_e2e.py::TestAdminPanel -v
```

#### TestConcurrentRequests (2 тести)
- ✅ Паралельні GET запити (20 одночасно)
- ✅ Змішані методи (GET, POST, DELETE)

```bash
pytest tests/test_integration_e2e.py::TestConcurrentRequests -v
```

#### TestErrorHandling (3 тести)
- ✅ 404 від бекенду
- ✅ Обмеження розміру request body
- ✅ Malformed запити

## 3️⃣ Benchmark Tests

Вимірювання latency та throughput.

### Запуск

```bash
./run_tests.sh benchmark
# або
pytest tests/test_benchmarks.py --benchmark-only -v
```

### Що вимірюється

| Бенчмарк | Вимірює |
|----------|---------|
| `test_simple_get_request` | Базова latency GET |
| `test_get_with_query_params` | Query параметри overhead |
| `test_post_with_body` | POST з 1KB payload |
| `test_post_with_large_body` | POST з 100KB payload |
| `test_many_headers` | 50 заголовків overhead |
| `test_waf_scan_normal_request` | WAF сканування час |
| `test_throughput_sequential` | 100 послідовних запитів |

### Приклад результату

```
Name (time in ms)              Min      Max     Mean  StdDev  Median     IQR
test_simple_get_request     8.75   34.12   10.58   4.52    9.57   0.91
test_get_with_query_params  9.23   35.10   11.01   4.73    9.89   0.95
test_post_with_body        10.12   40.25   12.34   5.12   11.05   1.10
test_many_headers          12.45   50.30   14.89   6.21   13.45   1.50

OPS: Operations Per Second (1 / Mean)
- test_simple_get_request: 94.49 ops/sec
- test_post_with_large_body: 78.32 ops/sec
```

### Вимірювання Percentiles

```bash
./run_tests.sh latency
# виведе: p50, p95, p99 latency in ms
```

### Порівняння Бенчмарків

```bash
./run_tests.sh benchmark-compare
# порівнює з попередньою baseline
```

## 4️⃣ Load Testing (Locust)

Тестування під навантаженням з реалістичними користувачами.

### Запуск з Web UI

```bash
# 1. Запустити сервіси (якщо локально)
docker-compose up -d

# 2. Запустити Locust
./run_tests.sh locust

# 3. Відкрити http://localhost:8089 в браузері
```

### Запуск Headless (без UI)

```bash
# 100 користувачів, 10 нових/сек, 2 хвилини
./run_tests.sh locust-headless 100 10 120s

# Результати збереглися в: reports/load_test_100users_stats.csv
```

### Стрес Тест

```bash
# 1000 користувачів, 100 нових/сек, 60 секунд
./run_tests.sh stress

# Результати: reports/stress_test_stats.csv
```

### Сценарії користувачів

#### ProxyUser (базовий користувач)
- 60% — простий GET
- 20% — GET з ID
- 20% — search запит

#### AdminUser (admin операції)
- Отримання дашборду
- Отримання конфігурації
- Отримання статистики

#### HighTrafficUser (stress тест)
- Дуже швидкі послідовні GET запити

#### DataUploadUser (завантаження даних)
- Малі (1KB), середні (100KB), великі (1MB) payload

#### ComplexScenarioUser (реальний сценарій)
- Читання ресурсу (70%)
- Оновлення ресурсу (20%)
- Створення пов'язаних ресурсів (10%)

### Інтерпретація результатів

```
Response Time Stats (ms):
  Type        Name     # requests  # failures  Median  95%ile  99%ile  Mean
  GET        /api/test    5000      0         12      35      89      15
  POST       /api/upload  1000      5         45      120     350      52
  
Failure Rate: 0.1% (5 failures з 50,000 requests)

Throughput: 833 req/sec (50,000 requests за 60 секунд)
```

**Норми:**
- p50 latency: < 50ms ✅
- p95 latency: < 200ms ✅
- p99 latency: < 500ms ✅
- Failure rate: < 0.5% ✅

## 5️⃣ Coverage Report

Покриття коду тестами.

```bash
./run_tests.sh coverage
# Результати в: htmlcov/index.html
```

Відкрити в браузері для деталізованої статистики.

## 📊 Інтерпретація Результатів

### Benchmarks

```
Mean: 10.58 ms - середній час виконання
Median: 9.57 ms - 50-й percentile
StdDev: 4.52 - стандартне відхилення (вищий = менш стабільно)
IQR: 0.91 - interquartile range
OPS: 94.49 - операцій за секунду

Good ✅:
- Median < 20ms
- StdDev < 50% of Median
- Consistent across rounds

Bad ❌:
- High StdDev (> 100% of Median)
- Many Outliers
- Increasing trend over time
```

### Load Testing

```
Response Time Percentiles:
- p50 (median): половина запитів швидша за це
- p95: 95% запитів швидше за це (важливо!)
- p99: 99% запитів швидше за це (екстремум)

Example:
p50=12ms → типовий користувач чекає ~12ms
p95=35ms → в гіршому разі чекає ~35ms
p99=89ms → дуже рідкі спіки до 89ms

Good ✅:
- p50 < 50ms
- p95 < 200ms
- p99 < 500ms
- Failure rate < 0.5%

Bad ❌:
- p95 > 500ms
- Failure rate > 1%
- Failure rate increasing over time
```

## 🔧 Налаштування для Різних Сценаріїв

### Development

```bash
# Швидкі тести
./run_tests.sh unit
./run_tests.sh benchmark | head -20
```

### Pre-Commit

```bash
# Всі тести перед commit
./run_tests.sh all
```

### CI/CD Pipeline

```bash
# Unit тести (швидко)
pytest tests/test_proxy.py -v -x

# Integration тести (повільніше)
pytest tests/test_integration_e2e.py -v

# Бенчмарки (порівняння з baseline)
./run_tests.sh benchmark-compare
```

### Performance Regression Detection

```bash
# Встановити baseline
pytest tests/test_benchmarks.py --benchmark-save=baseline

# Згодом — порівняти
pytest tests/test_benchmarks.py --benchmark-compare=baseline \
  --benchmark-compare-fail=mean:5%
# Fail якщо mean latency виросла на 5%+
```

### Load Testing Before Production

```bash
# 1. Baseline тест (нормальна конфігурація)
./run_tests.sh locust-headless 100 10 300s

# 2. Stress тест (граничні умови)
./run_tests.sh stress

# 3. Endurance тест (довготривалий)
./run_tests.sh locust-headless 200 20 1800s

# 4. Аналіз результатів
cat reports/load_test_100users_stats.csv | grep Response
```

## 🐛 Трубллшутинг

### Тести падають з timeout

```bash
# Збільшити timeout
pytest tests/ --timeout=30
```

### Redis недоступний

```
WARNING root:config.py:80 Redis is unavailable...

Рішення:
- Запустити Redis: docker-compose up redis
- Або вимкнути Redis-залежні функції в тесті
```

### Locust не з'єднується до сервера

```bash
# Перевірити що сервіс запущений
curl http://localhost:8000/livez

# Запустити сервіс локально
uvicorn proxy.app:app --host 0.0.0.0 --port 8000
```

### Load тест дуже повільний

```bash
# Зменшити користувачів
./run_tests.sh locust-headless 50 5 60s

# Використовувати меньше метрик
locust -f locustfile.py --no-stats
```

## 📈 Continuous Monitoring

Для моніторингу в production:

```bash
# Щоденний benchmark run
0 2 * * * cd /path/to/project && ./run_tests.sh benchmark > logs/daily_benchmark.log

# Щотижневий load тест
0 3 * * 0 cd /path/to/project && ./run_tests.sh stress > logs/weekly_stress.log
```

---

**Додаткова інформація:**
- [pytest документація](https://docs.pytest.org/)
- [pytest-benchmark](https://pytest-benchmark.readthedocs.io/)
- [Locust документація](https://docs.locust.io/)
