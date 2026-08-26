"""
Load тести з Locust для перевірки продуктивності proxy під навантаженням.

Запуск:
  1. Запустити сервіси: docker-compose up -d
  2. Запустити Locust: locust -f locustfile.py --host=http://localhost:8000 --web
  3. Відкрити http://localhost:8089 в браузері

Або запустити в headless режимі:
  locust -f locustfile.py --host=http://localhost:8000 --headless -u 100 -r 10 -t 60s
"""
import random
import string
from locust import HttpUser, between, task


class ProxyUser(HttpUser):
    """Base користувач для тестування proxy"""
    wait_time = between(0.5, 2.0)  # Час очікування між запитами (0.5-2.0 сек)
    
    @task(3)
    def get_simple_request(self):
        """GET запит (3x більша вага)"""
        self.client.get('/api/test', name='/api/test')
    
    @task(2)
    def get_with_params(self):
        """GET з параметрами"""
        query_id = random.randint(1, 1000)
        self.client.get(f'/api/users/{query_id}', name='/api/users/[id]')
    
    @task(2)
    def search_request(self):
        """Search запит"""
        query = ''.join(random.choices(string.ascii_lowercase, k=5))
        self.client.get(f'/api/search?q={query}', name='/api/search?q=[query]')
    
    @task(1)
    def post_request(self):
        """POST запит"""
        payload = {
            'name': f'user_{random.randint(1, 1000)}',
            'email': f'user{random.randint(1, 1000)}@example.com'
        }
        self.client.post('/api/users', json=payload, name='/api/users [POST]')


class AdminUser(HttpUser):
    """Admin користувач для тестування admin панелі"""
    wait_time = between(2.0, 5.0)  # Більше часу для admin операцій
    
    def on_start(self):
        """Ініціалізація перед запуском тестів"""
        self.admin_token = 'test-admin-token'
    
    @task(1)
    def get_admin_dashboard(self):
        """Отримання admin дашборду"""
        headers = {'X-Admin-Token': self.admin_token}
        self.client.get('/', headers=headers, name='/ [admin dashboard]')
    
    @task(2)
    def get_config(self):
        """Отримання конфігурації"""
        headers = {'X-Admin-Token': self.admin_token}
        self.client.get('/api/config', headers=headers, name='/api/config [admin]')
    
    @task(1)
    def get_stats(self):
        """Отримання статистики"""
        headers = {'X-Admin-Token': self.admin_token}
        self.client.get('/api/stats', headers=headers, name='/api/stats [admin]')


class HighTrafficUser(HttpUser):
    """Користувач з високим трафіком (stress тест)"""
    wait_time = between(0.1, 0.5)  # Дуже мало часу між запитами
    
    @task(10)
    def rapid_requests(self):
        """Швидкі послідовні запити"""
        self.client.get('/api/test', name='/api/test [high-traffic]')


class DataUploadUser(HttpUser):
    """Користувач, що завантажує дані"""
    wait_time = between(1.0, 3.0)
    
    @task(1)
    def upload_small_data(self):
        """Завантаження малих даних"""
        data = {'content': 'x' * 1024}  # 1KB
        self.client.post('/api/upload', json=data, name='/api/upload [1KB]')
    
    @task(1)
    def upload_medium_data(self):
        """Завантаження середніх даних"""
        data = {'content': 'x' * (100 * 1024)}  # 100KB
        self.client.post('/api/upload', json=data, name='/api/upload [100KB]')
    
    @task(1)
    def upload_large_data(self):
        """Завантаження великих даних"""
        data = {'content': 'x' * (1024 * 1024)}  # 1MB
        self.client.post('/api/upload', json=data, name='/api/upload [1MB]')


class ComplexScenarioUser(HttpUser):
    """Користувач зі складним сценарієм роботи"""
    wait_time = between(1.0, 3.0)
    
    def on_start(self):
        """Ініціалізація - отримати ID ресурсу"""
        self.resource_id = random.randint(1, 1000)
    
    @task(5)
    def read_resource(self):
        """Читання ресурсу"""
        self.client.get(f'/api/users/{self.resource_id}', name='/api/users/[id] [read]')
    
    @task(1)
    def update_resource(self):
        """Оновлення ресурсу"""
        payload = {'name': f'updated_{random.randint(1, 1000)}'}
        self.client.post(
            f'/api/users/{self.resource_id}',
            json=payload,
            name='/api/users/[id] [update]'
        )
    
    @task(1)
    def create_related(self):
        """Створення пов'язаного ресурсу"""
        payload = {'parent_id': self.resource_id}
        self.client.post(
            '/api/comments',
            json=payload,
            name='/api/comments [POST]'
        )


# Конфігурація для різних сценаріїв
"""
Приклади запусків:

1. Базове навантаження (100 користувачів, 10 нових юзерів на секунду, 2 хвилини):
   locust -f locustfile.py --host=http://localhost:8000 --headless \\
     -u 100 -r 10 -t 120s

2. Stress тест (1000 користувачів, 100 нових юзерів на секунду):
   locust -f locustfile.py --host=http://localhost:8000 --headless \\
     -u 1000 -r 100 -t 60s

3. Довготривалий тест (500 користувачів, 50 нових юзерів на секунду, 10 хвилин):
   locust -f locustfile.py --host=http://localhost:8000 --headless \\
     -u 500 -r 50 -t 600s

4. High traffic тест (користувачі з високим трафіком):
   locust -f locustfile.py --host=http://localhost:8000 \\
     -u 200 -r 20 --stop-timeout 60 \\
     --locustfile-classes HighTrafficUser

Опції:
  -u, --users NUM        - Загальна кількість користувачів
  -r, --hatch-rate NUM   - Скільки нових користувачів запустити за секунду
  -t, --run-time TIME    - Час запуску (наприклад 60s, 2m, 1h)
  --headless             - Запуск без веб-інтерфейсу
  --stop-timeout SECS    - Timeout для зупинки
  --csv PREFIX           - Експорт результатів в CSV
"""
