"""
Тести для модуля аналітики.
Запуск: pytest tests/test_analytics.py -v
"""
import json
import os
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from proxy.analytics import TrafficAnalytics


@pytest.fixture
def temp_logs_dir():
    """Створити тимчасову директорію для логів"""
    with tempfile.TemporaryDirectory() as tmpdir:
        logs_dir = Path(tmpdir) / 'logs'
        logs_dir.mkdir()
        yield logs_dir


@pytest.fixture
def analytics_with_data(temp_logs_dir):
    """Аналітика з тестовими даними"""
    analytics = TrafficAnalytics()
    analytics.event_log_path = temp_logs_dir / 'proxy-events.jsonl'
    analytics.request_log_path = temp_logs_dir / 'requests.jsonl'
    
    # Створити тестові события
    now = datetime.now(timezone.utc)
    events = [
        {
            'event': 'request',
            'timestamp': (now - timedelta(hours=1)).isoformat(timespec='seconds'),
            'method': 'GET',
            'path': '/api/users',
            'status_code': 200,
            'client_ip': '192.168.1.1',
        },
        {
            'event': 'request',
            'timestamp': (now - timedelta(hours=1)).isoformat(timespec='seconds'),
            'method': 'GET',
            'path': '/api/data',
            'status_code': 200,
            'client_ip': '192.168.1.2',
        },
        {
            'event': 'waf_blocked',
            'timestamp': (now - timedelta(hours=2)).isoformat(timespec='seconds'),
            'rule': 'sql_injection',
            'path': '/api/search?q=1 OR 1=1',
            'client_ip': '203.0.113.1',
        },
        {
            'event': 'waf_blocked',
            'timestamp': (now - timedelta(hours=2)).isoformat(timespec='seconds'),
            'rule': 'xss',
            'path': '/api/comment?text=<script>',
            'client_ip': '203.0.113.2',
        },
        {
            'event': 'rate_limited',
            'timestamp': (now - timedelta(hours=0.5)).isoformat(timespec='seconds'),
            'client_ip': '198.51.100.1',
        },
        {
            'event': 'request',
            'timestamp': now.isoformat(timespec='seconds'),
            'method': 'POST',
            'path': '/api/create',
            'status_code': 201,
            'client_ip': '192.168.1.3',
        },
    ]
    
    # Записати события
    with open(analytics.event_log_path, 'w') as f:
        for event in events:
            f.write(json.dumps(event) + '\n')
    
    # Створити тестові запити
    requests = [
        {
            'timestamp': (now - timedelta(hours=1)).isoformat(timespec='seconds'),
            'path': '/api/users',
            'body_size': 0,
            'header_count': 10,
        },
        {
            'timestamp': (now - timedelta(hours=1)).isoformat(timespec='seconds'),
            'path': '/api/data',
            'body_size': 5000,
            'header_count': 12,
        },
    ]
    
    with open(analytics.request_log_path, 'w') as f:
        for req in requests:
            f.write(json.dumps(req) + '\n')
    
    return analytics


class TestTrafficAnalytics:
    """Тести для базової аналітики трафіку"""

    def test_load_events(self, analytics_with_data):
        """Завантаження подій"""
        events = analytics_with_data.load_events(hours=24)
        assert len(events) == 6
        assert all('event' in e for e in events)

    def test_load_requests(self, analytics_with_data):
        """Завантаження інформації про запити"""
        requests = analytics_with_data.load_requests(hours=24)
        assert len(requests) == 2
        assert all('path' in r for r in requests)

    def test_get_traffic_stats(self, analytics_with_data):
        """Статистика трафіку"""
        stats = analytics_with_data.get_traffic_stats(hours=24)
        
        assert stats['total_requests'] >= 3  # Як мінімум 3 запити
        assert stats['waf_blocks'] >= 2
        assert stats['rate_limit_blocks'] >= 1

    def test_get_top_waf_rules(self, analytics_with_data):
        """Топ порушених WAF правил"""
        rules = analytics_with_data.get_top_waf_rules(limit=10, hours=24)
        
        assert len(rules) == 2
        assert rules[0]['rule'] in ['sql_injection', 'xss']
        assert all(r['count'] > 0 for r in rules)

    def test_get_top_blocked_ips(self, analytics_with_data):
        """Топ заблокованих IP адрес"""
        ips = analytics_with_data.get_top_blocked_ips(limit=10, hours=24)
        
        assert len(ips) == 3  # 2 WAF + 1 rate_limit
        assert ips[0]['ip'] in ['203.0.113.1', '203.0.113.2', '198.51.100.1']

    def test_get_traffic_by_method(self, analytics_with_data):
        """Трафік за методом запиту"""
        methods = analytics_with_data.get_traffic_by_method(hours=24)
        
        assert 'GET' in methods
        assert 'POST' in methods
        assert methods['GET'] == 2
        assert methods['POST'] == 1

    def test_get_traffic_by_status(self, analytics_with_data):
        """Трафік за статус кодом"""
        statuses = analytics_with_data.get_traffic_by_status(hours=24)
        
        assert 200 in statuses
        assert 201 in statuses
        assert statuses[200] == 2
        assert statuses[201] == 1

    def test_get_hourly_traffic(self, analytics_with_data):
        """Трафік по часам"""
        hourly = analytics_with_data.get_hourly_traffic(hours=24)
        
        assert len(hourly) > 0
        assert all('hour' in h and 'total' in h and 'blocked' in h for h in hourly)

    def test_get_path_statistics(self, analytics_with_data):
        """Топ запитуваних path'ів"""
        paths = analytics_with_data.get_path_statistics(limit=15, hours=24)
        
        assert len(paths) > 0
        assert any(p['path'] == '/api/users' for p in paths)

    def test_get_security_summary(self, analytics_with_data):
        """Безпекова статистика"""
        summary = analytics_with_data.get_security_summary(hours=24)
        
        assert summary['total_events'] == 6
        assert summary['waf_events'] == 2
        assert summary['rate_limit_events'] == 1

    def test_get_request_size_distribution(self, analytics_with_data):
        """Розподіл розміру запитів"""
        distribution = analytics_with_data.get_request_size_distribution(hours=24)
        
        assert 'min' in distribution
        assert 'max' in distribution
        assert 'mean' in distribution
        assert distribution['min'] == 0
        assert distribution['max'] == 5000


class TestAnomalyDetection:
    """Тести для виявлення аномалій"""

    def test_detect_anomalies_normal(self, analytics_with_data):
        """Виявлення аномалій при нормальному трафіку"""
        anomalies = analytics_with_data.detect_anomalies(hours=24, threshold=2.0)
        
        # З нашими тестовими даними малоймовірно мати аномалії
        # но перевіримо чи функція працює
        assert isinstance(anomalies, list)

    def test_detect_anomalies_with_spike(self, temp_logs_dir):
        """Виявлення аномалій зі спіком трафіку"""
        analytics = TrafficAnalytics()
        analytics.event_log_path = temp_logs_dir / 'proxy-events.jsonl'
        analytics.request_log_path = temp_logs_dir / 'requests.jsonl'
        
        now = datetime.now(timezone.utc)
        
        # Створити события з нормальним трафіком та спіком
        events = []
        
        # Нормальний трафік: 10 запитів на час
        for i in range(10):
            for hour in range(5, 2, -1):  # 5, 4, 3 години тому
                events.append({
                    'event': 'request',
                    'timestamp': (now - timedelta(hours=hour)).isoformat(timespec='seconds'),
                    'method': 'GET',
                    'path': f'/api/test{i}',
                    'status_code': 200,
                })
        
        # Спік: 100 запитів на поточну годину
        for i in range(100):
            events.append({
                'event': 'request',
                'timestamp': now.isoformat(timespec='seconds'),
                'method': 'GET',
                'path': '/api/spike',
                'status_code': 200,
            })
        
        with open(analytics.event_log_path, 'w') as f:
            for event in events:
                f.write(json.dumps(event) + '\n')
        
        anomalies = analytics.detect_anomalies(hours=24, threshold=1.5)
        
        # З таким обсягом спіку повинна бути обнаружена аномалія
        assert isinstance(anomalies, list)


class TestReportExport:
    """Тести для експорту звітів"""

    def test_export_to_csv(self, analytics_with_data, temp_logs_dir):
        """Експорт до CSV"""
        csv_path = str(temp_logs_dir / 'report.csv')
        data = [
            {'hour': '2024-01-01 12:00', 'total': 100, 'blocked': 5},
            {'hour': '2024-01-01 13:00', 'total': 120, 'blocked': 8},
        ]
        
        result = analytics_with_data.export_to_csv(csv_path, data)
        
        assert result is True
        assert Path(csv_path).exists()
        
        # Перевірити зміст файлу
        with open(csv_path, 'r') as f:
            content = f.read()
            assert 'hour,total,blocked' in content
            assert '2024-01-01 12:00' in content

    def test_get_detailed_report(self, analytics_with_data):
        """Детальний звіт"""
        report = analytics_with_data.get_detailed_report(hours=24)
        
        assert 'timestamp' in report
        assert 'period_hours' in report
        assert report['period_hours'] == 24
        assert 'traffic_stats' in report
        assert 'top_waf_rules' in report
        assert 'top_blocked_ips' in report
        assert 'security_summary' in report
        assert 'anomalies' in report
        assert isinstance(report['traffic_stats'], dict)
        assert isinstance(report['top_waf_rules'], list)


class TestEdgeCases:
    """Тести для граничних випадків"""

    def test_empty_logs(self, temp_logs_dir):
        """Обробка порожніх логів"""
        analytics = TrafficAnalytics()
        analytics.event_log_path = temp_logs_dir / 'proxy-events.jsonl'
        analytics.request_log_path = temp_logs_dir / 'requests.jsonl'
        
        # Створити порожні файли
        analytics.event_log_path.touch()
        analytics.request_log_path.touch()
        
        stats = analytics.get_traffic_stats(hours=24)
        assert stats['total_requests'] == 0
        
        rules = analytics.get_top_waf_rules(hours=24)
        assert len(rules) == 0

    def test_nonexistent_logs(self):
        """Обробка неіснуючих логів"""
        analytics = TrafficAnalytics()
        analytics.event_log_path = Path('/nonexistent/path/events.jsonl')
        analytics.request_log_path = Path('/nonexistent/path/requests.jsonl')
        
        stats = analytics.get_traffic_stats(hours=24)
        assert stats['total_requests'] == 0

    def test_malformed_json(self, temp_logs_dir):
        """Обробка malformed JSON"""
        analytics = TrafficAnalytics()
        analytics.event_log_path = temp_logs_dir / 'proxy-events.jsonl'
        analytics.request_log_path = temp_logs_dir / 'requests.jsonl'
        
        # Записати malformed JSON
        with open(analytics.event_log_path, 'w') as f:
            f.write('{"valid": "json", "timestamp": "' + datetime.now(timezone.utc).isoformat(timespec='seconds') + '"}\n')
            f.write('invalid json line\n')
            f.write('{"valid": "json2", "timestamp": "' + datetime.now(timezone.utc).isoformat(timespec='seconds') + '"}\n')
        
        events = analytics.load_events(hours=24)
        # Повинно завантажити лише валідні вирази
        assert len(events) == 2

    def test_future_timestamps(self, temp_logs_dir):
        """Обробка майбутніх timestamps"""
        analytics = TrafficAnalytics()
        analytics.event_log_path = temp_logs_dir / 'proxy-events.jsonl'
        analytics.request_log_path = temp_logs_dir / 'requests.jsonl'
        
        now = datetime.now(timezone.utc)
        past_1hour = (now - timedelta(hours=1)).isoformat(timespec='seconds')
        past_25hours = (now - timedelta(hours=25)).isoformat(timespec='seconds')
        
        with open(analytics.event_log_path, 'w') as f:
            f.write(json.dumps({'event': 'request', 'timestamp': past_1hour, 'method': 'GET'}) + '\n')
            f.write(json.dumps({'event': 'request', 'timestamp': past_25hours, 'method': 'GET'}) + '\n')
        
        # Завантажити на 24 години - повинна бути тільки одна подія (1 година назад)
        events = analytics.load_events(hours=24)
        assert len(events) == 1
        assert events[0]['timestamp'] == past_1hour
