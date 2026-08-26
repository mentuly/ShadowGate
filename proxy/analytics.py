"""
Analytics модуль для збору та аналізу даних про трафік, WAF порушення і тренди.
"""
import json
import logging
from collections import defaultdict, Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import pandas as pd

logger = logging.getLogger('analytics')


class TrafficAnalytics:
    """Аналіз трафіку та порушень WAF"""
    
    EVENT_LOG_PATH = Path('logs/proxy-events.jsonl')
    REQUEST_LOG_PATH = Path('logs/requests.jsonl')
    
    def __init__(self):
        self.event_log_path = self.EVENT_LOG_PATH
        self.request_log_path = self.REQUEST_LOG_PATH
    
    def load_events(self, hours: int = 24) -> list[dict]:
        """Завантажити события за останні N годин"""
        if not self.event_log_path.exists():
            return []
        
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        events = []
        
        try:
            with open(self.event_log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        event = json.loads(line)
                        if 'timestamp' in event:
                            ts = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                            if ts >= cutoff_time:
                                events.append(event)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.error(f"Error loading events: {e}")
        
        return events
    
    def load_requests(self, hours: int = 24) -> list[dict]:
        """Завантажити інформацію про запити"""
        if not self.request_log_path.exists():
            return []
        
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        requests = []
        
        try:
            with open(self.request_log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        req = json.loads(line)
                        if 'timestamp' in req:
                            ts = datetime.fromisoformat(req['timestamp'].replace('Z', '+00:00'))
                            if ts >= cutoff_time:
                                requests.append(req)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.error(f"Error loading requests: {e}")
        
        return requests
    
    def get_traffic_stats(self, hours: int = 24) -> dict:
        """Статистика трафіку"""
        events = self.load_events(hours)
        
        total_requests = len([e for e in events if e.get('event') == 'request'])
        blocked_requests = len([e for e in events if e.get('event') == 'blocked'])
        waf_blocks = len([e for e in events if e.get('event') == 'waf_blocked'])
        rate_limit_blocks = len([e for e in events if e.get('event') == 'rate_limited'])
        
        return {
            'total_requests': total_requests,
            'blocked_requests': blocked_requests,
            'waf_blocks': waf_blocks,
            'rate_limit_blocks': rate_limit_blocks,
            'block_rate': round((blocked_requests / total_requests * 100) if total_requests > 0 else 0, 2),
            'waf_block_rate': round((waf_blocks / total_requests * 100) if total_requests > 0 else 0, 2),
        }
    
    def get_top_waf_rules(self, limit: int = 10, hours: int = 24) -> list[dict]:
        """Топ порушених WAF правил"""
        events = self.load_events(hours)
        waf_events = [e for e in events if e.get('event') == 'waf_blocked']
        
        rule_counts = Counter(e.get('rule', 'unknown') for e in waf_events)
        
        return [
            {'rule': rule, 'count': count}
            for rule, count in rule_counts.most_common(limit)
        ]
    
    def get_top_blocked_ips(self, limit: int = 10, hours: int = 24) -> list[dict]:
        """Топ заблокованих IP адрес"""
        events = self.load_events(hours)
        blocked_events = [e for e in events if e.get('event') in ['blocked', 'waf_blocked', 'rate_limited']]
        
        ip_counts = Counter(e.get('client_ip', 'unknown') for e in blocked_events)
        
        return [
            {'ip': ip, 'count': count}
            for ip, count in ip_counts.most_common(limit)
        ]
    
    def get_traffic_by_method(self, hours: int = 24) -> dict:
        """Трафік за методом запиту"""
        events = self.load_events(hours)
        req_events = [e for e in events if e.get('event') == 'request']
        
        method_counts = Counter(e.get('method', 'UNKNOWN') for e in req_events)
        return dict(method_counts)
    
    def get_traffic_by_status(self, hours: int = 24) -> dict:
        """Трафік за статус кодом"""
        events = self.load_events(hours)
        
        status_counts = Counter()
        for e in events:
            if e.get('event') == 'request':
                status = e.get('status_code', 'unknown')
                status_counts[status] += 1
        
        return dict(status_counts)
    
    def get_hourly_traffic(self, hours: int = 24) -> list[dict]:
        """Трафік по часам"""
        events = self.load_events(hours)
        
        hourly = defaultdict(lambda: {'total': 0, 'blocked': 0})
        
        for e in events:
            if 'timestamp' in e:
                ts = datetime.fromisoformat(e['timestamp'].replace('Z', '+00:00'))
                hour_key = ts.strftime('%Y-%m-%d %H:00')
                
                hourly[hour_key]['total'] += 1
                if e.get('event') in ['blocked', 'waf_blocked', 'rate_limited']:
                    hourly[hour_key]['blocked'] += 1
        
        return sorted([
            {'hour': k, **v}
            for k, v in hourly.items()
        ], key=lambda x: x['hour'])
    
    def get_request_size_distribution(self, hours: int = 24) -> dict:
        """Розподіл розміру запитів"""
        requests = self.load_requests(hours)
        
        sizes = [r.get('body_size', 0) for r in requests]
        if not sizes:
            return {}
        
        return {
            'min': min(sizes),
            'max': max(sizes),
            'mean': round(sum(sizes) / len(sizes)),
            'median': sorted(sizes)[len(sizes) // 2],
            'p95': sorted(sizes)[int(len(sizes) * 0.95)],
        }
    
    def get_path_statistics(self, limit: int = 15, hours: int = 24) -> list[dict]:
        """Топ запитуваних path'ів"""
        events = self.load_events(hours)
        req_events = [e for e in events if e.get('event') == 'request']
        
        path_counts = Counter(e.get('path', '/') for e in req_events)
        
        return [
            {'path': path, 'count': count}
            for path, count in path_counts.most_common(limit)
        ]
    
    def detect_anomalies(self, hours: int = 24, threshold: float = 2.0) -> list[dict]:
        """Виявлення аномалій у трафіку"""
        hourly_data = self.get_hourly_traffic(hours)
        
        if len(hourly_data) < 3:
            return []
        
        # Обчислення середнього та стандартного відхилення
        totals = [h['total'] for h in hourly_data]
        mean = sum(totals) / len(totals)
        variance = sum((x - mean) ** 2 for x in totals) / len(totals)
        std_dev = variance ** 0.5
        
        anomalies = []
        for h in hourly_data:
            z_score = abs((h['total'] - mean) / std_dev) if std_dev > 0 else 0
            if z_score > threshold:
                anomalies.append({
                    'hour': h['hour'],
                    'traffic': h['total'],
                    'z_score': round(z_score, 2),
                    'anomaly_type': 'spike' if h['total'] > mean else 'dip'
                })
        
        return anomalies
    
    def get_security_summary(self, hours: int = 24) -> dict:
        """Загальна безпекова статистика"""
        events = self.load_events(hours)
        
        return {
            'total_events': len(events),
            'waf_events': len([e for e in events if e.get('event') == 'waf_blocked']),
            'rate_limit_events': len([e for e in events if e.get('event') == 'rate_limited']),
            'ssrf_blocked': len([e for e in events if e.get('event') == 'ssrf_blocked']),
            'admin_auth_failures': len([e for e in events if e.get('event') == 'admin_auth_failed']),
        }
    
    def export_to_csv(self, filepath: str, data: list[dict]) -> bool:
        """Експорт даних до CSV"""
        try:
            df = pd.DataFrame(data)
            df.to_csv(filepath, index=False)
            logger.info(f"Exported {len(data)} records to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}")
            return False
    
    def get_detailed_report(self, hours: int = 24) -> dict:
        """Детальний звіт з усіма метриками"""
        return {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'period_hours': hours,
            'traffic_stats': self.get_traffic_stats(hours),
            'top_waf_rules': self.get_top_waf_rules(limit=10, hours=hours),
            'top_blocked_ips': self.get_top_blocked_ips(limit=10, hours=hours),
            'traffic_by_method': self.get_traffic_by_method(hours),
            'traffic_by_status': self.get_traffic_by_status(hours),
            'hourly_traffic': self.get_hourly_traffic(hours),
            'request_size_distribution': self.get_request_size_distribution(hours),
            'top_paths': self.get_path_statistics(limit=15, hours=hours),
            'anomalies': self.detect_anomalies(hours),
            'security_summary': self.get_security_summary(hours),
        }
