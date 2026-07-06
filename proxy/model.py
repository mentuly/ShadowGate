import json
from pathlib import Path
from typing import Any

from sklearn.ensemble import IsolationForest

MODEL_PATH = Path('model.pkl')
LOG_PATH = Path('logs/requests.jsonl')
FEATURE_COLUMNS = ['path_length', 'header_count', 'body_size', 'frequency', 'user_agent_length']


class AnomalyModel:
    def __init__(self, model_path: str | Path = MODEL_PATH, threshold: float = 0.0):
        self.model_path = Path(model_path)
        self.threshold = threshold
        self.model: IsolationForest | None = None
        self.last_training_count = 0
        self.load_model()

    def load_model(self) -> None:
        if self.model_path.exists():
            import joblib
            self.model = joblib.load(self.model_path)
        else:
            self.model = None

    def _build_feature_vector(self, features: dict[str, Any]) -> list[float]:
        return [
            features.get('path_length', 0),
            features.get('header_count', 0),
            features.get('body_size', 0),
            features.get('frequency', 0),
            len(str(features.get('user_agent', ''))),
        ]

    def score_request(self, features: dict[str, Any]) -> float | None:
        if not self.model:
            return None
        vector = self._build_feature_vector(features)
        score = float(self.model.decision_function([vector])[0])
        return score

    def is_anomalous(self, score: float) -> bool:
        return score < self.threshold

    def retrain_if_needed(self, log_path: str | Path = LOG_PATH, model_path: str | Path | None = None, min_records: int = 1000, contamination: float = 0.01) -> bool:
        model_path = Path(model_path or self.model_path)
        log_path = Path(log_path)
        if not log_path.exists():
            return False

        records = []
        with open(log_path, 'r', encoding='utf-8') as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                    records.append(record)
                except json.JSONDecodeError:
                    continue

        if len(records) < min_records:
            return False
        if self.model is not None and self.last_training_count and len(records) <= self.last_training_count:
            return False

        import joblib
        import pandas as pd

        df = pd.DataFrame(records)
        if df.empty:
            return False
        df = df.copy()
        if 'user_agent_length' not in df.columns and 'user_agent' in df.columns:
            df['user_agent_length'] = df['user_agent'].fillna('').astype(str).str.len()
        features = df[FEATURE_COLUMNS].fillna(0)
        model = IsolationForest(contamination=contamination, random_state=42)
        model.fit(features.values)
        joblib.dump(model, model_path)
        self.model = model
        self.last_training_count = len(records)
        return True


def log_request_features(features: dict[str, Any], log_path: str | Path = LOG_PATH) -> None:
    log_path = Path(log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    record = {
        'event': 'request',
        'timestamp': features.get('timestamp'),
        'client_ip': features.get('client_ip'),
        'method': features.get('method'),
        'path': features.get('path'),
        'query': features.get('query'),
        'path_length': features.get('path_length'),
        'header_count': features.get('header_count'),
        'body_size': features.get('body_size'),
        'frequency': features.get('frequency'),
        'user_agent': features.get('user_agent'),
    }
    with open(log_path, 'a', encoding='utf-8') as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + '\n')


def train_model(log_path: str | Path = LOG_PATH, model_path: str | Path = MODEL_PATH, contamination: float = 0.01) -> dict[str, Any]:
    model = AnomalyModel(model_path=model_path)
    success = model.retrain_if_needed(log_path=log_path, model_path=model_path, min_records=1000, contamination=contamination)
    return {'success': success, 'model_path': str(model_path), 'log_path': str(log_path), 'records_used': model.last_training_count}
