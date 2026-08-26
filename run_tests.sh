#!/bin/bash
# Скрипт для запуску різних типів тестів

set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

# Активація virtual environment
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi
source .venv/bin/activate

# Встановлення залежностей
echo "Installing dependencies..."
pip install -q -r requirements.txt

# Парсинг аргументів
TEST_TYPE="${1:-all}"
VERBOSE="${2:-}"

case "$TEST_TYPE" in
    unit)
        echo "Running unit tests..."
        pytest tests/test_proxy.py tests/test_admin_csrf.py -v $VERBOSE
        ;;
    
    integration)
        echo "Running integration/E2E tests..."
        pytest tests/test_integration_e2e.py -v $VERBOSE
        ;;
    
    benchmark)
        echo "Running benchmark tests..."
        pytest tests/test_benchmarks.py --benchmark-only -v $VERBOSE
        ;;
    
    benchmark-compare)
        echo "Running benchmarks with comparison..."
        if [ ! -f ".benchmarks/baseline" ]; then
            echo "Creating baseline benchmark..."
            pytest tests/test_benchmarks.py --benchmark-only --benchmark-save=baseline
        fi
        pytest tests/test_benchmarks.py --benchmark-only --benchmark-compare=baseline -v
        ;;
    
    all)
        echo "Running all tests..."
        pytest tests/ -v $VERBOSE
        ;;
    
    locust)
        echo "Starting Locust load testing..."
        echo "Ensure docker-compose is running: docker-compose up -d"
        echo ""
        locust -f locustfile.py --host=http://localhost:8000 --web
        ;;
    
    locust-headless)
        USERS="${2:-100}"
        RATE="${3:-10}"
        TIME="${4:-120s}"
        echo "Running Locust headless: users=$USERS, rate=$RATE/s, time=$TIME"
        locust -f locustfile.py --host=http://localhost:8000 --headless \
            -u "$USERS" -r "$RATE" -t "$TIME" --csv=reports/load_test_${USERS}users
        ;;
    
    stress)
        echo "Running stress test (1000 users, 100/s, 60s)..."
        mkdir -p reports
        locust -f locustfile.py --host=http://localhost:8000 --headless \
            -u 1000 -r 100 -t 60s --csv=reports/stress_test
        ;;
    
    latency)
        echo "Measuring latency percentiles..."
        pytest tests/test_benchmarks.py::test_latency_percentiles -v -s
        ;;
    
    coverage)
        echo "Running tests with coverage report..."
        pip install -q pytest-cov
        pytest tests/ --cov=proxy --cov=admin --cov-report=html --cov-report=term
        echo "Coverage report generated in htmlcov/index.html"
        ;;
    
    *)
        echo "Usage: $0 {unit|integration|benchmark|benchmark-compare|all|locust|locust-headless|stress|latency|coverage} [args]"
        echo ""
        echo "Examples:"
        echo "  $0 unit              # Run unit tests"
        echo "  $0 integration       # Run E2E tests"
        echo "  $0 benchmark         # Run benchmarks"
        echo "  $0 all               # Run all tests"
        echo "  $0 locust            # Start Locust web UI"
        echo "  $0 locust-headless 100 10 60s  # Run load test headless"
        echo "  $0 stress            # Run stress test"
        echo "  $0 latency           # Measure latency percentiles"
        echo "  $0 coverage          # Generate coverage report"
        exit 1
        ;;
esac

echo ""
echo "✓ Done!"
