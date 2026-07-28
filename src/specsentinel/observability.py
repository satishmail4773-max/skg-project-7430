import threading
import time
from collections import Counter


class Metrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._requests: Counter[tuple[str, str, int]] = Counter()
        self._durations_ms: Counter[tuple[str, str]] = Counter()

    def record(self, method: str, route: str, status: int, started: float) -> None:
        route = route if route in {"/v1/generate", "/v1/diff", "/v1/bundle", "/healthz", "/metrics"} else "other"
        with self._lock:
            self._requests[(method, route, status)] += 1
            self._durations_ms[(method, route)] += int((time.perf_counter() - started) * 1000)

    def render(self) -> str:
        with self._lock:
            requests, durations = dict(self._requests), dict(self._durations_ms)
        lines = ["# HELP specsentinel_requests_total Request count without content labels.", "# TYPE specsentinel_requests_total counter"]
        for (method, route, status), value in sorted(requests.items()):
            lines.append(f'specsentinel_requests_total{{method="{method}",route="{route}",status="{status}"}} {value}')
        lines.extend(["# HELP specsentinel_request_duration_milliseconds_total Aggregate request duration.", "# TYPE specsentinel_request_duration_milliseconds_total counter"])
        for (method, route), value in sorted(durations.items()):
            lines.append(f'specsentinel_request_duration_milliseconds_total{{method="{method}",route="{route}"}} {value}')
        return "\n".join(lines) + "\n"


metrics = Metrics()

