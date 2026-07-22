# APIFortress

APIFortress is a professional API monitoring tool designed for developers and IT support teams to ensure backend reliability.

## Features
- **Latency Tracking**: Measures endpoint response time in milliseconds.
- **Health Validation**: Confirms 2xx/3xx status codes as "UP" status.
- **Bulk Monitoring**: Checks multiple endpoints in a single execution.
- **Session Summaries**: Provides uptime percentages and average latency stats.
- **Logging**: Detailed standard logging for easy integration with system monitors.

## Grok Build Standards
- **OOP Principles**: Utilizes clean class structures and dataclasses for state management.
- **Robustness**: Handles request exceptions (timeouts, DNS failures) gracefully.
- **Professionalism**: Includes comprehensive docstrings and structured output.

## Usage
```python
from fortress import APIFortress

fortress = APIFortress()
health = fortress.check_endpoint("https://api.example.com/v1/status")
print(f"Status: {health.status_code}, Latency: {health.latency}ms")
```
