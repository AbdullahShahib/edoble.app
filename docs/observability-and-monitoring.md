**Observability & Monitoring (concise plan)**

- **Metrics**: Use Prometheus for metrics collection. Expose `/metrics` from services via a small middleware.
- **Dashboards**: Grafana for dashboards and alerting (CPU, memory, request latency, 4xx/5xx rates, auth failure spikes).
- **Tracing**: Instrument services with OpenTelemetry; send traces to Jaeger or Tempo for distributed tracing.
- **Logging**: Send structured JSON logs to Loki/Fluent Bit (or ELK). Use a sidecar/daemonset (Fluent Bit) to forward stdout to central store.
- **Error tracking**: Integrate Sentry on client and server for exception capture and performance monitoring.

Quick setup notes:
- Deploy Prometheus Operator (kube-prometheus-stack) for Kubernetes.
- Deploy Grafana and import basic dashboards for node, k8s, and app metrics.
- Add a Prometheus scrape target for the API gateway and backend services.
- Use OpenTelemetry SDKs in Node services; sample instrumentation available in many official repos.

Alerting:
- Create SLO-based alerts: p99 latency > X ms, error rate > Y% for 5 minutes.
- Alert channels: pager (PagerDuty), Slack, email.
