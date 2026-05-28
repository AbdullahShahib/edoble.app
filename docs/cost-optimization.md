**Cost Optimization (practical tactics)**

- **Right-size instances**: Start with conservative resource requests/limits in k8s and use metrics-based autoscaling. Review CPU/memory utilization weekly.
- **Use spot/spot-like instances for non-critical workloads**: CI runners, batch jobs, worker pools.
- **Use reserved/capacity-savings for steady-state infra**: DB read replicas, primary caches.
- **Cache aggressively**: Use CDN for static assets and signed URLs for media; set cache TTLs conservatively.
- **Storage lifecycle**: Move cold media to cheaper storage classes (S3 IA / Glacier) and enable lifecycle transitions.
- **Serverless for spiky workloads**: Use serverless functions where possible to avoid idle costs.
- **Monitor cost with alerts**: Use cloud cost APIs to alert on unexpected spend.

Small changes that yield big wins:
- Reduce container images size (multi-stage builds, alpine/musl bases, remove dev deps in final image).
- Limit replica counts via HPA based on real traffic patterns.
