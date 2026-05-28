**Backup & Disaster Recovery (summary)**

- **Databases (Postgres/RDS)**: Enable automated snapshots daily, and take hourly snapshots for critical tables. Use point-in-time recovery (PITR). Replicate to a standby in another AZ/region for RTO < 1 hour.
- **Redis**: Use managed Redis with AOF + replication; enable backups to S3 and cross-region replication for failover.
- **Object storage**: Store media in S3 with versioning and lifecycle rules. Enable cross-region replication for hot assets.
- **Kubernetes**: Keep manifests in Git. Use cluster snapshots for etcd (if self-managed). Use provider-managed control plane for faster recovery.
- **Disaster drills**: Quarterly failover tests with runbooks. Maintain runbooks in `docs/ops.md`.

Recovery targets:
- RTO: define per service (frontend < 5m via CDN + static hosting; backend < 15m for critical services).
- RPO: for messages, target seconds-to-minutes using WAL and replication; for audit logs, ensure append-only replication to durable store.

Recommended tooling:
- AWS: RDS snapshots, S3 replication, EBS snapshots, Route53 health checks + failover routing.
- GCP/Azure equivalents available via managed DB snapshots and storage replication.
