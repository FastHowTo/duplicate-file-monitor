# Duplicate File Monitor v0.6.8

## Fixed

- **Scan finalization latency:** Disable SQLite's automatic WAL checkpoint for the scan writer and perform a best-effort PASSIVE checkpoint separately after the inventory transaction is durably committed. Retain SQLite synchronous FULL durability.
- **Writer-close checkpoint stalls:** Keep a short SQLite read transaction open through scan-writer closure so connection shutdown does not trigger a blocking last-connection checkpoint.
- **Detailed finalization timing:** Log separate durations for duplicate-path archive staging, archive insertion, scan-history writes, SQLite commit and completion timestamp persistence.
- **Accurate elapsed time:** The scan's elapsed-time display continues running through finalization; the saved scan history and report timestamps now include the database publication commit.
- Historical duplicate-path snapshots, SHA-256 verification, lifetime-savings logic and report-only NAS access are unchanged.

## Upgrade

Back up the existing DFM persistent `/data` volume, including any SQLite WAL and SHM files, with the container stopped. Preserve the existing Compose environment, NAS read-only mounts, administrator account, MQTT settings and monitoring credentials. Change the image to `ghcr.io/fasthowto/duplicate-file-monitor:0.6.8`, then run:

```bash
sudo docker compose pull duplicate-file-monitor
sudo docker compose up -d duplicate-file-monitor
```

Do not use `docker compose down -v`. The deferred WAL checkpoint can continue to consume disk I/O briefly after a scan is reported complete; if necessary, SQLite safely resumes its work on a later connection. No new configuration or schema migration is required.
