# Duplicate File Monitor v0.6.9

## Changed

- **Automatic duplicate-directory analysis:** Each successfully published Full or Quick Scan, whether All Volumes or a selected scope, automatically queues duplicate-directory analysis after the scan has fully finished. Scans completed with recoverable warnings also qualify.
- **Independent completion:** The scan's completion state, finalized duration, history and archived scan report become available before directory analysis starts. Directory matching runs in a separate background worker with its own database connection, never as part of scan finalization.
- **Unified progress indication:** The Duplicate Directory Trees section displays “Analyzing inventory” with the same cycling dots used for file discovery. Results appear automatically when ready; no spinner, separate Analyze Inventory button or manual refresh.
- **No stale cleanup results:** Previously saved directory matches are withheld while a new analysis is pending or running. Superseded snapshots are not presented as current. If analysis fails, the section shows an error without changing the completed scan's outcome.
- **Recovery and consistency:** Missing or stale saved directory analysis regenerates automatically at application startup. Changes to volume inventory also queue an update. Existing directory matching logic, persisted analysis and sorting remain unchanged.
- Source storage stays read-only. Existing authentication, permissions, MQTT, Prometheus and privacy behavior are unchanged; no additional external requests or data transmission are introduced.

## Upgrade

Preserve existing Compose environment, credentials, persistent database and read-only NAS mounts. Back up the persistent `/data` volume, including SQLite WAL and SHM files, with the container stopped before upgrading. Set your image to `ghcr.io/fasthowto/duplicate-file-monitor:0.6.9`, then run:

```bash
sudo docker compose pull duplicate-file-monitor
sudo docker compose up -d duplicate-file-monitor
```

Do not use `docker compose down -v`. No new configuration variables or database migrations are required.
