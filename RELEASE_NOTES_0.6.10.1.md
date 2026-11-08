# Duplicate File Monitor v0.6.10.1

## Fixed

- **Consistent column sorting:** Duplicate Files now uses clickable column headers like Duplicate Directories. Sort by filename, file size, copies, or wasted space; select a header again to reverse direction. The active column displays its sort arrow, and keyboard navigation remains supported. Sorting operates across the confirmed duplicate-file inventory before pagination.
- **Search layout:** The Search button remains immediately to the right of the filename/path search box, including at narrower dashboard widths.
- **Correct update notices:** The browser uses the version supplied by the running DFM server instead of a stale hardcoded UI version. Release comparisons support four-component version numbers such as v0.6.10.1, so an installed release no longer reports itself as an available update.

## Unchanged

Scan and directory-match engines, automatic directory analysis, scan history, read-only source mounts, authentication, permissions, MQTT, Prometheus and existing privacy safeguards remain unchanged. No additional external requests or data transmission are introduced.

## Upgrade

Keep your current Docker Compose settings, credentials, persistent database, monitoring integrations and read-only NAS mounts. Back up the persistent `/data` volume with the container stopped, including SQLite WAL and SHM files. Update the image to `ghcr.io/fasthowto/duplicate-file-monitor:0.6.10.1`, then run:

```bash
sudo docker compose pull duplicate-file-monitor
sudo docker compose up -d duplicate-file-monitor
```

Do not run `docker compose down -v`. No new environment variables or database schema changes are required.
