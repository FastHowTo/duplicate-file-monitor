# Duplicate File Monitor v0.6.10.3

## Fixed

- **Consistent directory-analysis progress:** When a scan completes and the background duplicate-directory inventory analysis begins, the **Duplicate root directories** summary card now displays **Analyzing** followed by the same cycling `. .. ...` ellipsis already used in the Duplicate Directories section. All three indicators share the existing animation clock, and the numeric total returns automatically when analysis completes.
- **Stable summary behavior:** The ellipsis occupies a consistent width while animating. If directory analysis is unavailable or fails, the card shows an unavailable value rather than an outdated directory count.

## Unchanged

Duplicate-matching algorithms, background analysis triggers, scan reports, scanning performance, read-only NAS access, authentication, monitoring integrations and established privacy protections remain unchanged. No additional outbound connections or data transmission are introduced.

## Upgrade

Preserve existing Compose configuration, credentials, persistent SQLite data and read-only NAS mounts. Back up the persistent `/data` volume, including WAL and SHM files, with the container stopped before upgrading. Change the image to `ghcr.io/fasthowto/duplicate-file-monitor:0.6.10.3` and run:

```bash
sudo docker compose pull duplicate-file-monitor
sudo docker compose up -d duplicate-file-monitor
```

Do not use `docker compose down -v`. No database migrations or new configuration variables are required.
