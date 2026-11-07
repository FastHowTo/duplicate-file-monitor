# Duplicate File Monitor (DFM)

**Version 0.6.5** — A read-only, Docker-hosted duplicate-file and duplicate-directory inventory tool for network storage.

DFM inventories selected directories, identifies SHA-256-confirmed duplicate files, analyzes identical directory trees, and estimates redundant logical storage. **It never deletes, renames, moves, or alters source files.** Cleanup is a separate, manual administrator decision.

## Features

- Full and Quick Scans, including selected volumes
- Scheduled scans
- Duplicate-file grouping and exact duplicate-directory-tree reporting
- Saved duplicate-directory reports with staleness indication and sortable columns
- Global and per-volume inventory statistics and scan history
- Estimated lifetime logical space savings from verified duplicate removals
- MQTT publishing for Home Assistant
- Prometheus metrics
- Persistent SQLite inventory
- Built-in administrator login, authenticated API and Prometheus bearer-token access
- Immutable archived scan reports, including full paths of confirmed duplicate groups in selected volumes
- On-demand, permanently saved legacy reports, with unknown historical details explicitly marked unavailable
- Recoverable warning tracking
- HTTP dashboard

## Install with Docker Compose

1. Mount the storage you want to scan on the Docker host first.
2. Copy `docker-compose.example.yml` to `docker-compose.yml`. The example uses the published image `ghcr.io/fasthowto/duplicate-file-monitor:0.6.5` (no local build required).
3. Change `/path/to/your/mounted/files` to the actual host mount path; add more **read-only** mounts and colon-delimited `SCAN_ROOTS` paths as needed.
4. Start DFM:

```sh
sudo docker compose up -d
```

**Authentication (mandatory since v0.6.4):** Add a private `DFM_SETUP_TOKEN` (at least 24 random characters, e.g. output of `openssl rand -hex 32`) to your existing Compose environment before upgrading. By default, login requires HTTPS so the Secure session cookie works. First visit: choose your username and a 12+-character password, and enter the setup token. For a trusted HTTP-only LAN installation set `DFM_COOKIE_SECURE: "false"` explicitly. A separate `DFM_METRICS_TOKEN` (at least 24 random characters) may be configured for Prometheus bearer-token scrapes. **Read [v0.6.5 release notes](RELEASE_NOTES_0.6.5.md) before upgrading**, especially for monitoring authentication and the existing-data-volume backup.

The dashboard footer checks the latest **published, non-prerelease GitHub Release** periodically and provides an update link when a newer release exists. It never installs updates automatically.

Browse `http://your-docker-host:18080`. Allow the initial Full Scan to establish an inventory before relying on Quick Scan results.

**Security:** Built-in authentication is enabled by default. Use HTTPS, restrict network exposure, and never forward its plain HTTP port directly to the public internet. The SQLite data volume may contain MQTT connection credentials; protect its backups.

**Important:** Confirm that your NAS shares are fully mounted and accessible before scanning. DFM's logical space estimates do not account for ZFS snapshot retention, compression, deduplication, or hard links. Directory analysis uses confirmed hashes and may exclude empty directories or files without full hashes.

## Testing

```sh
python -m pip install -r requirements.txt -r requirements-dev.txt
python -m playwright install chromium
python -m pytest -q tests
```

## License

Free noncommercial use under [PolyForm Noncommercial 1.0.0](LICENSE.md). Commercial deployment requires a separate license; see [Commercial Licensing](COMMERCIAL.md) or email **jeff@fasthowtochannel.com**.

Copyright © 2026 FastHowTo.
