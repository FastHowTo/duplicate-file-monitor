# Duplicate File Monitor v0.6.7

## Fixed

- **Scan Progress:** The File Discovery status now displays only “Discovering files…”. Removed the directory-visited count and current filesystem path from the visible status line. The existing Files Discovered counter remains unchanged.
- No changes to duplicate scanning, the SQLite inventory, report history, authentication, MQTT, Prometheus or configured NAS read-only mounts.

## Upgrade

Keep your existing Compose environment, credentials, persistent data volume and read-only source mounts. Back up the persistent `/data` volume before changing versions. Set the image to `ghcr.io/fasthowto/duplicate-file-monitor:0.6.7` and run:

```bash
sudo docker compose pull duplicate-file-monitor
sudo docker compose up -d duplicate-file-monitor
```

Do not use `docker compose down -v`.
