# Duplicate File Monitor (DFM)

**Version 0.6.3** — A read-only, Docker-hosted duplicate-file and duplicate-directory inventory tool for network storage.

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
- HTTP dashboard

## Install with Docker Compose

1. Mount the storage you want to scan on the Docker host first.
2. Copy `docker-compose.example.yml` to `docker-compose.yml`. The example uses the published image `ghcr.io/fasthowto/duplicate-file-monitor:0.6.3` (no local build required).
3. Change `/path/to/your/mounted/files` to the actual host mount path; add more **read-only** mounts and colon-delimited `SCAN_ROOTS` paths as needed.
4. Start DFM:

```sh
sudo docker compose up -d
```

**Registry access:** While the GHCR package is private, Docker must be authenticated to pull it. To test a truly unauthenticated Compose-only install, make the *container package* public in GitHub Packages after reviewing its exposure; the GitHub source repository can remain private. A pushed workflow is not proof that the image has been successfully built—check GitHub Actions and Packages first.

The dashboard footer checks the latest **published, non-prerelease GitHub Release** periodically and provides an update link when a newer release exists. Private releases are not visible to the unauthenticated browser check; it fails silently and never auto-updates.

Browse `http://your-docker-host:18080`. Allow the initial Full Scan to establish an inventory before relying on Quick Scan results.

**Security:** The web service does not include authentication. Keep it on a trusted network or use a secure reverse proxy with authentication. Do not forward its HTTP port directly to the internet. The SQLite data volume may contain MQTT connection credentials; protect its backups.

**Important:** Confirm that your NAS shares are fully mounted and accessible before scanning. DFM's logical space estimates do not account for ZFS snapshot retention, compression, deduplication, or hard links. Directory analysis uses confirmed hashes and may exclude empty directories or files without full hashes.

## Testing

```sh
python -m pip install -r requirements.txt pytest
python -m pytest -q tests
```

## License

Free noncommercial use under [PolyForm Noncommercial 1.0.0](LICENSE.md). Commercial deployment requires a separate license; see [Commercial Licensing](COMMERCIAL.md) or email **jeff@fasthowtochannel.com**.

Copyright © 2026 FastHowTo.
