# DFM v0.6.0 — Exact Duplicate Directory Trees

## Changes

- Read-only **Duplicate directory trees** dashboard panel, calculated on demand from the committed SQLite inventory. Displays exact matching directory tree groups, per-copy file count, logical size, and potential logical savings.
- File names and relative subfolder structure must match exactly; files must also match in size and have confirmed full SHA-256 hashes. **A directory whose contents are merely duplicated at scattered locations does NOT qualify.**
- Highest-level qualifying directory groups are preferred; their descendant results are suppressed. Scan-volume roots are never proposed as cleanup directories.
- A directory with any file lacking a completed full hash cannot be declared an exact match. This is intentionally conservative: some valid directories may not appear until every file has a verified full SHA-256 hash.
- Matching uses the committed inventory; no NAS source files are opened, modified, moved, or deleted by this report.
- Global MQTT last-scan added/removed/modified/possible-moves and duplicate/wasted-space deltas now reflect the most recent completed **All Volumes** scan, not the latest scoped scan. Global inventory totals still refresh after any successful scoped scan. Per-volume last-scan metrics retain scope-specific behavior.

## Important limitations

- DFM does not inventory *empty directories*, symlinks, ownership/ACLs or filesystem-specific metadata in the current `files` schema. An exact match means **identical inventoried file trees**, not proof that every filesystem property matches. Use the report as a cleanup planning aid, not an automatic deletion authorization.
- Confirmation relies on saved full SHA-256 hashes from successful scans. Files not fully hashed are excluded; there is no automatic data reading to complete them.
- Logical savings are estimates, not guaranteed physical space reclamation (snapshots, hard links, compression and deduplication can change actual reclaimed space).
- Directory analysis runs on request and may take time on very large inventories. No scan engine or database migration changes are made.
- Actual production SMB throughput and Docker behavior have not been tested in this environment.

## Upgrade

1. Finish any running scan. Stop the container using `sudo docker compose stop`.
2. Back up the **entire** existing persistent SQLite Docker volume (including WAL/SHM) before updating application code.
3. Unzip this complete source release over the existing application directory. It does not contain your personalized `docker-compose.yml` or database.
4. Run `sudo docker compose up -d --build`.
5. Check `curl -fsS http://localhost:18080/api/startup | python3 -m json.tool` for `ready: true`, `version: "0.6.0"`.
6. Open the dashboard, use **Analyze inventory** in Duplicate directory trees, and compare results before taking any action manually.
