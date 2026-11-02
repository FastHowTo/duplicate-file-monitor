# Duplicate File Monitor v0.6.1 — shorter publication lock and finalization telemetry

- Calculate per-volume confirmed-duplicate snapshot against the completed work inventory **before** the SQLite publication transaction, instead of sorting/grouping published inventory under a write lock. Unchanged duplicate attribution semantics.
- Log precise finalization timings for inventory delta, cache pruning, total publication transaction including COMMIT, pre-publication volume metrics, and entire finalization.
- Report additional `wall_clock_seconds` in scan completion logs, including finalization; preserve existing legacy `scan_duration_seconds` for compatibility.
- No changes to database schema, NAS mounts, deletion rules, lifetime savings, MQTT entities, or duplicate-directory matching.
- This optimizes the time spent holding the SQLite write transaction; the actual gain depends on database workload and storage latency. Review `Finalization timings:` in Docker logs to identify the next bottleneck.
