"""Automatic directory matching, independent of scan publication/finalization.

One daemon processes requests sequentially. Requests coalesce, and snapshots
superseded by newer successful scans are never advertised as current.
"""
import threading
import traceback

from directory_report_cache import get_directory_report, refresh_directory_report
from scanner import connect


class AutomaticDirectoryAnalysis:
    def __init__(self, db):
        self.db = db
        self._wake = threading.Event()
        self._lock = threading.Lock()
        self._state = 'idle'
        self._started = False

    def start(self):
        with self._lock:
            if self._started:
                return
            self._started = True
        threading.Thread(target=self._run, name='directory-analysis',
                         daemon=True).start()
        # Recover missing/stale analysis after a restart, without a scan or
        # heavy analysis in the startup/database-initialization thread.
        self.request()

    def request(self):
        with self._lock:
            self._state = 'pending'
            self._wake.set()

    def status(self):
        with self._lock:
            return self._state

    def _run(self):
        while True:
            self._wake.wait()
            with self._lock:
                self._wake.clear()
                self._state = 'running'
            outcome = 'completed'
            try:
                c = connect(self.db, readonly=True)
                try:
                    has_scan = c.execute(
                        "SELECT 1 FROM scans WHERE status='success' LIMIT 1"
                    ).fetchone() is not None
                    existing = get_directory_report(c, limit=500) if has_scan else None
                finally:
                    c.close()
                if not has_scan:
                    outcome = 'idle'
                elif not existing['saved'] or existing['stale']:
                    c = connect(self.db)
                    try:
                        updated = refresh_directory_report(c, limit=500)
                    finally:
                        c.close()
                    if updated['stale']:
                        # Another scan published while analysis was running.
                        # Never accept that superseded result as final.
                        self.request()
                        outcome = 'pending'
            except Exception as exc:
                outcome = 'failed'
                print('Directory analysis failed: ' + repr(exc), flush=True)
                traceback.print_exc()
            with self._lock:
                # A scan or volume change may have arrived during the work.
                # Never clear a newer request or report it as completed.
                self._state = 'pending' if self._wake.is_set() else outcome
