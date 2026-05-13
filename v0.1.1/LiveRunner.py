from __future__ import annotations

import json
import platform
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

try:
    import win32evtlog
    import win32evtlogutil
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────
#  Configuration constants
# ─────────────────────────────────────────────────────────────────

REBUILD_COUNT    = 100      # rebuild after this many new logs
REBUILD_INTERVAL = 5 * 60  # … or after this many seconds (whichever first)
AI_INTERVAL      = 30 * 60 # periodic AI optimisation call
WIN_POLL_SECS    = 5        # Windows event log poll frequency

CRITICAL_LEVELS = {'ERROR', 'CRITICAL', 'EMERGENCY', 'ALERT', 'AUDIT_FAILURE'}

WIN_CHANNELS_DEFAULT = ['System', 'Application', 'Security']


class LiveRunner:
    """
    Continuously streams OS logs (journalctl -f on Linux, win32evtlog polling
    on Windows) and keeps all four dataset variants fresh in the Vectorizer.

    Rebuild schedule
    ────────────────
    • Every REBUILD_COUNT new logs   → re-vectorize + re-pattern + save
    • Every REBUILD_INTERVAL seconds → same (even if < REBUILD_COUNT new logs)
    • Immediate on ERROR/CRITICAL    → same, then calls AI

    AI call schedule
    ────────────────
    • Immediate on ERROR/CRITICAL event (after rebuild)
    • Every AI_INTERVAL seconds for optimisation review

    Usage
    ─────
        runner = LiveRunner(elm, vec, pc, console, ai=ai_instance)
        runner.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            runner.stop()
            runner.join()
    """

    def __init__(
        self,
        elm,            # EventLogManager
        vec,            # Vectorizer
        pc,             # PatternControl
        console,        # RichConsole or BackupConsole
        ai=None,        # AIinterface (optional)
        channels=None,  # Windows channels; None = default three
        dataset_name='live_stream',
    ):
        self.elm          = elm
        self.vec          = vec
        self.pc           = pc
        self.console      = console
        self.ai           = ai
        self.channels     = channels or WIN_CHANNELS_DEFAULT
        self.dataset_name = dataset_name
        self.data_dir     = Path('event_logs')
        self.data_dir.mkdir(exist_ok=True)

        # ── Shared state ────────────────────────────────────────
        self._lock             = threading.Lock()
        self.all_logs          = []      # master list — append-only
        self._new_since_build  = []      # cleared on each rebuild

        # ── Timing ──────────────────────────────────────────────
        self._last_rebuild = time.monotonic()
        self._last_ai      = time.monotonic()

        # ── Trigger events ──────────────────────────────────────
        self._stop             = threading.Event()
        self._immediate_build  = threading.Event()   # set on CRITICAL/ERROR
        self._immediate_ai     = threading.Event()   # set on CRITICAL/ERROR

        # ── Threads ─────────────────────────────────────────────
        self._collector_thread = threading.Thread(
            target=self._run_collector, name='LR-collector', daemon=True
        )
        self._monitor_thread   = threading.Thread(
            target=self._run_monitor, name='LR-monitor', daemon=True
        )

    # ─────────────────────────────────────────────────────────────
    #  Public API
    # ─────────────────────────────────────────────────────────────

    def start(self):
        self._log('Live runner starting...')
        self._collector_thread.start()
        self._monitor_thread.start()

    def stop(self):
        self._log('Stopping live runner...')
        self._stop.set()

    def join(self, timeout=10):
        self._collector_thread.join(timeout=timeout)
        self._monitor_thread.join(timeout=timeout)

    # ─────────────────────────────────────────────────────────────
    #  Collector thread
    # ─────────────────────────────────────────────────────────────

    def _run_collector(self):
        if platform.system() == 'Windows':
            self._collect_windows()
        else:
            self._collect_linux()

    def _collect_linux(self):
        """Stream journalctl -f in JSON mode."""
        cmd = ['journalctl', '-f', '--output=json', '--no-pager']
        self._log('Starting Linux collector: ' + ' '.join(cmd))
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except FileNotFoundError:
            self._log('journalctl not found — Linux collector cannot start.', 'ERROR')
            return

        try:
            for raw_line in proc.stdout:
                if self._stop.is_set():
                    break
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    j = json.loads(raw_line)
                except json.JSONDecodeError:
                    continue
                rec = self.elm._parse_journald_entry(j, raw_line)
                self._ingest(rec)
        finally:
            try:
                proc.terminate()
            except Exception:
                pass

    def _collect_windows(self):
        """
        Poll Windows Event Logs for new records.

        Strategy: open each channel, drain all existing records (so we only
        process *new* events going forward), then loop reading the handle —
        once drained it only returns records appended after the drain.
        """
        if not WIN32_AVAILABLE:
            self._log('pywin32 not available — Windows collector cannot start.', 'ERROR')
            return

        flags_fwd = (win32evtlog.EVENTLOG_FORWARDS_READ |
                     win32evtlog.EVENTLOG_SEQUENTIAL_READ)
        handles = {}

        # ── Open handles and drain existing records ──────────────
        for ch in self.channels:
            try:
                h = win32evtlog.OpenEventLog(None, ch)
                # Drain: read until empty so position is at end
                while True:
                    batch = win32evtlog.ReadEventLog(h, flags_fwd, 0)
                    if not batch:
                        break
                handles[ch] = h
                self._log(f'Windows channel "{ch}" opened and drained.')
            except Exception as e:
                self._log(f'Cannot open channel "{ch}": {e}', 'WARNING')

        if not handles:
            self._log('No Windows channels available.', 'ERROR')
            return

        # ── Poll loop ────────────────────────────────────────────
        self._log(f'Windows collector polling every {WIN_POLL_SECS}s.')
        while not self._stop.is_set():
            for ch, h in handles.items():
                try:
                    batch = win32evtlog.ReadEventLog(h, flags_fwd, 0)
                    for evt in (batch or []):
                        rec = self.elm._parse_win_event(evt, ch)
                        self._ingest(rec)
                except Exception as e:
                    self._log(f'Error reading "{ch}": {e}', 'WARNING')
            self._stop.wait(WIN_POLL_SECS)

        for h in handles.values():
            try:
                win32evtlog.CloseEventLog(h)
            except Exception:
                pass

    # ─────────────────────────────────────────────────────────────
    #  Record ingestion
    # ─────────────────────────────────────────────────────────────

    def _ingest(self, rec):
        """Thread-safe: add record to buffers and flag critical events."""
        level    = rec.get('level', '')
        critical = level in CRITICAL_LEVELS

        with self._lock:
            self.all_logs.append(rec)
            self._new_since_build.append(rec)
            total = len(self.all_logs)
            new   = len(self._new_since_build)

        if critical:
            self._log(
                f'[{level}] {rec.get("source","")} | {rec.get("message","")[:80]}',
                level,
            )
            self._immediate_build.set()
            self._immediate_ai.set()

        # Lightweight status every 50 records
        if total % 50 == 0:
            self._log(f'Ingested {total} total logs ({new} since last rebuild).')

    # ─────────────────────────────────────────────────────────────
    #  Monitor thread
    # ─────────────────────────────────────────────────────────────

    def _run_monitor(self):
        self._log('Monitor thread started.')
        while not self._stop.is_set():
            now = time.monotonic()

            with self._lock:
                new_count = len(self._new_since_build)

            # ── Rebuild conditions ─────────────────────────────
            immediate   = self._immediate_build.is_set()
            count_hit   = new_count >= REBUILD_COUNT
            time_hit    = new_count > 0 and (now - self._last_rebuild) >= REBUILD_INTERVAL

            if immediate or count_hit or time_hit:
                reason = ('critical event' if immediate
                          else 'count threshold' if count_hit
                          else 'time interval')
                self._immediate_build.clear()
                self._rebuild(reason)

            # ── AI conditions ──────────────────────────────────
            if self._immediate_ai.is_set():
                self._immediate_ai.clear()
                self._call_ai(reason='critical_event')
            elif (now - self._last_ai) >= AI_INTERVAL:
                self._last_ai = now
                self._call_ai(reason='optimisation')

            self._stop.wait(1)  # check every second

        self._log('Monitor thread stopped.')

    # ─────────────────────────────────────────────────────────────
    #  Rebuild pipeline
    # ─────────────────────────────────────────────────────────────

    def _rebuild(self, reason='scheduled'):
        with self._lock:
            records = list(self.all_logs)
            self._new_since_build = []
        self._last_rebuild = time.monotonic()

        if not records:
            return

        name = self.dataset_name
        self._log(
            f'Rebuild triggered ({reason}) — {len(records)} total records.',
            'INFO',
        )

        # Ensure text fields are populated
        records = self.elm.vectorizeLogs(records)

        # Vectorize full dataset
        self.vec.vectorize(records, name)

        # Level and source sub-datasets
        self.vec.split_by_level(name)
        self.vec.split_by_field(name, field='os_source')

        # Pattern detection
        self.pc.run(self.vec, name)

        # Save all to disk
        self.vec.save_all(name)
        for sub in list(self.vec.list_datasets()):
            if sub.startswith(name + '__') and self.vec.get(sub, 'original'):
                self.vec.save_all(sub)

        # Also save plain + vec through EventLogManager for compatibility
        self.elm.logs[name] = records
        self.elm.saveLogs(name)

        self._log(
            f'Rebuild complete. Datasets: {len(self.vec.list_datasets())}, '
            f'Patterns: {len(self.pc.patterns)}.'
        )
        self.pc.display_patterns(self.console)

    # ─────────────────────────────────────────────────────────────
    #  AI call
    # ─────────────────────────────────────────────────────────────

    def _call_ai(self, reason='optimisation'):
        if not self.ai:
            self._log('No AI interface configured — skipping AI call.', 'WARNING')
            return

        with self._lock:
            records = list(self.all_logs)

        sample   = self.vec.get(self.dataset_name, 'sample')
        patterns = self.pc.patterns
        critical = [
            r for r in records
            if r.get('level', '') in CRITICAL_LEVELS
        ][-20:]  # last 20 critical

        prompt = self._build_prompt(reason, patterns, sample, critical, len(records))

        self._log(f'Calling AI interface (reason={reason})...')
        try:
            response = self.ai.generate_response(prompt)
        except Exception as e:
            self._log(f'AI call failed: {e}', 'ERROR')
            return

        self._log('=== AI RESPONSE ===', 'INFO')
        # Split into lines so the console can display each one cleanly
        for line in response.splitlines():
            self._log(line, 'INFO')
        self._log('=== END AI RESPONSE ===', 'INFO')

        self._save_ai_response(response, reason)
        self._last_ai = time.monotonic()

    def _build_prompt(self, reason, patterns, sample, critical_recs, total):
        ts_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        header = (
            'URGENT — Critical/Error events detected. Provide immediate triage.'
            if reason == 'critical_event'
            else 'Periodic optimisation review (30-minute interval).'
        )

        # Pattern block
        pat_lines = []
        for p in patterns[:15]:
            pat_lines.append(
                f"  [{p['type'].upper():<16}] {p['label']} "
                f"(count={p['count']}, conf={p['confidence']:.2f})"
            )
            pat_lines.append(f"    {p['description']}")
        pat_block = '\n'.join(pat_lines) if pat_lines else '  (none yet)'

        # Sample records block
        samp_lines = []
        for r in sample[:10]:
            samp_lines.append(
                '  [{ts}] [{level}] [{os_source}] {source}: {msg}'.format(
                    ts=r.get('timestamp', '')[:19],
                    level=r.get('level', ''),
                    os_source=r.get('os_source', ''),
                    source=r.get('source', ''),
                    msg=r.get('message', '')[:120],
                )
            )
        samp_block = '\n'.join(samp_lines) if samp_lines else '  (none)'

        # Critical records block
        crit_lines = []
        for r in critical_recs:
            crit_lines.append(
                '  [{ts}] [{level}] {source}: {msg}'.format(
                    ts=r.get('timestamp', '')[:19],
                    level=r.get('level', ''),
                    source=r.get('source', ''),
                    msg=r.get('message', '')[:120],
                )
            )
        crit_block = '\n'.join(crit_lines) if crit_lines else '  (none)'

        request = (
            'Analyze the critical events. Identify root causes and provide '
            'specific, actionable immediate fixes.'
            if reason == 'critical_event'
            else 'Review the patterns. Provide optimization recommendations '
                 'and preventive measures for the next 30-minute window.'
        )

        prompt = (
            f'{header}\n'
            f'Timestamp: {ts_now}\n'
            f'Total logs collected: {total}\n\n'
            f'=== DETECTED PATTERNS ===\n{pat_block}\n\n'
            f'=== SAMPLE RECORDS (representative per cluster) ===\n{samp_block}\n\n'
            f'=== RECENT CRITICAL/ERROR EVENTS ===\n{crit_block}\n\n'
            f'=== REQUEST ===\n{request}\n\n'
            f'Respond with:\n'
            f'1. Assessment: <1-2 sentences on overall system health>\n'
            f'2. Issues: <bulleted list of specific problems>\n'
            f'3. Actions: <numbered list of concrete steps to take now>\n'
        )
        return prompt

    def _save_ai_response(self, response, reason):
        """Append the AI response to the shared Responses.log file."""
        # Import here to avoid a circular import at module level
        import Main as _Main
        log_path = _Main.Main.append_responses_log(
            response,
            reason=f'live_{reason}',
            prompt='',
            data_dir=self.data_dir,
        )
        self._log(f'AI response appended -> {log_path}')

    # ─────────────────────────────────────────────────────────────
    #  Internal helper
    # ─────────────────────────────────────────────────────────────

    def _log(self, msg, level='INFO'):
        self.console.log(f'[LiveRunner] {msg}', level, loud=True)
