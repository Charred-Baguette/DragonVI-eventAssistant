from __future__ import annotations

import platform
import re
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import Logger
import EventLogManager
import RichConsole
import BackupConsole
import Vectorizer
import PatternControl
import LiveRunner as LiveRunnerModule
import AIinterface

# ─────────────────────────────────────────────────────────────────
#  Message-template regexes for condensing repetitive records
# ─────────────────────────────────────────────────────────────────
_VAR_SUBS = [
    # IPv4 with optional port
    (re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?'), '<IP>'),
    # UUIDs
    (re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}'
                r'-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'), '<UUID>'),
    # ISO timestamps inside message
    (re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?'), '<TS>'),
    # Kernel uptime stamps  [12345.678]
    (re.compile(r'\[\s*\d+\.\d+\]'), '[<T>]'),
    # "port 22443" style
    (re.compile(r'\bport \d+'), 'port <N>'),
    # PIDs / bracketed numbers
    (re.compile(r'\[\d+\]'), '[<PID>]'),
    # File paths
    (re.compile(r'(?:/[\w.\-]+){2,}'), '<PATH>'),
    # Hex addresses
    (re.compile(r'\b0x[0-9a-fA-F]+\b'), '<HEX>'),
    # Remaining plain integers (last, so IPs/ports are already gone)
    (re.compile(r'\b\d+\b'), '<N>'),
]


def _msg_template(msg: str) -> str:
    """Strip variable parts from a log message to produce a grouping key."""
    for pattern, replacement in _VAR_SUBS:
        msg = pattern.sub(replacement, msg)
    return ' '.join(msg.split())  # normalise whitespace

# ─────────────────────────────────────────────────────────────────
#  Synthetic demo data
# ─────────────────────────────────────────────────────────────────

_DEMO_LINUX_LINES = [
    'Jan 10 12:00:00 webserver sshd[1022]: Accepted publickey for alice from 10.0.0.5 port 41222 ssh2',
    'Jan 10 12:00:01 webserver sshd[1023]: Failed password for root from 10.0.0.9 port 22 ssh2',
    'Jan 10 12:00:02 webserver sudo[2001]:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash',
    'Jan 10 12:00:03 webserver kernel: [12345.678] Out of memory: Kill process 3001 (python3) score 900',
    'Jan 10 12:00:04 webserver cron[999]: (root) CMD (/usr/bin/apt-get update)',
    'Jan 10 12:00:05 webserver systemd[1]: Starting Daily apt upgrade and clean activities...',
    'Jan 10 12:00:06 webserver kernel: [12346.000] EXT4-fs error (device sda1): ext4_find_entry: reading directory',
    'Jan 10 12:00:07 webserver sshd[1024]: Failed password for root from 10.0.0.9 port 22 ssh2',
    'Jan 10 12:00:08 webserver sshd[1025]: Failed password for root from 10.0.0.9 port 22 ssh2',
    'Jan 10 12:00:09 webserver sshd[1026]: Failed password for root from 10.0.0.9 port 22 ssh2',
    'Jan 10 12:00:10 webserver CRON[3100]: (root) CMD (test -e /run/systemd/system && systemctl --quiet is-active anacron.service)',
    'Jan 10 12:00:11 webserver NetworkManager[800]: <info> manager: NetworkManager state is now CONNECTED_GLOBAL',
    'Jan 10 12:00:12 webserver kernel: audit: type=1400 apparmor="DENIED" operation="open" profile="snap.chromium"',
    'Jan 10 12:00:13 webserver dbus-daemon[600]: [system] Successfully activated service org.freedesktop.hostname1',
    'Jan 10 12:00:14 webserver systemd[1]: Finished Daily apt upgrade and clean activities.',
    'Jan 10 12:00:15 webserver sshd[1027]: Failed password for root from 10.0.0.9 port 22 ssh2',
    'Jan 10 12:00:16 webserver sshd[1028]: error: maximum authentication attempts exceeded for root',
    'Jan 10 12:00:17 webserver kernel: [12350.001] EXT4-fs error (device sda1): ext4_find_entry: inode #2: reading directory lblock 0',
    'Jan 10 12:01:00 webserver sudo[2002]:    bob : command not allowed ; USER=root ; COMMAND=/usr/bin/passwd',
    'Jan 10 12:02:00 webserver pam_unix[3200]: session opened for user root by (uid=0)',
]

_DEMO_WIN_RECORDS = [
    ('System',      'Service Control Manager',                  'INFO',          7036, 'The Print Spooler service entered the running state.'),
    ('System',      'Microsoft-Windows-Kernel-Power',           'INFO',          41,   'The system has rebooted without cleanly shutting down first.'),
    ('Application', 'VSS',                                      'WARNING',       8194, 'Volume Shadow Copy Service error: Unexpected error querying for the IVssWriterCallback interface.'),
    ('Application', 'Application Error',                        'ERROR',         1000, 'Faulting application name: explorer.exe, version 10.0.19041.1'),
    ('Security',    'Microsoft-Windows-Security-Auditing',      'AUDIT_SUCCESS', 4624, 'An account was successfully logged on. Subject: SYSTEM'),
    ('Security',    'Microsoft-Windows-Security-Auditing',      'AUDIT_FAILURE', 4625, 'An account failed to log on. Account Name: Administrator'),
    ('Security',    'Microsoft-Windows-Security-Auditing',      'AUDIT_FAILURE', 4625, 'An account failed to log on. Account Name: Administrator'),
    ('Security',    'Microsoft-Windows-Security-Auditing',      'AUDIT_FAILURE', 4625, 'An account failed to log on. Account Name: Administrator'),
    ('Security',    'Microsoft-Windows-Security-Auditing',      'AUDIT_SUCCESS', 4672, 'Special privileges assigned to new logon. Account Name: alice'),
    ('System',      'Disk',                                     'WARNING',       51,   'An error was detected on device \\Device\\Harddisk0\\DR0 during a paging operation.'),
    ('Application', '.NET Runtime',                             'ERROR',         1026, 'Application: myapp.exe Framework Version: v4.0.30319 UnhandledException: NullReferenceException'),
    ('Setup',       'Microsoft-Windows-Servicing',              'INFO',          2,    'Package KB5000842 was successfully changed to the Installed state.'),
    ('System',      'Microsoft-Windows-WindowsUpdateClient',    'INFO',          19,   'Installation Successful: Windows successfully installed the following update: KB5000842'),
    ('Application', 'Application Error',                        'ERROR',         1000, 'Faulting application name: chrome.exe, version 99.0.4844.84'),
    ('Security',    'Microsoft-Windows-Security-Auditing',      'AUDIT_FAILURE', 4771, 'Kerberos pre-authentication failed. Account Name: svc_backup'),
]


class Main:
    def __init__(self):
        self.logger         = Logger.Logger('event_log_demo.log')
        self.rich_console   = RichConsole.RichConsole(self.logger)
        self.backup_console = BackupConsole.BackupConsole(self.logger)

    def log(self, message, classification='INFO', save=False, loud=True):
        self.rich_console.log(f'[Main] {message}', classification, save=save, loud=loud)

    # ─────────────────────────────────────────────────────────────
    #  Dataset builders
    # ─────────────────────────────────────────────────────────────

    def _build_demo_linux(self, elm):
        records = []
        for line in _DEMO_LINUX_LINES:
            rec = elm._parse_syslog_line(line, '/var/log/auth.log')
            if rec:
                records.append(rec)
        elm.logs['demo_linux'] = records
        return records

    def _build_demo_windows(self, elm):
        records = []
        base_ts = datetime(2026, 1, 10, 12, 0, 0)
        for i, (channel, source, level, event_id, message) in enumerate(_DEMO_WIN_RECORDS):
            ts = (base_ts + timedelta(seconds=i * 30)).isoformat()
            rec = elm._make_record(
                os_type='Windows',
                os_source=channel,
                timestamp=ts,
                source=source,
                level=level,
                event_id=event_id,
                pid=None,
                hostname='DESKTOP-DEMO',
                facility=None,
                message=message,
                raw=f'EventID={event_id} Src={source}',
            )
            records.append(rec)
        elm.logs['demo_windows'] = records
        return records

    def _collect_live(self, elm):
        """Collect real OS logs. Returns (dataset_name, records)."""
        if platform.system() == 'Windows':
            records = elm.getWindowsEventLogs(
                channels=['System', 'Application', 'Security'],
                max_events=300,
                dataset_name='live_windows',
            )
            return 'live_windows', records
        else:
            records = elm.getLinuxSyslogs(
                log_files=[],
                use_journald=True,
                journald_since='2 hours ago',
                dataset_name='live_linux',
            )
            return 'live_linux', records

    # ─────────────────────────────────────────────────────────────
    #  Rich Console demo section
    # ─────────────────────────────────────────────────────────────

    def _demo_rich(self, elm, linux_logs, windows_logs):
        c = self.rich_console

        c.panel(
            'Event Log Assistant — Rich Console',
            'Styled tables  |  coloured levels  |  os_source badges',
            style='bold cyan',
        )

        c.rule('Linux Demo Logs', style='green')
        c.display_logs(linux_logs, title='Linux Syslogs (demo)', limit=len(linux_logs))
        c.display_summary(linux_logs, title='Linux Summary')

        c.rule('Windows Demo Logs', style='blue')
        c.display_logs(windows_logs, title='Windows Event Logs (demo)', limit=len(windows_logs))
        c.display_summary(windows_logs, title='Windows Summary')

    # ─────────────────────────────────────────────────────────────
    #  Backup Console demo section
    # ─────────────────────────────────────────────────────────────

    def _demo_backup(self, elm, linux_logs, windows_logs):
        c = self.backup_console

        c.panel(
            'Event Log Assistant — Backup Console',
            'tqdm progress  |  ASCII severity prefixes  |  plain-text tables',
        )

        c.rule('Linux Demo Logs')
        c.display_logs(linux_logs, title='Linux Syslogs (demo)', limit=len(linux_logs))
        c.display_summary(linux_logs, title='Linux Summary')

        c.rule('Windows Demo Logs')
        c.display_logs(windows_logs, title='Windows Event Logs (demo)', limit=len(windows_logs))
        c.display_summary(windows_logs, title='Windows Summary')

    # ─────────────────────────────────────────────────────────────
    #  Vectorization + Pattern pipeline
    # ─────────────────────────────────────────────────────────────

    def _run_vectorize_and_patterns(self, vec, pc, dataset_name, records, console):
        """
        Full pipeline for one dataset:
          1. Vectorize → produces original + vectorized + matrix
          2. Level split → sub-datasets per severity (ERROR, WARNING, etc.)
          3. OS-source split → sub-datasets per channel/log-file
          4. PatternControl.run() → pattern + sample datasets
          5. Save all to disk
        """
        console.log(
            f'Vectorizing "{dataset_name}" ({len(records)} records)...', 'INFO', loud=True
        )

        # ── 1. Vectorize main dataset ─────────────────────────────
        for _ in console.track(
            [None],                         # single-step — embedding is done inside
            description=f'Embedding {dataset_name}',
        ):
            vec.vectorize(records, dataset_name)

        console.log(
            f'Vectorized. Backend: {vec._backend}, '
            f'dim={len(vec.get(dataset_name, "vectorized")[0]["embedding"])}',
            'INFO', loud=True,
        )

        # ── 2. Level splits ───────────────────────────────────────
        console.log('Creating per-level sub-datasets...', 'INFO', loud=True)
        level_datasets = vec.split_by_level(dataset_name)
        for level, sub_name in level_datasets.items():
            cnt = len(vec.get(sub_name, 'original'))
            console.log(f'  Level split: {level} -> "{sub_name}" ({cnt} records)', 'DEBUG', loud=True)

        # ── 3. OS-source splits ───────────────────────────────────
        console.log('Creating per-os_source sub-datasets...', 'INFO', loud=True)
        src_datasets = vec.split_by_field(dataset_name, field='os_source')
        for val, sub_name in src_datasets.items():
            cnt = len(vec.get(sub_name, 'original'))
            console.log(f'  Source split: {val} -> "{sub_name}" ({cnt} records)', 'DEBUG', loud=True)

        # ── 4. Pattern detection on main dataset ──────────────────
        console.log('Running pattern detection...', 'INFO', loud=True)
        with console.progress_context() as progress:
            task = progress.add_task(f'Detecting patterns in {dataset_name}...', total=None)
            pattern_recs, sample_recs, patterns = pc.run(vec, dataset_name)
            progress.stop()

        console.log(
            f'Patterns: {len(patterns)} detected, '
            f'{len(pattern_recs)} annotated records, '
            f'{len(sample_recs)} in sample.',
            'INFO', loud=True,
        )

        # ── 5. Save all to disk ───────────────────────────────────
        console.log(f'Saving all datasets for "{dataset_name}"...', 'INFO', loud=True)
        paths = vec.save_all(dataset_name)
        for variant, path in paths.items():
            console.log(f'  {variant:<12} -> {path}', 'DEBUG', loud=True)

        # Save non-empty level and source sub-datasets too
        for sub_name in list(level_datasets.values()) + list(src_datasets.values()):
            if vec.get(sub_name, 'original'):
                sub_paths = vec.save_all(sub_name)
                for variant, path in sub_paths.items():
                    console.log(f'  {sub_name}/{variant} -> {path}', 'DEBUG', loud=True)

        return patterns

    # ─────────────────────────────────────────────────────────────
    #  Display results
    # ─────────────────────────────────────────────────────────────

    def _display_pipeline_results(self, vec, pc, dataset_name, console, is_rich):
        """Show pattern summary, sample records, and level-split tables."""

        # Pattern summary
        pc.display_patterns(console)

        # Sample dataset
        sample = vec.get(dataset_name, 'sample')
        if sample:
            console.log(
                f'Sample dataset: {len(sample)} representative records (no embedding).',
                'INFO', loud=True,
            )
            if is_rich:
                self.rich_console.display_logs(
                    sample, title=f'{dataset_name} — Sample (1 per cluster)', limit=len(sample)
                )
            else:
                self.backup_console.display_logs(
                    sample, title=f'{dataset_name} — Sample', limit=len(sample)
                )

        # Show per-level sub-datasets
        for level in ('ERROR', 'WARNING', 'AUDIT_FAILURE'):
            sub_name = f'{dataset_name}__{level.lower()}'
            sub_recs = vec.get(sub_name, 'original')
            if sub_recs:
                if is_rich:
                    self.rich_console.display_logs(
                        sub_recs,
                        title=f'{dataset_name} — {level} only ({len(sub_recs)} records)',
                        limit=min(len(sub_recs), 10),
                    )
                else:
                    self.backup_console.display_logs(
                        sub_recs,
                        title=f'{dataset_name} — {level} only',
                        limit=min(len(sub_recs), 10),
                    )

    # ─────────────────────────────────────────────────────────────
    #  One-shot live snapshot (used inside main() demo)
    # ─────────────────────────────────────────────────────────────

    def _demo_live_snapshot(self, elm, vec, pc):
        """Collect a one-shot snapshot of live OS logs, vectorize, pattern-detect."""
        c = self.rich_console

        c.rule('Live OS Log Snapshot', style='yellow')
        c.log('Collecting live OS logs (snapshot)...', 'INFO', loud=True)

        with c.progress_context() as progress:
            task = progress.add_task('Collecting live logs...', total=None)
            dataset_name, live_logs = self._collect_live(elm)
            progress.stop()

        if not live_logs:
            c.log('No live records retrieved.', 'WARNING', loud=True)
            return

        c.log(f'Collected {len(live_logs)} live records.', 'INFO', loud=True)
        elm.saveLogs(dataset_name)
        c.display_logs(live_logs, title=f'Live: {dataset_name} (first 15)', limit=15)
        c.display_summary(live_logs, title='Live Summary')

        self._run_vectorize_and_patterns(vec, pc, dataset_name, live_logs, c)
        self._display_pipeline_results(vec, pc, dataset_name, c, is_rich=True)

    # ─────────────────────────────────────────────────────────────
    #  Continuous live mode  (separate entry-point from main())
    # ─────────────────────────────────────────────────────────────

    def run_live(self, ai_type=None, duration_secs=None):
        """
        Start the LiveRunner for continuous streaming log collection.

        Parameters
        ----------
        ai_type      : 'GPTAPI' | 'localModel' | None.
                       When provided, initialises AIinterface for periodic
                       AI calls and immediate triage on critical events.
        duration_secs: how long to run before auto-stopping (None = run until
                       KeyboardInterrupt).
        """
        c   = self.rich_console
        elm = EventLogManager.EventLogManager(c)
        vec = Vectorizer.Vectorizer(c)
        pc  = PatternControl.PatternControl(c)

        # ── Optional AI setup ──────────────────────────────────
        ai = None
        if ai_type:
            try:
                ai = AIinterface.AIinterface(AIType=ai_type, logger=self.logger)
                if ai_type == 'GPTAPI':
                    ai.initialize_gpt_api()
                else:
                    ai.initialize_local_model()
                c.log(f'AI interface initialised ({ai_type}).', 'INFO', loud=True)
            except Exception as e:
                c.log(f'AI init failed ({e}) — continuing without AI.', 'WARNING', loud=True)
                ai = None

        # ── Start LiveRunner ───────────────────────────────────
        c.panel(
            'Live Log Runner',
            f'Rebuild every {LiveRunnerModule.REBUILD_COUNT} logs or '
            f'{LiveRunnerModule.REBUILD_INTERVAL // 60} min  |  '
            f'AI every {LiveRunnerModule.AI_INTERVAL // 60} min  |  '
            f'Immediate rebuild + AI on CRITICAL/ERROR',
            style='bold yellow',
        )

        runner = LiveRunnerModule.LiveRunner(
            elm=elm, vec=vec, pc=pc,
            console=c, ai=ai,
            dataset_name='live_stream',
        )
        runner.start()

        try:
            if duration_secs:
                c.log(f'Running for {duration_secs}s then stopping...', 'INFO', loud=True)
                end = time.monotonic() + duration_secs
                while time.monotonic() < end:
                    time.sleep(1)
            else:
                c.log('Press Ctrl+C to stop.', 'INFO', loud=True)
                while True:
                    time.sleep(1)
        except KeyboardInterrupt:
            c.log('KeyboardInterrupt received.', 'INFO', loud=True)
        finally:
            runner.stop()
            runner.join(timeout=15)

        # ── Final state ────────────────────────────────────────
        total = len(runner.all_logs)
        c.log(f'Live run complete. Total logs ingested: {total}.', 'INFO', save=True, loud=True)

        if total > 0:
            c.display_summary(runner.all_logs, title='Final Live Summary')
            all_ds = vec.list_datasets()
            c.log(f'Datasets in memory: {len(all_ds)}', 'INFO', loud=True)
            for name in all_ds:
                entry  = vec.store[name]
                n_orig = len(entry.get('original', []))
                n_pat  = len(entry.get('pattern', []))
                n_samp = len(entry.get('sample', []))
                c.log(
                    f'  {name:<40} orig={n_orig} pattern={n_pat} sample={n_samp}',
                    'INFO', loud=True,
                )

    # ─────────────────────────────────────────────────────────────
    #  AI consultation helpers
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _condense_records(records, max_per_template=2):
        """
        Collapse repetitive records by message template.

        Records whose (source, level, message_template) are identical are
        merged into a single entry with a ``count`` field and
        ``condensed=True``.  Only ``max_per_template`` unique templates are
        kept per (source, level) pair to bound token usage further.

        Returns the condensed list sorted by count descending.
        """
        groups = defaultdict(list)
        for rec in records:
            template = _msg_template(rec.get('message', ''))
            key = (rec.get('source', ''), rec.get('level', ''), template)
            groups[key].append(rec)

        condensed = []
        for (source, level, template), recs in groups.items():
            representative = dict(recs[0])          # keep first as base
            representative['message']   = template  # replace with template
            representative['count']     = len(recs)
            representative['condensed'] = True
            condensed.append(representative)

        # Sort most-frequent first, cap total entries
        condensed.sort(key=lambda r: r['count'], reverse=True)
        return condensed

    @staticmethod
    def _format_records_block(records, max_records=30, indent='  '):
        """Format a list of (possibly condensed) records as a prompt text block."""
        lines = []
        for rec in records[:max_records]:
            count  = rec.get('count', 1)
            prefix = f'x{count:<4}' if count > 1 else '     '
            ts     = (rec.get('timestamp') or '')[:19]
            level  = rec.get('level', '')
            src    = rec.get('source', '')
            os_src = rec.get('os_source', '')
            msg    = (rec.get('message') or '')[:120]
            lines.append(
                f'{indent}{prefix} [{ts}] [{level}] [{os_src}] {src}: {msg}'
            )
        if len(records) > max_records:
            lines.append(f'{indent}... {len(records) - max_records} more (omitted)')
        return '\n'.join(lines) if lines else f'{indent}(none)'

    def _build_ai_consultation_prompt(self, vec, pc):
        """
        Assemble a comprehensive prompt from ALL in-memory datasets and patterns.

        Repetitive records are condensed via _condense_records() before being
        included so that token usage scales with unique event types, not volume.
        """
        ts_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        all_ds = vec.list_datasets()

        # ── Gather all patterns across every dataset ──────────────
        all_patterns = list(pc.patterns)  # PatternControl keeps last-run patterns

        # ── Gather all error/critical records across all datasets ─
        error_levels = {'ERROR', 'CRITICAL', 'EMERGENCY', 'ALERT', 'AUDIT_FAILURE'}
        all_errors   = []
        ds_stats     = {}        # dataset_name -> Counter of levels
        error_blocks = []        # (dataset_name, condensed_records)

        for ds_name in all_ds:
            originals = vec.get(ds_name, 'original')
            if not originals:
                continue
            level_counter = Counter(r.get('level', '') for r in originals)
            ds_stats[ds_name] = level_counter

            errors = [r for r in originals if r.get('level', '') in error_levels]
            if errors:
                condensed_errors = self._condense_records(errors)
                all_errors.extend(errors)
                error_blocks.append((ds_name, condensed_errors))

        # ── Gather sample records (already representative, one per cluster) ──
        sample_blocks = []
        for ds_name in all_ds:
            # Skip sub-datasets (they have __ in name) to avoid redundancy
            if '__' in ds_name:
                continue
            sample = vec.get(ds_name, 'sample')
            if sample:
                sample_blocks.append((ds_name, sample))

        # ── Overview block ─────────────────────────────────────────
        os_types = set()
        total_records = 0
        for ds_name in all_ds:
            for r in vec.get(ds_name, 'original'):
                os_types.add(r.get('os_type', '?'))
                total_records += 1

        overview = (
            f'Timestamp       : {ts_now}\n'
            f'Total datasets  : {len(all_ds)}\n'
            f'Total records   : {total_records}\n'
            f'OS types        : {", ".join(sorted(os_types))}\n'
            f'Total errors    : {len(all_errors)}\n'
            f'Patterns found  : {len(all_patterns)}'
        )

        # ── Pattern block ──────────────────────────────────────────
        pat_lines = []
        for p in all_patterns:
            pat_lines.append(
                f"  [{p['type'].upper():<16}] {p['label']} "
                f"(count={p['count']}, conf={p['confidence']:.2f})"
            )
            pat_lines.append(f"    {p['description']}")
        pat_block = '\n'.join(pat_lines) if pat_lines else '  (none detected)'

        # ── Error block (condensed) ────────────────────────────────
        err_section_lines = []
        for ds_name, condensed in error_blocks:
            n_orig = sum(r.get('count', 1) for r in condensed)
            err_section_lines.append(
                f'\n  Dataset: {ds_name} '
                f'({n_orig} error records -> {len(condensed)} unique templates)'
            )
            err_section_lines.append(
                self._format_records_block(condensed, max_records=20, indent='    ')
            )
        err_block = '\n'.join(err_section_lines) if err_section_lines else '  (none)'

        # ── Sample block ───────────────────────────────────────────
        samp_section_lines = []
        for ds_name, sample in sample_blocks:
            condensed_sample = self._condense_records(sample)
            samp_section_lines.append(f'\n  Dataset: {ds_name}')
            samp_section_lines.append(
                self._format_records_block(condensed_sample, max_records=10, indent='    ')
            )
        samp_block = '\n'.join(samp_section_lines) if samp_section_lines else '  (none)'

        # ── Level distribution ─────────────────────────────────────
        stats_lines = []
        for ds_name, counter in ds_stats.items():
            if '__' in ds_name:
                continue  # skip sub-datasets, keep it readable
            parts = '  '.join(f'{lvl}={cnt}' for lvl, cnt in counter.most_common())
            stats_lines.append(f'  {ds_name:<35} {parts}')
        stats_block = '\n'.join(stats_lines) if stats_lines else '  (none)'

        prompt = (
            '=== SYSTEM LOG ANALYSIS — COMPREHENSIVE OPTIMIZATION CONSULTATION ===\n\n'
            f'{overview}\n\n'
            '=== ALL DETECTED PATTERNS ===\n'
            f'{pat_block}\n\n'
            '=== ERROR / CRITICAL RECORDS (condensed — x<N> = repeated occurrences) ===\n'
            f'{err_block}\n\n'
            '=== REPRESENTATIVE SAMPLE RECORDS PER CLUSTER ===\n'
            f'{samp_block}\n\n'
            '=== LEVEL DISTRIBUTION BY DATASET ===\n'
            f'{stats_block}\n\n'
            '=== REQUEST ===\n'
            'You are a senior system administrator and security analyst.\n'
            'Based on ALL of the above datasets, patterns, error records, and statistics:\n\n'
            '1. Security Assessment  — identify threats and their severity\n'
            '2. Stability Issues     — identify performance or crash-risk problems\n'
            '3. Root Cause Analysis  — specific root cause for each distinct error pattern\n'
            '4. Immediate Actions    — numbered concrete steps to take RIGHT NOW\n'
            '5. Optimization Plan    — long-term improvements and preventive measures\n'
            '6. Monitoring Guidance  — what metrics/logs to watch going forward\n\n'
            'Be specific, reference the actual source names and event patterns above.\n'
        )
        return prompt

    # ─────────────────────────────────────────────────────────────
    #  Shared Responses.log writer
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def append_responses_log(response, reason, prompt='', data_dir=None):
        """
        Append an AI response to the shared Responses.log file (append mode).
        All AI calls — consultation, live critical triage, periodic optimisation
        — funnel through here so there is one canonical response history.

        Format per entry:
            ════ [timestamp] reason ════
            --- PROMPT SUMMARY ---
            <first 500 chars of prompt>
            --- RESPONSE ---
            <full response>
            ════════════════════
        """
        if data_dir is None:
            data_dir = Path('event_logs')
        Path(data_dir).mkdir(exist_ok=True)
        log_path = Path(data_dir) / 'Responses.log'
        ts       = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        divider  = '=' * 80

        with open(log_path, 'a', encoding='utf-8') as fh:
            fh.write(f'\n{divider}\n')
            fh.write(f'[{ts}]  reason={reason}\n')
            fh.write(f'{divider}\n')
            if prompt:
                fh.write('--- PROMPT SUMMARY (first 500 chars) ---\n')
                fh.write(prompt[:500].replace('\n', ' ') + '\n')
                fh.write('--- RESPONSE ---\n')
            fh.write(response)
            fh.write(f'\n{divider}\n')

        return log_path

    # ─────────────────────────────────────────────────────────────
    #  Interactive helpers
    # ─────────────────────────────────────────────────────────────

    @staticmethod
    def _ask(question, choices):
        """
        Print a question with numbered choices and return the chosen key.
        Reprompts on invalid input.  Returns None on EOF / KeyboardInterrupt.

        choices : list of (key, label) tuples, e.g. [('y','Yes'),('n','No')]
        """
        print()
        print(f'  {question}')
        for i, (_, label) in enumerate(choices, 1):
            print(f'    {i}) {label}')
        keys = [k for k, _ in choices]
        while True:
            try:
                raw = input(f'  Select [{"/".join(str(i) for i in range(1, len(choices)+1))}]: ').strip()
            except (EOFError, KeyboardInterrupt):
                return None
            if raw.isdigit() and 1 <= int(raw) <= len(choices):
                return keys[int(raw) - 1]
            # also accept the key directly (e.g. 'y', 'n')
            if raw.lower() in keys:
                return raw.lower()
            print(f'  Invalid choice. Please enter a number 1–{len(choices)}.')

    def _init_ai(self):
        """
        Ask the user which AI backend to use and initialise it.
        Returns an AIinterface instance, or None if skipped / failed.
        """
        c      = self.rich_console
        choice = self._ask(
            'Select AI backend:',
            [('gpt',   'GPTAPI     — OpenAI GPT (requires OPENAI_API_KEY env var)'),
             ('local', 'localModel — local model server (127.0.0.1:8888)'),
             ('skip',  'Skip AI')],
        )
        if choice in (None, 'skip'):
            c.log('AI consultation skipped.', 'INFO', loud=True)
            return None

        ai_type = 'GPTAPI' if choice == 'gpt' else 'localModel'
        try:
            ai = AIinterface.AIinterface(AIType=ai_type, logger=self.logger)
            if ai_type == 'GPTAPI':
                ai.initialize_gpt_api()
            else:
                ai.initialize_local_model()
            c.log(f'AI interface ready ({ai_type}).', 'INFO', loud=True)
            return ai
        except Exception as e:
            c.log(f'AI initialisation failed: {e}', 'ERROR', loud=True)
            return None

    def _prompt_ai_consultation(self, vec, pc):
        """
        Ask the user if they want an AI optimization consultation.
        Builds a prompt from all in-memory datasets, calls AI, displays the
        response, and appends it to Responses.log.
        """
        c = self.rich_console
        c.rule('AI Optimization Consultation', style='bold magenta')

        choice = self._ask(
            'Would you like the AI to generate optimization measures and fixes?',
            [('y', 'Yes — run AI consultation now'),
             ('n', 'No  — skip')],
        )
        if choice != 'y':
            c.log('AI consultation skipped.', 'INFO', loud=True)
            return

        ai = self._init_ai()
        if ai is None:
            return

        c.log('Building comprehensive prompt from all datasets...', 'INFO', loud=True)
        prompt    = self._build_ai_consultation_prompt(vec, pc)
        token_est = len(prompt.split())
        c.log(
            f'Prompt ready: ~{token_est} words across '
            f'{len(vec.list_datasets())} datasets.',
            'INFO', loud=True,
        )

        with c.progress_context() as progress:
            progress.add_task('Waiting for AI response...', total=None)
            try:
                response = ai.generate_response(prompt)
            except Exception as e:
                progress.stop()
                c.log(f'AI call failed: {e}', 'ERROR', loud=True)
                return
            progress.stop()

        # Display
        c.rule('AI Response', style='magenta')
        for line in response.splitlines():
            c.log(line, 'INFO', loud=True)
        c.rule('End of AI Response', style='magenta')

        # Save to Responses.log
        log_path = self.append_responses_log(
            response, reason='consultation', prompt=prompt,
            data_dir=vec.data_dir,
        )
        c.log(f'Response appended -> {log_path}', 'INFO', save=True, loud=True)

    # ─────────────────────────────────────────────────────────────
    #  Standard mode  (real OS logs, one-time or live)
    # ─────────────────────────────────────────────────────────────

    def run_standard(self):
        """
        Collect real OS logs, analyse them, then let the user choose between
        a one-time report or switching to continuous live-watch mode.
        Finally offer the AI consultation.
        """
        c   = self.rich_console
        elm = EventLogManager.EventLogManager(c)
        vec = Vectorizer.Vectorizer(c)
        pc  = PatternControl.PatternControl(c)

        c.panel(
            'Event Log Assistant — Standard Mode',
            f'Collecting real OS logs from {platform.node()}',
            style='bold green',
        )

        # ── Collect snapshot ──────────────────────────────────────
        with c.progress_context() as progress:
            progress.add_task('Collecting OS logs...', total=None)
            dataset_name, logs = self._collect_live(elm)
            progress.stop()

        if not logs:
            c.log('No logs retrieved. Check permissions (try running as admin/root).',
                  'ERROR', loud=True)
            return

        c.log(f'Collected {len(logs)} records from {dataset_name}.', 'INFO', loud=True)
        elm.saveLogs(dataset_name)

        # Display snapshot
        c.display_logs(logs, title=f'{dataset_name} — snapshot (first 20)', limit=20)
        c.display_summary(logs, title='Snapshot Summary')

        # Vectorize + patterns on snapshot
        self._run_vectorize_and_patterns(vec, pc, dataset_name, logs, c)
        self._display_pipeline_results(vec, pc, dataset_name, c, is_rich=True)

        # ── Run-mode choice ───────────────────────────────────────
        run_choice = self._ask(
            'How would you like to proceed?',
            [('once', 'One-time analysis  — stay with this snapshot'),
             ('live', 'Live watch         — switch to continuous streaming')],
        )

        if run_choice == 'live':
            # Hand off to live runner; snapshot datasets remain in vec/pc
            ai_choice = self._ask(
                'Enable AI for live triage and periodic optimisation?',
                [('y', 'Yes — choose AI backend'),
                 ('n', 'No  — run without AI')],
            )
            ai = self._init_ai() if ai_choice == 'y' else None
            self._run_live_runner(elm, vec, pc, ai)
            return   # run_live_runner asks AI consultation before exiting

        # ── One-time: AI consultation ─────────────────────────────
        self._prompt_ai_consultation(vec, pc)

        c.rule('Standard mode complete')
        c.log(
            f'Datasets saved to: {vec.data_dir.resolve()}',
            'INFO', save=True, loud=True,
        )

    def _run_live_runner(self, elm, vec, pc, ai=None):
        """Shared helper: start LiveRunner and block until stopped."""
        c = self.rich_console
        c.panel(
            'Live Watch Active',
            f'Rebuild every {LiveRunnerModule.REBUILD_COUNT} logs or '
            f'{LiveRunnerModule.REBUILD_INTERVAL // 60} min  |  '
            f'Immediate rebuild + AI on ERROR/CRITICAL  |  '
            f'AI optimisation every {LiveRunnerModule.AI_INTERVAL // 60} min',
            style='bold yellow',
        )
        runner = LiveRunnerModule.LiveRunner(
            elm=elm, vec=vec, pc=pc,
            console=c, ai=ai,
            dataset_name='live_stream',
        )
        runner.start()
        try:
            c.log('Press Ctrl+C to stop live watch.', 'INFO', loud=True)
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            c.log('Stopping live watch...', 'INFO', loud=True)
        finally:
            runner.stop()
            runner.join(timeout=15)

        total = len(runner.all_logs)
        c.log(f'Live watch ended. Total logs ingested: {total}.', 'INFO', loud=True)
        if total:
            c.display_summary(runner.all_logs, title='Final Live Summary')

        # Offer AI consultation on the accumulated data
        self._prompt_ai_consultation(vec, pc)

    # ─────────────────────────────────────────────────────────────
    #  Interactive mode selector (no-arg entry point)
    # ─────────────────────────────────────────────────────────────

    def prompt_mode(self):
        """
        Ask the user which mode to run when no CLI arguments were supplied.
        """
        c = self.rich_console
        c.panel(
            'Event Log Assistant',
            'Passive log collection, vectorization, pattern detection & AI analysis',
            style='bold cyan',
        )

        choice = self._ask(
            'Select operating mode:',
            [('demo',     'Demo      — synthetic datasets + full pipeline showcase'),
             ('standard', 'Standard  — collect and analyse real OS logs'),
             ('live',     'Live      — continuous streaming with auto-rebuild & AI'),
             ('exit',     'Exit')],
        )

        if choice == 'demo':
            self.main()
        elif choice == 'standard':
            self.run_standard()
        elif choice == 'live':
            ai_choice = self._ask(
                'Enable AI for live triage and periodic optimisation?',
                [('y', 'Yes — choose AI backend'),
                 ('n', 'No  — run without AI')],
            )
            ai_type = None
            if ai_choice == 'y':
                key = self._ask(
                    'Select AI backend:',
                    [('gpt',   'GPTAPI     — OpenAI GPT'),
                     ('local', 'localModel — local server'),
                     ('skip',  'Skip')],
                )
                if key == 'gpt':
                    ai_type = 'GPTAPI'
                elif key == 'local':
                    ai_type = 'localModel'
            self.run_live(ai_type=ai_type)
        else:
            c.log('Exiting.', 'INFO', loud=True)

    # ─────────────────────────────────────────────────────────────
    #  Main entry-point
    # ─────────────────────────────────────────────────────────────

    def main(self):
        elm = EventLogManager.EventLogManager(self.rich_console)
        vec = Vectorizer.Vectorizer(self.rich_console)
        pc  = PatternControl.PatternControl(self.rich_console)

        # ── Build demo datasets ───────────────────────────────────
        self.log('Building demo datasets...')
        linux_logs   = self._build_demo_linux(elm)
        windows_logs = self._build_demo_windows(elm)
        self.log(
            f'Demo ready: {len(linux_logs)} Linux, {len(windows_logs)} Windows records.'
        )

        # ── Console display demos ─────────────────────────────────
        self._demo_rich(elm, linux_logs, windows_logs)
        self._demo_backup(elm, linux_logs, windows_logs)

        # ── Vectorization + Pattern pipeline: Linux demo ──────────
        self.rich_console.panel(
            'Vectorization & Pattern Detection — Linux Demo',
            f'{len(linux_logs)} synthetic syslog records',
            style='bold green',
        )
        self._run_vectorize_and_patterns(vec, pc, 'demo_linux', linux_logs, self.rich_console)
        self._display_pipeline_results(vec, pc, 'demo_linux', self.rich_console, is_rich=True)

        # ── Vectorization + Pattern pipeline: Windows demo ─────────
        self.rich_console.panel(
            'Vectorization & Pattern Detection — Windows Demo',
            f'{len(windows_logs)} synthetic Windows Event Log records',
            style='bold blue',
        )
        self._run_vectorize_and_patterns(vec, pc, 'demo_windows', windows_logs, self.backup_console)
        self._display_pipeline_results(vec, pc, 'demo_windows', self.backup_console, is_rich=False)

        # ── List all in-memory datasets ───────────────────────────
        self.rich_console.rule('In-memory datasets')
        all_datasets = vec.list_datasets()
        self.log(f'Total in-memory datasets: {len(all_datasets)}')
        for name in all_datasets:
            entry = vec.store[name]
            n_orig = len(entry.get('original', []))
            n_pat  = len(entry.get('pattern', []))
            n_samp = len(entry.get('sample', []))
            has_matrix = entry.get('matrix') is not None
            self.rich_console.log(
                f'  {name:<40} orig={n_orig:<5} pattern={n_pat:<5} '
                f'sample={n_samp:<4} matrix={has_matrix}',
                'INFO', loud=True,
            )

        # ── Live snapshot (one-shot, no streaming) ───────────────
        self.rich_console.panel(
            'Live OS Log Snapshot',
            'Real logs from this machine — vectorized and pattern-detected',
            style='bold yellow',
        )
        self._demo_live_snapshot(elm, vec, pc)

        # ── Final dataset inventory ───────────────────────────────
        self.rich_console.rule('In-memory datasets (final)')
        all_datasets = vec.list_datasets()
        self.log(f'Total in-memory datasets: {len(all_datasets)}')
        for name in all_datasets:
            entry  = vec.store[name]
            n_orig = len(entry.get('original', []))
            n_pat  = len(entry.get('pattern', []))
            n_samp = len(entry.get('sample', []))
            self.rich_console.log(
                f'  {name:<40} orig={n_orig:<5} pattern={n_pat:<5} sample={n_samp}',
                'INFO', loud=True,
            )

        # ── Interactive AI consultation ────────────────────────────
        self._prompt_ai_consultation(vec, pc)

        self.rich_console.rule('Complete')
        self.log(
            f'All done. {len(vec.list_datasets())} datasets in memory. '
            f'Files saved to: {vec.data_dir.resolve()}',
            save=True,
        )


if __name__ == '__main__':
    import sys

    _args = sys.argv[1:]

    def _arg(name):
        return name in _args

    def _arg_val(name):
        if name in _args:
            idx = _args.index(name)
            if idx + 1 < len(_args):
                return _args[idx + 1]
        return None

    m = Main()

    if _arg('--demo'):
        # Full demo: synthetic datasets + live snapshot + AI consultation prompt
        m.main()

    elif _arg('--standard'):
        # Real log collection: snapshot then optional live watch + AI
        m.run_standard()

    elif _arg('--live'):
        # Continuous streaming mode
        # Usage: python Main.py --live [--ai GPTAPI|localModel] [--duration N]
        ai_type  = _arg_val('--ai')
        duration = int(_arg_val('--duration')) if _arg_val('--duration') else None
        m.run_live(ai_type=ai_type, duration_secs=duration)

    else:
        # No recognised flag — ask the user interactively
        m.prompt_mode()
