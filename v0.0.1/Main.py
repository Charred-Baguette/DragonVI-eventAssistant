from __future__ import annotations

import platform
import sys
from pathlib import Path

import Logger
import EventLogManager
import RichConsole
import BackupConsole

# Synthetic syslog lines used for offline demo (cross-platform)
_DEMO_LINES = [
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
    'Jan 10 12:00:11 webserver NetworkManager[800]: <info>  [1234567890.000] manager: NetworkManager state is now CONNECTED_GLOBAL',
    'Jan 10 12:00:12 webserver kernel: audit: type=1400 audit(1234567890.000:100): apparmor="DENIED" operation="open"',
    'Jan 10 12:00:13 webserver dbus-daemon[600]: [system] Successfully activated service org.freedesktop.hostname1',
    'Jan 10 12:00:14 webserver systemd[1]: Finished Daily apt upgrade and clean activities.',
]

# Synthetic Windows-style records (populated when not on Windows)
_DEMO_WIN_RECORDS = [
    ('System',      'Service Control Manager', 'INFO',          7036, 'The Print Spooler service entered the running state.'),
    ('System',      'Microsoft-Windows-Kernel-Power', 'INFO',   41,   'The system has rebooted without cleanly shutting down first.'),
    ('Application', 'VSS',                     'WARNING',       8194, 'Volume Shadow Copy Service error: Unexpected error querying for the IVssWriterCallback interface.'),
    ('Application', 'Application Error',       'ERROR',         1000, 'Faulting application name: explorer.exe, version 10.0.19041.1'),
    ('Security',    'Microsoft-Windows-Security-Auditing', 'AUDIT_SUCCESS', 4624, 'An account was successfully logged on. Subject: SYSTEM'),
    ('Security',    'Microsoft-Windows-Security-Auditing', 'AUDIT_FAILURE', 4625, 'An account failed to log on. Account Name: Administrator'),
    ('Security',    'Microsoft-Windows-Security-Auditing', 'AUDIT_SUCCESS', 4672, 'Special privileges assigned to new logon. Account Name: alice'),
    ('System',      'Disk',                    'WARNING',       51,   'An error was detected on device \\Device\\Harddisk0\\DR0 during a paging operation.'),
    ('Application', '.NET Runtime',            'ERROR',         1026, 'Application: myapp.exe\nFramework Version: v4.0.30319\nUnhandled Exception: System.NullReferenceException'),
    ('Setup',       'Microsoft-Windows-Servicing', 'INFO',      2,    'Package KB5000842 was successfully changed to the Installed state.'),
]


class Main:
    def __init__(self):
        self.logger = Logger.Logger('event_log_demo.log')
        # Both consoles wrap the same Logger for file persistence
        self.rich_console   = RichConsole.RichConsole(self.logger)
        self.backup_console = BackupConsole.BackupConsole(self.logger)

    def log(self, message, classification, save=False, loud=True):
        message = f'[Main] {message}'
        self.rich_console.log(message, classification, save=save, loud=loud)

    # ─────────────────────────────────────────────────────────────
    #  Helpers to build demo datasets
    # ─────────────────────────────────────────────────────────────

    def _build_demo_linux(self, elm):
        """Parse synthetic syslog lines into a dataset."""
        records = []
        for line in _DEMO_LINES:
            rec = elm._parse_syslog_line(line, '/var/log/auth.log')
            if rec:
                records.append(rec)
        elm.logs['demo_linux'] = records
        return records

    def _build_demo_windows(self, elm):
        """Build synthetic Windows-style records."""
        import uuid
        from datetime import datetime
        records = []
        base_ts = datetime(2026, 1, 10, 12, 0, 0)
        for i, (channel, source, level, event_id, message) in enumerate(_DEMO_WIN_RECORDS):
            from datetime import timedelta
            ts = (base_ts + timedelta(seconds=i)).isoformat()
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
        """Attempt to collect real OS logs. Returns (dataset_name, records)."""
        if platform.system() == 'Windows':
            elm.print = lambda msg, cls, save=False, loud=True: \
                self.rich_console.log(f'[EventLogManager] {msg}', cls, save=save, loud=loud)
            records = elm.getWindowsEventLogs(
                channels=['System', 'Application', 'Security'],
                max_events=100,
                dataset_name='live_windows',
            )
            return 'live_windows', records
        else:
            records = elm.getLinuxSyslogs(
                log_files=[],
                use_journald=True,
                journald_since='30 minutes ago',
                dataset_name='live_linux',
            )
            return 'live_linux', records

    # ─────────────────────────────────────────────────────────────
    #  Demo — RichConsole section
    # ─────────────────────────────────────────────────────────────

    def _demo_rich(self, elm, linux_logs, windows_logs):
        c = self.rich_console

        c.panel(
            'Event Log Assistant — Rich Console Demo',
            'Styled tables, coloured severity levels, and os_source badges',
            style='bold cyan',
        )

        # ── Linux logs ───────────────────────────────────────────
        c.rule('Linux Logs', style='green')
        c.log('Displaying synthetic Linux syslog records', 'INFO', loud=True)
        c.display_logs(linux_logs, title='Linux Syslogs (demo)', limit=len(linux_logs))
        c.display_summary(linux_logs, title='Linux Summary')

        # ── Windows logs ─────────────────────────────────────────
        c.rule('Windows Logs', style='blue')
        c.log('Displaying synthetic Windows Event Log records', 'INFO', loud=True)
        c.display_logs(windows_logs, title='Windows Event Logs (demo)', limit=len(windows_logs))
        c.display_summary(windows_logs, title='Windows Summary')

        # ── Live logs (if available) ─────────────────────────────
        c.rule('Live OS Logs', style='yellow')
        c.log('Attempting live log collection with progress bar...', 'INFO', loud=True)

        with c.progress_context() as progress:
            task = progress.add_task('Collecting live logs...', total=None)
            dataset, live_logs = self._collect_live(elm)
            progress.stop()

        if live_logs:
            c.log(f'Collected {len(live_logs)} live records.', 'INFO', loud=True)
            condensed = elm.condenseLogs(live_logs)
            c.display_logs(condensed, title=f'Live Logs — {dataset} (condensed)', limit=20)
            c.display_summary(condensed, title='Live Summary')
            elm.saveLogs(dataset)
        else:
            c.log('No live records retrieved.', 'WARNING', loud=True)

        c.rule('Rich Console demo complete')

    # ─────────────────────────────────────────────────────────────
    #  Demo — BackupConsole section
    # ─────────────────────────────────────────────────────────────

    def _demo_backup(self, elm, linux_logs, windows_logs):
        c = self.backup_console

        c.panel(
            'Event Log Assistant — Backup Console Demo',
            'tqdm-based progress, ASCII-prefixed severity, plain-text tables',
        )

        # ── Linux logs ───────────────────────────────────────────
        c.rule('Linux Logs')
        c.log('Displaying synthetic Linux syslog records', 'INFO', loud=True)
        c.display_logs(linux_logs, title='Linux Syslogs (demo)', limit=len(linux_logs))
        c.display_summary(linux_logs, title='Linux Summary')

        # ── Windows logs ─────────────────────────────────────────
        c.rule('Windows Logs')
        c.log('Displaying synthetic Windows Event Log records', 'INFO', loud=True)
        c.display_logs(windows_logs, title='Windows Event Logs (demo)', limit=len(windows_logs))
        c.display_summary(windows_logs, title='Windows Summary')

        # ── vectorizeLogs with tqdm progress ─────────────────────
        c.rule('Vectorization prep')
        c.log('Running vectorizeLogs() on all records with tqdm progress...', 'INFO', loud=True)
        all_records = linux_logs + windows_logs
        vectorized = []
        for rec in c.track(all_records, description='Vectorizing records'):
            rec_copy = dict(rec)
            if not rec_copy.get('text'):
                rec_copy['text'] = elm._build_text_field(rec_copy)
            vectorized.append(rec_copy)
        c.log(f'Vectorized {len(vectorized)} records. Sample text field:', 'INFO', loud=True)
        c.log(vectorized[1]['text'], 'DEBUG', loud=True)

        c.rule('Backup Console demo complete')

    # ─────────────────────────────────────────────────────────────
    #  Main demo entry-point
    # ─────────────────────────────────────────────────────────────

    def main(self):
        # EventLogManager uses rich_console as its logger
        elm = EventLogManager.EventLogManager(self.rich_console)

        self.log('Building demo datasets...', 'INFO', loud=True)
        linux_logs   = self._build_demo_linux(elm)
        windows_logs = self._build_demo_windows(elm)
        self.log(
            f'Demo datasets ready: {len(linux_logs)} Linux, {len(windows_logs)} Windows records.',
            'INFO', loud=True,
        )

        # ── Rich Console demo ─────────────────────────────────────
        self._demo_rich(elm, linux_logs, windows_logs)

        # ── Backup Console demo ───────────────────────────────────
        self._demo_backup(elm, linux_logs, windows_logs)

        self.log('All demos complete. Check event_logs/ for saved datasets.', 'INFO', save=True, loud=True)


if __name__ == '__main__':
    Main().main()
