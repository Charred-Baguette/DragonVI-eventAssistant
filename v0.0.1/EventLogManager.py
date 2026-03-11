from __future__ import annotations

import os
import json
import platform
import re
import uuid
import subprocess
from datetime import datetime
from pathlib import Path


# Windows-only imports — guarded so Linux runs fine without pywin32
try:
    import win32evtlog
    import win32evtlogutil
    import pywintypes
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────
#  Syslog line-format regexes (RFC 3164 and ISO-8601 variants)
# ─────────────────────────────────────────────────────────────────
_SYSLOG_RFC3164 = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<proc>[^\[:]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$'
)
_SYSLOG_ISO = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[.\d]*[+-]\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+(?P<proc>[^\[:]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$'
)

# Map Windows EventType integers to readable levels
_WIN_LEVEL = {
    1: 'ERROR',
    2: 'WARNING',
    4: 'INFO',
    8: 'AUDIT_SUCCESS',
    16: 'AUDIT_FAILURE',
}

# Default Linux log files to scan (in priority order)
_DEFAULT_LINUX_LOGS = [
    '/var/log/syslog',
    '/var/log/messages',
    '/var/log/auth.log',
    '/var/log/kern.log',
    '/var/log/daemon.log',
]


def _linux_os_source(filepath: str) -> str:
    """
    Derive a short os_source label from a Linux log file path.
    e.g. '/var/log/auth.log' -> 'auth', 'journald' -> 'journald'
    """
    if filepath == 'journald':
        return 'journald'
    name = Path(filepath).name          # 'auth.log'
    stem = name.replace('.log', '')     # 'auth'
    return stem or filepath


class EventLogManager:
    """
    Collects OS event logs (Windows Event Log / Linux syslog + journald),
    normalises them into a consistent schema, and saves them in two formats:

      • Plain JSONL  (<name>.jsonl)     — one JSON record per line; ready for
                                          LLM analysis and pattern matching.
      • Vector JSONL (<name>.vec.jsonl) — same records plus a pre-built
                                          ``text`` field for direct embedding
                                          by the Vectorizer.

    Stored records share this schema:
        id          str   – UUID4
        timestamp   str   – ISO-8601
        os_type     str   – "Windows" | "Linux"
        os_source   str   – log channel / file:
                            Windows → "System" | "Application" | "Security" | …
                            Linux   → "syslog" | "auth" | "kern" | "journald" | …
        source      str   – process / provider name (e.g. sshd, kernel)
        level       str   – INFO / WARNING / ERROR / AUDIT_SUCCESS / …
        event_id    int   – Windows event ID (None on Linux)
        pid         int   – process ID (None if unavailable)
        hostname    str
        facility    str   – syslog facility keyword (None on Windows)
        message     str   – human-readable message body
        raw         str   – original unparsed line / record
        text        str   – embedding-ready plain-text summary
    """

    def __init__(self, logger):
        self.logger = logger
        self.logs = {}                      # dict[str, list[dict]]
        self.os_type = platform.system()    # "Windows" or "Linux"
        self.data_dir = Path("event_logs")
        self.data_dir.mkdir(exist_ok=True)

    # ─────────────────────────────────────────────────────────────
    #  Internal logging helper
    # ─────────────────────────────────────────────────────────────

    def print(self, message, classification, save=False, loud=True):
        message = f'[EventLogManager] {message}'
        self.logger.log(message, classification, save=save, loud=loud)

    # ─────────────────────────────────────────────────────────────
    #  Windows Event Log collection
    # ─────────────────────────────────────────────────────────────

    def getWindowsEventLogs(
        self,
        channels=None,      # list[str] | None
        max_events=2000,    # int
        dataset_name='windows',
    ):
        """
        Retrieve Windows Event Log entries via win32evtlog (pywin32).

        channels    : list of channel names, e.g. ['System','Application',
                      'Security']. Defaults to those three.
        max_events  : maximum records to pull per channel.
        dataset_name: key used to cache and save results.
        """
        if not WIN32_AVAILABLE:
            self.print(
                'win32evtlog not available — install pywin32 on Windows.',
                'ERROR', loud=True,
            )
            return []

        if channels is None:
            channels = ['System', 'Application', 'Security']

        records = []
        flags = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                 win32evtlog.EVENTLOG_SEQUENTIAL_READ)

        for channel in channels:
            self.print(f'Reading Windows channel: {channel}', 'INFO', loud=True)
            try:
                handle = win32evtlog.OpenEventLog(None, channel)
                collected = 0
                while collected < max_events:
                    batch = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not batch:
                        break
                    for evt in batch:
                        if collected >= max_events:
                            break
                        try:
                            msg = win32evtlogutil.SafeFormatMessage(evt, channel)
                        except Exception:
                            msg = ' | '.join(evt.StringInserts or [])

                        try:
                            ts = datetime.fromtimestamp(
                                int(evt.TimeGenerated)
                            ).isoformat()
                        except Exception:
                            ts = str(evt.TimeGenerated)

                        level = _WIN_LEVEL.get(evt.EventType, 'UNKNOWN')
                        event_id = evt.EventID & 0xFFFF
                        record = self._make_record(
                            os_type='Windows',
                            os_source=channel,
                            timestamp=ts,
                            source=str(evt.SourceName),
                            level=level,
                            event_id=event_id,
                            pid=None,
                            hostname=str(evt.ComputerName),
                            facility=None,
                            message=msg.strip(),
                            raw=f'EventID={event_id} Src={evt.SourceName} '
                                f'Inserts={evt.StringInserts}',
                        )
                        records.append(record)
                        collected += 1
                win32evtlog.CloseEventLog(handle)
            except Exception as exc:
                self.print(f'Failed to read {channel}: {exc}', 'ERROR', loud=True)

        self.logs[dataset_name] = records
        self.print(
            f'Collected {len(records)} Windows records -> dataset "{dataset_name}"',
            'INFO', loud=True,
        )
        return records

    # ─────────────────────────────────────────────────────────────
    #  Linux syslog / journald collection
    # ─────────────────────────────────────────────────────────────

    def getLinuxSyslogs(
        self,
        log_files=None,             # list[str] | None
        use_journald=True,
        journald_units=None,        # list[str] | None
        journald_since='24 hours ago',
        max_lines=10000,
        dataset_name='linux',
    ):
        """
        Retrieve Linux syslog entries from flat log files and/or journald.

        log_files       : list of file paths. Defaults to common /var/log paths.
        use_journald    : also query journalctl (requires systemd).
        journald_units  : filter to specific systemd units (None = all).
        journald_since  : --since argument for journalctl.
        max_lines       : maximum lines to read per file.
        dataset_name    : key used to cache and save results.
        """
        if log_files is None:
            log_files = _DEFAULT_LINUX_LOGS

        records = []

        # ── flat log files ──────────────────────────────────────
        for path in log_files:
            if not os.path.isfile(path):
                continue
            self.print(f'Parsing log file: {path}', 'INFO', loud=True)
            try:
                with open(path, 'r', errors='replace') as fh:
                    for i, line in enumerate(fh):
                        if i >= max_lines:
                            break
                        line = line.rstrip('\n')
                        rec = self._parse_syslog_line(line, path)
                        if rec:
                            records.append(rec)
            except PermissionError:
                self.print(
                    f'Permission denied: {path} — try running as root.',
                    'WARNING', loud=True,
                )
            except Exception as exc:
                self.print(f'Error reading {path}: {exc}', 'ERROR', loud=True)

        # ── journald ────────────────────────────────────────────
        if use_journald:
            records.extend(
                self._collect_journald(journald_units, journald_since)
            )

        # De-duplicate by raw line within this collection run
        seen = set()
        unique = []
        for r in records:
            key = r['raw']
            if key not in seen:
                seen.add(key)
                unique.append(r)

        self.logs[dataset_name] = unique
        self.print(
            f'Collected {len(unique)} Linux records -> dataset "{dataset_name}"',
            'INFO', loud=True,
        )
        return unique

    def _collect_journald(self, units, since):
        """Query journalctl --output=json and parse each line."""
        cmd = ['journalctl', '--output=json', '--no-pager', '--since=' + since]
        if units:
            for u in units:
                cmd += ['-u', u]
        self.print(f'Running: {" ".join(cmd)}', 'INFO', loud=True)
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
        except FileNotFoundError:
            self.print('journalctl not found — skipping.', 'WARNING', loud=True)
            return []
        except subprocess.TimeoutExpired:
            self.print('journalctl timed out.', 'WARNING', loud=True)
            return []

        records = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue

            try:
                ts_us = int(j.get('__REALTIME_TIMESTAMP', 0))
                ts = datetime.fromtimestamp(ts_us / 1_000_000).isoformat()
            except Exception:
                ts = ''

            priority_map = {
                '0': 'EMERGENCY', '1': 'ALERT', '2': 'CRITICAL',
                '3': 'ERROR', '4': 'WARNING', '5': 'NOTICE',
                '6': 'INFO', '7': 'DEBUG',
            }
            level = priority_map.get(str(j.get('PRIORITY', '')), 'INFO')
            msg = j.get('MESSAGE', '')
            if isinstance(msg, list):
                try:
                    msg = bytes(msg).decode('utf-8', errors='replace')
                except Exception:
                    msg = str(msg)

            source = j.get('SYSLOG_IDENTIFIER') or j.get('_COMM', 'unknown')
            pid_raw = j.get('_PID') or j.get('SYSLOG_PID')
            pid = int(pid_raw) if pid_raw and str(pid_raw).isdigit() else None
            hostname = j.get('_HOSTNAME', platform.node())
            facility_num = j.get('SYSLOG_FACILITY', '')
            facility = self._syslog_facility_name(facility_num)

            record = self._make_record(
                os_type='Linux',
                os_source='journald',
                timestamp=ts,
                source=source,
                level=level,
                event_id=None,
                pid=pid,
                hostname=hostname,
                facility=facility,
                message=msg.strip(),
                raw=line,
            )
            records.append(record)

        self.print(f'journald yielded {len(records)} records.', 'INFO', loud=True)
        return records

    # ─────────────────────────────────────────────────────────────
    #  Saving — plain JSONL and vector-ready JSONL
    # ─────────────────────────────────────────────────────────────

    def saveLogs(self, dataset_name, filename=None):
        """
        Save a dataset in both formats:
          <data_dir>/<filename>.jsonl        — plain text / LLM analysis
          <data_dir>/<filename>.vec.jsonl    — vector-ready (has ``text`` field)

        Returns (plain_path, vec_path).
        """
        records = self.logs.get(dataset_name)
        if not records:
            self.print(
                f'No records for dataset "{dataset_name}". Nothing saved.',
                'WARNING', loud=True,
            )
            return (Path(), Path())

        if filename is None:
            filename = dataset_name

        plain_path = self.data_dir / (filename + '.jsonl')
        vec_path   = self.data_dir / (filename + '.vec.jsonl')

        self._write_jsonl(records, plain_path, include_text=False)
        self._write_jsonl(records, vec_path,   include_text=True)

        self.print(
            f'Saved {len(records)} records -> {plain_path} and {vec_path}',
            'INFO', loud=True,
        )
        return plain_path, vec_path

    def _write_jsonl(self, records, path, include_text):
        with open(path, 'w', encoding='utf-8') as fh:
            for rec in records:
                if include_text:
                    fh.write(json.dumps(rec, ensure_ascii=False) + '\n')
                else:
                    slim = {k: v for k, v in rec.items() if k != 'text'}
                    fh.write(json.dumps(slim, ensure_ascii=False) + '\n')

    # ─────────────────────────────────────────────────────────────
    #  Loading
    # ─────────────────────────────────────────────────────────────

    def loadLogs(self, filepath, dataset_name=None):
        """Load records from a JSONL file (plain or vec) back into memory."""
        path = Path(filepath)
        if dataset_name is None:
            dataset_name = path.stem.replace('.vec', '')

        records = []
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        records.append(json.loads(line))
        except FileNotFoundError:
            self.print(f'File not found: {filepath}', 'ERROR', loud=True)
            return []
        except Exception as exc:
            self.print(f'Failed to load {filepath}: {exc}', 'ERROR', loud=True)
            return []

        self.logs[dataset_name] = records
        self.print(
            f'Loaded {len(records)} records from {path} -> dataset "{dataset_name}"',
            'INFO', loud=True,
        )
        return records

    # ─────────────────────────────────────────────────────────────
    #  vectorizeLogs — delegates to Vectorizer
    # ─────────────────────────────────────────────────────────────

    def vectorizeLogs(self, logs):
        """
        Ensure every record has its ``text`` field set (idempotent).
        Pass the result to Vectorizer for actual embedding.
        """
        for rec in logs:
            if not rec.get('text'):
                rec['text'] = self._build_text_field(rec)
        return logs

    # ─────────────────────────────────────────────────────────────
    #  displayLogs — plain-text fallback (consoles override this)
    # ─────────────────────────────────────────────────────────────

    def displayLogs(self, logs, limit=50):
        """Print a plain-text table (used when no console is attached)."""
        sep = '-' * 110
        print(sep)
        print(f'{"TIMESTAMP":<22} {"OS_SRC":<12} {"SOURCE":<18} {"LEVEL":<14} {"MESSAGE"}')
        print(sep)
        for rec in logs[:limit]:
            ts      = rec.get('timestamp', '')[:19]
            os_src  = rec.get('os_source', '')[:11]
            src     = rec.get('source', '')[:17]
            lvl     = rec.get('level', '')[:13]
            msg     = rec.get('message', '')
            print(f'{ts:<22} {os_src:<12} {src:<18} {lvl:<14} {msg[:55]}')
        if len(logs) > limit:
            print(f'  ... {len(logs) - limit} more records not shown.')
        print(sep)

    # ─────────────────────────────────────────────────────────────
    #  condenseLogs
    # ─────────────────────────────────────────────────────────────

    def condenseLogs(self, logs):
        """
        Remove records with identical (source, level, message),
        keeping the first occurrence with a ``count`` annotation.
        """
        seen = {}
        condensed = []
        index_map = {}

        for rec in logs:
            key = (rec.get('source', ''), rec.get('level', ''), rec.get('message', ''))
            if key not in seen:
                seen[key] = 1
                rec = dict(rec)
                rec['count'] = 1
                index_map[key] = len(condensed)
                condensed.append(rec)
            else:
                seen[key] += 1
                condensed[index_map[key]]['count'] = seen[key]

        self.print(
            f'Condensed {len(logs)} -> {len(condensed)} unique records.',
            'INFO', loud=True,
        )
        return condensed

    # ─────────────────────────────────────────────────────────────
    #  Internal helpers
    # ─────────────────────────────────────────────────────────────

    def _make_record(
        self,
        *,
        os_type,
        os_source,
        timestamp,
        source,
        level,
        event_id,
        pid,
        hostname,
        facility,
        message,
        raw,
    ):
        rec = {
            'id':        str(uuid.uuid4()),
            'timestamp': timestamp,
            'os_type':   os_type,
            'os_source': os_source,
            'source':    source,
            'level':     level,
            'event_id':  event_id,
            'pid':       pid,
            'hostname':  hostname,
            'facility':  facility,
            'message':   message,
            'raw':       raw,
            'text':      '',
        }
        rec['text'] = self._build_text_field(rec)
        return rec

    def _build_text_field(self, rec):
        """
        Compose an embedding-ready plain-text summary.
        Consistent format so similar events produce similar vectors.
        """
        parts = [
            '[' + rec.get('timestamp', '') + ']',
            '[' + rec.get('level', 'INFO') + ']',
            '[' + rec.get('os_type', '') + ':' + rec.get('os_source', '') + ']',
        ]
        if rec.get('hostname'):
            parts.append('host=' + rec['hostname'])
        if rec.get('source'):
            parts.append('source=' + rec['source'])
        if rec.get('pid'):
            parts.append('pid=' + str(rec['pid']))
        if rec.get('event_id'):
            parts.append('event_id=' + str(rec['event_id']))
        if rec.get('facility'):
            parts.append('facility=' + rec['facility'])
        parts.append(rec.get('message', ''))
        return ' '.join(parts)

    def _parse_syslog_line(self, line, filepath):
        """Parse a syslog line into a normalised record. Returns None on blank."""
        line = line.strip()
        if not line:
            return None

        os_src = _linux_os_source(filepath)

        m = _SYSLOG_ISO.match(line)
        if m:
            ts     = m.group('ts')
            host   = m.group('host')
            source = m.group('proc').strip()
            pid    = int(m.group('pid')) if m.group('pid') else None
            msg    = m.group('msg')
        else:
            m = _SYSLOG_RFC3164.match(line)
            if m:
                year = datetime.now().year
                raw_ts = '{} {} {} {}'.format(
                    year, m.group('month'), m.group('day'), m.group('time')
                )
                try:
                    ts = datetime.strptime(raw_ts, '%Y %b %d %H:%M:%S').isoformat()
                except ValueError:
                    ts = raw_ts
                host   = m.group('host')
                source = m.group('proc').strip()
                pid    = int(m.group('pid')) if m.group('pid') else None
                msg    = m.group('msg')
            else:
                return self._make_record(
                    os_type='Linux',
                    os_source=os_src,
                    timestamp='',
                    source='unknown',
                    level='UNKNOWN',
                    event_id=None,
                    pid=None,
                    hostname=platform.node(),
                    facility=None,
                    message=line,
                    raw=line,
                )

        level    = self._infer_level(source, msg)
        facility = self._infer_facility(source)

        return self._make_record(
            os_type='Linux',
            os_source=os_src,
            timestamp=ts,
            source=source,
            level=level,
            event_id=None,
            pid=pid,
            hostname=host,
            facility=facility,
            message=msg,
            raw=line,
        )

    @staticmethod
    def _infer_level(source, message):
        combined = (source + ' ' + message).lower()
        if any(w in combined for w in ('error', 'fail', 'fatal', 'crit', 'panic')):
            return 'ERROR'
        if any(w in combined for w in ('warn', 'warning')):
            return 'WARNING'
        if any(w in combined for w in ('debug',)):
            return 'DEBUG'
        if any(w in combined for w in ('notice',)):
            return 'NOTICE'
        return 'INFO'

    @staticmethod
    def _infer_facility(source):
        src = source.lower()
        if src in ('kernel', 'kern'):    return 'kern'
        if 'ssh' in src:                 return 'auth'
        if src in ('sudo', 'su', 'pam'): return 'auth'
        if 'cron' in src:                return 'cron'
        if 'mail' in src:                return 'mail'
        if src in ('systemd', 'init'):   return 'daemon'
        return 'user'

    @staticmethod
    def _syslog_facility_name(num):
        _MAP = {
            0: 'kern',   1: 'user',   2: 'mail',    3: 'daemon',
            4: 'auth',   5: 'syslog', 6: 'lpr',     7: 'news',
            8: 'uucp',   9: 'cron',  10: 'authpriv', 16: 'local0',
            17: 'local1', 18: 'local2', 19: 'local3',
            20: 'local4', 21: 'local5', 22: 'local6', 23: 'local7',
        }
        try:
            return _MAP.get(int(num))
        except (ValueError, TypeError):
            return None
