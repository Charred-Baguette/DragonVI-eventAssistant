from __future__ import annotations

import time
from collections import Counter

try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────
#  Level -> ASCII prefix map (no colour codes — pure text)
# ─────────────────────────────────────────────────────────────────

_LEVEL_PREFIX = {
    'ERROR':         '[!!]',
    'CRITICAL':      '[!!]',
    'EMERGENCY':     '[!!]',
    'ALERT':         '[!!]',
    'AUDIT_FAILURE': '[!F]',
    'WARNING':       '[W ]',
    'NOTICE':        '[N ]',
    'INFO':          '[  ]',
    'AUDIT_SUCCESS': '[OK]',
    'DEBUG':         '[D ]',
    'UNKNOWN':       '[? ]',
}


def _prefix(level: str) -> str:
    return _LEVEL_PREFIX.get(level, '[  ]')


def _write(line: str) -> None:
    """Thread-safe print: uses tqdm.write when available."""
    if TQDM_AVAILABLE:
        tqdm.write(line)
    else:
        print(line)


class BackupConsole:
    """
    tqdm-based fallback console compatible with the Logger interface.

    Uses tqdm.write() for all output so log lines don't corrupt active
    progress bars. No external colour dependencies — pure ASCII output.

    Drop-in replacement for Logger wherever a ``.log()`` method is expected.
    """

    def __init__(self, logger=None):
        self.logger = logger

    # ─────────────────────────────────────────────────────────────
    #  Logger-compatible interface
    # ─────────────────────────────────────────────────────────────

    def log(self, message, classification, save=False, loud=True):
        """
        Compatible with Logger.log(). Saves to file via wrapped Logger
        and prints prefixed output to the terminal.
        """
        if self.logger and save:
            self.logger.log(message, classification, save=True, loud=False)

        if loud:
            ts = time.strftime('%Y-%m-%d %H:%M:%S')
            _write(f'{_prefix(classification)} [{ts}] [{classification}] {message}')

    # ─────────────────────────────────────────────────────────────
    #  Section headers
    # ─────────────────────────────────────────────────────────────

    def panel(self, title: str, subtitle: str = '', style: str = '') -> None:
        """Print a plain-text section header."""
        border = '=' * 70
        _write('')
        _write(border)
        _write(f'  {title}')
        if subtitle:
            _write(f'  {subtitle}')
        _write(border)

    def rule(self, title: str = '', style: str = '') -> None:
        _write(f'--- {title} ' + '-' * max(0, 65 - len(title)))

    # ─────────────────────────────────────────────────────────────
    #  Log table display
    # ─────────────────────────────────────────────────────────────

    def display_logs(
        self,
        logs: list,
        title: str = 'Event Logs',
        limit: int = 50,
    ) -> None:
        """
        Display log records as a plain-text table.

        Columns: PREFIX | TIMESTAMP | OS SOURCE | SOURCE | LEVEL | PID | MESSAGE
        """
        sep = '-' * 115
        _write(f'\n{title} ({len(logs)} records)')
        _write(sep)
        _write('{:<4} {:<20} {:<12} {:<18} {:<14} {:<7} {}'.format(
            'PFX', 'TIMESTAMP', 'OS SOURCE', 'SOURCE', 'LEVEL', 'PID', 'MESSAGE'
        ))
        _write(sep)

        for rec in logs[:limit]:
            pfx     = _prefix(rec.get('level', 'INFO'))
            ts      = (rec.get('timestamp') or '')[:19]
            os_src  = (rec.get('os_source') or '')[:11]
            source  = (rec.get('source') or '')[:17]
            level   = (rec.get('level') or 'INFO')[:13]
            pid     = str(rec.get('pid') or '')[:6]
            message = (rec.get('message') or '')[:60]
            _write(f'{pfx:<4} {ts:<20} {os_src:<12} {source:<18} {level:<14} {pid:<7} {message}')

        if len(logs) > limit:
            _write(f'  ... {len(logs) - limit} more records not shown.')
        _write(sep)

    # ─────────────────────────────────────────────────────────────
    #  Summary
    # ─────────────────────────────────────────────────────────────

    def display_summary(self, logs: list, title: str = 'Summary') -> None:
        """Print summary counts by level and by os_source."""
        level_counts  = Counter(r.get('level', 'UNKNOWN') for r in logs)
        source_counts = Counter(r.get('os_source', '?') for r in logs)

        _write(f'\n--- {title} ({len(logs)} records) ---')
        _write('By level:')
        for level, count in level_counts.most_common():
            _write(f'  {_prefix(level)} {level:<16} {count}')
        _write('By os_source:')
        for src, count in source_counts.most_common():
            _write(f'  {src:<16} {count}')
        _write('')

    # ─────────────────────────────────────────────────────────────
    #  Progress tracking
    # ─────────────────────────────────────────────────────────────

    def track(self, iterable, description: str = 'Processing', total=None):
        """
        Wrap an iterable with a tqdm progress bar.
        Falls back to plain iteration if tqdm is unavailable.
        """
        if TQDM_AVAILABLE:
            yield from tqdm(
                iterable,
                desc=description,
                total=total,
                unit='rec',
                dynamic_ncols=True,
            )
        else:
            _write(f'[...] {description}')
            yield from iterable

    def progress_context(self):
        """
        Return a tqdm-compatible progress context for manual control.
        Usage:
            with console.progress_context() as p:
                bar = p.add_task('Loading...', total=100)
                for i in ...: p.advance(bar)
        """
        return _TqdmProgress()


class _TqdmProgress:
    """Thin wrapper that mimics the rich Progress API using tqdm."""

    def __init__(self):
        self._bars = {}
        self._next_id = 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        for bar in self._bars.values():
            bar.close()
        self._bars.clear()

    def add_task(self, description: str, total=None) -> int:
        tid = self._next_id
        self._next_id += 1
        if TQDM_AVAILABLE:
            self._bars[tid] = tqdm(
                total=total,
                desc=description,
                unit='rec',
                dynamic_ncols=True,
            )
        else:
            _write(f'[...] {description}')
        return tid

    def advance(self, task_id: int, advance: int = 1) -> None:
        bar = self._bars.get(task_id)
        if bar:
            bar.update(advance)

    def update(self, task_id: int, description: str = None, total=None) -> None:
        bar = self._bars.get(task_id)
        if bar:
            if description:
                bar.set_description(description)
            if total is not None:
                bar.total = total
                bar.refresh()

    def stop(self) -> None:
        for bar in self._bars.values():
            bar.close()
        self._bars.clear()
