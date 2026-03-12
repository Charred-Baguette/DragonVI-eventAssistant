from __future__ import annotations

import time
from collections import Counter

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn, TextColumn,
        TimeElapsedColumn, TaskProgressColumn,
    )
    from rich.columns import Columns
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────
#  Colour / style maps
# ─────────────────────────────────────────────────────────────────

_LEVEL_STYLE = {
    'ERROR':         'bold red',
    'CRITICAL':      'bold red',
    'EMERGENCY':     'bold red',
    'ALERT':         'bold red',
    'AUDIT_FAILURE': 'bold red',
    'WARNING':       'yellow',
    'NOTICE':        'cyan',
    'INFO':          'green',
    'AUDIT_SUCCESS': 'bright_green',
    'DEBUG':         'dim',
    'UNKNOWN':       'bright_black',
}

# Windows channels
_WIN_SOURCE_STYLE = {
    'System':      'bold blue',
    'Application': 'cyan',
    'Security':    'bold red',
    'Setup':       'magenta',
    'Forwarded':   'yellow',
}

# Linux log sources
_LIN_SOURCE_STYLE = {
    'auth':      'bold red',
    'syslog':    'green',
    'kern':      'bold yellow',
    'messages':  'bright_white',
    'daemon':    'cyan',
    'journald':  'blue',
}


def _level_style(level: str) -> str:
    return _LEVEL_STYLE.get(level, 'white')


def _os_source_style(os_source: str) -> str:
    style = _WIN_SOURCE_STYLE.get(os_source) or _LIN_SOURCE_STYLE.get(os_source)
    return style or 'bright_white'


class RichConsole:
    """
    Rich-powered console compatible with the Logger interface.

    Wraps an optional Logger for file saving while providing styled
    terminal output via the ``rich`` library.

    Drop-in replacement for Logger wherever a ``.log()`` method is expected.
    """

    def __init__(self, logger=None):
        self.logger = logger
        if RICH_AVAILABLE:
            self._console = Console()
        else:
            self._console = None

    # ─────────────────────────────────────────────────────────────
    #  Logger-compatible interface
    # ─────────────────────────────────────────────────────────────

    def log(self, message, classification, save=False, loud=True):
        """
        Compatible with Logger.log(). Saves to file via wrapped Logger
        and prints styled output to the terminal.
        """
        if self.logger and save:
            self.logger.log(message, classification, save=True, loud=False)

        if loud:
            ts    = time.strftime('%Y-%m-%d %H:%M:%S')
            style = _level_style(classification)
            if RICH_AVAILABLE:
                self._console.print(
                    f'[dim]{ts}[/dim] [{style}][{classification}][/{style}] {message}'
                )
            else:
                print(f'[{ts}] [{classification}] {message}')

    # ─────────────────────────────────────────────────────────────
    #  Panel / section headers
    # ─────────────────────────────────────────────────────────────

    def panel(self, title: str, subtitle: str = '', style: str = 'bold blue') -> None:
        """Print a styled section header panel."""
        if RICH_AVAILABLE:
            self._console.print(Panel(
                subtitle or '',
                title=title,
                border_style=style,
                expand=True,
            ))
        else:
            border = '=' * 70
            print(f'\n{border}\n  {title}  {subtitle}\n{border}')

    def rule(self, title: str = '', style: str = 'dim') -> None:
        """Print a horizontal rule."""
        if RICH_AVAILABLE:
            self._console.rule(title, style=style)
        else:
            print(f'--- {title} ---')

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
        Display log records in a rich Table.

        Columns: TIMESTAMP | OS SOURCE | SOURCE | LEVEL | PID | MESSAGE
        """
        if not RICH_AVAILABLE:
            self._fallback_table(logs, title, limit)
            return

        table = Table(
            title=title,
            box=box.ROUNDED,
            show_lines=False,
            highlight=True,
            expand=True,
        )
        table.add_column('TIMESTAMP',  style='dim',          width=20, no_wrap=True)
        table.add_column('OS SOURCE',  width=12,             no_wrap=True)
        table.add_column('SOURCE',     style='bright_white', width=16, no_wrap=True)
        table.add_column('LEVEL',      width=14,             no_wrap=True)
        table.add_column('PID',        style='dim',          width=7,  justify='right')
        table.add_column('MESSAGE',    ratio=1,              no_wrap=False)

        for rec in logs[:limit]:
            ts      = (rec.get('timestamp') or '')[:19]
            os_src  = rec.get('os_source') or ''
            source  = rec.get('source') or ''
            level   = rec.get('level') or 'INFO'
            pid     = str(rec.get('pid') or '')
            message = rec.get('message') or ''

            lvl_text   = Text(level,   style=_level_style(level))
            os_src_text = Text(os_src, style=_os_source_style(os_src))

            table.add_row(ts, os_src_text, source, lvl_text, pid, message)

        self._console.print(table)
        if len(logs) > limit:
            self._console.print(
                f'[dim]  ... {len(logs) - limit} more records not shown.[/dim]'
            )

    def _fallback_table(self, logs, title, limit):
        sep = '-' * 110
        print(f'\n{title}')
        print(sep)
        print(f'{"TIMESTAMP":<22} {"OS_SRC":<12} {"SOURCE":<18} {"LEVEL":<14} {"PID":<7} {"MESSAGE"}')
        print(sep)
        for rec in logs[:limit]:
            print('{:<22} {:<12} {:<18} {:<14} {:<7} {}'.format(
                (rec.get('timestamp') or '')[:19],
                (rec.get('os_source') or '')[:11],
                (rec.get('source') or '')[:17],
                (rec.get('level') or '')[:13],
                str(rec.get('pid') or ''),
                (rec.get('message') or '')[:60],
            ))
        if len(logs) > limit:
            print(f'  ... {len(logs) - limit} more records not shown.')
        print(sep)

    # ─────────────────────────────────────────────────────────────
    #  Summary panel
    # ─────────────────────────────────────────────────────────────

    def display_summary(self, logs: list, title: str = 'Summary') -> None:
        """Print a summary panel: counts by level and by os_source."""
        level_counts  = Counter(r.get('level', 'UNKNOWN') for r in logs)
        source_counts = Counter(r.get('os_source', '?') for r in logs)

        if not RICH_AVAILABLE:
            print(f'\n--- {title} ({len(logs)} records) ---')
            print('By level:    ', dict(level_counts))
            print('By os_source:', dict(source_counts))
            return

        # Level table
        lvl_table = Table(box=box.SIMPLE, show_header=True, expand=False)
        lvl_table.add_column('Level',  style='bold')
        lvl_table.add_column('Count',  justify='right')
        for level, count in level_counts.most_common():
            lvl_table.add_row(
                Text(level, style=_level_style(level)),
                str(count),
            )

        # OS source table
        src_table = Table(box=box.SIMPLE, show_header=True, expand=False)
        src_table.add_column('OS Source', style='bold')
        src_table.add_column('Count',     justify='right')
        for src, count in source_counts.most_common():
            src_table.add_row(
                Text(src, style=_os_source_style(src)),
                str(count),
            )

        self._console.print(Panel(
            Columns([lvl_table, src_table], equal=True, expand=True),
            title=f'{title} — {len(logs)} records',
            border_style='bright_blue',
        ))

    # ─────────────────────────────────────────────────────────────
    #  Progress tracking
    # ─────────────────────────────────────────────────────────────

    def track(self, iterable, description: str = 'Processing', total=None):
        """
        Wrap an iterable with a rich progress bar.
        Falls back to plain iteration if rich is unavailable.
        """
        if not RICH_AVAILABLE:
            for item in iterable:
                yield item
            return

        items = list(iterable)
        total = total or len(items)
        with Progress(
            SpinnerColumn(),
            TextColumn('[progress.description]{task.description}'),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self._console,
            transient=True,
        ) as progress:
            task = progress.add_task(description, total=total)
            for item in items:
                yield item
                progress.advance(task)

    def progress_context(self):
        """
        Return a rich Progress context manager for manual task control.
        Usage:
            with console.progress_context() as p:
                t = p.add_task('Loading...', total=None)
                do_work()
        """
        if RICH_AVAILABLE:
            return Progress(
                SpinnerColumn(),
                TextColumn('[progress.description]{task.description}'),
                BarColumn(),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=self._console,
                transient=True,
            )
        return _NullProgress()


class _NullProgress:
    """No-op progress context for when rich is unavailable."""
    def __enter__(self):
        return self
    def __exit__(self, *a):
        pass
    def add_task(self, desc, **kw):
        print(f'[...] {desc}')
        return 0
    def advance(self, task, advance=1):
        pass
    def stop(self):
        pass
    def update(self, task, **kw):
        pass
