"""CLI: log-analyzer analyze | watch | generate."""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import sys
import time
from collections.abc import Iterable
from datetime import datetime

from log_analyzer import __version__
from log_analyzer.alerting import AlertingError, TelegramNotifier, format_alert_text
from log_analyzer.config import Allowlist, ConfigError, load_config, load_dotenv
from log_analyzer.detectors import Detector
from log_analyzer.enrichment import Enricher
from log_analyzer.generate import generate_lines
from log_analyzer.models import Alert, Event, Severity
from log_analyzer.parser import (
    iter_events,
    looks_like_journal,
    parse_file,
    parse_journal_entry,
    parse_line_all,
)
from log_analyzer.report import build_summary, render_json, render_text, sort_alerts
from log_analyzer.sources import (
    DEFAULT_UNITS,
    SourceError,
    follow_file,
    follow_journal,
    read_journal,
)

log = logging.getLogger("log_analyzer")


# --- arguments ---------------------------------------------------------------------


def positive_int(value: str) -> int:
    n = int(value)
    if n <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return n


def severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log-analyzer",
        description="SSH brute force / password spraying detector for auth.log and journald.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-v", "--verbose", action="count", default=0, help="verbose tool logging")
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    g = common.add_argument_group("detection")
    g.add_argument("-c", "--config", help="YAML config (see config.example.yaml)")
    g.add_argument("--window", type=positive_int, help="brute-force window, seconds (60)")
    g.add_argument("--threshold", type=positive_int, help="failures within the window to alert (5)")
    g.add_argument("--cooldown", type=positive_int, help="deduplication gap, seconds (900)")
    g.add_argument(
        "--allow", action="append", default=[], metavar="CIDR", help="add to the allowlist"
    )
    g = common.add_argument_group("input")
    g.add_argument("--journal", action="store_true", help="read journald via journalctl")
    g.add_argument(
        "--unit", action="append", help="systemd unit for --journal (default: ssh and sshd)"
    )
    g.add_argument("--input-format", choices=["auto", "syslog", "journal"], default="auto")
    g.add_argument("--year", type=int, help="year for syslog lines without a year")
    g = common.add_argument_group("output")
    g.add_argument("--format", choices=["text", "json"], default="text")
    g.add_argument("--no-color", action="store_true")
    g.add_argument("--telegram", action="store_true", help="send alerts to Telegram")
    g.add_argument("--min-severity", type=severity, help="minimum severity for Telegram")
    g.add_argument("--env-file", default=".env", help="file with TG_BOT_TOKEN / TG_CHAT_ID")

    a = sub.add_parser("analyze", parents=[common], help="analyze log file(s) and print a report")
    a.add_argument("paths", nargs="*", help="auth.log, auth.log.1, auth.log.2.gz, '-' = stdin")
    a.add_argument("--since", help="for --journal: e.g. '1 hour ago'")
    a.add_argument("--top", type=positive_int, default=5, help="size of top lists in the report")
    a.add_argument(
        "--fail-on",
        type=severity,
        help="exit code 1 if there is an alert at this level or above (for cron/CI)",
    )

    w = sub.add_parser("watch", parents=[common], help="watch a log in real time")
    w.add_argument("path", nargs="?", help="log file (or --journal)")
    w.add_argument("--from-start", action="store_true", help="read the whole file first")
    w.add_argument("--interval", type=float, default=0.5, help="file polling interval, s")

    gen = sub.add_parser("generate", help="generate a demo log with attacks")
    gen.add_argument("-o", "--output", default="-", help="output file (default: stdout)")
    gen.add_argument("--seed", type=int, default=42)
    gen.add_argument("--start", help="log start time, ISO 8601 (default: today 03:00)")
    return p


# --- common setup ---------------------------------------------------------------------


@dataclasses.dataclass
class Runtime:
    detector: Detector
    allowlist: Allowlist
    enricher: Enricher
    notifier: TelegramNotifier | None
    min_severity: Severity
    max_alerts: int
    color: bool


def setup(args: argparse.Namespace) -> Runtime:
    cfg = load_config(args.config)
    det = cfg.detection
    for name in ("window", "threshold", "cooldown"):
        if getattr(args, name) is not None:
            setattr(det, name, getattr(args, name))
    allowlist = Allowlist([*cfg.allowlist, *args.allow])

    notifier = None
    if args.telegram:
        load_dotenv(args.env_file)
        notifier = TelegramNotifier.from_env(cfg.telegram.timeout)

    color = (
        args.format == "text"
        and not args.no_color
        and sys.stdout.isatty()
        and "NO_COLOR" not in os.environ
    )
    return Runtime(
        detector=Detector(det, allowlist),
        allowlist=allowlist,
        enricher=Enricher(cfg.enrichment),
        notifier=notifier,
        min_severity=args.min_severity or cfg.telegram.min_severity,
        max_alerts=cfg.telegram.max_alerts,
        color=color,
    )


def send_alerts(
    notifier: TelegramNotifier,
    alerts: list[Alert],
    min_severity: Severity,
    max_alerts: int,
    pause: float = 1.0,
) -> int:
    """Send alerts >= min_severity, at most max_alerts (the rest as one summary)."""
    eligible = [a for a in sort_alerts(alerts) if a.severity >= min_severity]
    sent = 0
    for a in eligible[:max_alerts]:
        try:
            notifier.send_alert(a)
            sent += 1
        except AlertingError as e:
            log.error("failed to send alert to Telegram: %s", e)
        if pause:
            time.sleep(pause)  # Telegram allows ~1 message per second per chat
    rest = len(eligible) - max_alerts
    if rest > 0:
        try:
            notifier.send_text(
                f"… and <b>{rest}</b> more alerts at level ≥ {min_severity.name}. "
                "Full report: <code>log-analyzer analyze --format json</code>"
            )
        except AlertingError as e:
            log.error("failed to send summary to Telegram: %s", e)
    return sent


def read_events(args: argparse.Namespace) -> list[Event]:
    units = tuple(args.unit or DEFAULT_UNITS)
    if args.journal:
        return list(iter_events(read_journal(units, args.since), "journal", args.year))
    if not args.paths:
        raise SourceError("specify a log path (e.g. /var/log/auth.log) or --journal")
    events: list[Event] = []
    for path in args.paths:
        events.extend(parse_file(path, args.input_format, args.year))
    events.sort(key=lambda e: e.time)
    return events


# --- commands ----------------------------------------------------------------------------


def cmd_analyze(args: argparse.Namespace) -> int:
    rt = setup(args)
    events = read_events(args)
    alerts = rt.detector.run(events)
    for a in alerts:
        rt.enricher.enrich(a)

    sent = None
    if rt.notifier:
        sent = send_alerts(rt.notifier, alerts, rt.min_severity, rt.max_alerts)

    kept = [e for e in events if e.ip not in rt.allowlist]
    summary = build_summary(kept, alerts, rt.detector.allowlisted, args.top)
    if args.format == "json":
        print(render_json(summary, alerts, sent))
    else:
        print(render_text(summary, alerts, rt.color, sent))

    if args.fail_on and any(a.severity >= args.fail_on for a in alerts):
        return 1
    return 0


def _emit(rt: Runtime, alert: Alert, fmt: str, summary: bool = False) -> None:
    if summary:
        alert = dataclasses.replace(alert, title=f"Summary: {alert.title} (attack stopped)")
    if fmt == "json":
        doc = alert.to_dict() | {"event": "summary" if summary else "alert"}
        print(json.dumps(doc, ensure_ascii=False), flush=True)
    else:
        print(format_alert_text(alert, rt.color) + "\n", flush=True)
    if rt.notifier and alert.severity >= rt.min_severity:
        try:
            rt.notifier.send_alert(alert)
        except AlertingError as e:
            log.error("failed to send alert to Telegram: %s", e)


def cmd_watch(args: argparse.Namespace) -> int:
    rt = setup(args)
    if args.journal:
        fmt = "journal"
        lines: Iterable[str] = follow_journal(tuple(args.unit or DEFAULT_UNITS))
        source = "journald"
    else:
        if not args.path:
            raise SourceError("specify a log path or --journal")
        fmt = args.input_format
        if fmt == "auto":
            fmt = "journal" if looks_like_journal(args.path) else "syslog"
        source = args.path
        if not os.path.exists(args.path):
            raise SourceError(f"file not found: {args.path}")
        lines = follow_file(args.path, args.from_start, args.interval, heartbeat=True)

    log.warning("watching %s (Ctrl+C to exit)", source)
    last_gc = time.monotonic()
    try:
        for line in lines:
            for event in parse_one(line, fmt, args.year):
                for alert in rt.detector.process(event):
                    _emit(rt, rt.enricher.enrich(alert), args.format)
            if time.monotonic() - last_gc > 30:  # every 30 s close attacks that have stopped
                last_gc = time.monotonic()
                for alert in rt.detector.expire(datetime.now()):
                    _emit(rt, rt.enricher.enrich(alert), args.format, summary=True)
    except KeyboardInterrupt:
        pass
    log.warning("stopped, alerts this session: %d", len(rt.detector.alerts))
    return 0


def parse_one(line: str, fmt: str, year: int | None) -> list[Event]:
    if not line:
        return []
    return parse_journal_entry(line) if fmt == "journal" else parse_line_all(line, year)


def cmd_generate(args: argparse.Namespace) -> int:
    start = datetime.fromisoformat(args.start) if args.start else None
    lines = generate_lines(start, args.seed)
    if args.output == "-":
        for line in lines:
            print(line)
    else:
        with open(args.output, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")
        log.warning("demo log written to %s", args.output)
    return 0


def fail(message: str) -> int:
    print(f"log-analyzer: error: {message}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=[logging.WARNING, logging.INFO, logging.DEBUG][min(args.verbose, 2)],
        format="log-analyzer: %(levelname)s: %(message)s",
        stream=sys.stderr,
    )
    handlers = {"analyze": cmd_analyze, "watch": cmd_watch, "generate": cmd_generate}
    try:
        return handlers[args.command](args)
    except (ConfigError, AlertingError, SourceError) as e:
        return fail(str(e))
    except FileNotFoundError as e:
        return fail(f"file not found: {e.filename}")
    except PermissionError as e:
        return fail(f"permission denied reading {e.filename} (need the adm group or sudo)")
    except BrokenPipeError:  # log-analyzer analyze ... | head
        return 0


if __name__ == "__main__":
    sys.exit(main())
