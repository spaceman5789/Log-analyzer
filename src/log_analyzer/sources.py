"""Line sources: `tail -f` on a file with rotation support, and journalctl (one-shot and -f)."""

from __future__ import annotations

import os
import shutil

# only journalctl with fixed arguments is run, no shell
import subprocess  # nosec B404
import time
from collections.abc import Callable, Iterator

DEFAULT_UNITS = ("ssh", "sshd")  # Ubuntu/Debian and RHEL name the unit differently


class SourceError(RuntimeError):
    pass


def follow_file(
    path: str,
    from_start: bool = False,
    interval: float = 0.5,
    idle_timeout: float | None = None,
    should_stop: Callable[[], bool] = lambda: False,
    heartbeat: bool = False,
) -> Iterator[str]:
    """Like `tail -F`: waits for new lines, reopens the file after logrotate rotation
    (inode changed) or truncation (copytruncate). heartbeat=True yields "" when idle
    every interval seconds so the caller can do background work."""
    # The file is reopened after rotation, hence no `with`
    f = open(path, encoding="utf-8", errors="replace")  # noqa: SIM115
    try:
        if not from_start:
            f.seek(0, os.SEEK_END)
        inode = os.fstat(f.fileno()).st_ino
        buf = ""
        idle_since = time.monotonic()
        while not should_stop():
            chunk = f.readline()
            if chunk:
                idle_since = time.monotonic()
                buf += chunk
                if buf.endswith("\n"):  # the line is complete
                    yield buf.rstrip("\r\n")
                    buf = ""
                continue

            try:
                st = os.stat(path)
            except FileNotFoundError:  # between mv and creation of the new file
                st = None
            if st is not None and (st.st_ino != inode or st.st_size < f.tell()):
                f.close()
                f = open(path, encoding="utf-8", errors="replace")  # noqa: SIM115
                inode = os.fstat(f.fileno()).st_ino
                buf = ""
                continue

            if idle_timeout is not None and time.monotonic() - idle_since > idle_timeout:
                return
            time.sleep(interval)
            if heartbeat:
                yield ""
    finally:
        f.close()


def _journalctl() -> str:
    exe = shutil.which("journalctl")
    if not exe:
        raise SourceError(
            "journalctl not found: not a systemd system? Pass a log file path instead."
        )
    return exe


def _unit_args(units: tuple[str, ...]) -> list[str]:
    args: list[str] = []
    for u in units:
        args += ["-u", u]
    return args


def read_journal(units: tuple[str, ...] = DEFAULT_UNITS, since: str | None = None) -> Iterator[str]:
    cmd = [_journalctl(), "-o", "json", "--no-pager", *_unit_args(units)]
    if since:
        cmd += ["--since", since]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)  # nosec B603
    if proc.returncode != 0:
        raise SourceError(f"journalctl exited with code {proc.returncode}: {proc.stderr.strip()}")
    yield from proc.stdout.splitlines()


def follow_journal(units: tuple[str, ...] = DEFAULT_UNITS) -> Iterator[str]:
    cmd = [_journalctl(), "-f", "-n", "0", "-o", "json", *_unit_args(units)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)  # nosec B603
    if proc.stdout is None:
        raise SourceError("failed to start journalctl")
    try:
        for line in proc.stdout:
            yield line.rstrip("\n")
    finally:
        proc.terminate()
