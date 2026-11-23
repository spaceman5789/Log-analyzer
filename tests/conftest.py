from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from log_analyzer.models import Event, EventType
from log_analyzer.parser import parse_file

FIXTURES = Path(__file__).parent / "fixtures"
T0 = datetime(2026, 11, 12, 3, 0, 0)


@pytest.fixture
def fixture_path():
    def _path(name: str) -> str:
        return str(FIXTURES / name)

    return _path


@pytest.fixture
def load():
    """Разобрать фикстуру с фиксированным годом, чтобы тесты не зависели от текущей даты."""

    def _load(name: str):
        return parse_file(str(FIXTURES / name), year=2026)

    return _load


def ev(
    offset_s: float,
    type_: EventType = EventType.FAILED,
    ip: str = "203.0.113.5",
    user: str = "root",
) -> Event:
    return Event(time=T0 + timedelta(seconds=offset_s), type=type_, ip=ip, user=user)
