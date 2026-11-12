import re
from datetime import datetime

from log_analyzer.models import Event, EventType

# Три шаблона — по одному на каждый тип события
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+"
)
INVALID_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port \d+"
)

# Пары «шаблон → какой тип события он означает»
PATTERNS = [
    (FAILED_RE, EventType.FAILED),
    (INVALID_RE, EventType.INVALID_USER),
    (ACCEPTED_RE, EventType.ACCEPTED),
]


def parse_time(line: str) -> datetime:
    # Первые 15 символов строки — это дата: "Nov 12 03:11:02"
    t = datetime.strptime(line[:15], "%b %d %H:%M:%S")
    # В логе нет года, поэтому подставляем текущий
    return t.replace(year=datetime.now().year)


def parse_line(line: str) -> Event | None:
    # Пробуем шаблоны по очереди. Первый подошедший — заполняем карточку.
    for pattern, event_type in PATTERNS:
        m = pattern.search(line)
        if m:
            return Event(
                time=parse_time(line),
                type=event_type,
                ip=m["ip"],
                user=m["user"],
            )
    # Ни один шаблон не подошёл — строка нам не нужна
    return None


def read_lines(path: str):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if "sshd[" in line:
                yield line.rstrip("\n")


def parse_file(path: str) -> list[Event]:
    events = []
    for line in read_lines(path):
        event = parse_line(line)
        if event is not None:
            events.append(event)
    return events