from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class EventType(Enum):
    FAILED = "failed"              # неверный пароль
    INVALID_USER = "invalid_user"  # такого пользователя нет
    ACCEPTED = "accepted"          # успешный вход


@dataclass
class Event:
    time: datetime
    type: EventType
    ip: str
    user: str