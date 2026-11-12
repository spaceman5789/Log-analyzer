import sys
from collections import Counter

from log_analyzer.models import EventType
from log_analyzer.parser import parse_file


def print_report(events) -> None:
    # 1. Сколько событий каждого типа
    by_type = Counter(e.type.value for e in events)

    # 2–3. Топ IP и топ логинов — считаем только неудачные попытки
    failed = [e for e in events if e.type == EventType.FAILED]
    top_ips = Counter(e.ip for e in failed).most_common(5)
    top_users = Counter(e.user for e in failed).most_common(5)

    # 4. Успешный вход с IP, с которого до этого были неудачи
    fails_by_ip = Counter()
    suspicious = []
    for e in sorted(events, key=lambda e: e.time):
        if e.type == EventType.FAILED:
            fails_by_ip[e.ip] += 1
        elif e.type == EventType.ACCEPTED and fails_by_ip[e.ip] > 0:
            suspicious.append((e, fails_by_ip[e.ip]))

    # Вывод
    print("=== События по типам ===")
    for name, count in by_type.items():
        print(f"  {name:<14} {count}")

    print("\n=== Топ-5 IP по неудачным попыткам ===")
    for ip, count in top_ips:
        print(f"  {ip:<16} {count}")

    print("\n=== Топ-5 перебираемых логинов ===")
    for user, count in top_users:
        print(f"  {user:<16} {count}")

    print("\n=== ⚠️  Успешный вход после неудач ===")
    if not suspicious:
        print("  не найдено")
    for e, fails in suspicious:
        print(f"  {e.ip} вошёл как {e.user} в {e.time:%H:%M:%S} "
              f"после {fails} неудачных попыток")


if __name__ == "__main__":
    print_report(parse_file(sys.argv[1]))