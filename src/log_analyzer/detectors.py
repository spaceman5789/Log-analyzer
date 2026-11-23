"""Правила детекта. Работают потоково (событие за событием), поэтому один и тот же
код используется и для разбора файла (`analyze`), и для режима реального времени (`watch`).

Правила:
* bruteforce          — >= threshold неудач с одного IP за window секунд     T1110.001
* success_after_fail  — успешный вход с IP, у которого перед этим был брутфорс  T1110.001 + T1078
* spraying            — >= spray_users разных логинов с одного IP           T1110.003
* distributed         — >= distributed_ips разных IP перебирают один логин    T1110.001
* scan                — много обрывов [preauth] / Invalid user с одного IP    T1595

Дедупликация: пока по ключу (правило, IP/логин) приходят события без пауз дольше
cooldown, они дописываются в уже открытый алерт, а не порождают новый.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from collections.abc import Iterable
from datetime import datetime, timedelta

from log_analyzer.config import Allowlist, DetectionConfig
from log_analyzer.models import Alert, Event, EventType, Severity

Window = deque[tuple[datetime, str]]

RECOMMENDATIONS = {
    "bruteforce": (
        "Заблокировать IP (fail2ban/nftables), проверить PasswordAuthentication no "
        "и PermitRootLogin no в sshd_config, перейти на вход по ключам."
    ),
    "success_after_fail": (
        "Считать учётку скомпрометированной: проверить активные сессии (who, last), "
        "сменить пароль, проверить ~/.ssh/authorized_keys, cron и новых пользователей, "
        "заблокировать IP, при сомнениях изолировать хост."
    ),
    "spraying": (
        "Заблокировать IP, проверить слабые пароли у перечисленных учёток, "
        "включить вход только по ключам или MFA."
    ),
    "distributed": (
        "Атака из ботнета — бан по одному IP не поможет. Отключить вход по паролю для этого "
        "логина, ключи/MFA, ограничить доступ к SSH (VPN, allowlist, GeoIP)."
    ),
    "scan": (
        "Фоновый шум интернета. Убедиться, что SSH не открыт наружу без нужды; "
        "можно ограничить доступ по IP или спрятать за VPN."
    ),
}


def _prune(dq: Window, cutoff: datetime) -> None:
    while dq and dq[0][0] < cutoff:
        dq.popleft()


class Detector:
    def __init__(self, cfg: DetectionConfig | None = None, allowlist: Allowlist | None = None):
        self.cfg = cfg or DetectionConfig()
        self.allowlist = allowlist or Allowlist()
        self.privileged = set(self.cfg.privileged_users)

        self.fail_window: defaultdict[str, Window] = defaultdict(deque)  # ip → (t, user)
        self.fail_history: defaultdict[str, Window] = defaultdict(deque)  # ip → (t, user)
        self.spray_window: defaultdict[str, Window] = defaultdict(deque)  # ip → (t, user)
        self.user_window: defaultdict[str, Window] = defaultdict(deque)  # user → (t, ip)
        self.recon_window: defaultdict[str, Window] = defaultdict(deque)  # ip → (t, user)

        self.active: dict[tuple[str, str], Alert] = {}  # (rule, key) → открытый алерт
        self.last_bruteforce: dict[str, Alert] = {}  # ip → последний алерт брутфорса
        self.alerts: list[Alert] = []
        self.allowlisted = 0

    # --- публичный API ---------------------------------------------------------

    def process(self, e: Event) -> list[Alert]:
        """Обработать одно событие, вернуть только НОВЫЕ алерты (их и нужно слать в Telegram)."""
        if e.ip in self.allowlist:
            self.allowlisted += 1
            return []

        new: list[Alert] = []
        if e.type is EventType.FAILED:
            new += self._bruteforce(e)
            new += self._spraying(e)
            new += self._distributed(e)
            hist = self.fail_history[e.ip]
            hist.append((e.time, e.user))
            _prune(hist, e.time - timedelta(seconds=self.cfg.success_lookback))
        elif e.type in (EventType.INVALID_USER, EventType.PREAUTH_CLOSE):
            new += self._scan(e)
        elif e.type is EventType.ACCEPTED:
            new += self._success_after_fail(e)
        return new

    def expire(self, now: datetime) -> list[Alert]:
        """Закрыть алерты, по которым атака стихла (нет событий дольше cooldown), и почистить
        окна неактивных IP (иначе в режиме watch память растёт от каждого сканера).
        Возвращает закрытые алерты, которые выросли после первой отправки, — по ним шлём сводку."""
        cooldown = timedelta(seconds=self.cfg.cooldown)
        finished = []
        for k, a in list(self.active.items()):
            if now - a.last_seen > cooldown:
                del self.active[k]
                if a.count > a.reported_count:
                    finished.append(a)

        horizon = timedelta(
            seconds=max(
                self.cfg.window,
                self.cfg.spray_window,
                self.cfg.distributed_window,
                self.cfg.success_lookback,
            )
        )
        for windows in (
            self.fail_window,
            self.fail_history,
            self.spray_window,
            self.user_window,
            self.recon_window,
        ):
            for key in [k for k, dq in windows.items() if not dq or now - dq[-1][0] > horizon]:
                del windows[key]
        for ip in [ip for ip, a in self.last_bruteforce.items() if now - a.last_seen > horizon]:
            del self.last_bruteforce[ip]
        return finished

    def run(self, events: Iterable[Event]) -> list[Alert]:
        for e in sorted(events, key=lambda ev: ev.time):
            self.process(e)
        return self.alerts

    # --- вспомогательное ----------------------------------------------------------

    def _active(self, rule: str, key: str, now: datetime) -> Alert | None:
        a = self.active.get((rule, key))
        if a and (now - a.last_seen).total_seconds() <= self.cfg.cooldown:
            return a
        return None

    def _register(self, a: Alert) -> list[Alert]:
        a.recommendation = RECOMMENDATIONS[a.rule]
        a.reported_count = a.count
        if a.rule == "bruteforce" and a.ip:
            self.last_bruteforce[a.ip] = a
        self.active[(a.rule, a.key)] = a
        self.alerts.append(a)
        return [a]

    def _bruteforce_severity(self, a: Alert) -> None:
        targeted = self.privileged & set(a.users)
        if targeted:
            a.severity = Severity.HIGH
            a.title = f"SSH brute force по привилегированной учётке ({', '.join(sorted(targeted))})"
        else:
            a.severity = Severity.MEDIUM
            a.title = "SSH brute force"

    # --- правила ------------------------------------------------------------------

    def _bruteforce(self, e: Event) -> list[Alert]:
        dq = self.fail_window[e.ip]
        dq.append((e.time, e.user))
        _prune(dq, e.time - timedelta(seconds=self.cfg.window))

        a = self._active("bruteforce", e.ip, e.time)
        if a:  # атака продолжается — копим в тот же алерт
            a.add(e)
            self._bruteforce_severity(a)
            return []
        if len(dq) < self.cfg.threshold:
            return []

        a = Alert(
            rule="bruteforce",
            severity=Severity.MEDIUM,
            title="SSH brute force",
            key=e.ip,
            ip=e.ip,
            host=e.host,
            first_seen=dq[0][0],
            last_seen=e.time,
            count=len(dq),
            users=Counter(u for _, u in dq),
            ips=Counter({e.ip: len(dq)}),
            mitre=["T1110.001"],
        )
        self._bruteforce_severity(a)
        return self._register(a)

    def _success_after_fail(self, e: Event) -> list[Alert]:
        hist = self.fail_history.get(e.ip, deque())
        _prune(hist, e.time - timedelta(seconds=self.cfg.success_lookback))
        bf = self.last_bruteforce.get(e.ip)
        recent_bf = bf is not None and (
            (e.time - bf.last_seen).total_seconds() <= self.cfg.success_lookback
        )
        if len(hist) < self.cfg.threshold and not recent_bf:
            return []

        login = f"Затем: Accepted {e.method or ''} for {e.user} в {e.time:%H:%M:%S}".replace(
            "  ", " "
        )
        a = self._active("success_after_fail", e.ip, e.time)
        if a:
            a.details.append(login)
            a.last_seen = e.time
            return []

        failed_users = Counter(u for _, u in hist)
        details = [login]
        if e.user in failed_users:
            details.append(f"Логин {e.user} перебирался — пароль, вероятно, подобран")
        else:
            details.append(
                f"Вход под другим логином ({e.user}), чем перебирали — проверить утечку учётки"
            )
        a = Alert(
            rule="success_after_fail",
            severity=Severity.CRITICAL,
            title="Успешный вход после брутфорса",
            key=e.ip,
            ip=e.ip,
            host=e.host,
            first_seen=hist[0][0] if hist else (bf.first_seen if bf else e.time),
            last_seen=e.time,
            count=len(hist) if hist else (bf.count if bf else 0),
            users=failed_users,
            ips=Counter({e.ip: len(hist)}),
            mitre=["T1110.001", "T1078"],
            details=details,
            compromised_user=e.user,
        )
        return self._register(a)

    def _spraying(self, e: Event) -> list[Alert]:
        dq = self.spray_window[e.ip]
        dq.append((e.time, e.user))
        _prune(dq, e.time - timedelta(seconds=self.cfg.spray_window))

        a = self._active("spraying", e.ip, e.time)
        if a:
            a.add(e)
            return []
        # Быстрый перебор многих логинов уже покрыт алертом bruteforce — не шумим дважды
        if self._active("bruteforce", e.ip, e.time):
            return []
        users = Counter(u for _, u in dq)
        if len(users) < self.cfg.spray_users:
            return []

        a = Alert(
            rule="spraying",
            severity=Severity.MEDIUM,
            title="Password spraying (много логинов с одного IP)",
            key=e.ip,
            ip=e.ip,
            host=e.host,
            first_seen=dq[0][0],
            last_seen=e.time,
            count=len(dq),
            users=users,
            ips=Counter({e.ip: len(dq)}),
            mitre=["T1110.003"],
            details=[
                "1–2 попытки на логин: медленно и тихо, правило брутфорса по одному "
                "логину такое не ловит"
            ],
        )
        return self._register(a)

    def _distributed(self, e: Event) -> list[Alert]:
        dq = self.user_window[e.user]
        dq.append((e.time, e.ip))
        _prune(dq, e.time - timedelta(seconds=self.cfg.distributed_window))

        a = self._active("distributed", e.user, e.time)
        if a:
            a.add(e)
            return []
        ips = Counter(ip for _, ip in dq)
        if len(ips) < self.cfg.distributed_ips:
            return []

        a = Alert(
            rule="distributed",
            severity=Severity.HIGH,
            title=f"Распределённый брутфорс логина {e.user!r}",
            key=e.user,
            ip=None,
            host=e.host,
            first_seen=dq[0][0],
            last_seen=e.time,
            count=len(dq),
            users=Counter({e.user: len(dq)}),
            ips=ips,
            mitre=["T1110.001"],
            details=["Каждый IP по отдельности ниже порога брутфорса — атака видна только в сумме"],
        )
        return self._register(a)

    def _scan(self, e: Event) -> list[Alert]:
        dq = self.recon_window[e.ip]
        dq.append((e.time, e.user))
        _prune(dq, e.time - timedelta(seconds=self.cfg.window))

        a = self._active("scan", e.ip, e.time)
        if a:
            a.add(e)
            return []
        if self._active("bruteforce", e.ip, e.time) or self._active("spraying", e.ip, e.time):
            return []
        if len(dq) < self.cfg.scan_threshold:
            return []

        users = Counter(u for _, u in dq if u)
        a = Alert(
            rule="scan",
            severity=Severity.LOW,
            title="SSH-сканер: обрывы до аутентификации / несуществующие логины",
            key=e.ip,
            ip=e.ip,
            host=e.host,
            first_seen=dq[0][0],
            last_seen=e.time,
            count=len(dq),
            users=users,
            ips=Counter({e.ip: len(dq)}),
            mitre=["T1595"],
        )
        return self._register(a)


def detect(
    events: Iterable[Event],
    cfg: DetectionConfig | None = None,
    allowlist: Allowlist | None = None,
) -> list[Alert]:
    """Удобная обёртка для тестов и разового анализа."""
    return Detector(cfg, allowlist).run(events)
