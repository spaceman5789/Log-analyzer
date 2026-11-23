"""Detection rules. They are streaming (event by event), so the same
code serves both file analysis (`analyze`) and real-time mode (`watch`).

Rules:
* bruteforce          — >= threshold failures from one IP within window s   T1110.001
* success_after_fail  — successful login from an IP that brute-forced before  T1110.001 + T1078
* spraying            — >= spray_users distinct usernames from one IP       T1110.003
* distributed         — >= distributed_ips distinct IPs on one username      T1110.001
* scan                — many [preauth] disconnects / Invalid user from one IP T1595

Deduplication: while events for a key (rule, IP/username) arrive with no gap longer than
cooldown, they are added to the open alert instead of creating a new one.
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
        "Block the IP (fail2ban/nftables), check PasswordAuthentication no "
        "and PermitRootLogin no in sshd_config, switch to key-based login."
    ),
    "success_after_fail": (
        "Treat the account as compromised: check active sessions (who, last), "
        "change the password, check ~/.ssh/authorized_keys, cron and new users, "
        "block the IP, isolate the host if in doubt."
    ),
    "spraying": (
        "Block the IP, check the listed accounts for weak passwords, "
        "allow only key-based login or MFA."
    ),
    "distributed": (
        "Botnet attack: banning single IPs will not help. Disable password login for this "
        "account, use keys/MFA, restrict SSH access (VPN, allowlist, GeoIP)."
    ),
    "scan": (
        "Internet background noise. Make sure SSH is not exposed without need; "
        "consider restricting access by IP or moving it behind a VPN."
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

        self.active: dict[tuple[str, str], Alert] = {}  # (rule, key) → open alert
        self.last_bruteforce: dict[str, Alert] = {}  # ip → latest brute-force alert
        self.alerts: list[Alert] = []
        self.allowlisted = 0

    # --- public API ------------------------------------------------------------

    def process(self, e: Event) -> list[Alert]:
        """Process one event and return only NEW alerts (the ones to send to Telegram)."""
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
        """Close alerts whose attack has stopped (no events for longer than cooldown) and clear
        windows of idle IPs (otherwise watch mode memory grows with every scanner).
        Returns closed alerts that grew after first being reported, to send a summary for them."""
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

    # --- helpers ------------------------------------------------------------------

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
            a.title = f"SSH brute force on a privileged account ({', '.join(sorted(targeted))})"
        else:
            a.severity = Severity.MEDIUM
            a.title = "SSH brute force"

    # --- rules --------------------------------------------------------------------

    def _bruteforce(self, e: Event) -> list[Alert]:
        dq = self.fail_window[e.ip]
        dq.append((e.time, e.user))
        _prune(dq, e.time - timedelta(seconds=self.cfg.window))

        a = self._active("bruteforce", e.ip, e.time)
        if a:  # attack continues: keep adding to the same alert
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

        login = f"Then: Accepted {e.method or ''} for {e.user} at {e.time:%H:%M:%S}".replace(
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
            details.append(
                f"Username {e.user} was being guessed: the password was probably cracked"
            )
        else:
            details.append(
                f"Login as a different user ({e.user}) than guessed: check for leaked credentials"
            )
        a = Alert(
            rule="success_after_fail",
            severity=Severity.CRITICAL,
            title="Successful login after brute force",
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
        # Fast guessing over many usernames is already covered by bruteforce, don't alert twice
        if self._active("bruteforce", e.ip, e.time):
            return []
        users = Counter(u for _, u in dq)
        if len(users) < self.cfg.spray_users:
            return []

        a = Alert(
            rule="spraying",
            severity=Severity.MEDIUM,
            title="Password spraying (many usernames from one IP)",
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
                "1–2 attempts per username: slow and quiet, the per-IP brute-force rule "
                "does not catch it"
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
            title=f"Distributed brute force on username {e.user!r}",
            key=e.user,
            ip=None,
            host=e.host,
            first_seen=dq[0][0],
            last_seen=e.time,
            count=len(dq),
            users=Counter({e.user: len(dq)}),
            ips=ips,
            mitre=["T1110.001"],
            details=[
                "Each IP alone is below the brute-force threshold: only the sum shows the attack"
            ],
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
            title="SSH scanner: pre-auth disconnects / non-existent usernames",
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
    """Convenience wrapper for tests and one-off analysis."""
    return Detector(cfg, allowlist).run(events)
