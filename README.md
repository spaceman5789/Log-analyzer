# log-analyzer

<!-- GitLab badges: replace <namespace> with your GitLab username
[![pipeline](https://gitlab.com/<namespace>/log-analyzer/badges/main/pipeline.svg)](https://gitlab.com/<namespace>/log-analyzer/-/pipelines)
[![coverage](https://gitlab.com/<namespace>/log-analyzer/badges/main/coverage.svg)](https://gitlab.com/<namespace>/log-analyzer/-/pipelines)
-->

A learning project: an SSH attack detector for Linux authentication logs. It reads `auth.log` /
`secure` / `journalctl`, detects brute force, password spraying, distributed attacks and, most
dangerous of all, a **successful login after a series of failures**. Each alert gets a severity,
is mapped to MITRE ATT&CK and can be sent to Telegram.

> This is a learning project. In production I would use Wazuh or CrowdSec, but I wrote my own
> detector to understand detection logic from the inside: sliding windows, thresholds,
> deduplication and fighting false positives.

> **Note:** the CLI output and alert texts are in Russian.

## Features

| | |
|---|---|
| **Sources** | `/var/log/auth.log`, `/var/log/secure`, rotated `.gz` files, stdin, `journalctl -o json`, Docker logs (`linuxserver/openssh-server`, s6/TAI64N) |
| **Timestamps** | syslog without a year (`Nov 12 03:11:42`, handles the New Year rollover), ISO 8601 with a timezone |
| **Modes** | `analyze` parses files and prints a report; `watch` works like `tail -f`, alerts immediately and survives logrotate |
| **Rules** | brute force, success after brute force, spraying, distributed attack, scanner |
| **Output** | colored text for humans, `--format json` for a SIEM, Telegram |
| **SOC context** | severity, MITRE ATT&CK, top usernames/IPs, address type (internal/public), GeoIP, blocklists, "what to do" recommendations |
| **Noise control** | subnet allowlist, cooldown and deduplication (an hour-long attack is one alert, not 700) |
| **DevSecOps** | Dockerfile (non-root), hardened systemd unit, GitLab CI/CD: ruff + pytest + bandit + gitleaks → image in Container Registry |

## Quick start

```bash
git clone https://github.com/spaceman5789/Log-analyzer.git
cd Log-analyzer
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# demo log with six attack scenarios (synthetic, TEST-NET IPs)
log-analyzer generate -o demo.log
log-analyzer analyze demo.log -c config.example.yaml
```

On a real server:

```bash
sudo log-analyzer analyze /var/log/auth.log /var/log/auth.log.1 /var/log/auth.log.2.gz
log-analyzer analyze --journal --since "24 hours ago"      # systemd without auth.log
log-analyzer analyze /var/log/auth.log --format json > report.json
log-analyzer analyze /var/log/auth.log --fail-on high       # exit 1 on HIGH+ (cron/CI)
sudo log-analyzer watch /var/log/auth.log -c config.yaml --telegram
```

All options: `log-analyzer analyze --help`.

## Sample output

```
$ log-analyzer analyze demo.log -c config.example.yaml

[CRITICAL] Успешный вход после брутфорса
  IP: 203.0.113.5   вошёл как: root   хост: srv
  Неудачных попыток до входа: 47 за 3 мин 42 с (2026-11-12 03:30:00 – 03:33:42)
  Логины: root(47)
  Затем: Accepted password for root в 03:33:42
  Логин root перебирался — пароль, вероятно, подобран
  MITRE ATT&CK: T1110.001 Password Guessing, T1078 Valid Accounts
  Что делать: Считать учётку скомпрометированной: проверить активные сессии (who, last),
  сменить пароль, проверить ~/.ssh/authorized_keys, cron и новых пользователей, ...

[HIGH] SSH brute force по привилегированной учётке (root)
  IP: 198.51.100.23   хост: srv
  Неудачных попыток: 297 за 4 мин 42 с (2026-11-12 04:00:00 – 04:04:42)
  Логины: root(125), admin(80), ubuntu(40), test(30), oracle(22)
  MITRE ATT&CK: T1110.001 Password Guessing

[HIGH] Распределённый брутфорс логина 'deploy'
  Логин: deploy   IP-адресов: 8   хост: srv
  IP: 203.0.113.105(2), 203.0.113.100(2), 203.0.113.102(2), ... и ещё 3
  Каждый IP по отдельности ниже порога брутфорса — атака видна только в сумме

[MEDIUM] Password spraying (много логинов с одного IP)
  IP: 203.0.113.77   хост: srv
  Попыток: 10 за 45 мин (2026-11-12 04:30:00 – 05:15:53)
  Логины: admin(1), test(1), user(1), guest(1), postgres(1) … и ещё 5
  MITRE ATT&CK: T1110.003 Password Spraying

[LOW] SSH-сканер: обрывы до аутентификации / несуществующие логины
  IP: 198.51.100.200   хост: srv
  MITRE ATT&CK: T1595 Active Scanning
...
=== События по типам ===
  failed          372
  invalid_user    190
  accepted        2
  preauth_close   48
  allowlist       24 (пропущено)
...
Итого: 612 событий, 12 атакующих IP, 6 алертов
```

The five alerts above are: a CRITICAL successful login after brute force, a HIGH brute force on
`root`, a HIGH distributed attack on `deploy`, a MEDIUM password spraying and a LOW scanner.
The summary line reads "612 events, 12 attacking IPs, 6 alerts".

(Output is shortened. Without `-c config.example.yaml` you also get a MEDIUM alert for the CI
runner `10.0.5.20`, a false positive that the allowlist removes.)

### Telegram alert

<!-- TODO after the live test bench: put a screenshot at docs/telegram_alert.png
     and uncomment the line below.
![Telegram alert](docs/telegram_alert.png)
-->
The message has the same blocks as the terminal output: severity with a colored marker, IP and
host, number of attempts and time range, usernames, MITRE ATT&CK and what to do next.

## Detection logic

All rules are **streaming**, event by event, so the same code runs both for file analysis and in
`watch` mode. For each key (IP or username) a `deque` of timestamps is kept: a new event is
appended on the right, anything older than the window is dropped from the left, and the length
is compared to the threshold.

| Rule | Condition (defaults) | Severity | MITRE ATT&CK |
|---|---|---|---|
| `bruteforce` | ≥ 5 failed passwords from one IP within 60 s (like `maxretry`/`findtime` in fail2ban) | MEDIUM, **HIGH** if `root` is targeted | T1110.001 Password Guessing |
| `success_after_fail` | `Accepted` from an IP with ≥ 5 failures in the last hour or a prior brute-force alert | **CRITICAL** | T1110.001 + T1078 Valid Accounts |
| `spraying` | ≥ 5 different usernames from one IP within an hour (1–2 attempts per username) | MEDIUM | T1110.003 Password Spraying |
| `distributed` | ≥ 5 different IPs attacking one username within 10 min | HIGH | T1110.001 Password Guessing |
| `scan` | ≥ 10 `[preauth]` disconnects / `Invalid user` from an IP within 60 s | LOW | T1595 Active Scanning |

**Why a window and not just "more than 5 failures":** 5 failures in a month is a forgetful
admin; 5 in 10 seconds is a bot. A threshold without time gives either noise or misses.

**Deduplication.** While events for a key (rule, IP/username) keep coming without a gap longer
than `cooldown` (15 min), they are added to the already open alert, so an hour-long attack is
one alert with a final counter. In `watch` mode the alert goes out immediately, and when the
attack stops a summary with final numbers follows. A fast brute force over many usernames is not
duplicated by a spraying alert.

**What counts as a failure.** Only `Failed password` / `keyboard-interactive`.
`Failed publickey` is normal for a user with several keys in their agent, so it is not counted.
`message repeated N times: [...]` lines (rsyslog collapses repeats) are expanded into N events,
otherwise an attack would be undercounted many times over. Lines from other programs are
ignored, even if they look like sshd.

### SOC analyst mindset

* **False positive**: a CI runner with a broken key hits the server every 10 seconds. Fix: a
  subnet allowlist in the config (`10.0.5.0/24`). An admin typo (2 failures, then a login) is
  not an alert: it is below the threshold.
* **False negative**: slow spraying (one attempt every 5 minutes) is not caught by the brute-force
  rule, so there is a separate rule with a long window. A distributed botnet attack is invisible
  per IP, so there is a separate window per username. Blind spots remain: credential stuffing
  from a botnet where each IP makes one attempt on different usernames, and attacks slower than
  the window.
* **Context**: every alert answers *what* (rule, MITRE), *where* (host, IP), *when* (first and
  last time), *how bad* (severity, attempts, usernames) and *what to do next*. Enrichment: whether
  the address is internal (an attack from inside means a compromised host), country via GeoIP,
  and whether the IP is on public blocklists.

## Configuration

```bash
cp config.example.yaml config.yaml   # config.yaml is in .gitignore
log-analyzer analyze /var/log/auth.log -c config.yaml
```

Thresholds, windows, allowlist, the minimum level for Telegram, GeoIP and blocklists are
documented with comments in [config.example.yaml](config.example.yaml). A typo in a key is an
error at startup, not a silently ignored setting. The `--window`, `--threshold`, `--cooldown`
and `--allow` flags override the config.

**GeoIP** (optional): `pip install '.[geoip]'`, download GeoLite2-Country.mmdb from maxmind.com
and set `enrichment.geoip_db`. **Blocklist:** for example FireHOL level1:
`curl -o firehol_level1.netset https://iplists.firehol.org/files/firehol_level1.netset`.

## Telegram

1. Create a bot with [@BotFather](https://t.me/BotFather) and get the token.
2. Message the bot, open `https://api.telegram.org/bot<TOKEN>/getUpdates` and take `chat.id`.
3. `cp .env.example .env` and fill in `TG_BOT_TOKEN` and `TG_CHAT_ID`.
4. `log-analyzer analyze demo.log --telegram --min-severity high`

Security: the token lives only in the environment or `.env` (which is in `.gitignore`) and never
appears in logs, `repr` or error messages. User-controlled data from the log (usernames) is
HTML-escaped, so a username like `<a href=...>` will not turn into a link in the chat. On flood
control (HTTP 429) the client waits for `retry_after`. One `analyze` run sends at most
`max_alerts` messages; the rest goes out as a single summary.

## Testing on a live bench

Only on your own machine!

```bash
docker run -d --name ssh-target -p 2222:2222 \
  -e PASSWORD_ACCESS=true -e USER_PASSWORD=secret123 -e USER_NAME=test \
  lscr.io/linuxserver/openssh-server

hydra -l test -P small_wordlist.txt -s 2222 ssh://127.0.0.1

docker exec ssh-target cat /config/logs/openssh/current > real.log
log-analyzer analyze real.log --telegram
log-analyzer analyze real.log --allow 172.17.0.0/16   # your own IP in the allowlist → no alerts
```

The parser understands the container's log format (s6-log with ISO or TAI64N timestamps).

## Running as a service

**systemd**: a hardened unit (`ProtectSystem=strict`, no capabilities, only
`AF_INET/AF_INET6/AF_UNIX`) with installation instructions: [deploy/log-analyzer.service](deploy/log-analyzer.service).

**Docker**: multi-stage, `python:3.12-slim`, unprivileged user (uid 10001):

```bash
docker build -t log-analyzer .
docker run --rm --read-only --cap-drop ALL --group-add 4 \
  -v /var/log/auth.log:/logs/auth.log:ro log-analyzer analyze /logs/auth.log
```

## Development

```bash
pytest                          # 85 tests: parser, rules, config, Telegram, CLI, tail -f
ruff check . && ruff format --check .
bandit -r src -c pyproject.toml
gitleaks detect                 # no secrets in the history
```

### GitLab CI/CD

The [.gitlab-ci.yml](.gitlab-ci.yml) pipeline runs on every push and merge request:

| Stage | Jobs | What it gives |
|---|---|---|
| `lint` | `ruff` | style and errors; Code Quality report right in the MR |
| `test` | `pytest` ×4 (Python 3.10–3.13) | JUnit report and coverage in the GitLab UI, CLI smoke test |
| `security` | `bandit`, `gitleaks` | SAST on the code; secret scanning across the **entire** git history (`GIT_DEPTH: 0`) |
| `build` | `wheel`, `docker-build` | wheel package; the image is built and checked to run as non-root and to detect attacks |
| `deploy` | `docker-publish` | image to GitLab Container Registry: `:latest` from `main`, `:1.2.3` from tag `v1.2.3` |

Publishing happens only if tests, bandit and gitleaks pass. A new push cancels the outdated
pipeline (`interruptible`), and merge requests do not get duplicate branch pipelines.

```bash
git tag v1.0.0 && git push origin v1.0.0     # release → registry.gitlab.com/<namespace>/log-analyzer:1.0.0
docker run --rm registry.gitlab.com/<namespace>/log-analyzer:latest --help
```

**Code on GitHub, CI on GitLab.** GitLab CI only runs in a GitLab repository. A simple free
setup: keep the main repository on GitLab and mirror it to GitHub
(GitLab → Settings → Repository → Mirroring repositories → Push, URL
`https://github.com/<user>/Log-analyzer.git`, password: a GitHub fine-grained token with
Contents: Read and write).

Test logs live in [tests/fixtures](tests/fixtures): brute force, clean traffic, success after
brute force, spraying, distributed attack, CI runner (false positive), ISO 8601 and journalctl JSON.

### Project layout

```
src/log_analyzer/
├── cli.py          # argparse: analyze / watch / generate
├── parser.py       # syslog / ISO / s6 / journald lines → Event
├── detectors.py    # sliding-window rules, deduplication
├── alerting.py     # alert formatting, Telegram Bot API
├── enrichment.py   # address type, GeoIP, blocklist
├── report.py       # summary: text and JSON
├── config.py       # YAML config, allowlist, .env
├── sources.py      # tail -F with rotation support, journalctl
├── generate.py     # demo log generator with attacks
└── models.py       # Event, Alert, Severity, MITRE
```

## Comparison with production tools

| | log-analyzer | fail2ban | CrowdSec | Wazuh / OSSEC |
|---|---|---|---|---|
| Window-based brute-force detection | ✅ | ✅ | ✅ | ✅ |
| Success after brute force | ✅ | ❌ | ✅ (scenarios) | ✅ (correlation rules) |
| Spraying / distributed attacks | ✅ | ❌ | partially | via correlation |
| IP blocking | ❌ alerts only | ✅ iptables/nftables | ✅ bouncers | ✅ active response |
| Shared malicious IP database | blocklist files | ❌ | ✅ community | threat intel |
| Scale | single host | single host | fleet | SIEM for a fleet |

The detections could also be written as [Sigma](https://github.com/SigmaHQ/sigma) rules: open
rules that convert into queries for any SIEM.

## Roadmap

* Screenshot of an alert from the live bench → `docs/telegram_alert.png`
* Rewrite the parser core in Rust via pyo3 and benchmark it on a large log
* Sigma rules, ECS export for Elastic
