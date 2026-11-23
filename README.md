# log-analyzer

<!-- Бейджи GitLab: замените <namespace> на свой логин в GitLab
[![pipeline](https://gitlab.com/<namespace>/log-analyzer/badges/main/pipeline.svg)](https://gitlab.com/<namespace>/log-analyzer/-/pipelines)
[![coverage](https://gitlab.com/<namespace>/log-analyzer/badges/main/coverage.svg)](https://gitlab.com/<namespace>/log-analyzer/-/pipelines)
-->

Учебный детектор атак на SSH по логам аутентификации Linux. Читает `auth.log` / `secure` /
`journalctl`, находит брутфорс, password spraying, распределённые атаки и — самое опасное —
**успешный вход после серии неудач**, присваивает severity, маппит на MITRE ATT&CK и шлёт
алерт в Telegram.

> Это учебный проект. В проде я бы использовал Wazuh или CrowdSec, но написал свой детектор,
> чтобы понять логику детекта изнутри: скользящие окна, пороги, дедупликацию, борьбу
> с false positive.

## Что умеет

| | |
|---|---|
| **Источники** | `/var/log/auth.log`, `/var/log/secure`, ротированные `.gz`, stdin, `journalctl -o json`, логи Docker (`linuxserver/openssh-server`, s6/TAI64N) |
| **Форматы времени** | syslog без года (`Nov 12 03:11:42`, с учётом перехода через Новый год), ISO 8601 с часовым поясом |
| **Режимы** | `analyze` — разбор файла и отчёт; `watch` — как `tail -f`, алерты сразу, переживает logrotate |
| **Правила** | брутфорс, успех после брутфорса, spraying, распределённая атака, сканер |
| **Вывод** | цветной текст для человека, `--format json` для SIEM, Telegram |
| **SOC-контекст** | severity, MITRE ATT&CK, топ логинов/IP, тип адреса (внутренний/публичный), GeoIP, blocklist'ы, рекомендации «что делать» |
| **Шум** | allowlist подсетей, cooldown и дедупликация (часовая атака — один алерт, а не 700) |
| **DevSecOps** | Dockerfile (non-root), systemd-юнит с хардненингом, GitLab CI/CD: ruff + pytest + bandit + gitleaks → образ в Container Registry |

## Быстрый старт

```bash
git clone https://github.com/spaceman5789/Log-analyzer.git
cd Log-analyzer
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# демо-лог с шестью сценариями атак (синтетика, IP из TEST-NET)
log-analyzer generate -o demo.log
log-analyzer analyze demo.log -c config.example.yaml
```

Реальный сервер:

```bash
sudo log-analyzer analyze /var/log/auth.log /var/log/auth.log.1 /var/log/auth.log.2.gz
log-analyzer analyze --journal --since "24 hours ago"      # systemd без auth.log
log-analyzer analyze /var/log/auth.log --format json > report.json
log-analyzer analyze /var/log/auth.log --fail-on high       # exit 1 при HIGH+ (cron/CI)
sudo log-analyzer watch /var/log/auth.log -c config.yaml --telegram
```

Все параметры: `log-analyzer analyze --help`.

## Пример вывода

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

(вывод сокращён; без `-c config.example.yaml` появится ещё MEDIUM-алерт на CI-раннер
`10.0.5.20` — это false positive, который убирает allowlist.)

### Алерт в Telegram

<!-- TODO после шага 12 (живой стенд): положить скриншот в docs/telegram_alert.png
     и раскомментировать строку ниже.
![Алерт в Telegram](docs/telegram_alert.png)
-->
Сообщение содержит те же блоки, что и вывод в терминале: severity с цветной меткой, IP и хост,
число попыток и временной диапазон, логины, MITRE ATT&CK и «что делать».

## Логика детекта

Все правила работают **потоково**, событие за событием — один и тот же код используется
и для разбора файла, и в режиме `watch`. Для каждого ключа (IP или логина) хранится `deque`
с временными метками: новое событие добавляется справа, всё старше окна выкидывается слева,
длина сравнивается с порогом.

| Правило | Условие (по умолчанию) | Severity | MITRE ATT&CK |
|---|---|---|---|
| `bruteforce` | ≥ 5 неудачных паролей с одного IP за 60 с (как `maxretry`/`findtime` в fail2ban) | MEDIUM, **HIGH** если перебирают `root` | T1110.001 Password Guessing |
| `success_after_fail` | `Accepted` с IP, у которого за последний час ≥ 5 неудач или был алерт брутфорса | **CRITICAL** | T1110.001 + T1078 Valid Accounts |
| `spraying` | ≥ 5 разных логинов с одного IP за час (1–2 попытки на логин) | MEDIUM | T1110.003 Password Spraying |
| `distributed` | ≥ 5 разных IP перебирают один логин за 10 мин | HIGH | T1110.001 Password Guessing |
| `scan` | ≥ 10 обрывов `[preauth]` / `Invalid user` с IP за 60 с | LOW | T1595 Active Scanning |

**Почему окно, а не «больше 5 неудач»:** 5 неудач за месяц — забывчивый админ, 5 за 10 секунд —
бот. Порог без времени даёт либо шум, либо пропуски.

**Дедупликация.** Пока по ключу (правило, IP/логин) события идут без пауз дольше `cooldown`
(15 мин), они дописываются в уже открытый алерт: часовая атака — один алерт с итоговым
счётчиком. В режиме `watch` алерт уходит сразу, а когда атака стихла — приходит сводка
с итоговыми цифрами. Быстрый перебор многих логинов не дублируется алертом spraying.

**Что считается неудачей.** Только `Failed password` / `keyboard-interactive`.
`Failed publickey` — норма для пользователя с несколькими ключами в агенте, его считать
нельзя. Строки `message repeated N times: [...]` (rsyslog схлопывает повторы) разворачиваются
в N событий — иначе атака недосчитывается в разы. Строки от других программ, даже похожие
на sshd, игнорируются.

### Мышление SOC-аналитика

* **False positive** — CI-раннер с битым ключом долбится каждые 10 секунд. Решение: allowlist
  подсетей в конфиге (`10.0.5.0/24`). Опечатка админа (2 неудачи и вход) — не алерт: ниже порога.
* **False negative** — медленный spraying (одна попытка в 5 минут) не ловится правилом
  брутфорса. Поэтому отдельное правило с длинным окном. Распределённая атака из ботнета не видна
  по каждому IP — поэтому отдельное окно по логину. Остаются слепые зоны: credential stuffing
  с ботнета, где каждый IP делает одну попытку на разные логины, и атаки медленнее окна.
* **Контекст.** Каждый алерт отвечает на вопросы *что* (правило, MITRE), *где* (хост, IP),
  *когда* (первое и последнее время), *насколько серьёзно* (severity, число попыток, логины),
  *что делать дальше*. Обогащение: внутренний ли адрес (атака изнутри = скомпрометированный хост),
  страна по GeoIP, есть ли IP в публичных blocklist'ах.

## Конфиг

```bash
cp config.example.yaml config.yaml   # config.yaml в .gitignore
log-analyzer analyze /var/log/auth.log -c config.yaml
```

Пороги, окна, allowlist, минимальный уровень для Telegram, GeoIP и blocklist'ы описаны
с комментариями в [config.example.yaml](config.example.yaml). Опечатка в ключе — ошибка при
старте, а не молча проигнорированная настройка. Флаги `--window`, `--threshold`, `--cooldown`,
`--allow` перекрывают конфиг.

**GeoIP** (опционально): `pip install '.[geoip]'`, скачать GeoLite2-Country.mmdb с maxmind.com,
указать `enrichment.geoip_db`. **Blocklist:** например FireHOL level1 —
`curl -o firehol_level1.netset https://iplists.firehol.org/files/firehol_level1.netset`.

## Telegram

1. Создать бота у [@BotFather](https://t.me/BotFather), получить токен.
2. Написать боту, открыть `https://api.telegram.org/bot<TOKEN>/getUpdates`, взять `chat.id`.
3. `cp .env.example .env` и заполнить `TG_BOT_TOKEN`, `TG_CHAT_ID`.
4. `log-analyzer analyze demo.log --telegram --min-severity high`

Безопасность: токен только в окружении или `.env` (он в `.gitignore`), никогда не попадает
в логи, `repr` и сообщения об ошибках. Пользовательские данные из лога (логины)
HTML-экранируются — логин вида `<a href=...>` не превратится в ссылку в чате. При flood
control (HTTP 429) клиент ждёт `retry_after`; за один `analyze` уходит не больше `max_alerts`
сообщений, остальное — одной сводкой.

## Проверка на живом стенде

Только на своей машине!

```bash
docker run -d --name ssh-target -p 2222:2222 \
  -e PASSWORD_ACCESS=true -e USER_PASSWORD=secret123 -e USER_NAME=test \
  lscr.io/linuxserver/openssh-server

hydra -l test -P small_wordlist.txt -s 2222 ssh://127.0.0.1

docker exec ssh-target cat /config/logs/openssh/current > real.log
log-analyzer analyze real.log --telegram
log-analyzer analyze real.log --allow 172.17.0.0/16   # свой IP в allowlist → алертов нет
```

Формат логов контейнера (s6-log с ISO- или TAI64N-временем) парсер понимает.

## Запуск как сервис

**systemd** — юнит с хардненингом (`ProtectSystem=strict`, без capabilities, только
`AF_INET/AF_INET6/AF_UNIX`) и инструкцией по установке: [deploy/log-analyzer.service](deploy/log-analyzer.service).

**Docker** — multi-stage, `python:3.12-slim`, пользователь без прав (uid 10001):

```bash
docker build -t log-analyzer .
docker run --rm --read-only --cap-drop ALL --group-add 4 \
  -v /var/log/auth.log:/logs/auth.log:ro log-analyzer analyze /logs/auth.log
```

## Разработка

```bash
pytest                          # 85 тестов: парсер, правила, конфиг, Telegram, CLI, tail -f
ruff check . && ruff format --check .
bandit -r src -c pyproject.toml
gitleaks detect                 # секретов в истории нет
```

### GitLab CI/CD

Пайплайн [.gitlab-ci.yml](.gitlab-ci.yml) запускается на каждый push и merge request:

| Стадия | Джобы | Что даёт |
|---|---|---|
| `lint` | `ruff` | стиль и ошибки; отчёт Code Quality прямо в MR |
| `test` | `pytest` ×4 (Python 3.10–3.13) | JUnit-отчёт и покрытие в интерфейсе GitLab, smoke-тест CLI |
| `security` | `bandit`, `gitleaks` | SAST по коду; поиск секретов во **всей** истории git (`GIT_DEPTH: 0`) |
| `build` | `wheel`, `docker-build` | wheel-пакет; образ собирается, проверяется что он не от root и находит атаки |
| `deploy` | `docker-publish` | образ в GitLab Container Registry: `:latest` с `main`, `:1.2.3` с тега `v1.2.3` |

Публикация идёт только если тесты, bandit и gitleaks прошли. Новый push отменяет устаревший
пайплайн (`interruptible`), для MR нет дублирующих пайплайнов по ветке.

```bash
git tag v1.0.0 && git push origin v1.0.0     # релиз → registry.gitlab.com/<namespace>/log-analyzer:1.0.0
docker run --rm registry.gitlab.com/<namespace>/log-analyzer:latest --help
```

**Код на GitHub, CI на GitLab.** GitLab CI запускается только в репозитории GitLab. Простой
бесплатный вариант: основной репозиторий в GitLab, а в GitHub — зеркало
(GitLab → Settings → Repository → Mirroring repositories → Push, URL
`https://github.com/<user>/Log-analyzer.git`, пароль — GitHub fine-grained token с правом
Contents: Read and write).

Тестовые логи лежат в [tests/fixtures](tests/fixtures): брутфорс, чистый трафик, успех после
брутфорса, spraying, распределённая атака, CI-раннер (false positive), ISO 8601,
journalctl JSON.

### Структура

```
src/log_analyzer/
├── cli.py          # argparse: analyze / watch / generate
├── parser.py       # строки syslog / ISO / s6 / journald → Event
├── detectors.py    # правила со скользящими окнами, дедупликация
├── alerting.py     # формат алерта, Telegram Bot API
├── enrichment.py   # тип адреса, GeoIP, blocklist
├── report.py       # сводка: текст и JSON
├── config.py       # YAML-конфиг, allowlist, .env
├── sources.py      # tail -F с учётом ротации, journalctl
├── generate.py     # генератор демо-лога с атаками
└── models.py       # Event, Alert, Severity, MITRE
```

## Сравнение со «взрослыми» инструментами

| | log-analyzer | fail2ban | CrowdSec | Wazuh / OSSEC |
|---|---|---|---|---|
| Детект брутфорса по окну | ✅ | ✅ | ✅ | ✅ |
| Успех после брутфорса | ✅ | ❌ | ✅ (сценарии) | ✅ (корреляционные правила) |
| Spraying / распределённые атаки | ✅ | ❌ | частично | через корреляцию |
| Блокировка IP | ❌ только алерт | ✅ iptables/nftables | ✅ bouncers | ✅ active response |
| Общая база вредоносных IP | blocklist-файлы | ❌ | ✅ community | threat intel |
| Масштаб | один хост | один хост | флот | SIEM для флота |

Детект можно было бы описать и в формате [Sigma](https://github.com/SigmaHQ/sigma) —
открытые правила, которые конвертируются в запросы для любого SIEM.

## Что дальше

* Скриншот алерта с живого стенда (шаг 12) → `docs/telegram_alert.png`
* Переписать ядро парсера на Rust через pyo3 и сравнить скорость на большом логе
* Правила в формате Sigma, экспорт в ECS для Elastic
