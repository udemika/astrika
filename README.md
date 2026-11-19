# Astrika — Нативный однофайловый Rust-сервер цифрового ТВ и IPTV

Автономный однофайловый асинхронный сервер приёма, буферизации и раздачи цифровых телевизионных потоков (**MPEG-TS / HLS / HTTP / HTTPS / UDP / RTP**) со встроенной веб-панелью управления — преемник **`udemika/astasy` (`astrag`)**, переписанный полностью на **Rust** (исходники в `astrika/src/`).

### Ключевые особенности `Astrika`

- **Один полностью статический ELF-бинарник `astrika` (~4.8 МБ, `x86_64-unknown-linux-musl`, `static-pie`)** — никаких зависимостей Python, `libssl`, `glibc` и распаковки в `/opt`. Работает «из коробки» на **Ubuntu 20.04 / 22.04 / 24.04 LTS**, Debian 10–12+, AlmaLinux / Rocky, Alpine.
- **Ускоренный запуск телеканалов (Zapping)** — HTTP/1.1 Keep-Alive с пулом соединений (`pool_max_idle_per_host=4`) и TLS session resumption (`rustls`), холодный старт HLS сразу с 1-го сегмента, мгновенное пробуждение подписчиков через `tokio::sync::Notify` (0 мс вместо 40 мс опроса), кэширование Variant URL между засыпаниями канала, адаптивный параллелизм HLS (3 на старте / 2 в работе) + параллельная загрузка AES-128 ключа.
- **Оптимизированный парсинг и кэширование** — однопроходный zero-copy парсер M3U8 + `gzip` + Conditional GET (`304 Not Modified`), встроенный DNS-кэш (до 512 доменов, TTL 120с, stale-while-revalidate 300с, singleflight), `O(1)` индексы каналов/пользователей/токенов, кэширование глобальных и выходных плейлистов, SIMD `memchr` поиск ключевых кадров H.264/HEVC/MPEG-2 и быстрый пропуск неизменных PAT/PMT по `version_number`.
- **Безопасность и стабильность** — верификация PBKDF2-SHA256 (600 000 раундов) кэшируется и вынесена в `spawn_blocking` (не блокирует стриминг), устранён DoS на `?token=`, закрыта проверка прав администратора в `/api/cluster-control`, неблокирующее атомарное сохранение конфига.
- **Минимальное потребление RAM и CPU** — режим «По запросу» (`IN_IDLE`: 0% CPU, 0 байт TS-буферов; **~14 МБ RSS при 100 настроенных каналах**), zero-copy сегменты `Arc<Bytes>`, компактный Tokio runtime (`clamp(cpus, 2, 4)`, стек 1 МБ), встроенный gzip-веб-интерфейс (`ETag` / `304`).
- **Полная совместимость с `astrag` / `astasy`** — конфиг `/etc/astrag/astrag.conf` автоматически переносится в `/etc/astrika/astrika.conf`, сохраняются все каналы, пользователи, API `/control/`, `/play/*`, `/live/*` и кластер.

---

## Установка на сервер (Ubuntu 20.04 / 22.04 / 24.04, Debian 10–12+, любой Linux `x86_64`)

### Вариант 1: Установка одним бинарником `astrika` (рекомендуется)

Скачайте готовый статический ELF-бинарник `astrika` из репозитория `udemika/astrika` в `/usr/bin/astrika`, сделайте его исполняемым и запустите системный сервис:

```bash
sudo curl -fLo /usr/bin/astrika https://raw.githubusercontent.com/udemika/astrika/main/astrika/astrika
sudo chmod +x /usr/bin/astrika
sudo astrika init 8000 --start
```

#### То же самое одной командой (быстрая установка и автозапуск):

```bash
sudo curl -fLo /usr/bin/astrika https://raw.githubusercontent.com/udemika/astrika/main/astrika/astrika && sudo chmod +x /usr/bin/astrika && sudo astrika init 8000 --start
```

> В `htop` работает один нативный процесс **`astrika`**. Если на сервере был `/etc/astrag/astrag.conf`, команда `astrika init` автоматически скопирует его в `/etc/astrika/astrika.conf`.

---

### Переход со старого `astrag` на `astrika` одной командой (удаление `astrag` + сохранение каналов и пользователей)

```bash
sudo bash -euo pipefail -c 'mkdir -p /etc/astrika; [ -f /etc/astrag/astrag.conf ] && [ ! -f /etc/astrika/astrika.conf ] && cp -a /etc/astrag/astrag.conf /etc/astrika/astrika.conf; for u in /etc/systemd/system/astrag*.service; do [ -e "$u" ] || continue; s=$(basename "$u" .service); systemctl stop "$s" 2>/dev/null || true; systemctl disable "$s" 2>/dev/null || true; rm -f "$u"; done; systemctl daemon-reload; rm -rf /etc/astrag /var/lib/astrag /usr/bin/astrag /usr/local/bin/astrag; curl -fLo /usr/bin/astrika https://raw.githubusercontent.com/udemika/astrika/main/astrika/astrika && chmod +x /usr/bin/astrika && astrika init 8000 --start'
```

---

### Вариант 2: Быстрая установка через `install.sh`

```bash
curl -fsSL https://raw.githubusercontent.com/udemika/astrika/main/astrika/install.sh | sudo bash -s -- --start --port 8000
```

---

### Вариант 3: Сборка из исходников Rust (`astrika/`)

```bash
sudo apt-get update && sudo apt-get install -y musl-tools curl git
curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"
git clone --depth 1 https://github.com/udemika/astrika.git
cd astrika/astrika
./build-static.sh
sudo install -m 0755 astrika /usr/bin/astrika
sudo astrika init 8000 --start
```

---

## Вход в веб-интерфейс

Откройте в браузере:

```text
http://<IP_ВАШЕГО_СЕРВЕРА>:8000/
```

Данные для входа по умолчанию (для новой установки):

- **Логин**: `admin`
- **Пароль**: `admin`

---

## Управление сервисом и конфигурацией

```bash
# Управление systemd
sudo systemctl start astrika
sudo systemctl stop astrika
sudo systemctl restart astrika
sudo systemctl reload astrika     # горячая перечитка конфига (SIGHUP)
sudo systemctl status astrika
sudo journalctl -u astrika -f

# Второй независимый экземпляр на другом порту (например, 8001):
sudo astrika init 8001 --start
sudo astrika remove 8001 --purge

# Сброс пароля администратора через консоль (PBKDF2-SHA256):
sudo astrika reset-password admin StrongPass2026
sudo systemctl restart astrika

# Обновление бинарника:
sudo curl -fLo /usr/bin/astrika https://raw.githubusercontent.com/udemika/astrika/main/astrika/astrika && sudo chmod +x /usr/bin/astrika && sudo systemctl restart astrika

# Полное удаление:
sudo astrika purge
```

## Переменные окружения (опционально)

| Переменная | По умолчанию | Описание |
| --- | --- | --- |
| `ASTRIKA_CONFIG_FILE` | `/etc/astrika/astrika.conf` | Путь к файлу конфигурации |
| `ASTRIKA_WORKERS` | `clamp(cpus, 2, 4)` | Число рабочих потоков Tokio |
| `ASTRIKA_VERIFY_TLS` | `0` | `1` — строгая проверка TLS-сертификатов источников |
| `ASTRIKA_DISABLE_EXTRA_PORTS` | `0` | `1` — отключить дополнительные порты HTTP-выходов |
