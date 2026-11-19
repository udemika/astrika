# Astrika

Высокопроизводительный асинхронный IPTV-стриминг сервер на **Rust** (полный безопасный и оптимизированный преемник `astasy`/`astrag`), скомпилированный в **единый статический бинарник (`x86_64-unknown-linux-musl`)** для работы на **Ubuntu 20.04, 22.04 и 24.04** без внешних библиотек (`glibc`/`libssl` не требуются).

## Что исправлено и оптимизировано (без роста потребления RAM/CPU)

1. **Безопасность и стабильность**
   - Устранён блокирующий PBKDF2-SHA256 (600 000 итераций) в основном цикле: кэш верификации (ограничен 1024 записями, ~128 КБ RAM, TTL + мгновенная инвалидация по `config_gen`) + вынос cache-miss в `spawn_blocking`.
   - Устранён DoS на `?token=`: мгновенный `O(1)` поиск по `token_index` вместо линейного перебора пользователей с PBKDF2.
   - Закрыта уязвимость отсутствующей проверки прав в `/api/cluster-control` — теперь требуется авторизация администратора.
   - Полная memory-safety на Rust (нет переполнений буфера, use-after-free, гонок данных).
   - Неблокирующая атомарная запись конфига (`tmp` + `fsync` + `rename` в отдельном пуле).

2. **Ускорение запуска телеканалов (Zapping)**
   - **HTTP/1.1 Keep-Alive + пул соединений + TLS session resumption** (`reqwest` + `rustls` с `pool_max_idle_per_host(4)`): убраны постоянные TCP+TLS рукопожатия на каждый плейлист и сегмент.
   - **Холодный старт HLS с 1-го сегмента**: плейлист отдаётся сразу после готовности 1-го сегмента, а клиенты просыпаются мгновенно через `tokio::sync::Notify` (0 мс ожидания вместо 40 мс опроса).
   - **Кэширование выбранного Master Variant URL** при засыпании канала в `IN_IDLE` — при повторном включении канала сразу грузится Media-плейлист.
   - **Адаптивный параллелизм HLS-сегментов** (до 3 на старте, 2 в установившемся режиме) + параллельная предзагрузка AES-128 ключа и сегмента + общий ограниченный кэш ключей (256 записей).
   - **Ускоренный MPEG-TS детектор ключевых кадров**: SIMD `memchr`, просмотр до 2 TS-пакетов PES для H.264/HEVC/MPEG-2 и быстрый пропуск неизменных PAT/PMT по `version_number`.

3. **Оптимизация парсинга и кэширования**
   - Однопроходный zero-copy парсер M3U8 + поддержка `gzip` + Conditional GET (`ETag`/`If-None-Match` → `304 Not Modified`).
   - Встроенный DNS-кэш (до 512 доменов, TTL 120с, stale-while-revalidate 300с, negative cache 10с, singleflight-коалесинг).
   - `O(1)` индексы для каналов, пользователей, токенов и кластерных алиасов (`HashMap`/`DashMap`).
   - Кэширование сгенерированных выходных HLS-плейлистов, глобальных `playlist.m3u8` / `playlist.xspf` и `ETag`/`304` для Web UI.

4. **Минимальное потребление ресурсов сервера**
   - В состоянии `IN_IDLE` канал **не держит ни кольцевой буфер TS, ни сетевых задач** (0 байт буферов, 0% CPU).
   - Zero-copy сегменты `Arc<Bytes>` (общий буфер на всех клиентов без копирования памяти).
   - Ограниченное число воркеров Tokio (`clamp(cpus, 2, 4)`, настраивается через `ASTRIKA_WORKERS`), компактный стек 1 МБ.
   - Нулевой расход CPU на WebSocket-телеметрию, когда в Web UI никто не подключён.

---

## Быстрая установка на Ubuntu 20.04 / 22.04 / 24.04

```bash
git clone https://github.com/<ВАШ_ЛОГИН>/astrika.git
cd astrika
sudo ./install.sh
```

Если на сервере уже стоял `astrag` (`/etc/astrag/astrag.conf`), команда `astrika init` автоматически перенесёт конфигурацию в `/etc/astrika/astrika.conf`.

## Сборка статического бинарника вручную

```bash
sudo apt-get update && sudo apt-get install -y musl-tools
./build-static.sh
```

## Перенос в новый репозиторий `astrika`

```bash
cd astrika
git init -b main
git add .
git commit -m "Initial release: Astrika Rust IPTV server"
git remote add origin https://github.com/<ВАШ_ЛОГИН>/astrika.git
git push -u origin main
```

## Управление сервисом и CLI

```bash
astrika --version
sudo astrika init 8000                   # создать и запустить systemd-сервис
sudo astrika reset-password admin <PASS> # сменить пароль (PBKDF2-SHA256)
sudo systemctl reload astrika            # горячая перечитка конфига (SIGHUP)
sudo astrika remove 8000                 # удалить сервис
sudo astrika purge                       # полное удаление
```
