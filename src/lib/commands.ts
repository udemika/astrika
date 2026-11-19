export interface UbuntuMigrateOptions {
  owner: string;
  repo: string;
  port: number;
  preserveConfig: boolean;
}

export function sanitizeGitHubOwner(raw: string): string {
  const cleaned = raw.trim().replace(/[^a-zA-Z0-9-]/g, '').replace(/^-+|-+$/g, '');
  return cleaned.slice(0, 39) || '<ВАШ_ЛОГИН>';
}

export function sanitizeRepoName(raw: string): string {
  const cleaned = raw.trim().replace(/[^a-zA-Z0-9._-]/g, '').replace(/^\.+/, '');
  return cleaned.slice(0, 100) || 'astrika';
}

export function normalizePort(raw: number | string): number {
  const n = typeof raw === 'number' ? raw : Number.parseInt(raw, 10);
  if (!Number.isFinite(n) || n < 1 || n > 65535) {
    return 8000;
  }
  return Math.floor(n);
}

export function redactSecret(input: string, secret: string): string {
  if (!secret) {
    return input;
  }
  return input.split(secret).join('***');
}

export function buildUbuntuMigrateCommand(opts: UbuntuMigrateOptions): string {
  const owner = sanitizeGitHubOwner(opts.owner);
  const repo = sanitizeRepoName(opts.repo);
  const port = normalizePort(opts.port);
  const repoUrl = `https://github.com/${owner}/${repo}.git`;

  if (opts.preserveConfig) {
    return [
      'sudo bash -euo pipefail -c \'',
      '  # 1. Сохраняем текущую конфигурацию astrag (каналы и пользователей)',
      '  mkdir -p /etc/astrika',
      '  if [ -f /etc/astrag/astrag.conf ] && [ ! -f /etc/astrika/astrika.conf ]; then',
      '    cp -a /etc/astrag/astrag.conf /etc/astrika/astrika.conf',
      '    echo "[+] Конфиг скопирован: /etc/astrag/astrag.conf -> /etc/astrika/astrika.conf"',
      '  fi',
      '',
      '  # 2. Останавливаем и полностью удаляем старый astrag',
      '  for u in /etc/systemd/system/astrag*.service; do',
      '    [ -e "$u" ] || continue',
      '    svc="$(basename "$u" .service)"',
      '    systemctl stop "$svc" 2>/dev/null || true',
      '    systemctl disable "$svc" 2>/dev/null || true',
      '    rm -f "$u"',
      '  done',
      '  systemctl daemon-reload',
      '  rm -rf /etc/astrag /var/lib/astrag /usr/bin/astrag /usr/local/bin/astrag',
      '',
      '  # 3. Скачиваем и устанавливаем новый Astrika (Ubuntu 20.04 / 22.04 / 24.04)',
      '  rm -rf /tmp/astrika-install',
      `  git clone --depth 1 "${repoUrl}" /tmp/astrika-install`,
      `  cd /tmp/astrika-install && ./install.sh ${port}`,
      '  rm -rf /tmp/astrika-install',
      '  systemctl --no-pager status astrika',
      '\'',
    ].join('\n');
  }

  return [
    'sudo bash -euo pipefail -c \'',
    '  # 1. Полное удаление старого astrag (сервисы, бинарник, конфиг)',
    '  for u in /etc/systemd/system/astrag*.service; do',
    '    [ -e "$u" ] || continue',
    '    svc="$(basename "$u" .service)"',
    '    systemctl stop "$svc" 2>/dev/null || true',
    '    systemctl disable "$svc" 2>/dev/null || true',
    '    rm -f "$u"',
    '  done',
    '  systemctl daemon-reload',
    '  rm -rf /etc/astrag /var/lib/astrag /usr/bin/astrag /usr/local/bin/astrag',
    '',
    '  # 2. Чистая установка Astrika (Ubuntu 20.04 / 22.04 / 24.04)',
    '  rm -rf /tmp/astrika-install',
    `  git clone --depth 1 "${repoUrl}" /tmp/astrika-install`,
    `  cd /tmp/astrika-install && ./install.sh ${port}`,
    '  rm -rf /tmp/astrika-install',
    '  systemctl --no-pager status astrika',
    '\'',
  ].join('\n');
}

export function buildManualGitPushCommand(ownerRaw: string, repoRaw: string): string {
  const owner = sanitizeGitHubOwner(ownerRaw);
  const repo = sanitizeRepoName(repoRaw);
  return [
    'cd astrika',
    'git init -b main',
    'git add .',
    'git commit -m "Initial release: Astrika 2.1 Rust IPTV server"',
    `git remote add origin https://github.com/${owner}/${repo}.git`,
    'git push -u origin main',
  ].join('\n');
}
