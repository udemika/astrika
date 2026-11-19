import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertCircle,
  Check,
  CheckCircle2,
  Copy,
  Download,
  ExternalLink,
  GitBranch,
  Loader2,
  LogOut,
  Search,
  Terminal,
  UploadCloud,
} from 'lucide-react';
import {
  buildManualGitPushCommand,
  buildUbuntuMigrateCommand,
  normalizePort,
} from './lib/commands';

interface GitHubUser {
  login: string;
  name: string;
  email: string;
  avatarUrl: string;
}

interface GitHubStatus {
  oauthConfigured: boolean;
  envTokenConfigured: boolean;
  connected: boolean;
  source: 'oauth' | 'env' | null;
  user: GitHubUser | null;
  callbackUrl: string;
  repoSummary: {
    filesCount: number;
    totalBytes: number;
    binaryBytes: number;
    ready: boolean;
  };
}

interface RepoFileEntry {
  path: string;
  size: number;
  executable: boolean;
}

interface PublishResult {
  ok: boolean;
  created: boolean;
  owner: string;
  repo: string;
  isPrivate: boolean;
  htmlUrl: string;
  cloneUrl: string;
  commitSha: string;
  filesCount: number;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function CopyButton({
  text,
  label = 'Копировать',
}: {
  text: string;
  label?: string;
}) {
  const [copied, setCopied] = useState(false);

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      // Clipboard blocked in restricted context
    }
  };

  return (
    <button
      type="button"
      onClick={onCopy}
      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-zinc-700 bg-zinc-800/80 text-zinc-200 hover:bg-zinc-700 hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer focus-visible:outline-2 focus-visible:outline-amber-400"
    >
      {copied ? (
        <>
          <Check className="w-3.5 h-3.5 text-emerald-400" />
          <span>Скопировано</span>
        </>
      ) : (
        <>
          <Copy className="w-3.5 h-3.5" />
          <span>{label}</span>
        </>
      )}
    </button>
  );
}

const BENCHMARKS = [
  {
    label: 'Статический бинарник',
    value: '4.71 MB',
    note: 'x86_64-unknown-linux-musl · static-pie · 0 зависимостей',
  },
  {
    label: 'RAM (100 idle-каналов)',
    value: '13.99 MB',
    note: '0 байт буферов в IN_IDLE · 18.59 MB при активном HLS',
  },
  {
    label: 'Холодный старт HLS',
    value: '92.7 ms',
    note: 'Отдача с 1-го сегмента + мгновенный Notify вместо 40 ms poll',
  },
  {
    label: 'PBKDF2 авторизация',
    value: '4.44 ms',
    note: 'Кэш 1024 записи + spawn_blocking + O(1) token_index',
  },
];

export default function App() {
  const [status, setStatus] = useState<GitHubStatus | null>(null);
  const [statusLoading, setStatusLoading] = useState(true);
  const [statusError, setStatusError] = useState<string | null>(null);

  const [files, setFiles] = useState<RepoFileEntry[]>([]);
  const [filesLoading, setFilesLoading] = useState(true);
  const [fileQuery, setFileQuery] = useState('');

  // GitHub publish form state
  const [repoName, setRepoName] = useState('astrika');
  const [isPrivate, setIsPrivate] = useState(false);
  const [description, setDescription] = useState(
    'Astrika — high-performance static Rust IPTV streaming server for Ubuntu 20.04/22.04/24.04'
  );
  const [connecting, setConnecting] = useState(false);
  const [publishing, setPublishing] = useState(false);
  const [publishError, setPublishError] = useState<string | null>(null);
  const [publishResult, setPublishResult] = useState<PublishResult | null>(null);
  const [showOauthGuide, setShowOauthGuide] = useState(true);

  // Ubuntu migration generator state
  const [ubuntuOwner, setUbuntuOwner] = useState('udemika');
  const [ubuntuPort, setUbuntuPort] = useState('8000');
  const [preserveConfig, setPreserveConfig] = useState(true);

  const loadStatus = useCallback(async () => {
    setStatusLoading(true);
    setStatusError(null);
    try {
      const r = await fetch('/api/github/status', { credentials: 'include' });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const data = (await r.json()) as GitHubStatus;
      setStatus(data);
      if (data.user?.login) {
        setUbuntuOwner((prev) => prev || data.user!.login);
      }
    } catch (err) {
      setStatusError(
        err instanceof Error ? err.message : 'Не удалось получить статус сервера'
      );
    } finally {
      setStatusLoading(false);
    }
  }, []);

  const loadFiles = useCallback(async () => {
    setFilesLoading(true);
    try {
      const r = await fetch('/api/astrika/files');
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const data = (await r.json()) as { files: RepoFileEntry[] };
      setFiles(data.files || []);
    } catch {
      setFiles([]);
    } finally {
      setFilesLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadStatus();
    void loadFiles();
  }, [loadStatus, loadFiles]);

  // Listen for GitHub OAuth popup completion
  useEffect(() => {
    const onMessage = (event: MessageEvent) => {
      const origin = event.origin;
      if (!origin.endsWith('.run.app') && !origin.includes('localhost')) {
        return;
      }
      if (event.data?.type === 'OAUTH_AUTH_SUCCESS') {
        setConnecting(false);
        setPublishError(null);
        void loadStatus();
      } else if (event.data?.type === 'OAUTH_AUTH_ERROR') {
        setConnecting(false);
        setPublishError(event.data?.message || 'Ошибка авторизации GitHub.');
      }
    };
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, [loadStatus]);

  const handleConnectGitHub = async () => {
    setPublishError(null);
    setConnecting(true);
    try {
      const r = await fetch('/api/auth/github/url', { credentials: 'include' });
      const data = (await r.json()) as { url?: string; error?: string };
      if (!r.ok || !data.url) {
        setConnecting(false);
        setShowOauthGuide(true);
        setPublishError(
          data.error || 'Настройте GitHub OAuth или GITHUB_TOKEN в Secrets.'
        );
        return;
      }
      const popup = window.open(
        data.url,
        'github_oauth_popup',
        'width=620,height=720'
      );
      if (!popup) {
        setConnecting(false);
        setPublishError(
          'Браузер заблокировал всплывающее окно. Разрешите pop-up и повторите попытку.'
        );
      }
    } catch (err) {
      setConnecting(false);
      setPublishError(
        err instanceof Error ? err.message : 'Не удалось открыть окно GitHub OAuth.'
      );
    }
  };

  const handleDisconnect = async () => {
    await fetch('/api/auth/github/logout', {
      method: 'POST',
      credentials: 'include',
    });
    setPublishResult(null);
    void loadStatus();
  };

  const handlePublish = async () => {
    setPublishError(null);
    setPublishResult(null);
    setPublishing(true);
    try {
      const r = await fetch('/api/github/publish', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repoName,
          isPrivate,
          description,
        }),
      });
      const data = (await r.json()) as PublishResult & { error?: string };
      if (!r.ok || !data.ok) {
        setPublishError(data.error || `Ошибка публикации (HTTP ${r.status})`);
        return;
      }
      setPublishResult(data);
      setUbuntuOwner(data.owner);
    } catch (err) {
      setPublishError(
        err instanceof Error ? err.message : 'Сбой сети при публикации в GitHub'
      );
    } finally {
      setPublishing(false);
    }
  };

  const effectiveOwner = publishResult?.owner || ubuntuOwner || status?.user?.login || '';
  const effectiveRepo = publishResult?.repo || repoName || 'astrika';

  const ubuntuCommand = useMemo(
    () =>
      buildUbuntuMigrateCommand({
        owner: effectiveOwner,
        repo: effectiveRepo,
        port: normalizePort(ubuntuPort),
        preserveConfig,
      }),
    [effectiveOwner, effectiveRepo, ubuntuPort, preserveConfig]
  );

  const manualPushCommand = useMemo(
    () => buildManualGitPushCommand(effectiveOwner, effectiveRepo),
    [effectiveOwner, effectiveRepo]
  );

  const filteredFiles = useMemo(() => {
    const q = fileQuery.trim().toLowerCase();
    if (!q) return files;
    return files.filter((f) => f.path.toLowerCase().includes(q));
  }, [files, fileQuery]);

  const originCallback =
    typeof window !== 'undefined'
      ? `${window.location.origin}/auth/callback`
      : status?.callbackUrl || '';

  return (
    <div className="min-h-screen bg-[#0b0d11] text-zinc-100 antialiased">
      {/* Top Bar: strict 3-zone contract */}
      <header className="sticky top-0 z-30 border-b border-zinc-800/80 bg-[#0b0d11]/95 backdrop-blur-sm">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between gap-8">
          <a
            href="#github-publish"
            className="text-lg font-semibold tracking-tight text-white whitespace-nowrap shrink-0"
          >
            Astrika
          </a>

          <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-zinc-400">
            <a
              href="#github-publish"
              className="hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Публикация Git
            </a>
            <a
              href="#ubuntu-migrate"
              className="hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Команда Ubuntu
            </a>
            <a
              href="#benchmarks"
              className="hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Показатели
            </a>
            <a
              href="#files"
              className="hover:text-white transition-colors whitespace-nowrap shrink-0"
            >
              Файлы
            </a>
          </nav>

          <div className="flex items-center shrink-0">
            <a
              href="/api/download/astrika.tar.gz"
              download="astrika-2.1-ubuntu-static.tar.gz"
              className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-md bg-amber-500 text-zinc-950 hover:bg-amber-400 transition-colors whitespace-nowrap shrink-0"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Скачать tar.gz</span>
            </a>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-10 space-y-12">
        {/* Intro block */}
        <section className="space-y-3">
          <div className="flex flex-wrap items-center gap-2 text-xs text-zinc-400 font-mono">
            <span>Rust 2.1.0</span>
            <span aria-hidden="true">·</span>
            <span>Ubuntu 20.04 / 22.04 / 24.04</span>
            <span aria-hidden="true">·</span>
            <span>x86_64-unknown-linux-musl</span>
            <span aria-hidden="true">·</span>
            <span className="tabular-nums">
              {status ? `${status.repoSummary.filesCount} файлов` : 'загрузка...'}
            </span>
          </div>
          <h1 className="text-3xl sm:text-4xl font-semibold tracking-tight text-white [text-wrap:balance]">
            Публикация репозитория astrika и миграция с astrag на Ubuntu
          </h1>
          <p className="text-sm sm:text-base text-zinc-400 max-w-3xl leading-relaxed">
            Создайте репозиторий <span className="font-mono text-zinc-200">astrika</span> в вашем
            GitHub и отправьте туда исходники Rust вместе со статическим бинарником в один клик, а
            затем выполните готовую команду на сервере для безопасного удаления старого{' '}
            <span className="font-mono text-zinc-200">astrag</span> и установки нового сервера.
          </p>
        </section>

        {/* Section 1: Automatic GitHub Repository Creation & Push */}
        <section
          id="github-publish"
          className="rounded-lg border border-zinc-800 bg-[#12151c] overflow-hidden"
        >
          <div className="px-6 py-5 border-b border-zinc-800/80 flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-white">
                01. Автоматическое создание и отправка в GitHub
              </h2>
              <p className="text-xs sm:text-sm text-zinc-400 mt-1">
                Сервер создаёт репозиторий через GitHub API, выполняет <span className="font-mono">git init</span>,
                коммит и <span className="font-mono">git push</span> в ветку <span className="font-mono">main</span>.
              </p>
            </div>

            <div className="flex items-center gap-3">
              {statusLoading ? (
                <span className="inline-flex items-center gap-2 text-xs text-zinc-400">
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Проверка GitHub...</span>
                </span>
              ) : status?.connected && status.user ? (
                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <div className="text-xs font-medium text-white">
                      @{status.user.login}
                    </div>
                    <div className="text-[11px] text-zinc-400">
                      {status.source === 'oauth' ? 'GitHub OAuth' : 'GITHUB_TOKEN (Secrets)'}
                    </div>
                  </div>
                  {status.source === 'oauth' && (
                    <button
                      type="button"
                      onClick={handleDisconnect}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md border border-zinc-700 text-zinc-300 hover:bg-zinc-800 hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                    >
                      <LogOut className="w-3.5 h-3.5" />
                      <span>Отключить</span>
                    </button>
                  )}
                </div>
              ) : (
                <button
                  type="button"
                  onClick={handleConnectGitHub}
                  disabled={connecting}
                  className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold rounded-md border border-zinc-600 bg-zinc-800 text-white hover:bg-zinc-700 transition-colors whitespace-nowrap shrink-0 disabled:opacity-60 cursor-pointer"
                >
                  {connecting ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <GitBranch className="w-3.5 h-3.5" />
                  )}
                  <span>Подключить GitHub</span>
                </button>
              )}
            </div>
          </div>

          <div className="p-6 space-y-6">
            {statusError && (
              <div className="p-3.5 rounded-md border border-red-500/30 bg-red-500/10 text-red-200 text-xs flex items-start gap-2.5">
                <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
                <span>{statusError}</span>
              </div>
            )}

            {/* Form controls */}
            <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
              <div className="md:col-span-4 space-y-1.5">
                <label
                  htmlFor="repo-name"
                  className="block text-xs font-medium text-zinc-300"
                >
                  Имя репозитория
                </label>
                <input
                  id="repo-name"
                  type="text"
                  value={repoName}
                  onChange={(e) => setRepoName(e.target.value)}
                  placeholder="astrika"
                  className="w-full h-10 px-3 rounded-md border border-zinc-700 bg-zinc-950 text-sm font-mono text-white placeholder-zinc-500 focus:outline-none focus:border-amber-500"
                />
              </div>

              <div className="md:col-span-4 space-y-1.5">
                <span className="block text-xs font-medium text-zinc-300">
                  Видимость репозитория
                </span>
                <div className="grid grid-cols-2 gap-1 p-1 h-10 rounded-md border border-zinc-700 bg-zinc-950">
                  <button
                    type="button"
                    onClick={() => setIsPrivate(false)}
                    className={`text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                      !isPrivate
                        ? 'bg-zinc-800 text-white'
                        : 'text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    Публичный
                  </button>
                  <button
                    type="button"
                    onClick={() => setIsPrivate(true)}
                    className={`text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap ${
                      isPrivate
                        ? 'bg-zinc-800 text-white'
                        : 'text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    Приватный
                  </button>
                </div>
              </div>

              <div className="md:col-span-4 flex items-end">
                <button
                  type="button"
                  onClick={handlePublish}
                  disabled={publishing || !status?.connected}
                  className="w-full h-10 inline-flex items-center justify-center gap-2 px-4 text-xs sm:text-sm font-semibold rounded-md bg-amber-500 text-zinc-950 hover:bg-amber-400 disabled:bg-zinc-800 disabled:text-zinc-500 transition-colors whitespace-nowrap cursor-pointer disabled:cursor-not-allowed"
                >
                  {publishing ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span>Создание и отправка...</span>
                    </>
                  ) : (
                    <>
                      <UploadCloud className="w-4 h-4" />
                      <span>Создать и отправить в GitHub</span>
                    </>
                  )}
                </button>
              </div>

              <div className="md:col-span-12 space-y-1.5">
                <label
                  htmlFor="repo-desc"
                  className="block text-xs font-medium text-zinc-300"
                >
                  Описание репозитория
                </label>
                <input
                  id="repo-desc"
                  type="text"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className="w-full h-10 px-3 rounded-md border border-zinc-700 bg-zinc-950 text-sm text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-amber-500"
                />
              </div>
            </div>

            {publishError && (
              <div className="p-4 rounded-md border border-red-500/30 bg-red-500/10 text-red-200 text-xs sm:text-sm flex items-start gap-2.5">
                <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
                <div className="space-y-1">
                  <div className="font-medium">Не удалось выполнить отправку</div>
                  <div className="font-mono text-xs text-red-200/90 break-all">
                    {publishError}
                  </div>
                </div>
              </div>
            )}

            {publishResult && (
              <div className="p-4 rounded-md border border-emerald-500/30 bg-emerald-500/10 text-emerald-100 text-sm flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-start gap-2.5">
                  <CheckCircle2 className="w-5 h-5 shrink-0 mt-0.5 text-emerald-400" />
                  <div className="space-y-1">
                    <div className="font-semibold">
                      {publishResult.created
                        ? 'Репозиторий создан и код успешно отправлен'
                        : 'Код успешно обновлён в репозитории'}
                    </div>
                    <div className="text-xs font-mono text-emerald-200/90">
                      {publishResult.owner}/{publishResult.repo} · ветка main · коммит{' '}
                      {publishResult.commitSha} · {publishResult.filesCount} файлов
                    </div>
                  </div>
                </div>
                <a
                  href={publishResult.htmlUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold rounded-md bg-emerald-500 text-zinc-950 hover:bg-emerald-400 transition-colors whitespace-nowrap shrink-0"
                >
                  <span>Открыть на GitHub</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </a>
              </div>
            )}

            {/* Auth setup guidance when not connected */}
            {!statusLoading && !status?.connected && (
              <div className="pt-4 border-t border-zinc-800/80 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <p className="text-xs sm:text-sm text-zinc-300">
                    Для автоматической отправки добавьте доступ GitHub в панель{' '}
                    <span className="font-semibold text-white">Secrets</span> AI Studio (два способа):
                  </p>
                  <button
                    type="button"
                    onClick={() => setShowOauthGuide((v) => !v)}
                    className="text-xs font-medium text-amber-400 hover:text-amber-300 underline underline-offset-4 cursor-pointer whitespace-nowrap"
                  >
                    {showOauthGuide ? 'Скрыть инструкцию' : 'Показать параметры Secrets / OAuth'}
                  </button>
                </div>

                {showOauthGuide && (
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 text-xs text-zinc-300">
                    <div className="p-4 rounded-md border border-zinc-800 bg-zinc-950/70 space-y-2.5">
                      <div className="font-semibold text-white">
                        Быстрый способ: один секрет GITHUB_TOKEN
                      </div>
                      <ol className="list-decimal list-inside space-y-1.5 text-zinc-400 leading-relaxed">
                        <li>
                          Создайте Classic Personal Access Token на{' '}
                          <a
                            href="https://github.com/settings/tokens/new?scopes=repo&description=Astrika+Publish"
                            target="_blank"
                            rel="noreferrer"
                            className="text-amber-400 hover:underline"
                          >
                            github.com/settings/tokens
                          </a>{' '}
                          с правом <span className="font-mono text-zinc-200">repo</span>.
                        </li>
                        <li>
                          Добавьте секрет <span className="font-mono text-zinc-200">GITHUB_TOKEN</span>{' '}
                          в панели Secrets AI Studio и обновите страницу — кнопка отправки активируется автоматически.
                        </li>
                      </ol>
                    </div>

                    <div className="p-4 rounded-md border border-zinc-800 bg-zinc-950/70 space-y-2.5">
                      <div className="font-semibold text-white">
                        Через GitHub OAuth App (кнопка «Подключить GitHub»)
                      </div>
                      <ol className="list-decimal list-inside space-y-1.5 text-zinc-400 leading-relaxed">
                        <li>
                          Откройте{' '}
                          <a
                            href="https://github.com/settings/developers"
                            target="_blank"
                            rel="noreferrer"
                            className="text-amber-400 hover:underline"
                          >
                            github.com/settings/developers
                          </a>{' '}
                          → New OAuth App.
                        </li>
                        <li>
                          Добавьте secrets{' '}
                          <span className="font-mono text-zinc-200">GITHUB_CLIENT_ID</span> и{' '}
                          <span className="font-mono text-zinc-200">GITHUB_CLIENT_SECRET</span>.
                        </li>
                      </ol>
                      {originCallback && (
                        <div className="pt-1 flex items-center justify-between gap-2 bg-zinc-900 px-3 py-2 rounded border border-zinc-800">
                          <code className="text-[11px] font-mono text-zinc-200 truncate">
                            {originCallback}
                          </code>
                          <CopyButton text={originCallback} label="Callback URL" />
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </section>

        {/* Section 2: Ubuntu Command — Remove old astrag & Install new astrika */}
        <section
          id="ubuntu-migrate"
          className="rounded-lg border border-zinc-800 bg-[#12151c] overflow-hidden"
        >
          <div className="px-6 py-5 border-b border-zinc-800/80 flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-white">
                02. Команда для Ubuntu 20.04 / 22.04 / 24.04: удалить astrag и поставить astrika
              </h2>
              <p className="text-xs sm:text-sm text-zinc-400 mt-1">
                Останавливает и удаляет все systemd-юниты и бинарник старого{' '}
                <span className="font-mono text-zinc-300">astrag</span>, затем устанавливает и
                запускает статический <span className="font-mono text-zinc-300">astrika</span>.
              </p>
            </div>
            <CopyButton text={ubuntuCommand} label="Копировать команду" />
          </div>

          <div className="p-6 space-y-5">
            <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
              <div className="md:col-span-4 space-y-1.5">
                <label
                  htmlFor="ubuntu-owner"
                  className="block text-xs font-medium text-zinc-300"
                >
                  Ваш логин GitHub
                </label>
                <input
                  id="ubuntu-owner"
                  type="text"
                  value={ubuntuOwner}
                  onChange={(e) => setUbuntuOwner(e.target.value)}
                  placeholder="например: udemika"
                  className="w-full h-10 px-3 rounded-md border border-zinc-700 bg-zinc-950 text-sm font-mono text-white placeholder-zinc-500 focus:outline-none focus:border-amber-500"
                />
              </div>

              <div className="md:col-span-2 space-y-1.5">
                <label
                  htmlFor="ubuntu-port"
                  className="block text-xs font-medium text-zinc-300"
                >
                  Порт Web UI
                </label>
                <input
                  id="ubuntu-port"
                  type="text"
                  inputMode="numeric"
                  value={ubuntuPort}
                  onChange={(e) => setUbuntuPort(e.target.value)}
                  className="w-full h-10 px-3 rounded-md border border-zinc-700 bg-zinc-950 text-sm font-mono tabular-nums text-white focus:outline-none focus:border-amber-500"
                />
              </div>

              <div className="md:col-span-6 space-y-1.5">
                <span className="block text-xs font-medium text-zinc-300">
                  Режим удаления старого astrag
                </span>
                <div className="grid grid-cols-2 gap-1 p-1 h-10 rounded-md border border-zinc-700 bg-zinc-950">
                  <button
                    type="button"
                    onClick={() => setPreserveConfig(true)}
                    className={`text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap px-2 truncate ${
                      preserveConfig
                        ? 'bg-zinc-800 text-white'
                        : 'text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    Перенести конфиг и каналы
                  </button>
                  <button
                    type="button"
                    onClick={() => setPreserveConfig(false)}
                    className={`text-xs font-medium rounded transition-colors cursor-pointer whitespace-nowrap px-2 truncate ${
                      !preserveConfig
                        ? 'bg-zinc-800 text-white'
                        : 'text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    Полностью удалить всё
                  </button>
                </div>
              </div>
            </div>

            <div className="rounded-md border border-zinc-800 bg-zinc-950 overflow-hidden">
              <div className="px-4 py-2 border-b border-zinc-800/80 flex items-center justify-between text-xs text-zinc-400">
                <span className="inline-flex items-center gap-2 font-mono">
                  <Terminal className="w-3.5 h-3.5 text-amber-400" />
                  <span>Ubuntu 20.04 / 22.04 / 24.04 (bash)</span>
                </span>
                <span className="text-[11px] text-zinc-500">
                  {preserveConfig
                    ? 'Копирует /etc/astrag/astrag.conf → /etc/astrika/astrika.conf до удаления'
                    : 'Удаляет /etc/astrag и создаёт чистую конфигурацию'}
                </span>
              </div>
              <pre className="p-4 text-xs sm:text-[13px] font-mono text-zinc-200 overflow-x-auto leading-relaxed">
                <code>{ubuntuCommand}</code>
              </pre>
            </div>

            {/* Manual local push fallback */}
            <details className="rounded-md border border-zinc-800/80 bg-zinc-950/50">
              <summary className="px-4 py-3 text-xs font-medium text-zinc-300 cursor-pointer hover:text-white select-none">
                Альтернатива: ручная отправка скачанного архива tar.gz в GitHub
              </summary>
              <div className="px-4 pb-4 space-y-2 border-t border-zinc-800/70 pt-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs text-zinc-400">
                    Распакуйте <span className="font-mono">astrika-2.1-ubuntu-static.tar.gz</span> и выполните:
                  </span>
                  <CopyButton text={manualPushCommand} label="Копировать git push" />
                </div>
                <pre className="p-3 rounded bg-zinc-950 border border-zinc-800 text-xs font-mono text-zinc-300 overflow-x-auto leading-relaxed">
                  <code>{manualPushCommand}</code>
                </pre>
              </div>
            </details>
          </div>
        </section>

        {/* Section 3: Measured benchmarks */}
        <section id="benchmarks" className="space-y-4">
          <h2 className="text-lg font-semibold text-white">
            03. Проверенные показатели собранного бинарника
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {BENCHMARKS.map((m) => (
              <div
                key={m.label}
                className="p-5 rounded-lg border border-zinc-800 bg-[#12151c]"
              >
                <div className="text-xs font-medium text-zinc-400">{m.label}</div>
                <div className="mt-2 text-2xl font-semibold font-mono tabular-nums text-white">
                  {m.value}
                </div>
                <p className="mt-2 text-xs text-zinc-400 leading-relaxed">{m.note}</p>
              </div>
            ))}
          </div>
        </section>

        {/* Section 4: Live repository file inventory */}
        <section id="files" className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-semibold text-white">
                04. Содержимое отправляемого репозитория (astrika/)
              </h2>
              <p className="text-xs text-zinc-400 mt-0.5 tabular-nums">
                {files.length} файлов · всего{' '}
                {formatBytes(files.reduce((sum, f) => sum + f.size, 0))} (включая статический бинарник)
              </p>
            </div>
            <div className="relative w-full sm:w-64">
              <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={fileQuery}
                onChange={(e) => setFileQuery(e.target.value)}
                placeholder="Фильтр файлов..."
                className="w-full h-9 pl-9 pr-3 rounded-md border border-zinc-800 bg-[#12151c] text-xs font-mono text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-amber-500"
              />
            </div>
          </div>

          <div className="rounded-lg border border-zinc-800 bg-[#12151c] overflow-hidden">
            {filesLoading ? (
              <div className="p-6 text-xs text-zinc-400 flex items-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Загрузка списка файлов...</span>
              </div>
            ) : filteredFiles.length === 0 ? (
              <div className="p-6 text-xs text-zinc-400">
                По запросу «{fileQuery}» файлы не найдены.
              </div>
            ) : (
              <div className="divide-y divide-zinc-800/70">
                {filteredFiles.map((f) => (
                  <div
                    key={f.path}
                    className="px-4 h-10 flex items-center justify-between gap-4 hover:bg-zinc-900/50 transition-colors"
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <code className="text-xs font-mono text-zinc-200 truncate">
                        astrika/{f.path}
                      </code>
                      {f.executable && (
                        <span className="text-[11px] font-mono text-amber-400/90 shrink-0">
                          +x
                        </span>
                      )}
                    </div>
                    <span className="text-xs font-mono tabular-nums text-zinc-400 shrink-0">
                      {formatBytes(f.size)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}
