import crypto from 'node:crypto';
import { execFile, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import dotenv from 'dotenv';
import express, { type Request, type Response } from 'express';
import { createServer as createViteServer } from 'vite';
import { redactSecret, sanitizeRepoName } from './src/lib/commands.ts';

dotenv.config();

const execFileAsync = promisify(execFile);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ASTRIKA_DIR = path.resolve(__dirname, 'astrika');
const PORT = 3000;

interface GitHubUser {
  login: string;
  name: string;
  email: string;
  avatarUrl: string;
}

interface SessionRecord {
  token: string;
  user: GitHubUser;
  createdAt: number;
}

const sessions = new Map<string, SessionRecord>();
const oauthStates = new Map<string, number>();

const COOKIE_NAME = 'astrika_gh_sid';
const SESSION_TTL_MS = 2 * 60 * 60 * 1000;
const STATE_TTL_MS = 10 * 60 * 1000;

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    out[k] = decodeURIComponent(v);
  }
  return out;
}

function getAppUrl(req: Request): string {
  const envUrl = (process.env.APP_URL || '').trim().replace(/\/+$/, '');
  if (envUrl && envUrl !== 'MY_APP_URL') {
    return envUrl;
  }
  const proto = (req.headers['x-forwarded-proto'] as string) || req.protocol || 'http';
  const host = req.headers['x-forwarded-host'] || req.headers.host || `localhost:${PORT}`;
  return `${proto}://${host}`;
}

function getCallbackUrl(req: Request): string {
  return `${getAppUrl(req)}/auth/callback`;
}

function cleanupExpired() {
  const now = Date.now();
  for (const [sid, rec] of sessions) {
    if (now - rec.createdAt > SESSION_TTL_MS) {
      sessions.delete(sid);
    }
  }
  for (const [st, ts] of oauthStates) {
    if (now - ts > STATE_TTL_MS) {
      oauthStates.delete(st);
    }
  }
}

async function fetchGitHubUser(token: string): Promise<GitHubUser> {
  const resp = await fetch('https://api.github.com/user', {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'Astrika-Publisher/2.1',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });
  if (!resp.ok) {
    throw new Error(`GitHub auth failed (HTTP ${resp.status})`);
  }
  const data = (await resp.json()) as {
    login?: string;
    name?: string | null;
    email?: string | null;
    avatar_url?: string;
  };
  const login = data.login || '';
  if (!login) {
    throw new Error('GitHub user response missing login');
  }
  return {
    login,
    name: data.name || login,
    email: data.email || `${login}@users.noreply.github.com`,
    avatarUrl: data.avatar_url || '',
  };
}

let cachedEnvUser: { tokenHash: string; user: GitHubUser; fetchedAt: number } | null = null;

async function resolveAuth(
  req: Request
): Promise<{ token: string; user: GitHubUser; source: 'oauth' | 'env' } | null> {
  cleanupExpired();
  const cookies = parseCookies(req.headers.cookie);
  const sid = cookies[COOKIE_NAME];
  if (sid) {
    const sess = sessions.get(sid);
    if (sess) {
      return { token: sess.token, user: sess.user, source: 'oauth' };
    }
  }

  const envToken = (process.env.GITHUB_TOKEN || '').trim();
  if (envToken) {
    const hash = crypto.createHash('sha256').update(envToken).digest('hex');
    if (
      cachedEnvUser &&
      cachedEnvUser.tokenHash === hash &&
      Date.now() - cachedEnvUser.fetchedAt < 5 * 60 * 1000
    ) {
      return { token: envToken, user: cachedEnvUser.user, source: 'env' };
    }
    try {
      const user = await fetchGitHubUser(envToken);
      cachedEnvUser = { tokenHash: hash, user, fetchedAt: Date.now() };
      return { token: envToken, user, source: 'env' };
    } catch {
      return null;
    }
  }

  return null;
}

interface RepoFileEntry {
  path: string;
  size: number;
  executable: boolean;
}

function listAstrikaFiles(baseDir: string): RepoFileEntry[] {
  const result: RepoFileEntry[] = [];
  if (!fs.existsSync(baseDir)) return result;

  function walk(dir: string) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const e of entries) {
      if (e.name === 'target' || e.name === '.git') continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        walk(full);
      } else if (e.isFile()) {
        const st = fs.statSync(full);
        const rel = path.relative(baseDir, full).split(path.sep).join('/');
        result.push({
          path: rel,
          size: st.size,
          executable: Boolean(st.mode & 0o111),
        });
      }
    }
  }

  walk(baseDir);
  result.sort((a, b) => a.path.localeCompare(b.path));
  return result;
}

function copyAstrikaForGit(srcDir: string, dstDir: string) {
  fs.mkdirSync(dstDir, { recursive: true });
  const entries = fs.readdirSync(srcDir, { withFileTypes: true });
  for (const e of entries) {
    if (e.name === 'target' || e.name === '.git') continue;
    const s = path.join(srcDir, e.name);
    const d = path.join(dstDir, e.name);
    if (e.isDirectory()) {
      copyAstrikaForGit(s, d);
    } else if (e.isFile()) {
      fs.copyFileSync(s, d);
      const st = fs.statSync(s);
      fs.chmodSync(d, st.mode);
    }
  }
}

async function runGit(cwd: string, args: string[], tokenToRedact = ''): Promise<string> {
  try {
    const { stdout, stderr } = await execFileAsync('git', args, {
      cwd,
      timeout: 120_000,
      maxBuffer: 10 * 1024 * 1024,
      env: {
        ...process.env,
        GIT_TERMINAL_PROMPT: '0',
        GIT_ASKPASS: 'echo',
      },
    });
    return redactSecret((stdout || stderr || '').trim(), tokenToRedact);
  } catch (err) {
    const e = err as { stderr?: string; stdout?: string; message?: string };
    const msg = redactSecret(
      (e.stderr || e.stdout || e.message || 'git command failed').trim(),
      tokenToRedact
    );
    throw new Error(msg);
  }
}

async function startServer() {
  const app = express();
  app.set('trust proxy', 1);
  app.use(express.json({ limit: '1mb' }));

  // 1. Status & package inventory
  app.get('/api/github/status', async (req: Request, res: Response) => {
    const oauthConfigured = Boolean(
      (process.env.GITHUB_CLIENT_ID || '').trim() &&
        (process.env.GITHUB_CLIENT_SECRET || '').trim()
    );
    const envTokenConfigured = Boolean((process.env.GITHUB_TOKEN || '').trim());
    const auth = await resolveAuth(req);
    const files = listAstrikaFiles(ASTRIKA_DIR);
    const totalBytes = files.reduce((acc, f) => acc + f.size, 0);
    const binaryFile = files.find((f) => f.path === 'astrika');

    res.json({
      oauthConfigured,
      envTokenConfigured,
      connected: Boolean(auth),
      source: auth?.source ?? null,
      user: auth?.user ?? null,
      callbackUrl: getCallbackUrl(req),
      repoSummary: {
        filesCount: files.length,
        totalBytes,
        binaryBytes: binaryFile?.size ?? 0,
        ready: Boolean(binaryFile && files.length > 0),
      },
    });
  });

  // 2. Real file inventory in /astrika
  app.get('/api/astrika/files', (_req: Request, res: Response) => {
    const files = listAstrikaFiles(ASTRIKA_DIR);
    res.json({
      root: 'astrika',
      count: files.length,
      totalBytes: files.reduce((sum, f) => sum + f.size, 0),
      files,
    });
  });

  // 3. GitHub OAuth URL generator (opens provider URL directly in popup)
  app.get('/api/auth/github/url', (req: Request, res: Response) => {
    const clientId = (process.env.GITHUB_CLIENT_ID || '').trim();
    const clientSecret = (process.env.GITHUB_CLIENT_SECRET || '').trim();
    if (!clientId || !clientSecret) {
      res.status(400).json({
        error:
          'GITHUB_CLIENT_ID и GITHUB_CLIENT_SECRET не настроены в Secrets (или задайте GITHUB_TOKEN).',
      });
      return;
    }

    cleanupExpired();
    const state = crypto.randomBytes(24).toString('hex');
    oauthStates.set(state, Date.now());

    const redirectUri = getCallbackUrl(req);
    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: 'repo',
      state,
    });

    res.json({
      url: `https://github.com/login/oauth/authorize?${params.toString()}`,
      redirectUri,
    });
  });

  // 4. GitHub OAuth Callback (handles both /auth/callback and /auth/callback/)
  app.get(['/auth/callback', '/auth/callback/'], async (req: Request, res: Response) => {
    const code = typeof req.query.code === 'string' ? req.query.code : '';
    const state = typeof req.query.state === 'string' ? req.query.state : '';
    const errParam = typeof req.query.error === 'string' ? req.query.error : '';

    const sendPopupResult = (ok: boolean, message: string) => {
      const safeMsg = JSON.stringify(message);
      const eventType = ok ? 'OAUTH_AUTH_SUCCESS' : 'OAUTH_AUTH_ERROR';
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(`<!doctype html>
<html lang="ru">
<head><meta charset="utf-8"><title>GitHub OAuth — Astrika</title></head>
<body style="font-family:sans-serif;background:#0b0d11;color:#f4f4f5;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;">
  <div style="text-align:center;max-width:420px;padding:24px;">
    <p>${ok ? 'Авторизация GitHub выполнена.' : 'Ошибка авторизации GitHub.'}</p>
    <p style="color:#a1a1aa;font-size:13px;">Окно закроется автоматически.</p>
  </div>
  <script>
    if (window.opener) {
      window.opener.postMessage({ type: ${JSON.stringify(eventType)}, message: ${safeMsg} }, '*');
      window.close();
    } else {
      window.location.href = '/';
    }
  </script>
</body>
</html>`);
    };

    if (errParam) {
      sendPopupResult(false, `GitHub отклонил запрос: ${errParam}`);
      return;
    }

    if (!code || !state || !oauthStates.has(state)) {
      sendPopupResult(false, 'Некорректный или истёкший параметр state.');
      return;
    }
    oauthStates.delete(state);

    const clientId = (process.env.GITHUB_CLIENT_ID || '').trim();
    const clientSecret = (process.env.GITHUB_CLIENT_SECRET || '').trim();
    if (!clientId || !clientSecret) {
      sendPopupResult(false, 'GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET не настроены.');
      return;
    }

    try {
      const tokenResp = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'User-Agent': 'Astrika-Publisher/2.1',
        },
        body: JSON.stringify({
          client_id: clientId,
          client_secret: clientSecret,
          code,
          redirect_uri: getCallbackUrl(req),
        }),
      });
      const tokenJson = (await tokenResp.json()) as {
        access_token?: string;
        error?: string;
        error_description?: string;
      };
      if (!tokenJson.access_token) {
        sendPopupResult(
          false,
          tokenJson.error_description || tokenJson.error || 'Не удалось получить access_token.'
        );
        return;
      }

      const user = await fetchGitHubUser(tokenJson.access_token);
      const sid = crypto.randomBytes(32).toString('hex');
      sessions.set(sid, { token: tokenJson.access_token, user, createdAt: Date.now() });

      res.cookie(COOKIE_NAME, sid, {
        httpOnly: true,
        secure: true,
        sameSite: 'none',
        maxAge: SESSION_TTL_MS,
        path: '/',
      });
      sendPopupResult(true, `Подключён аккаунт ${user.login}`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Ошибка обмена OAuth токена';
      sendPopupResult(false, msg);
    }
  });

  // 5. Logout OAuth session
  app.post('/api/auth/github/logout', (req: Request, res: Response) => {
    const cookies = parseCookies(req.headers.cookie);
    if (cookies[COOKIE_NAME]) {
      sessions.delete(cookies[COOKIE_NAME]);
    }
    res.clearCookie(COOKIE_NAME, {
      httpOnly: true,
      secure: true,
      sameSite: 'none',
      path: '/',
    });
    res.json({ ok: true });
  });

  // 6. Automatic create & push GitHub repository
  app.post('/api/github/publish', async (req: Request, res: Response) => {
    const auth = await resolveAuth(req);
    if (!auth) {
      res.status(401).json({
        error:
          'GitHub не подключён. Нажмите «Подключить GitHub» (OAuth) или добавьте GITHUB_TOKEN в Secrets AI Studio.',
      });
      return;
    }

    if (!fs.existsSync(ASTRIKA_DIR)) {
      res.status(500).json({ error: 'Каталог astrika/ не найден на сервере.' });
      return;
    }

    const body = (req.body || {}) as {
      repoName?: string;
      isPrivate?: boolean;
      description?: string;
    };
    const repoName = sanitizeRepoName(body.repoName || 'astrika');
    const isPrivate = Boolean(body.isPrivate);
    const description =
      (body.description || '').trim().slice(0, 240) ||
      'Astrika — high-performance static Rust IPTV streaming server for Ubuntu 20.04/22.04/24.04';

    const ghHeaders = {
      Authorization: `Bearer ${auth.token}`,
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json',
      'User-Agent': 'Astrika-Publisher/2.1',
      'X-GitHub-Api-Version': '2022-11-28',
    };

    let created = false;
    let htmlUrl = `https://github.com/${auth.user.login}/${repoName}`;
    let cloneUrl = `https://github.com/${auth.user.login}/${repoName}.git`;

    try {
      // Step 1: Check whether repository already exists
      const checkResp = await fetch(
        `https://api.github.com/repos/${encodeURIComponent(auth.user.login)}/${encodeURIComponent(repoName)}`,
        { headers: ghHeaders }
      );

      if (checkResp.status === 404) {
        const createResp = await fetch('https://api.github.com/user/repos', {
          method: 'POST',
          headers: ghHeaders,
          body: JSON.stringify({
            name: repoName,
            description,
            private: isPrivate,
            auto_init: false,
          }),
        });
        if (!createResp.ok) {
          const errBody = (await createResp.json().catch(() => ({}))) as { message?: string };
          res.status(createResp.status).json({
            error: `Не удалось создать репозиторий GitHub: ${errBody.message || `HTTP ${createResp.status}`}`,
          });
          return;
        }
        const createdRepo = (await createResp.json()) as {
          html_url?: string;
          clone_url?: string;
        };
        created = true;
        if (createdRepo.html_url) htmlUrl = createdRepo.html_url;
        if (createdRepo.clone_url) cloneUrl = createdRepo.clone_url;
      } else if (checkResp.ok) {
        const existingRepo = (await checkResp.json()) as {
          html_url?: string;
          clone_url?: string;
        };
        if (existingRepo.html_url) htmlUrl = existingRepo.html_url;
        if (existingRepo.clone_url) cloneUrl = existingRepo.clone_url;
      } else {
        const errBody = (await checkResp.json().catch(() => ({}))) as { message?: string };
        res.status(checkResp.status).json({
          error: `Ошибка проверки репозитория GitHub: ${errBody.message || `HTTP ${checkResp.status}`}`,
        });
        return;
      }

      // Step 2: Stage files in isolated temp directory and push cleanly
      const stageDir = fs.mkdtempSync(path.join(os.tmpdir(), 'astrika-git-'));
      try {
        copyAstrikaForGit(ASTRIKA_DIR, stageDir);
        const stagedFiles = listAstrikaFiles(stageDir);

        await runGit(stageDir, ['init', '-b', 'main'], auth.token);
        await runGit(stageDir, ['config', 'user.name', auth.user.name], auth.token);
        await runGit(stageDir, ['config', 'user.email', auth.user.email], auth.token);
        await runGit(stageDir, ['add', '-A'], auth.token);
        await runGit(
          stageDir,
          [
            'commit',
            '-m',
            'Initial release: Astrika 2.1 Rust IPTV server (static Ubuntu 20/22/24)',
          ],
          auth.token
        );
        const commitSha = await runGit(stageDir, ['rev-parse', '--short', 'HEAD'], auth.token);

        const pushUrl = `https://x-access-token:${encodeURIComponent(auth.token)}@github.com/${encodeURIComponent(auth.user.login)}/${encodeURIComponent(repoName)}.git`;
        await runGit(stageDir, ['push', '-u', pushUrl, 'main', '--force'], auth.token);

        res.json({
          ok: true,
          created,
          owner: auth.user.login,
          repo: repoName,
          isPrivate,
          htmlUrl,
          cloneUrl,
          commitSha,
          filesCount: stagedFiles.length,
        });
      } finally {
        fs.rmSync(stageDir, { recursive: true, force: true });
      }
    } catch (err) {
      const msg = redactSecret(
        err instanceof Error ? err.message : 'Ошибка отправки в GitHub',
        auth.token
      );
      res.status(500).json({ error: msg });
    }
  });

  // 7. One-click tar.gz download of the complete /astrika repo (with static binary)
  app.get('/api/download/astrika.tar.gz', (_req: Request, res: Response) => {
    if (!fs.existsSync(ASTRIKA_DIR)) {
      res.status(404).json({ error: 'Каталог astrika/ не найден.' });
      return;
    }
    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader('Content-Disposition', 'attachment; filename="astrika-2.1-ubuntu-static.tar.gz"');

    const tar = spawn(
      'tar',
      ['-czf', '-', '--exclude=astrika/target', '--exclude=astrika/.git', '-C', __dirname, 'astrika'],
      { stdio: ['ignore', 'pipe', 'pipe'] }
    );
    tar.stdout.pipe(res);
    tar.on('error', () => {
      if (!res.headersSent) {
        res.status(500).json({ error: 'Не удалось сформировать архив.' });
      } else {
        res.end();
      }
    });
  });

  // Mount Vite middleware in dev, static dist in production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Astrika publisher server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
