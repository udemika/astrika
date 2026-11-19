import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildManualGitPushCommand,
  buildUbuntuMigrateCommand,
  normalizePort,
  redactSecret,
  sanitizeGitHubOwner,
  sanitizeRepoName,
} from './commands.ts';

test('sanitizes GitHub owner and repository names safely', () => {
  assert.equal(sanitizeGitHubOwner('  udemika  '), 'udemika');
  assert.equal(sanitizeGitHubOwner('bad;rm -rf /'), 'badrm-rf');
  assert.equal(sanitizeGitHubOwner('   '), '<ВАШ_ЛОГИН>');

  assert.equal(sanitizeRepoName('astrika'), 'astrika');
  assert.equal(sanitizeRepoName('..astrika/bad'), 'astrikabad');
  assert.equal(sanitizeRepoName(''), 'astrika');
});

test('normalizes port bounds', () => {
  assert.equal(normalizePort(8000), 8000);
  assert.equal(normalizePort('9001'), 9001);
  assert.equal(normalizePort(0), 8000);
  assert.equal(normalizePort(70000), 8000);
  assert.equal(normalizePort('abc'), 8000);
});

test('preserveConfig Ubuntu command copies astrag.conf before removing astrag', () => {
  const cmd = buildUbuntuMigrateCommand({
    owner: 'udemika',
    repo: 'astrika',
    port: 8080,
    preserveConfig: true,
  });

  const copyIdx = cmd.indexOf('cp -a /etc/astrag/astrag.conf /etc/astrika/astrika.conf');
  const rmIdx = cmd.indexOf('rm -rf /etc/astrag /var/lib/astrag /usr/bin/astrag');
  const cloneIdx = cmd.indexOf('https://github.com/udemika/astrika.git');

  assert.ok(copyIdx > 0, 'must copy astrag.conf first');
  assert.ok(rmIdx > copyIdx, 'must remove /etc/astrag only after copying');
  assert.ok(cloneIdx > rmIdx, 'must clone astrika after removing astrag');
  assert.ok(cmd.includes('./install.sh 8080'));
});

test('clean Ubuntu command purges astrag without copying old config', () => {
  const cmd = buildUbuntuMigrateCommand({
    owner: 'udemika',
    repo: 'astrika',
    port: 8000,
    preserveConfig: false,
  });

  assert.ok(!cmd.includes('cp -a /etc/astrag/astrag.conf'));
  assert.ok(cmd.includes('rm -rf /etc/astrag /var/lib/astrag /usr/bin/astrag'));
  assert.ok(cmd.includes('./install.sh 8000'));
});

test('redacts tokens completely from command/error output', () => {
  const secret = 'ghp_SuperSecretToken12345';
  const raw = `fatal: unable to access 'https://x-access-token:${secret}@github.com/u/astrika.git'`;
  const clean = redactSecret(raw, secret);
  assert.ok(!clean.includes(secret));
  assert.ok(clean.includes('***'));
});

test('builds manual git push instructions', () => {
  const cmd = buildManualGitPushCommand('udemika', 'astrika');
  assert.ok(cmd.includes('git init -b main'));
  assert.ok(cmd.includes('https://github.com/udemika/astrika.git'));
});
