/**
 * Two sessions sharing one profile refresh at the same moment, from separate
 * processes — the shape of two bridge processes. A server that rotates the
 * refresh token (Obot does, per /mcp-connect/<id>) accepts exactly one use of a
 * refresh token, so the second refresh must carry the token the first one stored.
 *
 * This is the probe the profile-reuse fix asked for: run it before adding any
 * lock, and only add one if the probe shows the two refreshes invalidating each
 * other. The token endpoint is a local stand-in, so the result says what mcpc
 * sends, not what a particular server answers.
 */

import { spawn } from 'child_process';
import { createServer, type Server } from 'http';
import { mkdtemp, rm, writeFile } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { fileURLToPath } from 'url';
import { getAuthProfile, saveAuthProfile } from '../../../../src/lib/auth/profiles.js';
import {
  storeKeychainOAuthClientInfo,
  storeKeychainOAuthTokenInfo,
} from '../../../../src/lib/auth/keychain.js';

const SERVER_URL = 'https://obot.example.test/mcp-connect/ms1btctr';
const ISSUER_PATH = '/issuer';
const PROFILE = 'default';

interface RefreshBody {
  refresh_token?: string;
  resource?: string;
}

function startTokenServer(): Promise<{ server: Server; url: string; bodies: RefreshBody[] }> {
  const bodies: RefreshBody[] = [];
  // The one refresh token currently valid. A rotating server hands out a new one
  // on every refresh and rejects the previous one.
  let currentRefreshToken = 'refresh-0';
  let issued = 0;

  const server = createServer((req, res) => {
    if (req.method === 'GET') {
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ token_endpoint: `http://127.0.0.1:${port()}${ISSUER_PATH}` }));
      return;
    }
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const body = Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString()));
      bodies.push(body);
      res.setHeader('content-type', 'application/json');
      if (body.refresh_token !== currentRefreshToken) {
        res.statusCode = 400;
        res.end(JSON.stringify({ error: 'invalid_grant' }));
        return;
      }
      issued += 1;
      currentRefreshToken = `refresh-${issued}`;
      res.end(
        JSON.stringify({
          access_token: `access-${issued}`,
          token_type: 'Bearer',
          expires_in: 3600,
          refresh_token: currentRefreshToken,
        })
      );
    });
  });

  const port = (): number => (server.address() as { port: number }).port;

  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () =>
      resolve({ server, url: `http://127.0.0.1:${port()}`, bodies })
    );
  });
}

describe('two sessions refreshing one profile concurrently', () => {
  let homeDir: string;
  let originalHome: string | undefined;

  beforeEach(async () => {
    homeDir = await mkdtemp(join(tmpdir(), 'mcpc-concurrent-refresh-'));
    originalHome = process.env.MCPC_HOME_DIR;
    process.env.MCPC_HOME_DIR = homeDir;
    process.env.MCPC_FORCE_FILE_KEYCHAIN = '1';
  });

  afterEach(async () => {
    if (originalHome === undefined) delete process.env.MCPC_HOME_DIR;
    else process.env.MCPC_HOME_DIR = originalHome;
    delete process.env.MCPC_FORCE_FILE_KEYCHAIN;
    await rm(homeDir, { recursive: true, force: true });
  });

  it('does not present a refresh token the server has already rotated away', async () => {
    const { server, url, bodies } = await startTokenServer();
    try {
      await saveAuthProfile({
        name: PROFILE,
        serverUrl: SERVER_URL,
        authType: 'oauth',
        oauthIssuer: `${url}${ISSUER_PATH.replace(/\/token$/, '')}`,
        oauthResource: SERVER_URL,
        createdAt: '2026-11-04T00:00:00.000Z',
      });
      await storeKeychainOAuthClientInfo(SERVER_URL, PROFILE, { clientId: 'client-1' });
      await storeKeychainOAuthTokenInfo(SERVER_URL, PROFILE, {
        accessToken: 'expired-access',
        refreshToken: 'refresh-0',
        tokenType: 'Bearer',
        expiresAt: 1,
      });

      // tsx compiles a file outside the repo as CommonJS unless its own
      // directory declares a module, and the worker needs top-level await.
      await writeFile(join(homeDir, 'package.json'), '{ "type": "module" }\n');
      const worker = join(homeDir, 'refresh-worker.ts');
      const tokenRefreshModule = fileURLToPath(
        new URL('../../../../src/lib/auth/token-refresh.ts', import.meta.url)
      );
      await writeFile(
        worker,
        [
          `import { getValidAccessTokenFromKeychain } from ${JSON.stringify(tokenRefreshModule)};`,
          'const token = await getValidAccessTokenFromKeychain(process.argv[2], process.argv[3]);',
          'console.log(JSON.stringify({ token }));',
        ].join('\n')
      );

      const run = () =>
        new Promise<{ status: number; stdout: string; stderr: string }>((resolve) => {
          const child = spawn('pnpm', ['exec', 'tsx', worker, SERVER_URL, PROFILE], {
            cwd: process.cwd(),
            env: { ...process.env, MCPC_HOME_DIR: homeDir, MCPC_FORCE_FILE_KEYCHAIN: '1' },
          });
          let stdout = '';
          let stderr = '';
          child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString()));
          child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
          child.on('close', (status) => resolve({ status: status ?? 1, stdout, stderr }));
        });

      const [first, second] = await Promise.all([run(), run()]);

      const presented = bodies.map((body) => body.refresh_token);
      // A rotating server accepts a refresh token once, so the token read at the
      // start must be presented at most once. The refresh holds the profile lock
      // from that read until the rotated token is stored: the other session either
      // waits and then finds a still-valid access token, or is told the profile is
      // being refreshed and to retry. Neither spends the same token again.
      const spentOneTokenTwice = presented.filter((token) => token === 'refresh-0').length > 1;
      const outcomes = [first, second].map((result) =>
        result.status === 0
          ? 'refreshed'
          : // The busy lock surfaces either as the retry hint or as the raw ELOCKED
            // when it escapes a layer that wraps it. Both mean the token was not spent.
            result.stderr.includes('is refreshing') ||
              result.stderr.includes('Lock file is already being held')
            ? 'retry'
            : 'failed'
      );
      // Neither outcome order nor which session wins the lock is fixed. What must
      // not happen is one token being spent twice, or a session failing for any
      // reason other than losing the lock.
      expect(
        { failed: outcomes.includes('failed'), spentOneTokenTwice },
        `presented: ${JSON.stringify(presented)}\nfirst: ${first.stderr}\nsecond: ${second.stderr}`
      ).toEqual({ failed: false, spentOneTokenTwice: false });

      const stored = await getAuthProfile(SERVER_URL, PROFILE);
      expect(stored?.oauthResource).toBe(SERVER_URL);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  }, 60_000);
});
