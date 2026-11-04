import { mkdtemp, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { vi } from 'vitest';
import { OAuthTokenManager } from '../../../../src/lib/auth/oauth-token-manager.js';
import { createRuntimeAuthProvider } from '../../../../src/lib/auth/runtime-auth-provider.js';
import { getValidAccessTokenFromKeychain } from '../../../../src/lib/auth/token-refresh.js';
import {
  getAuthProfile,
  saveAuthProfile,
  updateAuthProfileRefreshedAt,
} from '../../../../src/lib/auth/profiles.js';
import {
  readKeychainOAuthTokenInfo,
  storeKeychainOAuthClientInfo,
  storeKeychainOAuthTokenInfo,
} from '../../../../src/lib/auth/keychain.js';
import { discoverAndRefreshToken } from '../../../../src/lib/auth/oauth-utils.js';

vi.mock('proper-lockfile', async (importOriginal) => {
  const original = await importOriginal<typeof import('proper-lockfile')>();
  return {
    ...original,
    lock: (file: string, options?: import('proper-lockfile').LockOptions) =>
      original.lock(file, { ...options, retries: 0 }),
  };
});

vi.mock('../../../../src/lib/auth/oauth-utils.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../../../src/lib/auth/oauth-utils.js')>();
  return { ...original, discoverAndRefreshToken: vi.fn() };
});

const SERVER_URL = 'https://refresh.example.test/mcp';
const PROFILE = 'default';
const mockRefresh = vi.mocked(discoverAndRefreshToken);

async function seedProfile(serverUrl = SERVER_URL, profileName = PROFILE): Promise<void> {
  await saveAuthProfile({
    name: profileName,
    serverUrl,
    authType: 'oauth',
    oauthIssuer: 'https://auth.example.test',
    oauthResource: serverUrl,
    scopes: ['old-scope'],
    createdAt: '2026-11-04T00:00:00.000Z',
  });
  await storeKeychainOAuthClientInfo(serverUrl, profileName, { clientId: 'test-client' });
  await storeKeychainOAuthTokenInfo(serverUrl, profileName, {
    accessToken: 'expired-test-access',
    refreshToken: 'test-refresh',
    tokenType: 'Bearer',
    expiresAt: 1,
  });
}

beforeEach(async () => {
  vi.stubEnv('MCPC_HOME_DIR', await mkdtemp(join(tmpdir(), 'mcpc-refresh-lock-')));
  vi.stubEnv('MCPC_FORCE_FILE_KEYCHAIN', '1');
  mockRefresh.mockReset();
  mockRefresh.mockResolvedValue({
    access_token: 'fresh-test-access',
    refresh_token: 'rotated-test-refresh',
    token_type: 'Bearer',
    expires_in: 3600,
    scope: 'new-scope',
  });
  await seedProfile();
});

afterEach(async () => {
  await rm(process.env.MCPC_HOME_DIR as string, { recursive: true, force: true });
  vi.unstubAllEnvs();
});

describe('OAuth refresh persistence locking', () => {
  it('finishes a refresh and persists both tokens and profile metadata', async () => {
    await expect(getValidAccessTokenFromKeychain(SERVER_URL, PROFILE)).resolves.toBe(
      'fresh-test-access'
    );
    expect(mockRefresh).toHaveBeenCalledTimes(1);
    expect(await readKeychainOAuthTokenInfo(SERVER_URL, PROFILE)).toMatchObject({
      accessToken: 'fresh-test-access',
      refreshToken: 'rotated-test-refresh',
    });
    expect(await getAuthProfile(SERVER_URL, PROFILE)).toMatchObject({
      refreshedAt: expect.any(String),
      scopes: ['new-scope'],
    });
  });

  it('preserves the refresh token when the server does not rotate it', async () => {
    mockRefresh.mockResolvedValue({
      access_token: 'fresh-test-access',
      token_type: 'Bearer',
      expires_in: 3600,
    });

    await expect(getValidAccessTokenFromKeychain(SERVER_URL, PROFILE)).resolves.toBe(
      'fresh-test-access'
    );
    expect(await readKeychainOAuthTokenInfo(SERVER_URL, PROFILE)).toMatchObject({
      accessToken: 'fresh-test-access',
      refreshToken: 'test-refresh',
    });
  });

  it('retries an SDK request after 401 with the bridge persistence callback', async () => {
    const manager = new OAuthTokenManager({
      serverUrl: SERVER_URL,
      profileName: PROFILE,
      clientId: 'test-client',
      refreshToken: 'test-refresh',
      accessToken: 'rejected-test-access',
      accessTokenExpiresAt: Math.floor(Date.now() / 1000) + 3600,
      onTokenRefresh: async (tokens) => {
        await storeKeychainOAuthTokenInfo(SERVER_URL, PROFILE, {
          accessToken: tokens.access_token,
          ...(tokens.refresh_token !== undefined && { refreshToken: tokens.refresh_token }),
          tokenType: tokens.token_type,
        });
        await updateAuthProfileRefreshedAt(SERVER_URL, PROFILE);
      },
    });
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(null, { status: 401 }))
      .mockResolvedValueOnce(new Response(null, { status: 202 }));
    const transport = new StreamableHTTPClientTransport(new URL(SERVER_URL), {
      authProvider: createRuntimeAuthProvider(manager),
      fetch: fetchMock,
    });

    try {
      await transport.send({ jsonrpc: '2.0', method: 'notifications/roots/list_changed' });
      expect(fetchMock).toHaveBeenCalledTimes(2);
      const authorization = fetchMock.mock.calls.map(([, init]) =>
        new Headers(init?.headers).get('authorization')
      );
      expect(authorization).toEqual(['Bearer rejected-test-access', 'Bearer fresh-test-access']);
      expect(await getAuthProfile(SERVER_URL, PROFILE)).toHaveProperty('refreshedAt');
      expect(mockRefresh).toHaveBeenCalledTimes(1);
    } finally {
      await transport.close();
    }
  });

  it.each([
    ['another host', 'https://other.example.test/mcp', PROFILE],
    ['another profile', SERVER_URL, 'work'],
  ])(
    'does not block %s or metadata reads during refresh',
    async (_label, serverUrl, profileName) => {
      await seedProfile(serverUrl, profileName);
      let markEntered!: () => void;
      let releaseRefresh!: () => void;
      const entered = new Promise<void>((resolve) => (markEntered = resolve));
      const released = new Promise<void>((resolve) => (releaseRefresh = resolve));
      mockRefresh.mockImplementationOnce(async () => {
        markEntered();
        await released;
        return { access_token: 'first-test-access', token_type: 'Bearer', expires_in: 3600 };
      });
      const first = getValidAccessTokenFromKeychain(SERVER_URL, PROFILE);
      const settledFirst = first.catch((error: unknown) => error);
      await entered;

      try {
        expect(await getAuthProfile(serverUrl, profileName)).toHaveProperty('name', profileName);
        await expect(getValidAccessTokenFromKeychain(serverUrl, profileName)).resolves.toBe(
          'fresh-test-access'
        );
      } finally {
        releaseRefresh();
        await settledFirst;
      }
      await expect(first).resolves.toBe('first-test-access');
      expect(mockRefresh).toHaveBeenCalledTimes(2);
    }
  );

  it('releases the refresh lock after an endpoint failure so the next attempt succeeds', async () => {
    mockRefresh.mockRejectedValueOnce(new Error('test endpoint unavailable'));
    await expect(getValidAccessTokenFromKeychain(SERVER_URL, PROFILE)).rejects.toThrow(
      'test endpoint unavailable'
    );

    await expect(getValidAccessTokenFromKeychain(SERVER_URL, PROFILE)).resolves.toBe(
      'fresh-test-access'
    );
    expect(mockRefresh).toHaveBeenCalledTimes(2);
  });
});
