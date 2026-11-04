/**
 * A profile is stored per host, but one host can front several authorization
 * servers (Obot serves one per `/mcp-connect/<id>`). A profile logged in for one
 * must not be handed to another: its refresh token rotates, and spending it at
 * the wrong server logs the right one out.
 */

import { mkdtemp, rm } from 'fs/promises';
import { tmpdir } from 'os';
import { join } from 'path';
import { getAuthProfile, saveAuthProfile } from '../../../../src/lib/auth/profiles.js';
import { loadAuthCredentials } from '../../../../src/lib/bridge-manager.js';
import { resolveAuthProfile } from '../../../../src/cli/helpers.js';
import { AuthError } from '../../../../src/lib/errors.js';
import { createServerAuthError, ClientError } from '../../../../src/lib/errors.js';
import type { AuthProfile } from '../../../../src/lib/types.js';

const HOST = 'https://obot.example.test';
const SERVER_A = `${HOST}/mcp-connect/ms1btctr`;
const SERVER_B = `${HOST}/mcp-connect/ms1ttjwq`;

const profileFor = (resource: string, name = 'default'): AuthProfile => ({
  name,
  serverUrl: resource,
  authType: 'oauth',
  oauthIssuer: 'https://obot.example.test/oauth',
  oauthResource: resource,
  createdAt: '2026-11-04T00:00:00.000Z',
});

describe('profile resource binding', () => {
  let homeDir: string;
  let originalHome: string | undefined;

  beforeEach(async () => {
    homeDir = await mkdtemp(join(tmpdir(), 'mcpc-profile-resource-'));
    originalHome = process.env.MCPC_HOME_DIR;
    process.env.MCPC_HOME_DIR = homeDir;
  });

  afterEach(async () => {
    if (originalHome === undefined) delete process.env.MCPC_HOME_DIR;
    else process.env.MCPC_HOME_DIR = originalHome;
    await rm(homeDir, { recursive: true, force: true });
  });

  describe('connecting', () => {
    it("rejects server A's profile for server B on the same host", async () => {
      await saveAuthProfile(profileFor(SERVER_A, 'work'));

      const error = await resolveAuthProfile(SERVER_B, SERVER_B, 'work').catch((e: unknown) => e);

      expect(error).toBeInstanceOf(AuthError);
      expect((error as AuthError).code).toBe(4);
      expect((error as Error).message).toContain(SERVER_A);
      expect((error as Error).message).toContain('--profile <new-name>');
    });

    it('connects when the profile belongs to that server', async () => {
      await saveAuthProfile(profileFor(SERVER_A, 'work'));

      await expect(resolveAuthProfile(SERVER_A, SERVER_A, 'work')).resolves.toBe('work');
    });

    it('treats a trailing slash as the same server', async () => {
      await saveAuthProfile(profileFor(`${SERVER_A}/`, 'work'));

      await expect(resolveAuthProfile(SERVER_A, SERVER_A, 'work')).resolves.toBe('work');
    });

    it('keeps using a profile that recorded no resource', async () => {
      const profile = profileFor(SERVER_A, 'work');
      delete profile.oauthResource;
      await saveAuthProfile(profile);

      await expect(resolveAuthProfile(SERVER_B, SERVER_B, 'work')).resolves.toBe('work');
    });

    it('does not silently attach a default profile that belongs to another server', async () => {
      await saveAuthProfile(profileFor(SERVER_A));

      await expect(resolveAuthProfile(SERVER_B, SERVER_B)).resolves.toBeUndefined();
    });
  });

  describe('starting the bridge', () => {
    it("refuses to load server A's credentials for server B", async () => {
      await saveAuthProfile(profileFor(SERVER_A));

      const error = await loadAuthCredentials(SERVER_B, 'default').catch((e: unknown) => e);

      expect(error).toBeInstanceOf(AuthError);
      expect((error as AuthError).code).toBe(4);
    });

    it('loads the credentials when the resource matches', async () => {
      await saveAuthProfile(profileFor(SERVER_A));

      const credentials = await loadAuthCredentials(SERVER_A, 'default');

      expect(credentials.oauthResource).toBe(SERVER_A);
    });
  });

  describe('logging in over an existing profile', () => {
    it('refuses, before touching stored credentials, when the profile belongs to another server', async () => {
      await saveAuthProfile(profileFor(SERVER_A));
      const { performOAuthFlow } = await import('../../../../src/lib/auth/oauth-flow.js');

      const error = await performOAuthFlow(SERVER_B, 'default').catch((e: unknown) => e);

      expect(error).toBeInstanceOf(ClientError);
      expect((error as ClientError).code).toBe(1);
      expect((error as Error).message).toContain(SERVER_A);
      expect((error as Error).message).toContain('--profile <new-name>');
      // The stored profile still names the server it was logged in for.
      expect((await getAuthProfile(SERVER_A, 'default'))?.oauthResource).toBe(SERVER_A);
    });

    it('allows logging in again to the same server', async () => {
      await saveAuthProfile(profileFor(SERVER_A));
      const { performOAuthFlow } = await import('../../../../src/lib/auth/oauth-flow.js');

      const error = await performOAuthFlow(SERVER_A, 'default').catch((e: unknown) => e);

      // The flow continues past the profile check and fails at the network,
      // which this test does not stand up. The clash check throws before any of that.
      expect(error).toBeInstanceOf(TypeError);
      expect((error as Error).message).not.toContain('already belongs to');
    });
  });
});

describe('re-authentication hint', () => {
  it("names the session's own server and profile", () => {
    const error = createServerAuthError(SERVER_B, { sessionName: '@b', profileName: 'work' });

    expect(error.message).toContain(`mcpc login ${SERVER_B} --profile work`);
    expect(error.message).not.toContain(SERVER_A);
  });

  it('omits --profile for the default profile', () => {
    const error = createServerAuthError(SERVER_B, { sessionName: '@b', profileName: 'default' });

    expect(error.message).toContain(`mcpc login ${SERVER_B}\n`);
    expect(error.message).not.toContain('--profile');
  });
});
