/**
 * Unit tests for trusting the OS CA store at startup.
 *
 * The module reads node:tls through a dynamic import, so each test gets a fresh
 * module instance (vi.resetModules) whose node:tls is the mocked one.
 */

const getCACertificates = vi.hoisted(() => vi.fn<(type?: string) => string[]>());
const setDefaultCACertificates = vi.hoisted(() => vi.fn<(certs: string[]) => void>());

vi.mock('node:tls', () => ({ getCACertificates, setDefaultCACertificates }));

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const BUNDLED = ['bundled-a', 'bundled-b'];
const SYSTEM = ['enterprise-ca'];

async function loadUseSystemCa(): Promise<() => Promise<void>> {
  const mod = await import('../../../src/lib/system-ca.js');
  return mod.useSystemCa;
}

beforeEach(() => {
  getCACertificates.mockImplementation((type?: string) => {
    if (type === 'system') return SYSTEM;
    if (type === 'default' || type === 'bundled') return BUNDLED;
    return [];
  });
});

afterEach(() => {
  vi.resetModules();
});

describe('useSystemCa', () => {
  it('adds the OS trust store to the CAs used for TLS verification', async () => {
    const useSystemCa = await loadUseSystemCa();

    await useSystemCa();

    expect(setDefaultCACertificates).toHaveBeenCalledWith([...BUNDLED, ...SYSTEM]);
  });

  it('keeps certificates added by an earlier caller and skips ones already trusted', async () => {
    const useSystemCa = await loadUseSystemCa();
    getCACertificates.mockImplementation((type?: string) =>
      type === 'default' ? [...BUNDLED, 'extra-ca', 'enterprise-ca'] : [...SYSTEM, 'enterprise-ca']
    );

    await useSystemCa();

    expect(setDefaultCACertificates).not.toHaveBeenCalled();
  });

  it('appends only the system certificates the default list does not have', async () => {
    const useSystemCa = await loadUseSystemCa();
    getCACertificates.mockImplementation((type?: string) => {
      if (type === 'default') return [...BUNDLED, 'enterprise-ca'];
      if (type === 'bundled') return BUNDLED;
      return [...SYSTEM, 'second-enterprise-ca'];
    });

    await useSystemCa();

    expect(setDefaultCACertificates).toHaveBeenCalledWith([
      ...BUNDLED,
      'enterprise-ca',
      'second-enterprise-ca',
    ]);
  });

  it('leaves the trust store untouched when the bundled CAs are not in the default list', async () => {
    // --use-openssl-ca keeps the bundled Mozilla CAs out of "default" while the
    // OpenSSL store (SSL_CERT_FILE) does the verifying. NODE_EXTRA_CA_CERTS only
    // adds its own file, so a non-empty "default" is still not the trust in force.
    const useSystemCa = await loadUseSystemCa();
    getCACertificates.mockImplementation((type?: string) => {
      if (type === 'system') return SYSTEM;
      if (type === 'bundled') return BUNDLED;
      if (type === 'default') return ['extra-ca'];
      return [];
    });

    await useSystemCa();

    expect(setDefaultCACertificates).not.toHaveBeenCalled();
  });

  it('does nothing when the OS trust store is empty', async () => {
    const useSystemCa = await loadUseSystemCa();
    getCACertificates.mockImplementation((type?: string) => (type === 'system' ? [] : BUNDLED));

    await useSystemCa();

    expect(setDefaultCACertificates).not.toHaveBeenCalled();
  });

  it('does nothing on a runtime without the system CA APIs', async () => {
    vi.doMock('node:tls', () => ({}));
    const useSystemCa = await loadUseSystemCa();

    await expect(useSystemCa()).resolves.toBeUndefined();
    expect(setDefaultCACertificates).not.toHaveBeenCalled();
  });

  it('leaves the bundled CAs in place when the OS trust store cannot be read', async () => {
    const useSystemCa = await loadUseSystemCa();
    getCACertificates.mockImplementation((type?: string) => {
      if (type === 'system') throw new Error('keychain unavailable');
      return BUNDLED;
    });

    await expect(useSystemCa()).resolves.toBeUndefined();
    expect(setDefaultCACertificates).not.toHaveBeenCalled();
  });

  it('applies once per process', async () => {
    vi.doUnmock('node:tls');
    vi.doMock('node:tls', () => ({ getCACertificates, setDefaultCACertificates }));
    const useSystemCa = await loadUseSystemCa();

    await useSystemCa();
    await useSystemCa();

    expect(setDefaultCACertificates).toHaveBeenCalledTimes(1);
  });
});
