/**
 * Trust the operating system's CA store for every TLS connection this process makes.
 *
 * Node.js verifies TLS against its bundled Mozilla CA snapshot and ignores CAs an
 * enterprise installed in the OS trust store (macOS Keychain, the Windows
 * certificate store, OpenSSL's default paths on Linux), so connections to internal
 * servers fail with "self signed certificate in certificate chain" unless the
 * process was started with NODE_USE_SYSTEM_CA=1 / --use-system-ca. That flag is
 * read before any JavaScript runs, which a library cannot arrange for its own
 * process, so this appends the system certificates to the defaults at startup
 * instead (tls.getCACertificates / tls.setDefaultCACertificates, Node >=22.19).
 *
 * The bridge is a child process spawned without the parent's execArgv, so it does
 * not inherit --use-system-ca from NODE_OPTIONS; both entry points call this.
 * Call it before the first TLS connection: it does not touch sessions the HTTPS
 * agent has already cached.
 *
 * Bun has neither API and already consults the OS trust store, so this is a no-op
 * there. On a Node older than 22.19 the APIs are absent too; nothing is trusted
 * beyond the bundled CAs, and a debug log line says so.
 */
import { createLogger } from './logger.js';

const logger = createLogger('system-ca');

let applied = false;

export async function useSystemCa(): Promise<void> {
  if (applied) return;
  applied = true;

  let getCACertificates: ((type?: string) => string[]) | undefined;
  let setDefaultCACertificates: ((certs: string[]) => void) | undefined;
  try {
    const tls = (await import('node:tls')) as {
      getCACertificates?: (type?: string) => string[];
      setDefaultCACertificates?: (certs: string[]) => void;
    };
    getCACertificates = tls.getCACertificates;
    setDefaultCACertificates = tls.setDefaultCACertificates;
  } catch {
    // A Node build without crypto support cannot import node:tls at all.
  }

  if (typeof getCACertificates !== 'function' || typeof setDefaultCACertificates !== 'function') {
    // Debug, not a warning: every command would otherwise print it on a runtime
    // without these APIs (Node <22.19, Bun), and the only remedy is outside mcpc.
    logger.debug(
      'OS certificate store is not available on this runtime (needs Node.js >=22.19); ' +
        'TLS uses the bundled CAs only'
    );
    return;
  }

  let systemCerts: string[];
  try {
    systemCerts = getCACertificates('system');
  } catch (error) {
    logger.debug('Could not read the OS certificate store; using the bundled CAs only:', error);
    return;
  }
  if (systemCerts.length === 0) return;

  // setDefaultCACertificates replaces the whole default list, so the bundled
  // Mozilla CAs (and anything NODE_EXTRA_CA_CERTS or --use-system-ca already
  // contributed) must be carried over. Duplicates are removed by Node.
  setDefaultCACertificates([...getCACertificates('default'), ...systemCerts]);
  logger.debug(`Trusting ${systemCerts.length} CA certificate(s) from the OS trust store`);
}
