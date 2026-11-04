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
 * It never replaces a trust store it cannot see whole. When Node trusts the
 * bundled Mozilla CAs, they show up inside "default" (plain startup and
 * --use-system-ca both do this). Under --use-openssl-ca they do not: the OpenSSL
 * store (SSL_CERT_FILE / SSL_CERT_DIR) verifies connections while staying out of
 * every list this function can read, and NODE_EXTRA_CA_CERTS only adds its own
 * file to "default". Rewriting the list from that view discards the OpenSSL
 * trust, so the bundled CAs missing from "default" means the trust is left as it
 * is.
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
  let defaultCerts: string[];
  let bundledCerts: string[];
  try {
    systemCerts = getCACertificates('system');
    defaultCerts = getCACertificates('default');
    bundledCerts = getCACertificates('bundled');
  } catch (error) {
    logger.debug('Could not read the OS certificate store; using the bundled CAs only:', error);
    return;
  }
  if (systemCerts.length === 0) return;

  // setDefaultCACertificates replaces the whole default list, and "default" is
  // not always the trust store in force. There is no API to read the OpenSSL
  // store back, so the only safe signal is whether "default" still accounts for
  // the bundled CAs. It does on a plain startup and with --use-system-ca; it
  // does not under --use-openssl-ca, whether or not NODE_EXTRA_CA_CERTS added
  // its own file to the list. Leave that trust exactly as Node set it.
  const trusted = new Set(defaultCerts);
  if (bundledCerts.some((cert) => !trusted.has(cert))) {
    logger.debug(
      'Bundled CAs are missing from the default CA list; leaving the active trust store untouched'
    );
    return;
  }

  // The system certs are already in "default" when Node reports them as trusted
  // (--use-system-ca, or a system store OpenSSL itself consults). Only append
  // the ones it does not already have.
  const missing = systemCerts.filter((cert) => !trusted.has(cert));
  if (missing.length === 0) {
    logger.debug('OS trust store is already part of the default CA list');
    return;
  }

  setDefaultCACertificates([...defaultCerts, ...missing]);
  logger.debug(`Trusting ${missing.length} more CA certificate(s) from the OS trust store`);
}
