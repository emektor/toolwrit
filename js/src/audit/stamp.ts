/**
 * Timestamped proofs that a file existed, unchanged, at a given time.
 *
 * The same RFC 3161 machinery that anchors a run's receipt works for any file:
 * hash it, have a Time-Stamp Authority sign the hash, keep the token beside the
 * file. Anyone holding the file and the stamp can later show that exactly
 * these bytes existed no later than the TSA's time -- the "I made this first"
 * proof a creator needs when a render is re-uploaded by someone else.
 *
 * The file itself never leaves the machine: only its SHA-256 goes to the TSA.
 */

import { createHash, type X509Certificate } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { basename } from 'node:path';
import { DEFAULT_TSA, requestTimestamp, verifyTimestamp, type RequestTimestampOptions } from './timestamp.js';

/** What `toolwrit stamp` writes next to a file, as `<file>.stamp.json`. */
export interface FileStamp {
  kind: 'toolwrit-file-stamp';
  version: 1;
  /** The file's name when it was stamped. Informational: the hash is what counts. */
  file: string;
  bytes: number;
  /** SHA-256 of the file's contents, lowercase hex. */
  sha256: string;
  tsa: string;
  /** The TSA's signed time, ISO 8601. Informational: `token` is authoritative. */
  time: string;
  /** The TimeStampToken (CMS ContentInfo), DER, base64. */
  token: string;
}

export interface StampCheck {
  ok: boolean;
  time: Date | null;
  signer: string | null;
  failure?: string;
}

/** Hash a file by streaming it, so a multi-gigabyte render costs no memory. */
export async function hashFile(path: string): Promise<{ sha256: string; bytes: number }> {
  const hash = createHash('sha256');
  let bytes = 0;
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk as Buffer);
    bytes += (chunk as Buffer).length;
  }
  return { sha256: hash.digest('hex'), bytes };
}

/** Hash `path` and have a TSA sign the hash. The returned token has been verified. */
export async function stampFile(path: string, options: RequestTimestampOptions = {}): Promise<FileStamp> {
  const { sha256, bytes } = await hashFile(path);
  const ts = await requestTimestamp(sha256, { ...options, tsa: options.tsa ?? DEFAULT_TSA });
  return { kind: 'toolwrit-file-stamp', version: 1, file: basename(path), bytes, sha256, tsa: ts.tsa, time: ts.time, token: ts.token };
}

/**
 * Check a stamp against a digest already computed from the file.
 *
 * Split from `checkFileStamp` so the comparison and the signature check can be
 * exercised without a file that happens to hash to a recorded token.
 */
export function checkStampDigest(
  stamp: FileStamp,
  sha256: string,
  options: { roots?: readonly X509Certificate[] } = {}
): StampCheck {
  if (stamp?.kind !== 'toolwrit-file-stamp') {
    return { ok: false, time: null, signer: null, failure: 'not a toolwrit file stamp' };
  }
  if (stamp.sha256 !== sha256) {
    return {
      ok: false,
      time: null,
      signer: null,
      failure: `file hashes to ${sha256.slice(0, 12)}, the stamp is for ${String(stamp.sha256).slice(0, 12)} — the file was changed or is a different file`,
    };
  }
  // The token is checked against the file's hash, never against the stamp's
  // own sha256 field alone: an edited field must not vouch for itself.
  const check = verifyTimestamp(stamp.token, sha256, { roots: options.roots });
  return check.ok
    ? { ok: true, time: check.time, signer: check.signer }
    : { ok: false, time: check.time, signer: check.signer, failure: check.failure };
}

/** Hash `path` and check it against `stamp`. */
export async function checkFileStamp(
  path: string,
  stamp: FileStamp,
  options: { roots?: readonly X509Certificate[] } = {}
): Promise<StampCheck> {
  const { sha256 } = await hashFile(path);
  return checkStampDigest(stamp, sha256, options);
}
