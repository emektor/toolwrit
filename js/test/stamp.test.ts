/**
 * File stamps: a stamp vouches for exactly one file's bytes, and any change to
 * the file, the recorded hash or the token is caught. The fixture token is a
 * real DigiCert one, so the signature path runs offline.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkStampDigest, hashFile, type FileStamp } from '../src/audit/stamp.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(
  readFileSync(join(here, '..', '..', 'test', 'fixtures', 'digicert-token.json'), 'utf8')
) as { head: string; token: string; tsa: string; time: string };

const stamp: FileStamp = {
  kind: 'toolwrit-file-stamp',
  version: 1,
  file: 'render.mp4',
  bytes: 1,
  sha256: fixture.head,
  tsa: fixture.tsa,
  time: fixture.time,
  token: fixture.token,
};

describe('file stamps', () => {
  it('hashes a file by streaming it', async () => {
    const file = join(mkdtempSync(join(tmpdir(), 'toolwrit-stamp-')), 'f.bin');
    writeFileSync(file, 'hello');
    const result = await hashFile(file);
    assert.equal(result.bytes, 5);
    assert.equal(result.sha256, createHash('sha256').update('hello').digest('hex'));
  });

  it('accepts the digest the token was issued for', () => {
    const check = checkStampDigest(stamp, fixture.head);
    assert.equal(check.ok, true, check.failure);
    assert.equal(check.time?.toISOString(), new Date(fixture.time).toISOString());
  });

  it('rejects a changed file', () => {
    const check = checkStampDigest(stamp, '0'.repeat(64));
    assert.equal(check.ok, false);
    assert.match(check.failure ?? '', /changed or is a different file/);
  });

  it('does not let an edited sha256 field vouch for itself', () => {
    const other = '1'.repeat(64);
    const check = checkStampDigest({ ...stamp, sha256: other }, other);
    assert.equal(check.ok, false);
  });

  it('rejects something that is not a stamp', () => {
    assert.equal(checkStampDigest({} as FileStamp, fixture.head).ok, false);
  });
});
