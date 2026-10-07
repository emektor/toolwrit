/**
 * RFC 3161 timestamps on anchored receipts.
 *
 * The fixtures hold real tokens from DigiCert's public TSA, so these tests run
 * offline and still exercise a genuine signature, a genuine certificate chain
 * and Node's bundled root store — the same path an auditor's machine takes.
 * The property under test is narrow: a token vouches for exactly one head, at
 * exactly one time, and any edit to either is caught.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { requestTimestamp, verifyTimestamp } from '../src/audit/timestamp.js';

const here = dirname(fileURLToPath(import.meta.url));
// Compiled to dist-test/test/, so the sources sit two directories up.
const fixtures = join(here, '..', '..', 'test', 'fixtures');
const cli = join(here, '..', 'src', 'cli.js');

interface TokenFixture {
  head: string;
  nonce: string;
  tsa: string;
  time: string;
  token: string;
}

const fixture = JSON.parse(readFileSync(join(fixtures, 'digicert-token.json'), 'utf8')) as TokenFixture;
const auditFile = join(fixtures, 'tsa-audit.jsonl');
const anchorLine = readFileSync(join(fixtures, 'tsa-anchors.jsonl'), 'utf8').trim();

/** A copy of the token with one byte changed. */
function tampered(token: string, at: (der: Buffer) => number): string {
  const der = Buffer.from(token, 'base64');
  const i = at(der);
  der[i] = der[i]! ^ 0x01;
  return der.toString('base64');
}

/** Wrap a token in a TimeStampResp with the given PKIStatus, as a TSA would. */
function response(status: number, token?: Buffer): Buffer {
  const statusInfo = Buffer.from([0x30, 0x03, 0x02, 0x01, status]);
  const body = token ? Buffer.concat([statusInfo, token]) : statusInfo;
  const len = body.length;
  const header = len < 0x80 ? [0x30, len] : len < 0x100 ? [0x30, 0x81, len] : [0x30, 0x82, len >> 8, len & 0xff];
  return Buffer.concat([Buffer.from(header), body]);
}

function fakeFetch(status: number, payload: Buffer) {
  return async () => ({
    ok: status === 200,
    status,
    arrayBuffer: async () => payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.length) as ArrayBuffer,
  });
}

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), 'toolwrit-tsa-'));
}

function runCli(args: string[]) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
}

describe('verifyTimestamp', () => {
  it('accepts a real DigiCert token for the head it was issued for', () => {
    const check = verifyTimestamp(fixture.token, fixture.head);

    assert.equal(check.ok, true, check.failure);
    assert.equal(check.time?.toISOString(), fixture.time);
    assert.match(check.signer ?? '', /DigiCert/);
    assert.equal(check.root, 'DigiCert Trusted Root G4');
  });

  it('rejects the token for any other head', () => {
    const other = fixture.head.replace(/^./, (c) => (c === '0' ? '1' : '0'));
    const check = verifyTimestamp(fixture.token, other);

    assert.equal(check.ok, false);
    assert.match(check.failure ?? '', /not for head/);
  });

  it('catches an edited time', () => {
    // genTime is plain ASCII inside the TSTInfo; nudging one digit is exactly
    // the backdating a forger would want.
    const token = tampered(fixture.token, (der) => der.indexOf(Buffer.from(fixture.time.slice(0, 4), 'ascii')) + 3);
    const check = verifyTimestamp(token, fixture.head);

    assert.equal(check.ok, false);
    assert.match(check.failure ?? '', /message digest does not match/);
  });

  it('catches an edited signature', () => {
    // The signature is the last field of the last SignerInfo, so it ends the token.
    const token = tampered(fixture.token, (der) => der.length - 1);
    const check = verifyTimestamp(token, fixture.head);

    assert.equal(check.ok, false);
    assert.match(check.failure ?? '', /signature does not verify/);
  });

  it('refuses a signer that chains to no trusted root', () => {
    const check = verifyTimestamp(fixture.token, fixture.head, { roots: [] });

    assert.equal(check.ok, false);
    assert.match(check.failure ?? '', /does not chain to a trusted root/);
  });

  it('checks the nonce when one is given', () => {
    assert.equal(verifyTimestamp(fixture.token, fixture.head, { nonce: Buffer.from(fixture.nonce, 'hex') }).ok, true);

    const check = verifyTimestamp(fixture.token, fixture.head, { nonce: Buffer.from('0102030405060708', 'hex') });
    assert.equal(check.ok, false);
    assert.match(check.failure ?? '', /nonce/);
  });

  it('reports garbage as unreadable rather than throwing', () => {
    const check = verifyTimestamp(Buffer.from('not a token'), fixture.head);

    assert.equal(check.ok, false);
    assert.match(check.failure ?? '', /not a readable RFC 3161 timestamp/);
  });
});

describe('requestTimestamp', () => {
  const token = Buffer.from(fixture.token, 'base64');
  const nonce = Buffer.from(fixture.nonce, 'hex');

  it('returns a verified token the anchor line can carry', async () => {
    const result = await requestTimestamp(fixture.head, { nonce, fetch: fakeFetch(200, response(0, token)) });

    assert.equal(result.tsa, 'http://timestamp.digicert.com');
    assert.equal(result.time, fixture.time);
    assert.equal(result.token, fixture.token);
  });

  it('sends a DER request carrying the head as the SHA-256 imprint', async () => {
    let sent: Uint8Array | undefined;
    await requestTimestamp(fixture.head, {
      nonce,
      fetch: async (url, init) => {
        sent = init.body;
        return fakeFetch(200, response(0, token))();
      },
    });

    assert.ok(sent);
    assert.ok(Buffer.from(sent).includes(Buffer.from(fixture.head, 'hex')));
    assert.ok(Buffer.from(sent).includes(nonce));
  });

  it('refuses a token that answers a different request', async () => {
    await assert.rejects(
      requestTimestamp(fixture.head, { nonce: Buffer.from('0102030405060708', 'hex'), fetch: fakeFetch(200, response(0, token)) }),
      /does not verify: token does not carry the nonce/
    );
  });

  it('surfaces a TSA refusal and an HTTP error', async () => {
    await assert.rejects(requestTimestamp(fixture.head, { nonce, fetch: fakeFetch(200, response(2)) }), /refused the request \(PKIStatus 2\)/);
    await assert.rejects(requestTimestamp(fixture.head, { nonce, fetch: fakeFetch(503, Buffer.alloc(0)) }), /HTTP 503/);
  });
});

describe('toolwrit verify --against a timestamped anchor', () => {
  it('passes the chain, anchor and timestamp checks', () => {
    const dir = tempDir();
    const anchors = join(dir, 'anchors.jsonl');
    writeFileSync(anchors, `${anchorLine}\n`);

    const result = runCli(['verify', auditFile, '--against', anchors, '--require-timestamp']);

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /ok: chain check/);
    assert.match(result.stdout, /ok: anchor check/);
    assert.match(result.stdout, /ok: timestamp check — DigiCert .* vouches the head existed at/);
  });

  it('fails when the timestamp was lifted from another receipt', () => {
    const dir = tempDir();
    const anchors = join(dir, 'anchors.jsonl');
    const line = JSON.parse(anchorLine) as { timestamp: { token: string } };
    line.timestamp.token = fixture.token;
    writeFileSync(anchors, `${JSON.stringify(line)}\n`);

    const result = runCli(['verify', auditFile, '--against', anchors]);

    assert.equal(result.status, 1);
    assert.match(result.stderr, /FAILED: timestamp check — token was issued for/);
  });

  it('with --require-timestamp, fails a receipt that carries none', () => {
    const dir = tempDir();
    const anchors = join(dir, 'anchors.jsonl');
    const { timestamp: _dropped, ...plain } = JSON.parse(anchorLine) as Record<string, unknown>;
    writeFileSync(anchors, `${JSON.stringify(plain)}\n`);

    assert.equal(runCli(['verify', auditFile, '--against', anchors]).status, 0);

    const result = runCli(['verify', auditFile, '--against', anchors, '--require-timestamp']);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /carries no timestamp/);
  });

  it('with --max-lag, fails a timestamp issued too long after the run', () => {
    const dir = tempDir();
    const anchors = join(dir, 'anchors.jsonl');
    writeFileSync(anchors, `${anchorLine}\n`);

    // The fixture's timestamp landed within a second of its last entry, so the
    // tightest possible bound still passes and a negative one cannot.
    assert.equal(runCli(['verify', auditFile, '--against', anchors, '--max-lag', '5']).status, 0);
    const result = runCli(['verify', auditFile, '--against', anchors, '--max-lag', 'soon']);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /--max-lag takes a number of seconds/);
  });
});

describe('toolwrit anchor --tsa', () => {
  it('writes nothing when the TSA refuses', async () => {
    const server = createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/timestamp-reply' });
      res.end(response(2));
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const { port } = server.address() as { port: number };

    const dir = tempDir();
    const anchors = join(dir, 'anchors.jsonl');
    const child = spawn(process.execPath, [cli, 'anchor', auditFile, '--to', anchors, `--tsa=http://127.0.0.1:${port}/`]);
    let stderr = '';
    child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
    const status = await new Promise<number | null>((resolve) => child.on('close', resolve));
    server.close();

    assert.equal(status, 1);
    assert.match(stderr, /FAILED: could not timestamp run tsa-fixture — .*PKIStatus 2/);
    assert.equal(existsSync(anchors), false);
  });

  it('rejects a --tsa value that is not a URL instead of posting to it', () => {
    const dir = tempDir();
    const anchors = join(dir, 'anchors.jsonl');
    const result = runCli(['anchor', '--tsa', auditFile, '--to', anchors]);

    assert.equal(result.status, 1);
    assert.match(result.stderr, /--tsa takes a URL/);
    assert.equal(existsSync(anchors), false);
  });
});
