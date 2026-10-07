/**
 * RFC 3161 timestamps for anchored receipts.
 *
 * An anchor file proves a head existed only as well as the anchor file itself
 * is protected — and Toolwrit cannot protect it. A timestamp from an outside
 * Time-Stamp Authority removes most of that dependence: the TSA signs "this
 * head existed at time T" with a key the agent does not hold, so the receipt
 * can be copied anywhere, kept next to the log, and still not be forged or
 * backdated. An attacker who rewrites a log and its anchor file can only obtain
 * a timestamp dated after the rewrite, and the gap between the run's last
 * entry and the timestamp shows it.
 *
 * The head is already a SHA-256 digest, so it goes to the TSA as the message
 * imprint unchanged. That keeps the token checkable with nothing but OpenSSL:
 * `openssl ts -verify -digest <head> -token_in -in token.der -CAfile roots.pem`.
 *
 * Everything here is hand-rolled DER over node:crypto, for the same reason the
 * CLI parser is: a security tool with a dependency tree is a harder sell.
 */

import { createHash, randomBytes, verify as verifySignature, X509Certificate } from 'node:crypto';
import { rootCertificates } from 'node:tls';

/** DigiCert's public RFC 3161 service: free, no account, chains to a root Node ships. */
export const DEFAULT_TSA = 'http://timestamp.digicert.com';

/** What an anchor line carries when its receipt was timestamped. */
export interface ReceiptTimestamp {
  /** URL of the Time-Stamp Authority that issued the token. */
  tsa: string;
  /** The time the TSA vouched for, ISO 8601. Informational: `token` is authoritative. */
  time: string;
  /** The TimeStampToken (CMS ContentInfo), DER, base64. */
  token: string;
}

export interface TimestampCheck {
  ok: boolean;
  /** The TSA's signed time, when the token could be read that far. */
  time: Date | null;
  /** Common name of the certificate that signed the token. */
  signer: string | null;
  /** Common name of the trusted root the signer chains to. */
  root: string | null;
  /** Why the check failed; absent when it passed. */
  failure?: string;
}

export interface VerifyTimestampOptions {
  /**
   * Roots the signer must chain to. Defaults to the Mozilla store bundled with
   * Node, which covers the large public TSAs. A private or hobby TSA needs its
   * own CA certificate passed here.
   */
  roots?: readonly X509Certificate[];
  /** Nonce sent with the request, checked when the token is fresh from the TSA. */
  nonce?: Buffer;
}

export interface RequestTimestampOptions {
  tsa?: string;
  roots?: readonly X509Certificate[];
  /** Milliseconds before the request is abandoned. */
  timeoutMs?: number;
  /** Replaces global fetch; for tests. */
  fetch?: (url: string, init: { method: string; headers: Record<string, string>; body: Uint8Array; signal: AbortSignal }) => Promise<{ ok: boolean; status: number; arrayBuffer(): Promise<ArrayBuffer> }>;
  /** Fixed nonce; for tests. A real request must use a fresh random one. */
  nonce?: Buffer;
}

/**
 * Ask a TSA to timestamp `head`, and verify the answer before returning it.
 *
 * A token that does not verify is never handed back: writing it into an anchor
 * file would produce a line that fails at audit time, which is the worst moment
 * to find out.
 */
export async function requestTimestamp(head: string, options: RequestTimestampOptions = {}): Promise<ReceiptTimestamp> {
  const tsa = options.tsa ?? DEFAULT_TSA;
  const nonce = options.nonce ?? freshNonce();
  const body = buildRequest(headBytes(head), nonce);

  const doFetch = options.fetch ?? (globalThis.fetch as unknown as NonNullable<RequestTimestampOptions['fetch']>);
  const response = await doFetch(tsa, {
    method: 'POST',
    headers: { 'Content-Type': 'application/timestamp-query' },
    body,
    signal: AbortSignal.timeout(options.timeoutMs ?? 15_000),
  });
  if (!response.ok) throw new Error(`TSA ${tsa} answered HTTP ${response.status}`);

  const token = readResponse(Buffer.from(await response.arrayBuffer()));
  const check = verifyTimestamp(token, head, { roots: options.roots, nonce });
  if (!check.ok || !check.time) throw new Error(`TSA ${tsa} returned a token that does not verify: ${check.failure}`);

  return { tsa, time: check.time.toISOString(), token: token.toString('base64') };
}

/**
 * Check that `token` is a TSA signature over `head`, by a certificate that
 * chains to a trusted root and was valid at the time it signed.
 */
export function verifyTimestamp(
  token: Buffer | string,
  head: string,
  options: VerifyTimestampOptions = {}
): TimestampCheck {
  const result: TimestampCheck = { ok: false, time: null, signer: null, root: null };
  try {
    const der = typeof token === 'string' ? Buffer.from(token, 'base64') : token;
    const parsed = parseToken(der);
    result.time = parsed.genTime;

    if (parsed.imprintAlg !== OID.sha256) return fail(result, `token imprint uses ${parsed.imprintAlg}, not SHA-256`);
    if (!parsed.imprint.equals(headBytes(head))) {
      return fail(result, `token was issued for ${parsed.imprint.toString('hex').slice(0, 12)}, not for head ${head.slice(0, 12)}`);
    }
    if (options.nonce && !(parsed.nonce && stripZeros(parsed.nonce).equals(stripZeros(options.nonce)))) {
      return fail(result, 'token does not carry the nonce that was sent');
    }

    // The signature covers the signed attributes, and the attributes cover the
    // TSTInfo through its digest. Both links have to hold, or a valid signature
    // could be paired with a different time or a different head.
    const digestName = DIGESTS[parsed.digestAlg];
    if (!digestName) return fail(result, `unsupported digest algorithm ${parsed.digestAlg}`);
    if (parsed.contentTypeAttr !== OID.tstInfo) return fail(result, 'signed content-type attribute is not TSTInfo');
    if (!parsed.messageDigest?.equals(createHash(digestName).update(parsed.tstInfo).digest())) {
      return fail(result, 'signed message digest does not match the TSTInfo — the time or imprint was altered');
    }

    const signer = findSigner(parsed);
    if (!signer) return fail(result, 'the token does not include the certificate that signed it');
    result.signer = commonName(signer.subject);

    const sigHash = SIGNATURE_HASHES[parsed.signatureAlg] ?? (parsed.signatureAlg === OID.rsaEncryption ? digestName : undefined);
    if (!sigHash) return fail(result, `unsupported signature algorithm ${parsed.signatureAlg}`);
    if (!verifySignature(sigHash, parsed.signedAttrs, signer.publicKey, parsed.signature)) {
      return fail(result, 'TSA signature does not verify');
    }

    if (!signer.keyUsage?.includes(OID.timeStamping)) {
      return fail(result, `${result.signer} is not a timestamping certificate`);
    }

    const chain = buildChain(signer, parsed.certificates, options.roots ?? bundledRoots());
    for (const cert of chain.path) {
      if (!validAt(cert, parsed.genTime)) {
        return fail(result, `${commonName(cert.subject)} was not valid at ${parsed.genTime.toISOString()}`);
      }
    }
    if (!chain.root) return fail(result, `${result.signer} does not chain to a trusted root`);
    result.root = commonName(chain.root.subject);

    result.ok = true;
    return result;
  } catch (err) {
    return fail(result, `token is not a readable RFC 3161 timestamp (${(err as Error).message})`);
  }
}

function fail(result: TimestampCheck, failure: string): TimestampCheck {
  result.ok = false;
  result.failure = failure;
  return result;
}

// ---------------------------------------------------------------------------
// Request and response
// ---------------------------------------------------------------------------

function buildRequest(imprint: Buffer, nonce: Buffer): Buffer {
  return tlv(0x30, [
    tlv(0x02, [Buffer.from([1])]),
    tlv(0x30, [tlv(0x30, [encodeOid(OID.sha256), tlv(0x05, [])]), tlv(0x04, [imprint])]),
    tlv(0x02, [nonce]),
    // certReq: without it most TSAs omit their certificate, and the token could
    // only be checked by someone who already has it.
    tlv(0x01, [Buffer.from([0xff])]),
  ]);
}

/** Pull the TimeStampToken out of a TimeStampResp, failing on any refusal. */
function readResponse(der: Buffer): Buffer {
  const [statusInfo, token] = children(parse(der, 0));
  const status = statusInfo ? children(statusInfo)[0] : undefined;
  if (!status || status.tag !== 0x02) throw new Error('TSA response has no status');
  const code = status.content.readUIntBE(0, status.content.length);
  // 0 granted, 1 granted with modifications; anything else is a refusal.
  if (code > 1) throw new Error(`TSA refused the request (PKIStatus ${code})`);
  if (!token) throw new Error('TSA response carries no token');
  return token.bytes;
}

function freshNonce(): Buffer {
  const nonce = randomBytes(8);
  // Positive and minimally encoded, so it survives as a DER INTEGER unchanged.
  nonce[0] = (nonce[0]! & 0x7f) | 0x40;
  return nonce;
}

function headBytes(head: string): Buffer {
  if (!/^[0-9a-f]{64}$/.test(head)) throw new Error(`head ${head} is not a SHA-256 hex digest`);
  return Buffer.from(head, 'hex');
}

// ---------------------------------------------------------------------------
// Token structure (RFC 3161 inside RFC 5652 SignedData)
// ---------------------------------------------------------------------------

interface ParsedToken {
  tstInfo: Buffer;
  imprintAlg: string;
  imprint: Buffer;
  genTime: Date;
  nonce: Buffer | null;
  certificates: X509Certificate[];
  sid: Asn1;
  digestAlg: string;
  signedAttrs: Buffer;
  contentTypeAttr: string | null;
  messageDigest: Buffer | null;
  signatureAlg: string;
  signature: Buffer;
}

function parseToken(der: Buffer): ParsedToken {
  const [contentType, wrapped] = children(parse(der, 0));
  if (!contentType || decodeOid(contentType) !== OID.signedData) throw new Error('not a CMS SignedData');
  const signedData = children(expect(wrapped, 0xa0))[0];
  const parts = children(expect(signedData, 0x30));

  const encap = children(expect(parts[2], 0x30));
  if (decodeOid(expect(encap[0], 0x06)) !== OID.tstInfo) throw new Error('content is not a TSTInfo');
  const tstInfo = expect(children(expect(encap[1], 0xa0))[0], 0x04).content;

  const certificates: X509Certificate[] = [];
  let signerInfos: Asn1 | undefined;
  for (const part of parts.slice(3)) {
    if (part.tag === 0xa0) for (const cert of children(part)) if (cert.tag === 0x30) certificates.push(new X509Certificate(cert.bytes));
    if (part.tag === 0x31) signerInfos = part;
  }
  const signerInfo = children(expect(signerInfos, 0x31))[0];
  const si = children(expect(signerInfo, 0x30));

  let i = 1;
  const sid = expect(si[i++], si[1]?.tag ?? 0x30);
  const digestAlg = decodeOid(children(expect(si[i++], 0x30))[0]!);
  const attrs = expect(si[i++], 0xa0);
  const signatureAlg = decodeOid(children(expect(si[i++], 0x30))[0]!);
  const signature = expect(si[i++], 0x04).content;

  let contentTypeAttr: string | null = null;
  let messageDigest: Buffer | null = null;
  for (const attr of children(attrs)) {
    const [type, values] = children(attr);
    const value = values ? children(values)[0] : undefined;
    if (!type || !value) continue;
    const oid = decodeOid(type);
    if (oid === OID.contentType) contentTypeAttr = decodeOid(value);
    if (oid === OID.messageDigest) messageDigest = value.content;
  }

  // The signature is computed over the attributes re-tagged as a SET OF, not
  // over the [0] IMPLICIT encoding they travel in (RFC 5652 §5.4).
  const signedAttrs = Buffer.from(attrs.bytes);
  signedAttrs[0] = 0x31;

  const tst = children(parse(tstInfo, 0));
  const imprintParts = children(expect(tst[2], 0x30));
  const imprintAlg = decodeOid(children(expect(imprintParts[0], 0x30))[0]!);
  const imprint = expect(imprintParts[1], 0x04).content;
  const genTime = parseGeneralizedTime(expect(tst[4], 0x18).content.toString('ascii'));
  // After genTime come optional accuracy (SEQUENCE) and ordering (BOOLEAN);
  // the nonce is the first INTEGER that follows.
  const nonce = tst.slice(5).find((node) => node.tag === 0x02)?.content ?? null;

  return {
    tstInfo,
    imprintAlg,
    imprint,
    genTime,
    nonce,
    certificates,
    sid,
    digestAlg,
    signedAttrs,
    contentTypeAttr,
    messageDigest,
    signatureAlg,
    signature,
  };
}

/** The certificate named by the signer identifier, or failing that, any that verifies. */
function findSigner(token: ParsedToken): X509Certificate | null {
  if (token.sid.tag === 0x30) {
    const [issuer, serial] = children(token.sid);
    for (const cert of token.certificates) {
      const tbs = children(children(parse(cert.raw, 0))[0]!);
      const offset = tbs[0]?.tag === 0xa0 ? 1 : 0;
      if (tbs[offset]?.content.equals(serial!.content) && tbs[offset + 2]?.bytes.equals(issuer!.bytes)) return cert;
    }
    return null;
  }
  // subjectKeyIdentifier form: the signature itself picks the certificate out.
  return token.certificates.find((cert) => cert.keyUsage?.includes(OID.timeStamping)) ?? null;
}

function buildChain(
  signer: X509Certificate,
  pool: readonly X509Certificate[],
  roots: readonly X509Certificate[]
): { path: X509Certificate[]; root: X509Certificate | null } {
  const path = [signer];
  let current = signer;
  for (let depth = 0; depth < 8; depth++) {
    const root = roots.find((r) => r.fingerprint256 === current.fingerprint256 || issuedBy(current, r));
    if (root) {
      if (root.fingerprint256 !== current.fingerprint256) path.push(root);
      return { path, root };
    }
    const next = pool.find((c) => c.fingerprint256 !== current.fingerprint256 && issuedBy(current, c));
    if (!next) break;
    path.push(next);
    current = next;
  }
  return { path, root: null };
}

function issuedBy(cert: X509Certificate, issuer: X509Certificate): boolean {
  try {
    return cert.checkIssued(issuer) && cert.verify(issuer.publicKey);
  } catch {
    return false;
  }
}

function validAt(cert: X509Certificate, time: Date): boolean {
  return new Date(cert.validFrom) <= time && time <= new Date(cert.validTo);
}

let bundled: X509Certificate[] | null = null;
function bundledRoots(): X509Certificate[] {
  bundled ??= rootCertificates.map((pem) => new X509Certificate(pem));
  return bundled;
}

function commonName(subject: string): string {
  const cn = subject.split('\n').find((line) => line.startsWith('CN='));
  return cn ? cn.slice(3) : subject.replace(/\n/g, ', ');
}

function parseGeneralizedTime(text: string): Date {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/.exec(text);
  if (!m) throw new Error(`unreadable genTime ${text}`);
  const ms = m[7] ? Math.round(Number(m[7]) * 1000) : 0;
  return new Date(Date.UTC(+m[1]!, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!, +m[6]!, ms));
}

function stripZeros(buf: Buffer): Buffer {
  let i = 0;
  while (i < buf.length - 1 && buf[i] === 0) i++;
  return buf.subarray(i);
}

// ---------------------------------------------------------------------------
// Minimal DER
// ---------------------------------------------------------------------------

interface Asn1 {
  tag: number;
  /** The whole TLV. */
  bytes: Buffer;
  /** The value only. */
  content: Buffer;
}

function parse(buf: Buffer, offset: number): Asn1 {
  const tag = buf[offset];
  let lenByte = buf[offset + 1];
  if (tag === undefined || lenByte === undefined) throw new Error('truncated DER');
  let length = lenByte;
  let header = 2;
  if (lenByte & 0x80) {
    const n = lenByte & 0x7f;
    if (n === 0 || n > 4) throw new Error('unsupported DER length');
    length = 0;
    for (let k = 0; k < n; k++) {
      lenByte = buf[offset + 2 + k];
      if (lenByte === undefined) throw new Error('truncated DER');
      length = length * 256 + lenByte;
    }
    header += n;
  }
  const end = offset + header + length;
  if (end > buf.length) throw new Error('truncated DER');
  return { tag, bytes: buf.subarray(offset, end), content: buf.subarray(offset + header, end) };
}

function children(node: Asn1): Asn1[] {
  const out: Asn1[] = [];
  let offset = 0;
  while (offset < node.content.length) {
    const child = parse(node.content, offset);
    out.push(child);
    offset += child.bytes.length;
  }
  return out;
}

function expect(node: Asn1 | undefined, tag: number): Asn1 {
  if (!node || node.tag !== tag) throw new Error(`expected DER tag 0x${tag.toString(16)}`);
  return node;
}

function tlv(tag: number, parts: Buffer[]): Buffer {
  const content = Buffer.concat(parts);
  const n = content.length;
  let length: Buffer;
  if (n < 0x80) length = Buffer.from([n]);
  else if (n < 0x100) length = Buffer.from([0x81, n]);
  else length = Buffer.from([0x82, n >> 8, n & 0xff]);
  return Buffer.concat([Buffer.from([tag]), length, content]);
}

function encodeOid(oid: string): Buffer {
  const [a, b, ...rest] = oid.split('.').map(Number);
  const bytes = [a! * 40 + b!];
  for (const arc of rest) {
    const chunk = [arc & 0x7f];
    for (let v = arc >>> 7; v > 0; v >>>= 7) chunk.unshift((v & 0x7f) | 0x80);
    bytes.push(...chunk);
  }
  return tlv(0x06, [Buffer.from(bytes)]);
}

function decodeOid(node: Asn1): string {
  const bytes = node.content;
  const first = bytes[0] ?? 0;
  const arcs = [Math.min(2, Math.floor(first / 40)), first - Math.min(2, Math.floor(first / 40)) * 40];
  let value = 0;
  for (const byte of bytes.subarray(1)) {
    value = value * 128 + (byte & 0x7f);
    if (!(byte & 0x80)) {
      arcs.push(value);
      value = 0;
    }
  }
  return arcs.join('.');
}

const OID = {
  sha256: '2.16.840.1.101.3.4.2.1',
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
  rsaEncryption: '1.2.840.113549.1.1.1',
  timeStamping: '1.3.6.1.5.5.7.3.8',
} as const;

const DIGESTS: Record<string, string> = {
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};

const SIGNATURE_HASHES: Record<string, string> = {
  '1.2.840.113549.1.1.11': 'sha256',
  '1.2.840.113549.1.1.12': 'sha384',
  '1.2.840.113549.1.1.13': 'sha512',
  '1.2.840.10045.4.3.2': 'sha256',
  '1.2.840.10045.4.3.3': 'sha384',
  '1.2.840.10045.4.3.4': 'sha512',
};
