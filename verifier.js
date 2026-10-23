// Charter attestation verifier: reads an EAS attestation on Base or Base Sepolia,
// decodes the Founding Charter data, fetches every text from IPFS and checks its sha256.
// Plain ES module, no dependency, runs in the browser and in Node 20.

export const EAS_ADDRESS = '0x4200000000000000000000000000000000000021';
export const CHARTER_SCHEMA = 'string version,string date,string[] names,bytes32[] digests,string[] cids';
/** getAttestation(bytes32) */
export const GET_ATTESTATION_SELECTOR = '0xa3112a64';

export const NETWORKS = {
  base: { chainId: 8453, name: 'Base', rpcUrl: 'https://mainnet.base.org', explorer: 'https://base.easscan.org' },
  'base-sepolia': { chainId: 84532, name: 'Base Sepolia', rpcUrl: 'https://sepolia.base.org', explorer: 'https://base-sepolia.easscan.org' },
};

export const DEFAULT_IPFS_GATEWAY = 'https://ipfs.io/ipfs/';
const ZERO32 = '0x' + '0'.repeat(64);
const UID_RE = /^0x[0-9a-fA-F]{64}$/;

// ---------- hex and ABI helpers ----------

function strip0x(hex) {
  if (typeof hex !== 'string') throw new Error('hex data must be a string');
  const h = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  if (h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error('not valid hex data');
  return h.toLowerCase();
}

function hexToBytes(hex) {
  const h = strip0x(hex);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(bytes) {
  let s = '0x';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

const utf8Decoder = new TextDecoder('utf-8', { fatal: true });
const utf8Encoder = new TextEncoder();

/** A reader over ABI encoded bytes; offsets are byte offsets. */
class AbiReader {
  constructor(bytes) { this.b = bytes; }
  word(at) {
    if (at < 0 || at + 32 > this.b.length) throw new Error('ABI data is too short');
    return this.b.subarray(at, at + 32);
  }
  uint(at) {
    let v = 0n;
    for (const x of this.word(at)) v = (v << 8n) | BigInt(x);
    return v;
  }
  /** A uint used as an offset or a length: must be small. */
  size(at) {
    const v = this.uint(at);
    if (v > BigInt(this.b.length)) throw new Error('ABI offset or length out of range');
    return Number(v);
  }
  bytes32(at) { return bytesToHex(this.word(at)); }
  address(at) { return bytesToHex(this.word(at).subarray(12)); }
  bool(at) { return this.uint(at) !== 0n; }
  bytesAt(at) {
    const len = this.size(at);
    if (at + 32 + len > this.b.length) throw new Error('ABI data is too short');
    return this.b.subarray(at + 32, at + 32 + len);
  }
  stringAt(at) { return utf8Decoder.decode(this.bytesAt(at)); }
  /** A dynamic array at `at`: its length then its items; item(base, i) reads one. */
  arrayAt(at, dynamicItems, read) {
    const len = this.size(at);
    const base = at + 32;
    const out = [];
    for (let i = 0; i < len; i++) {
      out.push(dynamicItems ? read(base + this.size(base + 32 * i)) : read(base + 32 * i));
    }
    return out;
  }
}

function pad32(bytes) {
  const out = new Uint8Array(Math.ceil(bytes.length / 32) * 32);
  out.set(bytes);
  return out;
}
function uintWord(n) {
  const out = new Uint8Array(32);
  let v = BigInt(n);
  for (let i = 31; i >= 0 && v > 0n; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}
function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
function encString(s) {
  const b = utf8Encoder.encode(s);
  return concat([uintWord(b.length), pad32(b)]);
}
function encDynamicTuple(items) {
  // items: [{dynamic: true, enc: Uint8Array}] all dynamic
  const heads = [];
  const tails = [];
  let offset = 32 * items.length;
  for (const enc of items) {
    heads.push(uintWord(offset));
    tails.push(enc);
    offset += enc.length;
  }
  return concat([...heads, ...tails]);
}
function encStringArray(arr) {
  return concat([uintWord(arr.length), encDynamicTuple(arr.map(encString))]);
}
function encBytes32Array(arr) {
  return concat([uintWord(arr.length), ...arr.map((h) => {
    const b = hexToBytes(h);
    if (b.length !== 32) throw new Error('a digest must be 32 bytes');
    return b;
  })]);
}

// ---------- Charter data ----------

/**
 * Encode the Charter data with the schema
 * "string version,string date,string[] names,bytes32[] digests,string[] cids".
 */
export function encodeCharterData({ version, date, names, digests, cids }) {
  return bytesToHex(encDynamicTuple([
    encString(version), encString(date), encStringArray(names), encBytes32Array(digests), encStringArray(cids),
  ]));
}

/**
 * Decode the Charter data. digests come back as 0x and 64 lowercase hex.
 * Throws an Error with a plain message when the data does not follow the schema.
 */
export function decodeCharterData(dataHex) {
  const r = new AbiReader(hexToBytes(dataHex));
  const version = r.stringAt(r.size(0));
  const date = r.stringAt(r.size(32));
  const names = r.arrayAt(r.size(64), true, (at) => r.stringAt(at));
  const digests = r.arrayAt(r.size(96), false, (at) => r.bytes32(at));
  const cids = r.arrayAt(r.size(128), true, (at) => r.stringAt(at));
  return { version, date, names, digests, cids };
}

// ---------- EAS attestation ----------

/**
 * Decode the return of EAS getAttestation(bytes32): one tuple
 * (uid, schema, time, expirationTime, revocationTime, refUID, recipient, attester, revocable, data).
 */
export function decodeAttestation(resultHex) {
  const r = new AbiReader(hexToBytes(resultHex));
  const t = r.size(0);
  return {
    uid: r.bytes32(t),
    schema: r.bytes32(t + 32),
    time: Number(r.uint(t + 64)),
    expirationTime: Number(r.uint(t + 96)),
    revocationTime: Number(r.uint(t + 128)),
    refUID: r.bytes32(t + 160),
    recipient: r.address(t + 192),
    attester: r.address(t + 224),
    revocable: r.bool(t + 256),
    data: bytesToHex(r.bytesAt(t + r.size(t + 288))),
  };
}

/** Encode a getAttestation return (used by the tests and to build fixtures). */
export function encodeAttestation(a) {
  const head = concat([
    hexToBytes(a.uid), hexToBytes(a.schema ?? ZERO32), uintWord(a.time ?? 0), uintWord(a.expirationTime ?? 0),
    uintWord(a.revocationTime ?? 0), hexToBytes(a.refUID ?? ZERO32),
    concat([new Uint8Array(12), hexToBytes(a.recipient ?? '0x' + '0'.repeat(40))]),
    concat([new Uint8Array(12), hexToBytes(a.attester ?? '0x' + '0'.repeat(40))]),
    uintWord(a.revocable ? 1 : 0), uintWord(320),
  ]);
  const data = hexToBytes(a.data ?? '0x');
  const tuple = concat([head, uintWord(data.length), pad32(data)]);
  return bytesToHex(concat([uintWord(32), tuple]));
}

export async function sha256Hex(bytes) {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) throw new Error('WebCrypto is not available');
  return bytesToHex(new Uint8Array(await subtle.digest('SHA-256', bytes)));
}

function errText(e) {
  if (e && typeof e === 'object') {
    const code = e.code !== undefined ? ` (code ${e.code})` : '';
    if (typeof e.message === 'string' && e.message) return e.message + code;
  }
  return String(e);
}

/**
 * Verify the Founding Charter attestation.
 * @param {{uid: string, network: 'base'|'base-sepolia', rpc: (method: string, params: unknown[]) => Promise<string>, ipfs: (cid: string) => Promise<Uint8Array>}} args
 * @returns {Promise<{ok: boolean, reason?: string, network?: string, chainId?: number, attestation: {uid, attester, time, revoked, schema?, revocationTime?}, texts: {name, cid, expected, actual, match, error?}[]}>}
 * Never throws: every failure is reported with ok false and a plain reason.
 */
export async function verifyCharter({ uid, network, rpc, ipfs } = {}) {
  const attestation = { uid: typeof uid === 'string' ? uid.toLowerCase() : null, attester: null, time: null, revoked: false };
  const fail = (reason, texts = []) => ({ ok: false, reason, attestation, texts });

  const net = NETWORKS[network];
  if (!net) return fail(`unknown network "${network}": use base or base-sepolia`);
  if (typeof uid !== 'string' || !UID_RE.test(uid)) return fail('the attestation UID must be 0x and 64 hex characters');
  if (typeof rpc !== 'function' || typeof ipfs !== 'function') return fail('rpc and ipfs functions are required');

  let raw;
  try {
    raw = await rpc('eth_call', [{ to: EAS_ADDRESS, data: GET_ATTESTATION_SELECTOR + uid.slice(2).toLowerCase() }, 'latest']);
  } catch (e) {
    return { ...fail(`could not read the attestation on ${net.name}: ${errText(e)}`), network, chainId: net.chainId };
  }

  let att;
  try {
    att = decodeAttestation(raw);
  } catch (e) {
    return { ...fail(`the attestation answer could not be decoded: ${errText(e)}`), network, chainId: net.chainId };
  }
  if (att.uid === ZERO32) {
    return { ...fail(`no attestation with this UID on ${net.name}`), network, chainId: net.chainId };
  }
  attestation.attester = att.attester;
  attestation.time = att.time;
  attestation.revoked = att.revocationTime !== 0;
  attestation.revocationTime = att.revocationTime;
  attestation.schema = att.schema;

  const revokedNote = attestation.revoked ? 'the attestation was revoked; ' : '';
  let charter;
  try {
    charter = decodeCharterData(att.data);
  } catch (e) {
    return { ...fail(`${revokedNote}the attestation data does not follow the Charter schema: ${errText(e)}`), network, chainId: net.chainId };
  }
  const n = charter.names.length;
  if (charter.digests.length !== n || charter.cids.length !== n) {
    return { ...fail(`${revokedNote}the attestation lists a different number of names, digests and CIDs`), network, chainId: net.chainId, charter };
  }

  const texts = await Promise.all(charter.names.map(async (name, i) => {
    const cid = charter.cids[i];
    const expected = charter.digests[i];
    try {
      const bytes = await ipfs(cid);
      if (!(bytes instanceof Uint8Array)) throw new Error('the IPFS fetch did not return bytes');
      const actual = await sha256Hex(bytes);
      return { name, cid, expected, actual, match: actual === expected };
    } catch (e) {
      return { name, cid, expected, actual: null, match: false, error: `could not fetch ${cid}: ${errText(e)}` };
    }
  }));

  const reasons = [];
  if (attestation.revoked) reasons.push('the attestation was revoked');
  if (n === 0) reasons.push('the attestation lists no texts');
  const missing = texts.filter((t) => t.error).map((t) => t.name);
  const mismatched = texts.filter((t) => !t.error && !t.match).map((t) => t.name);
  if (missing.length) reasons.push(`could not fetch: ${missing.join(', ')}`);
  if (mismatched.length) reasons.push(`digest mismatch: ${mismatched.join(', ')}`);

  const result = { ok: reasons.length === 0, attestation, texts, network, chainId: net.chainId, version: charter.version, date: charter.date };
  if (reasons.length) result.reason = reasons.join('; ');
  return result;
}

// ---------- fetch based helpers for the page ----------

/** A JSON-RPC caller over fetch. Throws an Error carrying the JSON-RPC code and message. */
export function makeRpc(url, fetchFn = (...a) => globalThis.fetch(...a)) {
  let id = 0;
  return async (method, params) => {
    const res = await fetchFn(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }),
    });
    if (!res.ok) throw new Error(`RPC answered HTTP ${res.status}`);
    const j = await res.json();
    if (j.error) {
      const e = new Error(j.error.message || 'JSON-RPC error');
      e.code = j.error.code;
      throw e;
    }
    return j.result;
  };
}

/** An IPFS fetcher through an https gateway such as https://ipfs.io/ipfs/. */
export function makeIpfs(gateway = DEFAULT_IPFS_GATEWAY, fetchFn = (...a) => globalThis.fetch(...a)) {
  const base = gateway.endsWith('/') ? gateway : gateway + '/';
  return async (cid) => {
    const clean = String(cid).replace(/^ipfs:\/\//, '');
    const res = await fetchFn(base + clean);
    if (!res.ok) throw new Error(`gateway answered HTTP ${res.status}`);
    return new Uint8Array(await res.arrayBuffer());
  };
}
