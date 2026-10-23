// Tests for verifier.js, one per acceptance item (A1 to A6). No network: rpc and ipfs are stubs
// or recorded answers. Run: npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import {
  decodeCharterData, encodeCharterData, decodeAttestation, encodeAttestation, verifyCharter,
  EAS_ADDRESS, GET_ATTESTATION_SELECTOR, NETWORKS, makeRpc, makeIpfs,
} from '../verifier.js';

const fx = JSON.parse(readFileSync(new URL('./fixtures/eth-abi-charter.json', import.meta.url), 'utf8'));
const recorded = JSON.parse(readFileSync(new URL('./fixtures/base-sepolia-recorded.json', import.meta.url), 'utf8'));
const enc = new TextEncoder();
const sha = (s) => '0x' + createHash('sha256').update(s).digest('hex');
const ATTESTER = '0x460dfacb909637f2e971b15e19727adb4a2adbd2';

/** A chain with one EAS contract: uid -> getAttestation answer. Records calls. */
function chain(answers) {
  const calls = [];
  const rpc = async (method, params) => {
    calls.push({ method, params });
    assert.equal(method, 'eth_call');
    assert.equal(params[0].to, EAS_ADDRESS);
    assert.ok(params[0].data.startsWith(GET_ATTESTATION_SELECTOR));
    const uid = '0x' + params[0].data.slice(10);
    if (answers instanceof Error) throw answers;
    return answers[uid] ?? encodeAttestation({ uid: '0x' + '0'.repeat(64) });
  };
  return { rpc, calls };
}
function store(files) {
  const asked = [];
  const ipfs = async (cid) => {
    asked.push(cid);
    if (!(cid in files)) throw new Error('504 gateway timeout');
    return enc.encode(files[cid]);
  };
  return { ipfs, asked };
}
const UID = fx.uid;
const files = Object.fromEntries(fx.decoded.names.map((n, i) => [fx.decoded.cids[i], fx.texts[n]]));

test('A1 decodeCharterData reads back what the schema encodes', () => {
  // independent encoder (eth_abi, Python): fixture made outside this code
  assert.deepEqual(decodeCharterData(fx.charterData), fx.decoded);
  // round trip, digests normalised to lowercase, unicode text kept
  const v = { version: '2.0', date: '2026-11-14', names: ['charter', 'constitution', 'soul'],
    digests: [sha('a'), sha('b'), sha('c').toUpperCase().replace('0X', '0x')], cids: ['bafy1', 'ipfs://bafy2', 'bafy3 é'] };
  const out = decodeCharterData(encodeCharterData(v));
  assert.deepEqual(out, { ...v, digests: v.digests.map((d) => d.toLowerCase()) });
  for (const d of out.digests) assert.match(d, /^0x[0-9a-f]{64}$/);
  // our encoder matches eth_abi byte for byte
  assert.equal(encodeCharterData(fx.decoded), fx.charterData);
  assert.deepEqual(decodeCharterData(encodeCharterData({ version: '', date: '', names: [], digests: [], cids: [] })),
    { version: '', date: '', names: [], digests: [], cids: [] });
  assert.throws(() => decodeCharterData('0x1234'), /too short|out of range/);
});

test('A2 a matching attestation shows a match for each text and ok true', async () => {
  const { rpc, calls } = chain({ [UID]: fx.getAttestationResult });
  const { ipfs } = store(files);
  const r = await verifyCharter({ uid: UID, network: 'base', rpc, ipfs });
  assert.equal(r.ok, true);
  assert.equal(r.reason, undefined);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].params, [{ to: EAS_ADDRESS, data: GET_ATTESTATION_SELECTOR + UID.slice(2) }, 'latest']);
  assert.deepEqual(r.attestation, { uid: UID, attester: ATTESTER, time: 1794614400, revoked: false, revocationTime: 0, schema: '0x' + '22'.repeat(32) });
  assert.equal(r.texts.length, 3);
  for (const [i, t] of r.texts.entries()) {
    assert.equal(t.name, fx.decoded.names[i]);
    assert.equal(t.cid, fx.decoded.cids[i]);
    assert.equal(t.expected, fx.decoded.digests[i]);
    assert.equal(t.actual, t.expected);
    assert.equal(t.match, true);
  }
});

test('A3 a tampered text shows a mismatch for that text only, with both digests, and ok false', async () => {
  const { rpc } = chain({ [UID]: fx.getAttestationResult });
  const tampered = { ...files, [fx.decoded.cids[1]]: fx.texts.constitution + ' ' };
  const r = await verifyCharter({ uid: UID, network: 'base', rpc, ipfs: store(tampered).ipfs });
  assert.equal(r.ok, false);
  assert.match(r.reason, /mismatch: constitution/);
  assert.deepEqual(r.texts.map((t) => t.match), [true, false, true]);
  const bad = r.texts[1];
  assert.equal(bad.expected, fx.decoded.digests[1]);
  assert.equal(bad.actual, sha(fx.texts.constitution + ' '));
  assert.notEqual(bad.actual, bad.expected);
});

test('A4 unknown UID, revoked attestation, unfetchable text and RPC failures are reported, never thrown', async () => {
  const { ipfs } = store(files);
  // unknown UID: EAS returns an empty attestation
  const unknown = await verifyCharter({ uid: '0x' + 'ab'.repeat(32), network: 'base', rpc: chain({}).rpc, ipfs });
  assert.equal(unknown.ok, false);
  assert.match(unknown.reason, /no attestation with this UID on Base/);
  assert.deepEqual(unknown.texts, []);

  // revoked: texts still checked, ok false
  const revokedAnswer = encodeAttestation({ uid: UID, attester: ATTESTER, time: 1, revocationTime: 2, revocable: true, data: fx.charterData });
  const revoked = await verifyCharter({ uid: UID, network: 'base', rpc: chain({ [UID]: revokedAnswer }).rpc, ipfs });
  assert.equal(revoked.ok, false);
  assert.equal(revoked.attestation.revoked, true);
  assert.match(revoked.reason, /revoked/);
  assert.ok(revoked.texts.every((t) => t.match));

  // a text that cannot be fetched
  const partial = { ...files }; delete partial[fx.decoded.cids[2]];
  const missing = await verifyCharter({ uid: UID, network: 'base', rpc: chain({ [UID]: fx.getAttestationResult }).rpc, ipfs: store(partial).ipfs });
  assert.equal(missing.ok, false);
  assert.match(missing.reason, /could not fetch: soul/);
  assert.equal(missing.texts[2].match, false);
  assert.equal(missing.texts[2].actual, null);
  assert.match(missing.texts[2].error, /504 gateway timeout/);
  assert.deepEqual(missing.texts.slice(0, 2).map((t) => t.match), [true, true]);

  // RPC error with a JSON-RPC code, bad input, non Charter data, garbage answers
  const rpcErr = Object.assign(new Error('execution reverted'), { code: 3 });
  const r1 = await verifyCharter({ uid: UID, network: 'base', rpc: chain(rpcErr).rpc, ipfs });
  assert.equal(r1.ok, false); assert.match(r1.reason, /execution reverted \(code 3\)/);
  for (const args of [{}, { uid: 'nope', network: 'base', rpc: chain({}).rpc, ipfs }, { uid: UID, network: 'mainnet', rpc: chain({}).rpc, ipfs }, { uid: UID, network: 'base' }]) {
    const r = await verifyCharter(args);
    assert.equal(r.ok, false); assert.equal(typeof r.reason, 'string');
  }
  const r2 = await verifyCharter({ uid: UID, network: 'base', rpc: async () => '0xdeadbeef', ipfs });
  assert.equal(r2.ok, false); assert.match(r2.reason, /could not be decoded/);
  const notCharter = encodeAttestation({ uid: UID, attester: ATTESTER, time: 1, data: '0x1234' });
  const r3 = await verifyCharter({ uid: UID, network: 'base', rpc: chain({ [UID]: notCharter }).rpc, ipfs });
  assert.equal(r3.ok, false); assert.match(r3.reason, /does not follow the Charter schema/);
  const uneven = encodeAttestation({ uid: UID, time: 1, data: encodeCharterData({ ...fx.decoded, cids: fx.decoded.cids.slice(0, 2) }) });
  const r4 = await verifyCharter({ uid: UID, network: 'base', rpc: chain({ [UID]: uneven }).rpc, ipfs });
  assert.equal(r4.ok, false); assert.match(r4.reason, /different number/);
  const throwsBytes = await verifyCharter({ uid: UID, network: 'base', rpc: chain({ [UID]: fx.getAttestationResult }).rpc, ipfs: async () => 'text' });
  assert.equal(throwsBytes.ok, false);

  // recorded Base Sepolia answers: a real revoked attestation of another schema, a real unknown UID
  const rec = async (_m, p) => recorded.calls['0x' + p[0].data.slice(10)];
  const realRevoked = await verifyCharter({ uid: '0xd1fdad2f9df296116125fdd8eb9b51d2a8f636647c442af73e3715b8446938c9', network: 'base-sepolia', rpc: rec, ipfs });
  assert.equal(realRevoked.ok, false);
  assert.equal(realRevoked.attestation.revoked, true);
  assert.equal(realRevoked.attestation.attester, '0xc59a5428ac1dede93463cbbc2ed005f10ea9fc54');
  assert.match(realRevoked.reason, /^the attestation was revoked; .*Charter schema/);
  const realUnknown = await verifyCharter({ uid: '0x' + '12'.repeat(32), network: 'base-sepolia', rpc: rec, ipfs });
  assert.match(realUnknown.reason, /no attestation with this UID on Base Sepolia/);
});

test('A5 works on Base and Base Sepolia, the network choosing the chain and the RPC', async () => {
  assert.equal(NETWORKS.base.chainId, 8453);
  assert.equal(NETWORKS['base-sepolia'].chainId, 84532);
  assert.equal(NETWORKS.base.rpcUrl, 'https://mainnet.base.org');
  assert.equal(NETWORKS['base-sepolia'].rpcUrl, 'https://sepolia.base.org');
  const { ipfs } = store(files);
  for (const network of ['base', 'base-sepolia']) {
    const r = await verifyCharter({ uid: UID, network, rpc: chain({ [UID]: fx.getAttestationResult }).rpc, ipfs });
    assert.equal(r.ok, true); assert.equal(r.network, network); assert.equal(r.chainId, NETWORKS[network].chainId);
  }
  // makeRpc posts to the URL it is given and surfaces JSON-RPC errors with their code
  const seen = [];
  const fakeFetch = async (url, init) => {
    seen.push(url);
    const body = JSON.parse(init.body);
    if (url.includes('sepolia')) return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, error: { code: 3, message: 'execution reverted' } }));
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: fx.getAttestationResult }));
  };
  const okBase = await verifyCharter({ uid: UID, network: 'base', rpc: makeRpc(NETWORKS.base.rpcUrl, fakeFetch), ipfs });
  assert.equal(okBase.ok, true);
  const sep = await verifyCharter({ uid: UID, network: 'base-sepolia', rpc: makeRpc(NETWORKS['base-sepolia'].rpcUrl, fakeFetch), ipfs });
  assert.equal(sep.ok, false); assert.match(sep.reason, /code 3/);
  assert.deepEqual(seen, ['https://mainnet.base.org', 'https://sepolia.base.org']);
  // makeIpfs maps ipfs:// to the chosen gateway
  const urls = [];
  const gw = makeIpfs('https://gw.example/ipfs', async (u) => { urls.push(u); return new Response('hi'); });
  assert.deepEqual(await gw('ipfs://bafyX'), enc.encode('hi'));
  assert.deepEqual(urls, ['https://gw.example/ipfs/bafyX']);
});

test('A6 the page is mobile friendly, light and dark, and uses verifier.js', () => {
  const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
  assert.match(html, /<meta name="viewport" content="width=device-width, initial-scale=1"/);
  assert.match(html, /prefers-color-scheme: dark/);
  assert.match(html, /from '\.\/verifier\.js'/);
  assert.match(html, /<select id="network"[\s\S]*value="base-sepolia"/);
  // nothing wider than 360 px is forced
  for (const m of html.matchAll(/(?:^|[^-])width:\s*(\d+)px/g)) assert.ok(Number(m[1]) <= 360, `fixed width ${m[1]}px`);
});

test('A6 verifies the Sepolia rehearsal UID Kognai publishes on this bundle', { todo: 'Kognai has not published the rehearsal UID yet; it will be recorded in test/fixtures and the README at M2' }, () => {});
