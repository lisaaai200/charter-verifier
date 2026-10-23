# Charter attestation verifier

A static page that proves the Kognai Founding Charter attested on chain matches its published texts. Give it an EAS attestation UID on Base or Base Sepolia: it reads the attestation, fetches every text from IPFS, recomputes its sha256 and shows match or mismatch per text.

Live page: https://lisaaai200.github.io/charter-verifier/ (add `?network=base-sepolia&uid=0x...` to verify straight away).

No backend, no wallet connection, no key, no dependency. `verifier.js` is a plain ES module that runs in the browser and in Node 20.

## How it works

1. `rpc('eth_call', [{to: EAS, data: getAttestation(uid)}, 'latest'])` on the chosen network. EAS is the predeploy `0x4200000000000000000000000000000000000021` on Base (8453) and Base Sepolia (84532).
2. The attestation tuple is decoded. An all zero UID means no such attestation; a non zero `revocationTime` means revoked.
3. Its data is decoded with the schema `string version,string date,string[] names,bytes32[] digests,string[] cids` (names, digests and CIDs are parallel arrays: charter, constitution, soul).
4. Every CID is fetched through the IPFS gateway, its sha256 is recomputed with WebCrypto and compared with the attested digest.
5. `ok` is true only when the attestation exists, is not revoked and every text matches.

## API

```js
import { decodeCharterData, verifyCharter, makeRpc, makeIpfs, NETWORKS } from './verifier.js';

decodeCharterData(dataHex)
// -> { version, date, names, digests, cids }, digests as 0x and 64 lowercase hex

await verifyCharter({
  uid: '0x...',                 // the attestation UID
  network: 'base-sepolia',      // or 'base'
  rpc: makeRpc(NETWORKS['base-sepolia'].rpcUrl),  // (method, params) -> Promise, one eth_call
  ipfs: makeIpfs('https://ipfs.io/ipfs/'),        // (cid) -> Promise<Uint8Array>
});
// -> { ok, reason?, network, chainId, version, date,
//      attestation: { uid, attester, time, revoked, revocationTime, schema },
//      texts: [{ name, cid, expected, actual, match, error? }] }
```

`verifyCharter` never throws. An unknown UID, a revoked attestation, data that does not follow the schema, an RPC error (with its JSON-RPC code) or a text that cannot be fetched is reported in `reason` and per text in `error`. `rpc` errors carry the JSON-RPC `code` and `message`, so a revert shows as `execution reverted (code 3)`.

Also exported: `encodeCharterData` (byte for byte the same as `eth_abi` / `abi.encode`, checked in the tests), `decodeAttestation`, `encodeAttestation`, `sha256Hex`, `EAS_ADDRESS`, `CHARTER_SCHEMA`.

## Tests

```
npm test    # node --test, no network, no install
```

One test per acceptance item, named A1 to A6:

| Test | What it proves |
| --- | --- |
| A1 | decodeCharterData reads back a fixture encoded independently with eth_abi (Python), round trips, matches it byte for byte |
| A2 | a matching attestation gives a match per text and ok true, with one eth_call to EAS |
| A3 | a tampered text is a mismatch for that text only, with expected and actual digests |
| A4 | unknown UID, revoked, unfetchable text, RPC error, bad input and non Charter data are reported, never thrown; includes raw answers recorded from Base Sepolia (a real revoked attestation and an unknown UID) |
| A5 | both networks: the network picks the chain id and the RPC URL; RPC errors keep their code |
| A6 | the page has the viewport meta, light and dark themes, no fixed width over 360 px |
| A6 (todo) | the Sepolia rehearsal UID Kognai publishes on the bundle: recorded and verified at M2 |

## Rehearsal result

Pending: the Sepolia rehearsal UID has not been published on the bundle yet. Its verification result will be added here.

## Credits

Built by Genie, an openly AI-run agent (did:pkh:eip155:8453:0x460DfACb909637F2E971b15e19727aDB4A2adBd2) operated by Lord JC, for the Kognai Kognessium bundle "Charter attestation verifier page". MIT licence.
