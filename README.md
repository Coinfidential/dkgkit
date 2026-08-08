# dkgkit

Threshold cryptography for Bitcoin — FROST distributed key generation,
resharing and signing; MuSig2 transaction-tree cosigning; BIP-352 silent
payments. Rust core compiled to WebAssembly, with a TypeScript API over it.

> **Status: reserved, extraction pending.** The implementation currently lives
> in a private monorepo and moves here as a unit. This repo holds the boundary
> contract until then. Nothing here is published to a registry yet.

## Design

**Transport-agnostic.** No networking, no message format, no opinion about how
participants reach each other. FROST participants are identified by
`participantId: number` — not by a public key from any particular identity
system. Whatever carries the ceremony messages is somebody else's problem.

**Dual-runtime from one build.** `initFrost(wasmBytes?)` takes optional bytes:
a browser omits them and lets the module fetch, a server runtime passes
`readFileSync(path)`. One `wasm-pack --target web` build serves both, so the
same code runs in a webview and under Node/Bun without a second target.

**The crate and the package are one unit.** The TypeScript package's `wasm/`
directory is *generated* from the Rust crate. A change to the crate is a change
to the package whether or not the diff shows it. They are versioned, reviewed
and released together.

## API

### Lifecycle
`initFrost(wasmBytes?)` — must be awaited before any FROST call.

### FROST
| Area | Functions |
|---|---|
| Key generation | `dkgRound1`, `dkgRound2`, `dkgFinalize` |
| Resharing | `reshareDeal`, `reshareFinalize`, `reshareGroupKey`, `verifyClaimedShares`, `shareScalar` |
| Signing | `signNonce`, `signShare`, `signShareForOutput`, `signAggregate`, `signAggregateForOutput` |
| Key tweaking | `tweakGroupKey`, `outputTweak` |

Resharing performs a distributed Shamir redistribution under the *same* group
key: the roster or threshold changes without a new DKG, no party ever holds
`f(0)`, and derived addresses are untouched.

### MuSig2 — transaction-tree cosigning
`musigTreeNonce`, `musigTreePartial`, `aggregateTreeNonce`,
`aggregateTreePartials`, `treeCoefficients`, `treeLagrangeHex`,
`treeAggregateOutputXonly`, `treeTxSighashes`, `validateFinalizedRoot`,
`validateVtxoBranch`

### BIP-352 — silent payments
`encodeSilentPaymentAddress`, `decodeSilentPaymentAddress`,
`encodeSilentArkAddress`, `decodeSilentArkAddress`, `deriveArkSilentOutput`,
`scanTxWithTweaks`, `scanArkTx`, `combineEcdh`, `deriveFromCombinedEcdh`,
`vaultAnchorEcdh`, `expectedP`

Scanning and derivation work against a delegated scan secret, so a scanner can
detect incoming payments without any spending authority.

### DLEQ
`dleqProve`, `dleqVerify` — used to prove a threshold ECDH share was computed
from the same secret as the participant's committed public share.

### Transaction & taproot primitives
`buildUnsignedTx`, `parseTx`, `parsePsbtTx`, `assembleKeyPathTx`,
`taprootSighashes`, `taprootScriptSighashes`, `tapLeafHash`, `p2trScriptHex`,
`decodeP2TR`, `toXOnly`, `txidOf`, `vaultInputContext`

### Ark structures
`encodeArkAddress`, `decodeArkAddress`, `vtxoTaprootOutput`,
`vtxoForfeitScriptHex`, `arkCheckpointOutput`, `arkCheckpointTxid`,
`assertCanonicalCheckpointUnroll`, `recoverBatchExpiry`, `sweepTapRoot`

## Dependencies

`@noble/curves`, `@noble/hashes`, `@scure/base`, `@scure/btc-signer` — no
network, no I/O, no framework.

## Security

**Pre-audit software handling real key material.** It has not been reviewed by
an external auditor and is not recommended for production custody. Treat every
change as consensus-critical.

If you find a vulnerability, please report it privately rather than opening a
public issue.

## License

MIT
