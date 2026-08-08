# dkgkit

Threshold cryptography core — FROST distributed key generation, resharing and
signing, MuSig2 transaction-tree cosigning, and BIP-352 silent payments.

> **Status: ready to extract.** The code currently lives in
> [`coinfidential`](https://github.com/Coinfidential/coinfidential) at
> `crates/dkgkit-wasm/` and `packages/crypto/`. This repo is the reserved home;
> extraction is step 1 of the split.

## What lands here

| Path in monorepo | LOC | Role |
|---|---|---|
| `crates/dkgkit-wasm/` | 2.6k | Rust FROST implementation, compiled to wasm |
| `packages/crypto/` | 8.5k | TypeScript API over the wasm, plus BIP-352 and taproot primitives |

**These two move together, always.** `packages/crypto/wasm/` is *generated* from
the crate by `bun run build:wasm`. A change to the crate is a change to the
package whether or not the diff shows it. Never split them, and never grant
review ownership of one without the other.

## Why this unit is extractable first

- **Zero transport coupling** — `nostr-tools` appears in 0 files.
- **Zero upward dependencies** — imports no other `@coinfidential/*` package.
- **Transport-agnostic identity** — FROST participants are `participantId: number`,
  not Nostr pubkeys. The pubkey→id mapping lives one layer up.
- **Dual-runtime already** — `initFrost(wasmBytes?)` takes optional bytes: the
  browser omits them and fetches, Bun passes `readFileSync(path)`. One
  `--target web` build serves both.

## Public API

Grouped by concern. Full symbol-by-symbol tables, with which consumer uses what,
are in the monorepo at [`docs/architecture/01-crypto.md`](https://github.com/Coinfidential/coinfidential/blob/main/docs/architecture/01-crypto.md).

- **Lifecycle** — `initFrost`
- **FROST keygen** — `dkgRound1`, `dkgRound2`, `dkgFinalize`
- **FROST reshare** — `reshareDeal`, `reshareFinalize`, `reshareGroupKey`, `verifyClaimedShares`
- **FROST signing** — `signNonce`, `signShare`, `signAggregate`, `tweakGroupKey`, `outputTweak`
- **MuSig2 tree** — `musigTreeNonce`, `musigTreePartial`, `aggregateTreeNonce`, `aggregateTreePartials`, `validateVtxoBranch`
- **BIP-352** — `encodeSilentPaymentAddress`, `deriveArkSilentOutput`, `scanTxWithTweaks`, `scanArkTx`, `combineEcdh`
- **DLEQ** — `dleqProve`, `dleqVerify`
- **Tx / taproot** — `buildUnsignedTx`, `taprootSighashes`, `assembleKeyPathTx`, `p2trScriptHex`, `txidOf`
- **Ark structures** — `encodeArkAddress`, `vtxoTaprootOutput`, `arkCheckpointTxid`, `assertCanonicalCheckpointUnroll`

## Consumers

| Repo | Symbols imported |
|---|---|
| [`rails`](https://github.com/Coinfidential/rails) | 15 |
| [`steward`](https://github.com/Coinfidential/steward) | 38 |
| [`desktop`](https://github.com/Coinfidential/desktop) | 58 |

## Extraction checklist

- [ ] Move `crates/` + `packages/crypto/` with `git filter-repo` (preserves history)
- [ ] Keep `build:wasm` here — it is the crate→package bridge
- [ ] Publish the wasm artifact **with** the package; consumers must not need a Rust toolchain
- [ ] Pin consumers to an exact version — a floating range on a signing library is a supply-chain hole
- [ ] Unit tests come along; they need no regtest stack and already skip when the wasm is absent

## Security

This repo is the audit surface for everything that touches key material. Treat
every change as consensus-critical. Findings and their resolution status are
tracked in the monorepo under `docs/security/`.
