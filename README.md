# dkgkit

Threshold cryptography for Bitcoin — FROST distributed key generation,
resharing and signing; MuSig2 transaction-tree cosigning; BIP-352 silent
payments. Rust core compiled to WebAssembly, with a TypeScript API over it.

> **Status: key generation, signing and resharing work.** BIP-352 and the
> MuSig2 tree paths are documented targets, not code. Nothing is published to a
> registry.

## What exists today

| | |
|---|---|
| Key generation | `dkg_round1` · `dkg_round2` · `dkg_finalize` |
| Signing | `sign_nonce` · `sign_share` · `sign_aggregate` |
| Resharing | `reshare_round1` · `reshare_round2` · `reshare_finalize` |

Thin JSON marshalling over
[`frost-secp256k1-tr`](https://crates.io/crates/frost-secp256k1-tr), the Zcash
Foundation's RFC 9591 implementation in its BIP-340/341 taproot variant.
Signatures are aggregated with the taproot tweak applied, so they verify
against the output key a Bitcoin node checks.

**`sign_share` and `sign_aggregate` must be given the same merkle root.** The
tweak is applied to each signer's key package, so a disagreement produces
shares the aggregator rejects. Nothing in the types enforces this; a test
does. Note `None` and `""` mean the same thing — the key-path-only tweak.

## Resharing

Redistributes shares on fresh polynomials while the group key — and therefore
the address and its UTXOs — stays put. Distributed: no party ever reconstructs
the secret.

Two limits, both verified by tests rather than read off documentation:

| | |
|---|---|
| Refresh shares in place | yes |
| **Remove** a member | yes |
| **Add** a member | **no** — finalisation needs the caller's own previous key package, which a new member does not have |
| Change the threshold | **no** — upstream compares `min_signers` against the old key package and refuses |

So a t-of-n vault stays t-of-n for life. Changing `t`, or admitting someone who
has never held a share, means a fresh DKG — a new group key and a new address.

## Entropy

`dkg_round1` and `sign_nonce` take an optional hex `extra_entropy` — dice rolls,
a hardware RNG, a second device. It is folded in **on top of** the OS draw:

```
seed = SHA-512(os_entropy ‖ extra)[..32]
```

The OS draw always participates. Bad extra entropy therefore cannot weaken the
result, while good extra entropy rescues a compromised OS source. A seed that
*replaced* the OS draw would only move the single point of failure.

A degenerate OS draw (all-zero, or every byte identical) is a hard error rather
than a warning. Key generation refuses to proceed.

This is shaped by Coldcard's 2026 incident: a 2021 firmware error silently
routed seed generation from the STM32 hardware RNG to a software PRNG, dropping
effective entropy from 128 bits to roughly 40. It went unnoticed for five years
and cost ~1,367 BTC. The device *had* a hardware TRNG — the failure was silent
substitution, so what matters is never trusting one source and never failing
quietly.

Threshold generation helps structurally too: a group key is the sum of every
participant's polynomial, so one honest entropy source among N keeps it
unpredictable. That does not extend to a participant's own share or nonces,
which is why per-device entropy still matters.

This crate deliberately contains **no cryptography of its own**: no curve
arithmetic, no polynomial evaluation, no challenge or binding-factor
derivation. Those are delegated wholesale, because subtly wrong versions of
them are how threshold schemes leak shares.

```
cargo test                                  # 2-of-3 DKG, end to end
cargo build --target wasm32-unknown-unknown --release
```

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

## Still to port

Everything below still lives in the private monorepo as TypeScript. Listed so
the remaining surface is visible, not as a claim that it exists here.

| Area | What it covers |
|---|---|
| BIP-352 silent payments | address encode/decode, output derivation, scanning against tweak data |
| MuSig2 transaction tree | Ark cosigning: nonces, partials, branch validation |
| DLEQ | proving a threshold ECDH share came from the committed secret |
| Transaction & taproot | sighashes, key-path assembly, script helpers |
| Ark structures | VTXO outputs, checkpoints, batch expiry |

Most of it is pure TypeScript over `@noble` and `@scure` with no browser
dependency, so it may not need to become Rust at all — only FROST did, and only
because the implementation it delegates to is a Rust crate.

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
