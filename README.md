# dkgkit

FROST threshold key generation, resharing and signing for Bitcoin. A Rust
crate, compiled to WebAssembly for hosts that want it.

> **Status: key generation, signing and resharing work.** Nothing is published
> to a registry.

## Scope

**Everything that touches a share, and nothing else.**

That is the whole rule, and it is meant to be applied literally. Silent
payments, taproot construction, transaction serialisation and address encoding
are all *absent by design* — none of them touch a share, so none of them belong
here. They are Bitcoin format and protocol work, they carry a different risk
profile, and they want different reviewers.

An earlier version of this README described a TypeScript half living alongside
the crate. There isn't one. The only JavaScript dkgkit emits is wasm-bindgen's
generated glue in `pkg/`; each host writes its own thin wrapper over it, which
is a dozen lines and lets the host own its own loading and error handling.

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

**One build, and the host supplies the bytes.** `wasm-pack --target web` serves
every host, but initialise with `initSync` and hand it the module bytes
yourself. wasm-bindgen's default async export — the one that fetches the module
when given nothing — **never resolves under Bare**: no error, no rejection, so a
ceremony waits forever on a wallet that merely looks slow. `WebAssembly.
instantiate` works there; the combination with this module's imports does not.

The defect lives in generated glue, so a routine `wasm-pack` rebuild can
reintroduce it without any crate change. Keep a test that loads the module on
the runtime you ship to, or the failure surfaces in the field rather than in CI.

## What lives elsewhere

Not a roadmap — a boundary. These exist as TypeScript and are staying that way,
because none of them touch a share.

| Area | Home |
|---|---|
| BIP-352 silent payments, taproot construction, transaction serialisation | `chain` |
| DLEQ **verification**, Lagrange combination of ECDH partials | `chain` |
| MuSig2 transaction tree, VTXO structures, unilateral exit packages | `vtxo` (frozen) |

One boundary case, recorded because it will come up. Silent-payment *sending*
from a threshold key needs `a_sum · B_scan`, and `a_sum` never exists — so it
needs an ECDH partial per signer, with a DLEQ proof that the partial came from
that signer's committed share. **Producing** the partial and its proof touches a
share, so it belongs here. Everything downstream — combining, verifying,
deriving the output — is public-data arithmetic and does not.

Do not export the raw signing share to let a caller do that multiplication
outside. That trades the entire boundary for one scalar multiplication.

## Dependencies

Five direct crates, exactly one of them cryptography. See `Cargo.toml`, which
explains each. No network, no I/O.

## Security

**Pre-audit software handling real key material.** It has not been reviewed by
an external auditor and is not recommended for production custody. Treat every
change as consensus-critical.

If you find a vulnerability, please report it privately rather than opening a
public issue.

## License

MIT
