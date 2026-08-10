# Redistribution test vectors

`redistribute.json` states what a Shamir redistribution must produce, in hex and
plain integers. It exists so that **an implementation in another language can be
checked against this one without reading any Rust** — the way BIP-352 got its
review, and the only way anyone sensibly audits a redistribution protocol.

Redistribution is the operation that hands a `t`-of-`n` vault to a *different*
roster — adding a member, removing one, replacing a lost device, or moving the
threshold — while the group key, and therefore the taproot address, stays
exactly where it was. Each dealer re-splits its own share `f(i)` with a fresh
polynomial across the new roster; each recipient sums the sub-shares addressed
to it, weighted by the Lagrange coefficients of the dealer set:

```
g_j = Σ_d  λ_d · s_dj
```

Because `Σ_d λ_d · f(d) = f(0)` for any `t`-subset, the new shares reconstruct
the same secret, and **no party ever reconstructs `f(0)`**.

## What these vectors pin, and what they cannot

They pin **finalisation** — the recipient's half. They do **not** pin dealing.

That is not an omission. Dealing draws a fresh random polynomial, and this
implementation deliberately mixes OS entropy into every draw with no way for a
caller to override it (`caller_entropy_cannot_make_output_deterministic` in
`src/lib.rs` exists to keep it that way). So there is no input from which a
second implementation could reproduce a given deal byte for byte, and a vector
that claimed otherwise would either be testing nothing or documenting a
weakness.

Finalisation, by contrast, is a pure function of public inputs plus the
sub-shares addressed to you — and it is where every check that matters lives:

| # | Check | Caught by |
| - | ----- | --------- |
| 1 | Feldman/VSS: the sub-share lies on the polynomial its dealer committed to | `feldman-verification-fails` |
| 2 | Binding: the commitment's constant term is that dealer's certified verifying share | `dealer-resplits-a-foreign-secret` |
| 3 | The dealer set interpolates to the group key | `sub-threshold-dealer-set` |
| 4 | The summed share agrees with the verifying share derived from the commitments | (arithmetic backstop; no vector can force it in isolation) |

So dealers are checked here — just through the deals they produced, which is
also how they are checked in a real ceremony. What a dealer implementation must
satisfy is a property rather than a vector, and the property is this: given a
key package for participant `d` in a vault whose group key is `G`, a deal at
threshold `t'` must have a commitment of exactly `t'` coefficients whose
constant term is `d`'s verifying share in `G`, and every sub-share it emits must
pass Feldman verification against that commitment. Feed your dealer's output
into *this* file's finalisation checks and you have tested it end to end.

## Format

```jsonc
{
  "version": 1,
  "ciphersuite": "FROST(secp256k1, SHA-256) — BIP-340/341 taproot variant, RFC 9591",
  "note": "...",
  "valid":   [ /* cases that must succeed, and produce exactly these shares */ ],
  "invalid": [ /* cases that must be refused */ ]
}
```

### Encodings

Every byte string is lowercase hex. Participant ids are integers ≥ 1 and appear
as JSON object **keys** where they index a map, so they are quoted there and
bare in arrays.

| Field | Encoding |
| ----- | -------- |
| `group_key`, `verifying_shares.*`, `commitment[]`, `commitment_evaluations.*` | 33-byte compressed secp256k1 point |
| `signing_shares.*`, `deals.*.shares.*`, `lagrange` | 32-byte big-endian scalar |

Points are the RFC 9591 group serialisation for this ciphersuite; scalars are
its scalar serialisation. If your library round-trips a compressed SEC1 point
and a big-endian field element, you already agree.

### A valid case

```jsonc
{
  "name": "add-a-member",
  "description": "...",

  // The vault as it stood. All public — this is the old public key package,
  // spelled out. A member being ADDED can derive this for itself from the
  // ceremony transcript and need trust nobody for it.
  "old": {
    "threshold": 2,
    "participants": [1, 2, 3],
    "group_key": "03af…",
    "verifying_shares": { "1": "02…", "2": "03…", "3": "02…" }
  },

  // Which old members dealt. Any t of them suffice; a departing member need
  // not be among them, which is what makes this a recovery path.
  "dealers": [1, 2],

  "new": { "threshold": 2, "participants": [1, 2, 3, 4] },

  // One entry per dealer. `commitment` is public and identical in every copy
  // of that dealer's deal; each entry in `shares` is secret to its recipient
  // and in a real ceremony travels pairwise and sealed.
  "deals": {
    "1": { "commitment": ["02…", "03…"], "shares": { "1": "…", "2": "…", "3": "…", "4": "…" } },
    "2": { "commitment": ["03…", "02…"], "shares": { "1": "…", "2": "…", "3": "…", "4": "…" } }
  },

  // Working shown, so a mismatch tells you WHERE you diverged. Per dealer:
  // λ_d over the dealer set, and Φ_d(j) — that dealer's commitment evaluated
  // at each new participant, before λ weighting and before summation.
  "intermediates": {
    "1": { "lagrange": "…", "commitment_evaluations": { "1": "02…", "…": "…" } }
  },

  // What every recipient must end up with.
  "expected": {
    "group_key": "03af…",                       // identical to old.group_key
    "verifying_shares": { "1": "…", "…": "…" }, // agreed by all recipients
    "signing_shares":   { "1": "…", "…": "…" }  // each secret to its own holder
  }
}
```

`expected.group_key` equals `old.group_key` in every valid case. That is the
whole point of the operation and the first thing to assert.

### An invalid case

Same shape, minus `intermediates` and `expected`, plus:

| Field | Meaning |
| ----- | ------- |
| `participant` | who attempts to finalise |
| `expected_group_key` | the group key that finaliser pins to — normally `old.group_key`; `pinned-to-another-vault` deliberately differs |
| `error_contains` | a substring your error message should make findable |

`error_contains` is a hint, not a conformance requirement — **the contract is
that finalisation fails**. Do not match on wording. Do check you fail for the
stated reason rather than incidentally; several of these cases are constructed
so that every *other* check passes.

Each invalid case is `add-a-member` with exactly one thing broken, so the
difference between accepted and refused is legible by diffing them.

## Checking an independent implementation

For each entry in `valid`:

1. Rebuild the old public key package from `old` — group key and verifying
   shares, nothing else.
2. For **each** `j` in `new.participants`, gather the sub-shares addressed to
   `j`: one from each dealer, `deals[d].shares[j]`, carrying `deals[d].commitment`.
3. Finalise as participant `j`, pinning `old.group_key` and passing
   `new.threshold` and `new.participants`.
4. Assert the resulting group key equals `old.group_key`; that `j`'s signing
   share equals `expected.signing_shares[j]`; and that the verifying shares `j`
   derives for the *whole* roster equal `expected.verifying_shares`.

Step 4's last clause matters: every recipient must independently arrive at the
same public view. Checking only your own share would miss a divergence that
surfaces much later, as signature shares that will not aggregate.

For each entry in `invalid`: run the same procedure as `participant` and assert
it **fails**.

If `intermediates` helps you localise a failure, compare `Φ_d(j)` first — if
those match and the final share does not, the bug is in your Lagrange weighting
or your summation, not in your VSS evaluation.

## Regenerating

```sh
cargo test generate_vectors -- --ignored
```

Dealing is randomised, so a regenerated file differs from the old one
*everywhere*. Regenerate only when the **format** changes, and review the result
as a new artefact rather than as an edit — a diff will not be readable.

`the_vectors_reproduce_byte_for_byte` in `src/lib.rs` replays this file from its
bytes on every `cargo test`, so the vectors and the implementation cannot drift
apart silently.
