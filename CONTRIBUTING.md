# Contributing

## Commits

Conventional Commits — `type: subject`, imperative mood, lower case:

```
feat: mix caller-supplied physical entropy into keys and nonces
fix: hex decoder accepted signs and panicked on multi-byte chars
refactor: replace the O(n²) identifier mapping
docs: boundary contract and extraction status
test: cover the tweak mismatch at aggregation
chore: bump frost-secp256k1-tr
```

Anything altering a public signature carries a `BREAKING CHANGE:` footer, so
the crate's version bump can be derived rather than remembered.

**The PR title must follow the same rule.** Squash merges take their subject
from the PR title, not from the branch's commits, so a carefully written
`feat:` commit otherwise lands on `main` under whatever the PR was called —
which is exactly how #3 got a prose subject. CI checks the title; the
individual commit messages survive in the squash body.

The body is where the value is. Say why, and say what a reviewer would
otherwise have to rediscover — a rejected alternative, a bug the change fixes,
an upstream assumption now being relied on.

## Formatting is automatic

Enable the repo's hooks once per clone:

```
git config core.hooksPath .githooks
```

`pre-commit` then runs `cargo fmt` and re-stages the Rust files you had already
staged. `cargo fmt --check` is the first thing CI runs, and a red build over
whitespace tells you nothing you wanted to know.

It re-stages only what was staged to begin with — if the formatter also touches
something you deliberately left out, that stays unstaged. `--no-verify` skips it.

Note `cargo fmt` only formats files reachable from the crate root, so a new
module is formatted once it is declared, not before.

## Before pushing

CI runs exactly these, and no more:

```
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --target wasm32-unknown-unknown --release
```

The wasm build is not optional. A host `cargo test` cannot catch a feature gap
that only bites on wasm — `OsRng` sitting behind `rand_core/getrandom` was
exactly that, with a dev-dependency quietly supplying the feature so the suite
passed against a broken wasm build.

## Scope

This crate marshals JSON across the wasm boundary and delegates every
cryptographic operation to `frost-secp256k1-tr`. It derives no challenges, sums
no nonces, evaluates no polynomial and implements no field arithmetic.

**One deliberate exception**, in `redistribute_finalize`: combining a set of
dealers' contributions means weighting scalars and group elements by Lagrange
coefficients, and no upstream function does that for a roster that changes.
Every piece of it still comes from `frost-core`'s `internals` surface —
`compute_lagrange_coefficient`, VSS evaluation via
`VerifyingShare::from_commitment`, and the `Field`/`Group` traits. What this
crate contributes is the summation, not the arithmetic.

That exception is the boundary, not an opening. Patches adding hand-written
cryptography, or hand-written parsers for cryptographic input, will be turned
down. The hex decoder this repo shipped briefly is the cautionary example:
`u8::from_str_radix` accepts a sign, so `"+f"` parsed as a byte.
