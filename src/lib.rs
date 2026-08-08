//! Minimal FROST distributed key generation for Bitcoin taproot vaults.
//!
//! Three functions, one per DKG round. Everything cryptographic is delegated to
//! `frost-secp256k1-tr` (Zcash Foundation's RFC 9591 implementation, BIP-340/341
//! variant). This crate only marshals JSON across the wasm boundary — it derives
//! no challenges, sums no nonces and touches no scalars.
//!
//! Participants are plain `u16` ids, so nothing here depends on how the round
//! packages are delivered. Transport is somebody else's problem.

use std::collections::BTreeMap;

use frost::Identifier;
use frost_secp256k1_tr as frost;
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use wasm_bindgen::prelude::*;

type Packages<T> = BTreeMap<u16, T>;

/// Round 1 output. `secret` is held by the participant and fed back into
/// round 2; `package` is broadcast to everyone.
#[derive(Serialize, Deserialize)]
pub struct Round1 {
    pub secret: frost::keys::dkg::round1::SecretPackage,
    pub package: frost::keys::dkg::round1::Package,
}

/// Round 2 output. Each entry in `packages` is addressed to one recipient and
/// must reach it over a confidential channel.
#[derive(Serialize, Deserialize)]
pub struct Round2 {
    pub secret: frost::keys::dkg::round2::SecretPackage,
    pub packages: Packages<frost::keys::dkg::round2::Package>,
}

/// Final DKG output. `group_key` is the x-only taproot internal key, hex-encoded.
#[derive(Serialize, Deserialize)]
pub struct Finalized {
    pub key_package: frost::keys::KeyPackage,
    pub public_key_package: frost::keys::PublicKeyPackage,
    pub group_key: String,
}

// ── Entropy ─────────────────────────────────────────────────────────────────

/// Build the RNG for one operation from the OS source, optionally strengthened
/// with caller-supplied physical entropy (dice, a hardware RNG, a second
/// device).
///
/// `seed = SHA-512(os_entropy ‖ extra)[..32]`, and **the OS draw is always
/// included** — bad extra entropy cannot weaken the result, good extra entropy
/// rescues a compromised OS source. See the README for why replacing the OS
/// draw rather than adding to it would be worse.
fn rng(extra: Option<String>) -> Result<ChaCha20Rng, String> {
    let mut os = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut os)
        .map_err(|e| format!("OS entropy unavailable: {e}"))?;

    // Catches a stubbed or misrouted source, not statistical bias — no cheap
    // check detects that. The point is that it fails loudly rather than
    // quietly producing keys.
    if os == [0u8; 32] || os.iter().all(|&b| b == os[0]) {
        return Err("OS entropy returned a constant — refusing to generate keys".into());
    }

    let mut h = Sha512::new();
    h.update(os);
    if let Some(extra) = extra {
        h.update(unhex(&extra)?);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&h.finalize()[..32]);
    Ok(ChaCha20Rng::from_seed(seed))
}

fn ident(n: u16) -> Result<Identifier, String> {
    Identifier::try_from(n).map_err(|e| format!("bad participant id {n}: {e}"))
}

/// Inverse of [`ident`]. An `Identifier` is the participant number as a
/// big-endian scalar, so the number is the low two bytes and everything above
/// them must be zero.
fn unident(id: &Identifier) -> Result<u16, String> {
    let b = id.serialize();
    let (high, low) = b.split_at(b.len() - 2);
    if high.iter().any(|&x| x != 0) {
        return Err("participant id outside u16".into());
    }
    Ok(u16::from_be_bytes([low[0], low[1]]))
}

fn keyed<T>(m: BTreeMap<Identifier, T>) -> Result<Packages<T>, String> {
    m.into_iter().map(|(k, v)| Ok((unident(&k)?, v))).collect()
}

fn unkeyed<T>(m: Packages<T>) -> Result<BTreeMap<Identifier, T>, String> {
    m.into_iter().map(|(n, v)| Ok((ident(n)?, v))).collect()
}

fn from_json<T: for<'de> Deserialize<'de>>(s: &str, what: &str) -> Result<T, String> {
    serde_json::from_str(s).map_err(|e| format!("bad {what}: {e}"))
}

fn to_json<T: Serialize>(v: &T) -> Result<String, String> {
    serde_json::to_string(v).map_err(|e| e.to_string())
}

/// Round 1: commit to a random polynomial and prove possession of its constant
/// term. Broadcast `package`; keep `secret`.
#[wasm_bindgen]
pub fn dkg_round1(
    participant: u16,
    threshold: u16,
    total: u16,
    extra_entropy: Option<String>,
) -> Result<String, String> {
    let (secret, package) =
        frost::keys::dkg::part1(ident(participant)?, total, threshold, rng(extra_entropy)?)
            .map_err(|e| format!("dkg round1: {e}"))?;
    to_json(&Round1 { secret, package })
}

/// Round 2: verify everyone's round-1 commitments and produce one secret share
/// per other participant. `round1` maps participant id → round-1 package, and
/// must NOT contain this participant's own.
#[wasm_bindgen]
pub fn dkg_round2(secret: &str, round1: &str) -> Result<String, String> {
    let secret: frost::keys::dkg::round1::SecretPackage = from_json(secret, "round1 secret")?;
    let received: Packages<frost::keys::dkg::round1::Package> =
        from_json(round1, "round1 packages")?;
    let (secret, packages) = frost::keys::dkg::part2(secret, &unkeyed(received)?)
        .map_err(|e| format!("dkg round2: {e}"))?;
    to_json(&Round2 {
        secret,
        packages: keyed(packages)?,
    })
}

/// Round 3: verify the shares addressed to this participant and derive the long
/// -term key package. Fails if any dealer sent an inconsistent share, which is
/// what makes the result trustworthy without a trusted dealer.
#[wasm_bindgen]
pub fn dkg_finalize(secret: &str, round1: &str, round2: &str) -> Result<String, String> {
    let secret: frost::keys::dkg::round2::SecretPackage = from_json(secret, "round2 secret")?;
    let r1: Packages<frost::keys::dkg::round1::Package> = from_json(round1, "round1 packages")?;
    let r2: Packages<frost::keys::dkg::round2::Package> = from_json(round2, "round2 packages")?;

    let (key_package, public_key_package) =
        frost::keys::dkg::part3(&secret, &unkeyed(r1)?, &unkeyed(r2)?)
            .map_err(|e| format!("dkg finalize: {e}"))?;

    let group_key = hex::encode(
        &public_key_package
            .verifying_key()
            .serialize()
            .map_err(|e| format!("group key: {e}"))?,
    );
    to_json(&Finalized {
        key_package,
        public_key_package,
        group_key,
    })
}

// ── Signing ─────────────────────────────────────────────────────────────────

/// Signing round 1 output. `nonces` never leaves the participant and is
/// single-use; `commitments` is published.
#[derive(Serialize, Deserialize)]
pub struct SignNonce {
    pub nonces: frost::round1::SigningNonces,
    pub commitments: frost::round1::SigningCommitments,
}

/// Both signers and the aggregator must build the identical package, or
/// aggregation fails. Keeping it in one function is what guarantees that.
fn signing_package(commitments: &str, message: &str) -> Result<frost::SigningPackage, String> {
    let c: Packages<frost::round1::SigningCommitments> = from_json(commitments, "commitments")?;
    Ok(frost::SigningPackage::new(unkeyed(c)?, &unhex(message)?))
}

/// Hex merkle root for the BIP-341 tweak. `Some(hex)` commits to a script
/// tree; `None` and `Some("")` are **the same thing** — the key-path-only
/// tweak `H_TapTweak(P)`, since hashing an empty root is a no-op upstream.
///
/// There is no "untweaked" option here: `sign_share` and `sign_aggregate`
/// always tweak. That is deliberate — an untweaked FROST signature does not
/// verify against a taproot output key, so offering it would only invite
/// producing signatures no Bitcoin node accepts.
fn merkle_root(root: Option<String>) -> Result<Option<Vec<u8>>, String> {
    root.map(|r| unhex(&r)).transpose()
}

/// Signing round 1: derive a single-use nonce pair. FROST is only safe if each
/// nonce signs at most one message, so callers must discard `nonces` after one
/// `sign_share` — reuse across two digests leaks the signing share outright.
#[wasm_bindgen]
pub fn sign_nonce(key_package: &str, extra_entropy: Option<String>) -> Result<String, String> {
    let kp: frost::keys::KeyPackage = from_json(key_package, "key package")?;
    let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut rng(extra_entropy)?);
    to_json(&SignNonce {
        nonces,
        commitments,
    })
}

/// Signing round 2: produce this participant's signature share over `message`
/// (hex) given every signer's round-1 commitments.
///
/// `merkle_root_hex` MUST match what the aggregator passes to
/// [`sign_aggregate`]. The tweak is applied to the key package before signing,
/// so a signer that omits it produces a share the aggregator rejects with
/// "Invalid signature share" — a mismatch the type system cannot catch, since
/// both sides compile happily.
#[wasm_bindgen]
pub fn sign_share(
    key_package: &str,
    nonces: &str,
    commitments: &str,
    message: &str,
    merkle_root_hex: Option<String>,
) -> Result<String, String> {
    let kp: frost::keys::KeyPackage = from_json(key_package, "key package")?;
    let n: frost::round1::SigningNonces = from_json(nonces, "nonces")?;
    let root = merkle_root(merkle_root_hex)?;

    let share = frost::round2::sign_with_tweak(
        &signing_package(commitments, message)?,
        &n,
        &kp,
        root.as_deref(),
    )
    .map_err(|e| format!("sign share: {e}"))?;
    to_json(&share)
}

/// Verify every share and aggregate into one BIP-340 signature, applying the
/// BIP-341 tweak. Aggregation is verifying: a share that does not check out
/// fails here rather than producing an invalid signature.
#[wasm_bindgen]
pub fn sign_aggregate(
    commitments: &str,
    shares: &str,
    public_key_package: &str,
    message: &str,
    merkle_root_hex: Option<String>,
) -> Result<String, String> {
    let shares: Packages<frost::round2::SignatureShare> = from_json(shares, "signature shares")?;
    let pubkeys: frost::keys::PublicKeyPackage = from_json(public_key_package, "public keys")?;
    let root = merkle_root(merkle_root_hex)?;

    let sig = frost::aggregate_with_tweak(
        &signing_package(commitments, message)?,
        &unkeyed(shares)?,
        &pubkeys,
        root.as_deref(),
    )
    .map_err(|e| format!("aggregate: {e}"))?;

    Ok(hex::encode(
        sig.serialize().map_err(|e| format!("signature: {e}"))?,
    ))
}

fn unhex(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| format!("bad hex: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MSG: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn kp(k: &Finalized) -> String {
        serde_json::to_string(&k.key_package).unwrap()
    }

    /// Runs a full DKG through the same JSON boundary the wasm callers use and
    /// returns one `Finalized` per participant, in `ids` order.
    fn run_dkg(ids: &[u16], threshold: u16) -> Vec<Finalized> {
        let total = ids.len() as u16;

        // Round 1 — everyone commits.
        let r1: Vec<Round1> = ids
            .iter()
            .map(|&i| {
                serde_json::from_str(&dkg_round1(i, threshold, total, None).unwrap()).unwrap()
            })
            .collect();

        // Round 2 — each participant sees the others' round-1 packages.
        let r2: Vec<Round2> = ids
            .iter()
            .enumerate()
            .map(|(k, _)| {
                let others: Packages<_> = ids
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != k)
                    .map(|(j, &id)| (id, r1[j].package.clone()))
                    .collect();
                let secret = serde_json::to_string(&r1[k].secret).unwrap();
                serde_json::from_str(
                    &dkg_round2(&secret, &serde_json::to_string(&others).unwrap()).unwrap(),
                )
                .unwrap()
            })
            .collect();

        // Round 3 — each participant collects the shares addressed to it.
        ids.iter()
            .enumerate()
            .map(|(k, &me)| {
                let r1_others: Packages<_> = ids
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != k)
                    .map(|(j, &id)| (id, r1[j].package.clone()))
                    .collect();
                let r2_mine: Packages<_> = ids
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != k)
                    .map(|(j, &id)| (id, r2[j].packages[&me].clone()))
                    .collect();
                let secret = serde_json::to_string(&r2[k].secret).unwrap();
                serde_json::from_str(
                    &dkg_finalize(
                        &secret,
                        &serde_json::to_string(&r1_others).unwrap(),
                        &serde_json::to_string(&r2_mine).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap()
            })
            .collect()
    }

    /// Signing round 1 for a set of signers. Returns their nonces alongside the
    /// commitments JSON, which signers and aggregator must both use verbatim.
    fn commit(signers: &[(u16, &Finalized)]) -> (Vec<SignNonce>, String) {
        let nonces: Vec<SignNonce> = signers
            .iter()
            .map(|(_, k)| serde_json::from_str(&sign_nonce(&kp(k), None).unwrap()).unwrap())
            .collect();
        let commitments: Packages<_> = signers
            .iter()
            .zip(&nonces)
            .map(|((id, _), n)| (*id, n.commitments))
            .collect();
        (nonces, serde_json::to_string(&commitments).unwrap())
    }

    /// Signing round 2 for every signer, under one merkle root.
    fn shares(
        signers: &[(u16, &Finalized)],
        nonces: &[SignNonce],
        commitments: &str,
        root: Option<String>,
    ) -> String {
        let m: Packages<frost::round2::SignatureShare> = signers
            .iter()
            .zip(nonces)
            .map(|((id, k), n)| {
                let n = serde_json::to_string(&n.nonces).unwrap();
                let s = sign_share(&kp(k), &n, commitments, MSG, root.clone()).unwrap();
                (*id, serde_json::from_str(&s).unwrap())
            })
            .collect();
        serde_json::to_string(&m).unwrap()
    }

    #[test]
    fn dkg_2_of_3_agrees_on_one_group_key() {
        let keys = run_dkg(&[1, 2, 3], 2);

        assert_eq!(keys[0].group_key, keys[1].group_key);
        assert_eq!(keys[1].group_key, keys[2].group_key);
        assert_eq!(keys[0].group_key.len(), 66, "33-byte compressed point");
    }

    /// The hand-rolled decoder this replaced had two bugs the `hex` crate does
    /// not: `u8::from_str_radix` accepts a sign, so "+f" parsed as 0x0f, and
    /// `&s[i..i + 2]` panics when it lands inside a multi-byte char.
    #[test]
    fn malformed_hex_is_rejected() {
        for bad in ["+f+f", "€a", "abc", "zz", " f"] {
            assert!(unhex(bad).is_err(), "accepted {bad:?}");
        }
    }

    /// Pins the assumption `unident` makes about upstream's scalar encoding.
    /// If frost ever changes it, round-2 packages would be misaddressed.
    #[test]
    fn participant_ids_round_trip() {
        for n in [1u16, 2, 255, 256, u16::MAX] {
            assert_eq!(unident(&ident(n).unwrap()).unwrap(), n);
        }
    }

    /// The safety property of the mixing rule: caller entropy is folded in ON
    /// TOP of the OS draw, never instead of it. The same `extra` twice must
    /// still produce different keys — otherwise a caller with a fixed
    /// "physical" seed would silently make every vault identical.
    #[test]
    fn caller_entropy_cannot_make_output_deterministic() {
        let fixed = Some("de".repeat(32));
        let a = dkg_round1(1, 2, 3, fixed.clone()).unwrap();
        let b = dkg_round1(1, 2, 3, fixed).unwrap();
        assert_ne!(a, b, "OS entropy must always be mixed in");
    }

    /// And the converse: a parameter accepted and ignored looks identical from
    /// outside, which is exactly how entropy bugs survive for years.
    #[test]
    fn caller_entropy_reaches_the_rng() {
        let mut x = rng(Some("00".into())).unwrap();
        let mut y = rng(Some("01".into())).unwrap();
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        x.fill_bytes(&mut a);
        y.fill_bytes(&mut b);
        assert_ne!(a, b);
    }

    /// The assertion that matters: two of three sign, and the aggregate
    /// verifies against the BIP-341-tweaked output key. A signature that
    /// aggregates but does not verify is the failure worth catching.
    #[test]
    fn two_of_three_produces_a_verifying_signature() {
        use frost::keys::Tweak;

        let keys = run_dkg(&[1, 2, 3], 2);
        let signers = [(1u16, &keys[0]), (2u16, &keys[1])];
        // Empty merkle root = BIP-341 key-path-only spend. Both sides use it.
        let root = Some(String::new());

        let (nonces, commitments) = commit(&signers);
        let sig = sign_aggregate(
            &commitments,
            &shares(&signers, &nonces, &commitments, root.clone()),
            &serde_json::to_string(&keys[0].public_key_package).unwrap(),
            MSG,
            root,
        )
        .unwrap();

        let tweaked = keys[0]
            .public_key_package
            .clone()
            .tweak(Some(Vec::<u8>::new()));
        tweaked
            .verifying_key()
            .verify(
                &unhex(MSG).unwrap(),
                &frost::Signature::deserialize(&unhex(&sig).unwrap()).unwrap(),
            )
            .expect("aggregate must verify against the tweaked output key");
    }

    /// Signer and aggregator must commit to the same script tree. Nothing in
    /// the types enforces it and the failure surfaces only at aggregation.
    ///
    /// Note `None` and `Some("")` are NOT a mismatch — upstream hashes an empty
    /// root as a no-op, so both mean the key-path-only tweak. Hence a genuinely
    /// different root here.
    #[test]
    fn tweak_must_match_on_both_sides() {
        let keys = run_dkg(&[1, 2, 3], 2);
        let signers = [(1u16, &keys[0]), (2u16, &keys[1])];

        let (nonces, commitments) = commit(&signers);
        let err = sign_aggregate(
            &commitments,
            &shares(&signers, &nonces, &commitments, Some("ff".repeat(32))),
            &serde_json::to_string(&keys[0].public_key_package).unwrap(),
            MSG,
            Some(String::new()),
        )
        .expect_err("mismatched merkle root must not produce a signature");
        assert!(err.contains("Invalid signature share"), "got: {err}");
    }
}
