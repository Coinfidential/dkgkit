//! Minimal FROST distributed key generation for Bitcoin taproot vaults.
//!
//! Three functions, one per DKG round. Everything cryptographic is delegated to
//! `frost-secp256k1-tr` (Zcash Foundation's RFC 9591 implementation, BIP-340/341
//! variant). This crate only marshals JSON across the wasm boundary — it derives
//! no challenges, sums no nonces, evaluates no polynomial and implements no
//! field arithmetic.
//!
//! [`redistribute_finalize`] is the one place that combines scalars and group
//! elements, because handing a vault to a different roster means weighting each
//! dealer's contribution by its Lagrange coefficient and no upstream function
//! does that. The coefficients, the VSS evaluation and the arithmetic itself
//! are all still frost-core's; only the summation is here.
//!
//! Participants are plain `u16` ids, so nothing here depends on how the round
//! packages are delivered. Transport is somebody else's problem.

use std::collections::{BTreeMap, BTreeSet};

use frost::Identifier;
use frost_core::compute_lagrange_coefficient;
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

// ── Resharing ───────────────────────────────────────────────────────────────

// Rounds 1 and 2 reuse `Round1`/`Round2`: upstream models resharing as a DKG
// over a zero-valued secret, so the packages are the same types. Only
// finalisation differs, because it folds the result into the existing key.

/// Reshare round 1. `total` is the size of the NEW roster; `threshold` must
/// stay what it is today — see [`reshare_finalize`].
#[wasm_bindgen]
pub fn reshare_round1(
    participant: u16,
    threshold: u16,
    total: u16,
    extra_entropy: Option<String>,
) -> Result<String, String> {
    let (secret, package) = frost::keys::refresh::refresh_dkg_part1(
        ident(participant)?,
        total,
        threshold,
        rng(extra_entropy)?,
    )
    .map_err(|e| format!("reshare round1: {e}"))?;
    to_json(&Round1 { secret, package })
}

/// Reshare round 2. Same shape as [`dkg_round2`]: `round1` must hold every
/// other participant's package and not this participant's own.
#[wasm_bindgen]
pub fn reshare_round2(secret: &str, round1: &str) -> Result<String, String> {
    let secret: frost::keys::dkg::round1::SecretPackage = from_json(secret, "round1 secret")?;
    let received: Packages<frost::keys::dkg::round1::Package> =
        from_json(round1, "round1 packages")?;
    let (secret, packages) = frost::keys::refresh::refresh_dkg_part2(secret, &unkeyed(received)?)
        .map_err(|e| format!("reshare round2: {e}"))?;
    to_json(&Round2 {
        secret,
        packages: keyed(packages)?,
    })
}

/// Reshare round 3: fold the refreshing shares into the existing key.
///
/// The group key and therefore the vault address are unchanged — that is the
/// point. What changes is who holds a share.
///
/// **The threshold cannot change.** Upstream rejects a differing `min_signers`
/// outright, so a t-of-n vault stays t-of-n across a reshare; only the roster
/// and its size move. Changing `t` needs a fresh DKG and a new address.
#[wasm_bindgen]
pub fn reshare_finalize(
    secret: &str,
    round1: &str,
    round2: &str,
    old_key_package: &str,
    old_public_key_package: &str,
) -> Result<String, String> {
    let secret: frost::keys::dkg::round2::SecretPackage = from_json(secret, "round2 secret")?;
    let r1: Packages<frost::keys::dkg::round1::Package> = from_json(round1, "round1 packages")?;
    let r2: Packages<frost::keys::dkg::round2::Package> = from_json(round2, "round2 packages")?;
    let old_kp: frost::keys::KeyPackage = from_json(old_key_package, "old key package")?;
    let old_pkp: frost::keys::PublicKeyPackage =
        from_json(old_public_key_package, "old public keys")?;

    let (key_package, public_key_package) = frost::keys::refresh::refresh_dkg_shares(
        &secret,
        &unkeyed(r1)?,
        &unkeyed(r2)?,
        old_pkp,
        old_kp,
    )
    .map_err(|e| format!("reshare finalize: {e}"))?;

    let group_key = hex::encode(
        public_key_package
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

// ── Redistribution ──────────────────────────────────────────────────────────
//
// `reshare_*` above cannot add a member and cannot move the threshold, because
// upstream's `refresh_dkg_shares` folds the refreshing packages into an
// EXISTING key package — a participant who holds none cannot finalise — and it
// compares `min_signers` against that package and refuses a change.
//
// Redistribution lifts both limits. Each dealer re-splits its OWN share f(i) on
// a fresh polynomial across the NEW roster at the NEW threshold; each recipient
// sums the sub-shares it receives, weighted by each dealer's Lagrange
// coefficient over the dealer set. Because Σ λᵢ·f(i) = f(0) for any authorised
// dealer set, the new shares lie on a fresh degree-(t_new−1) polynomial through
// the SAME secret: the group key, the taproot output key and therefore the
// vault address and its UTXOs are all unchanged, and no party ever reconstructs
// f(0).
//
// A recipient needs no prior key package. That is what makes adding a member
// possible.
//
// Every scalar and group operation below comes from frost-core's own
// `internals` surface — `compute_lagrange_coefficient`, VSS evaluation via
// `VerifyingShare::from_commitment`, and the `Field`/`Group` traits. This crate
// still derives no challenges, evaluates no polynomial by hand and writes no
// field arithmetic.

type Ctx = frost::Secp256K1Sha256TR;
type Group_ = <Ctx as frost_core::Ciphersuite>::Group;
type Field_ = <Group_ as frost_core::Group>::Field;
type Scalar_ = frost_core::Scalar<Ctx>;
type Element_ = frost_core::Element<Ctx>;

fn zero() -> Scalar_ {
    <Field_ as frost_core::Field>::zero()
}

fn identity() -> Element_ {
    <Group_ as frost_core::Group>::identity()
}

fn generator() -> Element_ {
    <Group_ as frost_core::Group>::generator()
}

/// One dealer's contribution: a fresh Shamir split of that dealer's own share,
/// addressed to the new roster.
///
/// `shares` is keyed by NEW participant id and each entry is secret to its
/// recipient — the transport must deliver them pairwise, exactly like round-2
/// DKG packages. The commitment travelling inside each share is public and is
/// identical across all of them.
#[derive(Serialize, Deserialize)]
pub struct Deal {
    /// The dealer's participant id in the OLD roster.
    pub dealer: u16,
    pub shares: Packages<frost::keys::SecretShare>,
}

/// Parse a roster, rejecting duplicates — a repeated id would otherwise be
/// silently deduplicated and change the effective `n`.
fn roster(json: &str, what: &str) -> Result<Vec<Identifier>, String> {
    let ids: Vec<u16> = from_json(json, what)?;
    let idents: Vec<Identifier> = ids.iter().map(|&n| ident(n)).collect::<Result<_, _>>()?;
    if idents.iter().collect::<BTreeSet<_>>().len() != idents.len() {
        return Err(format!("duplicate participant in {what}"));
    }
    Ok(idents)
}

/// Redistribution, dealer half. Re-split this participant's own share across
/// `new_participants` at `new_threshold`.
///
/// Any `t` holders of a current share can act as dealers; a departing member
/// need not take part, which is what makes this a recovery path for a lost
/// device. Members being ADDED are recipients only and supply nothing here.
#[wasm_bindgen]
pub fn redistribute_deal(
    old_key_package: &str,
    new_participants: &str,
    new_threshold: u16,
    extra_entropy: Option<String>,
) -> Result<String, String> {
    let kp: frost::keys::KeyPackage = from_json(old_key_package, "old key package")?;
    let new_idents = roster(new_participants, "new roster")?;

    if (new_threshold as usize) > new_idents.len() {
        return Err(format!(
            "threshold {new_threshold} exceeds the new roster size {}",
            new_idents.len()
        ));
    }

    // The dealer's share becomes the constant term of its fresh polynomial.
    // `from_scalar` rejects a zero scalar, which cannot occur for a real share
    // but would silently produce a degenerate split if it did.
    let secret = frost::SigningKey::from_scalar(kp.signing_share().to_scalar())
        .map_err(|e| format!("share is not a usable scalar: {e}"))?;

    let (shares, _) = frost::keys::split(
        &secret,
        new_idents.len() as u16,
        new_threshold,
        frost::keys::IdentifierList::Custom(&new_idents),
        &mut rng(extra_entropy)?,
    )
    .map_err(|e| format!("redistribute deal: {e}"))?;

    to_json(&Deal {
        dealer: unident(kp.identifier())?,
        shares: keyed(shares)?,
    })
}

/// Redistribution, recipient half. Combine the sub-shares addressed to this
/// participant into a share of the unchanged group key.
///
/// `deals` maps DEALER id → the [`frost::keys::SecretShare`] that dealer
/// addressed to `participant`.
///
/// Three things are checked, and all three matter:
///
/// 1. **Feldman/VSS** — each sub-share lies on the polynomial its dealer
///    committed to. Catches a dealer sending one recipient a share off its own
///    curve.
/// 2. **Dealer binding** — each dealer's commitment constant term equals that
///    dealer's verifying share in the OLD public key package. Without this a
///    dealer could re-split *some other* secret and silently move the group
///    key; the Feldman check alone would not notice, because that polynomial is
///    internally consistent.
/// 3. **Group-key invariant** — the dealer set's old verifying shares
///    interpolate to the old verifying key. This is what proves the dealer set
///    is authorised: with fewer than `t_old` dealers the interpolation lands
///    somewhere else, so a sub-threshold group cannot redistribute.
///
/// # Every recipient must combine the SAME dealer set
///
/// The caller decides which dealers to fold in, and that choice is part of the
/// ceremony rather than of this function. Two recipients using different dealer
/// sets get shares on **different** polynomials — both passing through the same
/// secret at zero, so both report the expected `group_key`, and neither can
/// sign with the other.
///
/// Nothing here can detect that: each recipient's own view is internally
/// consistent, and check (3) passes for any authorised set. The failure appears
/// later, as signature shares that will not aggregate — fail-closed, but
/// remote from its cause. `divergent_dealer_sets_produce_incompatible_shares`
/// pins the behaviour so it is discovered here rather than in a vault.
///
/// The ceremony layer owns this: pin the dealer set when the redistribution
/// opens, and hand every recipient the same one.
#[wasm_bindgen]
pub fn redistribute_finalize(
    participant: u16,
    deals: &str,
    old_public_key_package: &str,
    new_threshold: u16,
    new_participants: &str,
) -> Result<String, String> {
    let me = ident(participant)?;
    let received: Packages<frost::keys::SecretShare> = from_json(deals, "deals")?;
    let old_pkp: frost::keys::PublicKeyPackage =
        from_json(old_public_key_package, "old public keys")?;
    let new_idents = roster(new_participants, "new roster")?;

    if received.is_empty() {
        return Err("redistribute: no deals".into());
    }
    if !new_idents.contains(&me) {
        return Err(format!(
            "participant {participant} is not in the new roster"
        ));
    }
    if new_threshold < 2 || (new_threshold as usize) > new_idents.len() {
        return Err(format!(
            "threshold {new_threshold} is outside 2..={}",
            new_idents.len()
        ));
    }

    let dealers: BTreeSet<Identifier> = received
        .keys()
        .map(|&n| ident(n))
        .collect::<Result<_, _>>()?;

    let old_shares = old_pkp.verifying_shares();
    let mut share = zero();
    let mut new_shares: BTreeMap<Identifier, Element_> =
        new_idents.iter().map(|&j| (j, identity())).collect();
    let mut anchor = identity();

    for (&dealer_num, deal) in &received {
        let dealer = ident(dealer_num)?;

        if *deal.identifier() != me {
            return Err(format!(
                "dealer {dealer_num} sent a share addressed to someone else"
            ));
        }
        // A shorter commitment means a lower-degree polynomial, i.e. a vault
        // that reconstructs below the threshold everyone agreed to.
        if deal
            .commitment()
            .serialize()
            .map_err(|e| e.to_string())?
            .len()
            != new_threshold as usize
        {
            return Err(format!("dealer {dealer_num} dealt at the wrong threshold"));
        }

        // (1) Feldman. Also hands back the commitment's constant term.
        let (_, dealt_from) = deal
            .verify()
            .map_err(|e| format!("dealer {dealer_num}: invalid share: {e}"))?;

        // (2) Binding: that constant term must be the dealer's real old share.
        let old = old_shares
            .get(&dealer)
            .ok_or_else(|| format!("dealer {dealer_num} is not in the old roster"))?;
        if dealt_from.to_element() != old.to_element() {
            return Err(format!(
                "dealer {dealer_num} re-split a secret that is not its own share"
            ));
        }

        let lambda = compute_lagrange_coefficient(&dealers, None, dealer)
            .map_err(|e| format!("lagrange for dealer {dealer_num}: {e}"))?;

        share += lambda * deal.signing_share().to_scalar();
        anchor += old.to_element() * lambda;
        for (&j, acc) in new_shares.iter_mut() {
            let phi = frost::keys::VerifyingShare::from_commitment(j, deal.commitment());
            *acc += phi.to_element() * lambda;
        }
    }

    // (3) The dealer set must actually be authorised.
    if anchor != old_pkp.verifying_key().to_element() {
        return Err(
            "redistribute: dealer set does not reconstruct the group key \
                    (fewer than the threshold, or a forged roster)"
                .into(),
        );
    }

    // Belt and braces: the share we just built must match the verifying share
    // derived independently from the commitments.
    if new_shares[&me] != generator() * share {
        return Err("redistribute: derived share disagrees with its commitment".into());
    }

    let signing_share = frost::keys::SigningShare::new(share);
    let verifying_shares: BTreeMap<Identifier, frost::keys::VerifyingShare> = new_shares
        .into_iter()
        .map(|(j, e)| (j, frost::keys::VerifyingShare::new(e)))
        .collect();

    let key_package = frost::keys::KeyPackage::new(
        me,
        signing_share,
        verifying_shares[&me],
        *old_pkp.verifying_key(),
        new_threshold,
    );
    let public_key_package = frost::keys::PublicKeyPackage::new(
        verifying_shares,
        *old_pkp.verifying_key(),
        Some(new_threshold),
    );

    let group_key = hex::encode(
        public_key_package
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
    .map_err(aggregate_error)?;

    Ok(hex::encode(
        sig.serialize().map_err(|e| format!("signature: {e}"))?,
    ))
}

/// Turn an aggregation failure into something a caller can act on.
///
/// RFC 9591 calls this an *identifiable abort*: aggregation verifies every
/// share, so when one does not check out the protocol knows exactly whose it
/// was. Collapsing that to a message throws away the only fact that makes the
/// failure actionable — a griefer who submits a bad share every round is
/// indistinguishable from a flaky network unless you can name them.
///
/// The message stays human-readable and gains a machine-readable tail:
/// `aggregate: <reason> [culprits: 2,3]`. Participants are `u16` here, as
/// everywhere else in this crate, so the caller needs no `Identifier` type.
fn aggregate_error(e: frost::Error) -> String {
    let culprits: Vec<String> = e
        .culprits()
        .iter()
        .filter_map(|id| unident(id).ok())
        .map(|n| n.to_string())
        .collect();

    if culprits.is_empty() {
        format!("aggregate: {e}")
    } else {
        format!("aggregate: {e} [culprits: {}]", culprits.join(","))
    }
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

    /// Reshare rounds 1 and 2 for `ids`. Split out from `run_reshare` so a test
    /// can drive finalisation with deliberately mismatched inputs.
    fn reshare_rounds(ids: &[u16], threshold: u16) -> (Vec<Round1>, Vec<Round2>) {
        let total = ids.len() as u16;
        let r1: Vec<Round1> = ids
            .iter()
            .map(|&i| {
                serde_json::from_str(&reshare_round1(i, threshold, total, None).unwrap()).unwrap()
            })
            .collect();

        let r2 = (0..ids.len())
            .map(|k| {
                let others = others_round1(ids, &r1, k);
                let secret = serde_json::to_string(&r1[k].secret).unwrap();
                serde_json::from_str(
                    &reshare_round2(&secret, &serde_json::to_string(&others).unwrap()).unwrap(),
                )
                .unwrap()
            })
            .collect();
        (r1, r2)
    }

    /// Every round-1 package except participant `k`'s own.
    fn others_round1(
        ids: &[u16],
        r1: &[Round1],
        k: usize,
    ) -> Packages<frost::keys::dkg::round1::Package> {
        ids.iter()
            .enumerate()
            .filter(|(j, _)| *j != k)
            .map(|(j, &id)| (id, r1[j].package.clone()))
            .collect()
    }

    /// The round-2 packages addressed to participant `me`.
    fn round2_for(
        ids: &[u16],
        r2: &[Round2],
        k: usize,
        me: u16,
    ) -> Packages<frost::keys::dkg::round2::Package> {
        ids.iter()
            .enumerate()
            .filter(|(j, _)| *j != k)
            .map(|(j, &id)| (id, r2[j].packages[&me].clone()))
            .collect()
    }

    /// One reshare round over `ids`, returning each participant's new keys.
    fn run_reshare(ids: &[u16], threshold: u16, old: &[Finalized]) -> Vec<Finalized> {
        let (r1, r2) = reshare_rounds(ids, threshold);
        ids.iter()
            .enumerate()
            .map(|(k, &me)| {
                serde_json::from_str(
                    &reshare_finalize(
                        &serde_json::to_string(&r2[k].secret).unwrap(),
                        &serde_json::to_string(&others_round1(ids, &r1, k)).unwrap(),
                        &serde_json::to_string(&round2_for(ids, &r2, k, me)).unwrap(),
                        &kp(&old[k]),
                        &serde_json::to_string(&old[k].public_key_package).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap()
            })
            .collect()
    }

    /// Sign with `signers` and verify the aggregate against the BIP-341-tweaked
    /// output key. A roster that cannot do this is not a working vault, whatever
    /// its group key says.
    fn sign_and_verify(signers: &[(u16, &Finalized)]) {
        use frost::keys::Tweak;
        let root = Some(String::new());

        let (nonces, commitments) = commit(signers);
        let sig = sign_aggregate(
            &commitments,
            &shares(signers, &nonces, &commitments, root.clone()),
            &serde_json::to_string(&signers[0].1.public_key_package).unwrap(),
            MSG,
            root,
        )
        .unwrap();

        signers[0]
            .1
            .public_key_package
            .clone()
            .tweak(Some(Vec::<u8>::new()))
            .verifying_key()
            .verify(
                &unhex(MSG).unwrap(),
                &frost::Signature::deserialize(&unhex(&sig).unwrap()).unwrap(),
            )
            .expect("signature must verify against the tweaked output key");
    }

    /// Every dealer's deal, at `new_t` over `new_ids`.
    fn deals_from(dealers: &[(u16, &Finalized)], new_ids: &[u16], new_t: u16) -> Vec<Deal> {
        let new_json = serde_json::to_string(new_ids).unwrap();
        dealers
            .iter()
            .map(|(_, k)| {
                serde_json::from_str(&redistribute_deal(&kp(k), &new_json, new_t, None).unwrap())
                    .unwrap()
            })
            .collect()
    }

    /// The sub-shares addressed to `me`, keyed by dealer.
    fn deals_for(deals: &[Deal], me: u16) -> String {
        let mine: Packages<frost::keys::SecretShare> = deals
            .iter()
            .map(|d| (d.dealer, d.shares[&me].clone()))
            .collect();
        serde_json::to_string(&mine).unwrap()
    }

    /// One redistribution: `dealers` (any authorised subset of the old roster)
    /// hand the vault to `new_ids` at threshold `new_t`.
    fn run_redistribute(
        dealers: &[(u16, &Finalized)],
        old_pkp: &Finalized,
        new_ids: &[u16],
        new_t: u16,
    ) -> Vec<Finalized> {
        let deals = deals_from(dealers, new_ids, new_t);
        let new_json = serde_json::to_string(new_ids).unwrap();
        let pkp = serde_json::to_string(&old_pkp.public_key_package).unwrap();

        new_ids
            .iter()
            .map(|&me| {
                serde_json::from_str(
                    &redistribute_finalize(me, &deals_for(&deals, me), &pkp, new_t, &new_json)
                        .unwrap(),
                )
                .unwrap()
            })
            .collect()
    }

    /// **Adding a member** — the case upstream's `refresh` cannot do, and the
    /// reason this code exists. The vault address is untouched, so the funds
    /// never move, and the newcomer can sign.
    #[test]
    fn redistribution_can_add_a_member() {
        let old = run_dkg(&[1, 2, 3], 2);
        let new = run_redistribute(&[(1, &old[0]), (2, &old[1])], &old[0], &[1, 2, 3, 4], 2);

        for (k, n) in new.iter().enumerate() {
            assert_eq!(n.group_key, old[0].group_key, "participant {k}");
        }
        // The newcomer (id 4) held no share before and can sign now.
        sign_and_verify(&[(3, &new[2]), (4, &new[3])]);
    }

    /// **Changing the threshold** — the other thing upstream refuses. 2-of-3
    /// becomes 3-of-4 under the same group key.
    #[test]
    fn redistribution_can_change_the_threshold() {
        let old = run_dkg(&[1, 2, 3], 2);
        let new = run_redistribute(&[(1, &old[0]), (2, &old[1])], &old[0], &[1, 2, 3, 4], 3);

        assert_eq!(new[0].group_key, old[0].group_key);
        sign_and_verify(&[(1, &new[0]), (2, &new[1]), (4, &new[3])]);
    }

    /// **Replacing a device.** Member 3 lost theirs and returns as id 4. They
    /// cannot help — and are not needed.
    #[test]
    fn redistribution_can_replace_a_lost_device() {
        let old = run_dkg(&[1, 2, 3], 2);
        let new = run_redistribute(&[(1, &old[0]), (2, &old[1])], &old[0], &[1, 2, 4], 2);

        assert_eq!(new[0].group_key, old[0].group_key);
        assert_eq!(new[2].group_key, old[0].group_key);
        sign_and_verify(&[(1, &new[0]), (4, &new[2])]);
    }

    /// **Removing a member**, with only the survivors dealing.
    #[test]
    fn redistribution_can_remove_a_member() {
        let old = run_dkg(&[1, 2, 3], 2);
        let new = run_redistribute(&[(1, &old[0]), (2, &old[1])], &old[0], &[1, 2], 2);

        assert_eq!(new[0].group_key, old[0].group_key);
        sign_and_verify(&[(1, &new[0]), (2, &new[1])]);
    }

    /// Exactly `t` dealers is enough. Requiring more would mean a vault whose
    /// own threshold cannot authorise a roster change.
    #[test]
    fn t_dealers_suffice() {
        let old = run_dkg(&[1, 2, 3, 4, 5], 3);
        let new = run_redistribute(
            &[(1, &old[0]), (2, &old[1]), (3, &old[2])],
            &old[0],
            &[1, 2, 3, 4, 5, 6],
            3,
        );
        assert_eq!(new[5].group_key, old[0].group_key);
        sign_and_verify(&[(4, &new[3]), (5, &new[4]), (6, &new[5])]);
    }

    /// And below `t` it must fail. A sub-threshold group redistributing at will
    /// would be a complete break: two of five could deal themselves a vault.
    #[test]
    fn sub_threshold_dealers_are_refused() {
        let old = run_dkg(&[1, 2, 3], 2);
        let deals = deals_from(&[(1, &old[0])], &[1, 2, 3], 2);

        let err = redistribute_finalize(
            1,
            &deals_for(&deals, 1),
            &serde_json::to_string(&old[0].public_key_package).unwrap(),
            2,
            "[1,2,3]",
        )
        .expect_err("one dealer must not be able to redistribute a 2-of-3");
        assert!(
            err.contains("does not reconstruct the group key"),
            "got: {err}"
        );
    }

    /// A dealer re-splitting something other than its own share. The Feldman
    /// check passes — the polynomial is internally consistent — so only the
    /// binding to the old public key package catches this.
    #[test]
    fn a_dealer_resplitting_a_foreign_secret_is_refused() {
        let old = run_dkg(&[1, 2, 3], 2);
        let other = run_dkg(&[1, 2, 3], 2); // a different vault entirely

        let deals = deals_from(&[(1, &old[0]), (2, &other[1])], &[1, 2, 3], 2);
        let err = redistribute_finalize(
            1,
            &deals_for(&deals, 1),
            &serde_json::to_string(&old[0].public_key_package).unwrap(),
            2,
            "[1,2,3]",
        )
        .expect_err("a foreign secret must not be dealt into this vault");
        assert!(err.contains("not its own share"), "got: {err}");
    }

    /// A dealer sending one recipient a share off its own committed curve.
    /// This is the Feldman check doing its job.
    #[test]
    fn a_tampered_sub_share_is_refused() {
        let old = run_dkg(&[1, 2, 3], 2);
        let deals = deals_from(&[(1, &old[0]), (2, &old[1])], &[1, 2, 3], 2);

        // Dealer 2 swaps in the share it meant for participant 3.
        let mut mine: Packages<frost::keys::SecretShare> = deals
            .iter()
            .map(|d| (d.dealer, d.shares[&1].clone()))
            .collect();
        let wrong = deals[1].shares[&3].clone();
        mine.insert(
            2,
            frost::keys::SecretShare::new(
                ident(1).unwrap(),
                *wrong.signing_share(),
                wrong.commitment().clone(),
            ),
        );

        let err = redistribute_finalize(
            1,
            &serde_json::to_string(&mine).unwrap(),
            &serde_json::to_string(&old[0].public_key_package).unwrap(),
            2,
            "[1,2,3]",
        )
        .expect_err("a share off the committed polynomial must be refused");
        assert!(err.contains("invalid share"), "got: {err}");
    }

    /// A dealer quietly dealing at a lower threshold than everyone agreed to
    /// would leave a vault that reconstructs below its stated `t`.
    #[test]
    fn a_deal_at_the_wrong_threshold_is_refused() {
        let old = run_dkg(&[1, 2, 3], 2);
        let honest = deals_from(&[(1, &old[0])], &[1, 2, 3], 3);
        let cheat = deals_from(&[(2, &old[1])], &[1, 2, 3], 2);

        let mine: Packages<frost::keys::SecretShare> = [
            (honest[0].dealer, honest[0].shares[&1].clone()),
            (cheat[0].dealer, cheat[0].shares[&1].clone()),
        ]
        .into_iter()
        .collect();

        let err = redistribute_finalize(
            1,
            &serde_json::to_string(&mine).unwrap(),
            &serde_json::to_string(&old[0].public_key_package).unwrap(),
            3,
            "[1,2,3]",
        )
        .expect_err("a lower-degree deal must be refused");
        assert!(err.contains("wrong threshold"), "got: {err}");
    }

    /// Handing a participant a share addressed to somebody else.
    #[test]
    fn a_share_addressed_elsewhere_is_refused() {
        let old = run_dkg(&[1, 2, 3], 2);
        let deals = deals_from(&[(1, &old[0]), (2, &old[1])], &[1, 2, 3], 2);

        let err = redistribute_finalize(
            1,
            &deals_for(&deals, 2), // participant 2's shares, handed to 1
            &serde_json::to_string(&old[0].public_key_package).unwrap(),
            2,
            "[1,2,3]",
        )
        .expect_err("a misaddressed share must be refused");
        assert!(err.contains("addressed to someone else"), "got: {err}");
    }

    /// A roster with a repeated id would silently shrink `n` — the caller would
    /// believe it built a 2-of-4 and have a 2-of-3.
    #[test]
    fn a_duplicated_roster_entry_is_refused() {
        let old = run_dkg(&[1, 2, 3], 2);
        let err = redistribute_deal(&kp(&old[0]), "[1,2,3,3]", 2, None)
            .expect_err("a duplicate participant must be refused");
        assert!(err.contains("duplicate participant"), "got: {err}");
    }

    /// Two recipients folding in DIFFERENT dealer sets land on different
    /// polynomials. Both pass through the same secret at zero, so both report
    /// the expected `group_key` — and they cannot sign with each other.
    ///
    /// This is the trap worth pinning: **the group-key check does not catch
    /// it.** It is fail-closed (aggregation refuses) rather than a fund risk,
    /// but the failure is remote from its cause, so the ceremony layer has to
    /// pin the dealer set rather than let each recipient pick.
    #[test]
    fn divergent_dealer_sets_produce_incompatible_shares() {
        let old = run_dkg(&[1, 2, 3, 4, 5], 3);
        let new_ids = [1u16, 2, 3, 4, 5];
        let roster = serde_json::to_string(&new_ids).unwrap();
        let pkp = serde_json::to_string(&old[0].public_key_package).unwrap();

        // All four deal; the two recipients disagree about whom to fold in.
        let deals = deals_from(
            &[(1, &old[0]), (2, &old[1]), (3, &old[2]), (4, &old[3])],
            &new_ids,
            3,
        );
        let subset = |me: u16, dealers: &[u16]| {
            let m: Packages<frost::keys::SecretShare> = deals
                .iter()
                .filter(|d| dealers.contains(&d.dealer))
                .map(|d| (d.dealer, d.shares[&me].clone()))
                .collect();
            serde_json::to_string(&m).unwrap()
        };

        let a: Finalized = serde_json::from_str(
            &redistribute_finalize(1, &subset(1, &[1, 2, 3]), &pkp, 3, &roster).unwrap(),
        )
        .unwrap();
        let b: Finalized = serde_json::from_str(
            &redistribute_finalize(2, &subset(2, &[2, 3, 4]), &pkp, 3, &roster).unwrap(),
        )
        .unwrap();
        let c: Finalized = serde_json::from_str(
            &redistribute_finalize(3, &subset(3, &[2, 3, 4]), &pkp, 3, &roster).unwrap(),
        )
        .unwrap();

        // Both succeeded, and both agree on the group key. That is precisely
        // why this cannot be caught by checking it.
        assert_eq!(a.group_key, old[0].group_key);
        assert_eq!(b.group_key, old[0].group_key);

        // But 1 is on a different polynomial from 2 and 3, so the quorum fails.
        let signers = [(1u16, &a), (2u16, &b), (3u16, &c)];
        let root = Some(String::new());
        let (nonces, commitments) = commit(&signers);
        let err = sign_aggregate(
            &commitments,
            &shares(&signers, &nonces, &commitments, root.clone()),
            &serde_json::to_string(&b.public_key_package).unwrap(),
            MSG,
            root,
        )
        .expect_err("shares from divergent dealer sets must not aggregate");
        assert!(err.contains("Invalid signature share"), "got: {err}");
    }

    /// Redistribution is not a one-shot: the result must itself be
    /// redistributable, or a vault can only ever change hands once.
    #[test]
    fn redistribution_composes() {
        let old = run_dkg(&[1, 2, 3], 2);
        let once = run_redistribute(&[(1, &old[0]), (2, &old[1])], &old[0], &[1, 2, 3, 4], 3);
        let twice = run_redistribute(
            &[(1, &once[0]), (2, &once[1]), (4, &once[3])],
            &once[0],
            &[2, 4, 5],
            2,
        );

        assert_eq!(twice[0].group_key, old[0].group_key);
        sign_and_verify(&[(4, &twice[1]), (5, &twice[2])]);
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

    /// An identifiable abort, per RFC 9591: aggregation verifies every share,
    /// so a failure knows exactly whose share was bad. Reporting only that
    /// "aggregation failed" discards the one fact that makes it actionable — a
    /// participant who submits a bad share every round is indistinguishable
    /// from a flaky network unless you can name them.
    #[test]
    fn a_bad_share_is_attributed_to_its_signer() {
        let keys = run_dkg(&[1, 2, 3], 2);
        let signers = [(1u16, &keys[0]), (2u16, &keys[1])];
        let root = Some(String::new());

        let (nonces, commitments) = commit(&signers);
        let good = shares(&signers, &nonces, &commitments, root.clone());

        // Participant 2 submits participant 1's share as its own: structurally
        // valid, cryptographically wrong, and attributable.
        let mut map: Packages<frost::round2::SignatureShare> = serde_json::from_str(&good).unwrap();
        let first = *map.get(&1).unwrap();
        map.insert(2, first);

        let err = sign_aggregate(
            &commitments,
            &serde_json::to_string(&map).unwrap(),
            &serde_json::to_string(&keys[0].public_key_package).unwrap(),
            MSG,
            root,
        )
        .expect_err("a forged share must not aggregate");

        assert!(
            err.contains("culprits: 2"),
            "must name participant 2, got: {err}"
        );
    }

    /// The invariant that makes resharing useful: shares are redistributed on
    /// fresh polynomials, but the group key — and therefore the vault address
    /// and its existing UTXOs — is untouched.
    #[test]
    fn reshare_preserves_the_group_key() {
        let ids = [1u16, 2, 3];
        let old = run_dkg(&ids, 2);
        let new = run_reshare(&ids, 2, &old);

        for (k, n) in new.iter().enumerate() {
            assert_eq!(n.group_key, old[0].group_key, "participant {k}");
        }
        assert_ne!(
            serde_json::to_string(&new[0].key_package).unwrap(),
            serde_json::to_string(&old[0].key_package).unwrap(),
            "shares must actually be re-dealt, not returned unchanged"
        );
    }

    /// And the refreshed shares must still sign together.
    #[test]
    fn reshared_roster_can_still_sign() {
        use frost::keys::Tweak;

        let keys = run_reshare(&[1, 2, 3], 2, &run_dkg(&[1, 2, 3], 2));
        let signers = [(1u16, &keys[0]), (2u16, &keys[1])];
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

        keys[0]
            .public_key_package
            .clone()
            .tweak(Some(Vec::<u8>::new()))
            .verifying_key()
            .verify(
                &unhex(MSG).unwrap(),
                &frost::Signature::deserialize(&unhex(&sig).unwrap()).unwrap(),
            )
            .expect("post-reshare signature must verify");
    }

    /// Removing a member works: reshare over the surviving subset, and the
    /// group key — hence the address and its UTXOs — survives.
    #[test]
    fn reshare_can_remove_a_member() {
        let old = run_dkg(&[1, 2, 3], 2);
        let new = run_reshare(&[1, 2], 2, &old);

        assert_eq!(new[0].group_key, old[0].group_key);
        assert_eq!(new[1].group_key, old[0].group_key);
    }

    /// The threshold cannot move. Upstream compares min_signers against the old
    /// key package and refuses, so a t-of-n vault stays t-of-n for life; only
    /// the roster changes. Raising or lowering `t` needs a fresh DKG, which
    /// means a new group key and a new address.
    ///
    /// Worth a test rather than a comment: the app's reshare command offers
    /// threshold changes today, and this is where that stops being possible.
    #[test]
    fn threshold_cannot_change_across_a_reshare() {
        let ids = [1u16, 2, 3];
        let old = run_dkg(&ids, 2);

        // Rounds 1 and 2 at the NEW threshold succeed; finalising against a
        // 2-of-3 key package is what fails.
        let (r1, r2) = reshare_rounds(&ids, 3);
        let err = reshare_finalize(
            &serde_json::to_string(&r2[0].secret).unwrap(),
            &serde_json::to_string(&others_round1(&ids, &r1, 0)).unwrap(),
            &serde_json::to_string(&round2_for(&ids, &r2, 0, 1)).unwrap(),
            &kp(&old[0]),
            &serde_json::to_string(&old[0].public_key_package).unwrap(),
        )
        .expect_err("threshold change must be refused");
        assert!(err.to_lowercase().contains("min"), "got: {err}");
    }
}
