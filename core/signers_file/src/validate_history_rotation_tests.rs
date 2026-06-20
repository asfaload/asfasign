//! Scenario-table tests for `validate_chain` covering multi-entry rotation
//! transitions, mirroring the style of `validate_history_first_entry_scenarios`
//! in `lib.rs`.
//!
//! ## Rotation rule (enforced by `aggregate_signature::validate_signers_update`)
//!
//! For each adjacent `(parent, updated)` pair the `updated` entry's
//! `signers_file` bytes must be signed by:
//! - `(parent admin OR parent master)`, AND
//! - `(updated admin OR updated master)`, AND
//! - every key in `updated.all_signer_keys() − parent.all_signer_keys()`
//!

#![cfg(test)]

use chrono::{DateTime, Duration, Utc};
use signatures::types::AsfaloadPublicKeys;
use signers_file_types::{CurrentSignersInfo, HistoryEntry, SignersChain, SignersConfig};
use test_helpers::history_helpers::{sign_config, sign_metadata};
use test_helpers::{TestKeys, test_metadata};

use crate::validate_chain;

struct RotationScenario {
    name: &'static str,
    chain: SignersChain,
    expected_valid: bool,
}

/// Build a `HistoryEntry` whose signers_file is signed by `file_indices` and
/// whose metadata is signed by `meta_indices`. For the first (genesis) entry
/// both index sets must cover every key in `config.all_signer_keys()`. For
/// subsequent entries metadata signatures are not checked, so `meta_indices`
/// only needs to be well-formed.
fn make_entry(
    config: &SignersConfig,
    keys: &TestKeys,
    file_indices: &[usize],
    meta_indices: &[usize],
    obsoleted_at: DateTime<Utc>,
) -> HistoryEntry {
    let metadata = test_metadata();
    let (json, sig) = sign_config(config, keys, file_indices).unwrap();
    let (meta_json, meta_sig) = sign_metadata(&metadata, keys, meta_indices).unwrap();
    HistoryEntry {
        obsoleted_at,
        signers_file: json,
        signatures: sig,
        metadata: meta_json,
        metadata_signatures: meta_sig,
    }
}

fn pk(keys: &TestKeys, i: usize) -> AsfaloadPublicKeys {
    keys.pub_key(i).unwrap().clone()
}

fn with_admin(keys: &TestKeys, artifact: (&[usize], u32), admin: (&[usize], u32)) -> SignersConfig {
    SignersConfig::with_keys(
        1,
        (
            artifact.0.iter().map(|&i| pk(keys, i)).collect(),
            artifact.1,
        ),
        Some((admin.0.iter().map(|&i| pk(keys, i)).collect(), admin.1)),
        None,
        None,
    )
    .unwrap()
}

fn with_admin_and_revocation(
    keys: &TestKeys,
    artifact: (&[usize], u32),
    admin: (&[usize], u32),
    revocation: (&[usize], u32),
) -> SignersConfig {
    SignersConfig::with_keys(
        1,
        (
            artifact.0.iter().map(|&i| pk(keys, i)).collect(),
            artifact.1,
        ),
        Some((admin.0.iter().map(|&i| pk(keys, i)).collect(), admin.1)),
        None,
        Some((
            revocation.0.iter().map(|&i| pk(keys, i)).collect(),
            revocation.1,
        )),
    )
    .unwrap()
}

/// Create a CurrentSignersInfo from a HistoryEntry. Useful only in tests
fn current_from_he(e: HistoryEntry) -> Option<CurrentSignersInfo> {
    Some(CurrentSignersInfo {
        signers_file: e.signers_file,
        signatures: e.signatures,
        metadata: e.metadata,
        metadata_signatures: e.metadata_signatures,
    })
}
fn rotation_scenarios() -> Vec<RotationScenario> {
    // Key index allocation (kept stable across scenarios for readability):
    //   0..3 — artifact signer keys (X, Y, Z, W)
    //   4..6 — admin keys (A, B, C)
    //   6..8 — revocation keys (R1, R2)  (overlap with admin range avoided)
    let keys = TestKeys::new(8);

    // Distinct timestamps so strict ordering is satisfied unless a scenario
    // deliberately violates it.
    let base = Utc::now() - Duration::seconds(600);
    let t = |secs: i64| base + Duration::seconds(secs);

    let mut scenarios: Vec<RotationScenario> = Vec::new();

    // ============================================================
    // Group A — valid rotations (must pass)
    // ============================================================

    // A1. rotation_adds_one_signer
    {
        // Old: artifact=[X], admin=[A]
        // New: artifact=[X, Y], admin=[A]   (Y is newly added)
        let old = with_admin(&keys, (&[0], 1), (&[4], 1));
        let new = with_admin(&keys, (&[0, 1], 1), (&[4], 1));
        let entry1 = make_entry(&old, &keys, &[0, 4], &[0, 4], t(10));
        // Rotation needs: old admin (A=4), new admin (A=4), added (Y=1).
        let entry2 = make_entry(&new, &keys, &[1, 4], &[1, 4], t(20));
        scenarios.push(RotationScenario {
            name: "rotation_adds_one_signer",
            chain: SignersChain {
                history_entries: vec![entry1],
                current_signers_info: current_from_he(entry2),
            },
            expected_valid: true,
        });
    }

    // A2. rotation_removes_one_signer
    {
        // Old: artifact=[X, Y], admin=[A]
        // New: artifact=[X],    admin=[A]   (Y removed; no added signers)
        let old = with_admin(&keys, (&[0, 1], 1), (&[4], 1));
        let new = with_admin(&keys, (&[0], 1), (&[4], 1));
        let entry1 = make_entry(&old, &keys, &[0, 1, 4], &[0, 1, 4], t(10));
        // Rotation needs: old admin (A) + new admin (A). No added signers.
        let entry2 = make_entry(&new, &keys, &[4], &[4], t(20));
        scenarios.push(RotationScenario {
            name: "rotation_removes_one_signer",
            chain: SignersChain {
                history_entries: vec![entry1],
                current_signers_info: current_from_he(entry2),
            },
            expected_valid: true,
        });
    }

    // A3. rotation_replaces_one_signer
    {
        // Old: artifact=[X, Y], admin=[A]
        // New: artifact=[X, Z], admin=[A]   (Y removed, Z added)
        let old = with_admin(&keys, (&[0, 1], 1), (&[4], 1));
        let new = with_admin(&keys, (&[0, 2], 1), (&[4], 1));
        let entry1 = make_entry(&old, &keys, &[0, 1, 4], &[0, 1, 4], t(10));
        // Rotation needs: old admin (A) + new admin (A) + added (Z=2).
        let entry2 = make_entry(&new, &keys, &[2, 4], &[2, 4], t(20));
        scenarios.push(RotationScenario {
            name: "rotation_replaces_one_signer",
            chain: SignersChain {
                history_entries: vec![entry1],
                current_signers_info: current_from_he(entry2),
            },
            expected_valid: true,
        });
    }

    // A4. rotation_raises_threshold
    {
        // Same artifact signers [X, Y], admin=[A]; threshold 1 → 2.
        let old = with_admin(&keys, (&[0, 1], 1), (&[4], 1));
        let new = with_admin(&keys, (&[0, 1], 2), (&[4], 1));
        let entry1 = make_entry(&old, &keys, &[0, 1, 4], &[0, 1, 4], t(10));
        // No added signers. Rotation needs old admin + new admin = [A].
        let entry2 = make_entry(&new, &keys, &[4], &[4], t(20));
        scenarios.push(RotationScenario {
            name: "rotation_raises_threshold",
            chain: SignersChain {
                history_entries: vec![entry1],
                current_signers_info: current_from_he(entry2),
            },
            expected_valid: true,
        });
    }

    // A5. rotation_lowers_threshold
    {
        let old = with_admin(&keys, (&[0, 1], 2), (&[4], 1));
        let new = with_admin(&keys, (&[0, 1], 1), (&[4], 1));
        let entry1 = make_entry(&old, &keys, &[0, 1, 4], &[0, 1, 4], t(10));
        let entry2 = make_entry(&new, &keys, &[4], &[4], t(20));
        scenarios.push(RotationScenario {
            name: "rotation_lowers_threshold",
            chain: SignersChain {
                history_entries: vec![entry1],
                current_signers_info: current_from_he(entry2),
            },
            expected_valid: true,
        });
    }

    // A6. rotation_changes_admin_key
    {
        // Old admin=[A], new admin=[B]. B is newly added (admin keys are part
        // of all_signer_keys), so the rotation must be co-signed by A and B.
        let old = with_admin(&keys, (&[0], 1), (&[4], 1));
        let new = with_admin(&keys, (&[0], 1), (&[5], 1));
        let entry1 = make_entry(&old, &keys, &[0, 4], &[0, 4], t(10));
        let entry2 = make_entry(&new, &keys, &[4, 5], &[4, 5], t(20));
        scenarios.push(RotationScenario {
            name: "rotation_changes_admin_key",
            chain: SignersChain {
                history_entries: vec![entry1],
                current_signers_info: current_from_he(entry2),
            },
            expected_valid: true,
        });
    }

    // A7. rotation_changes_revocation_key
    {
        // Revocation keys ARE in `all_signer_keys()`, so swapping
        // revocation key 6→7 introduces key 7 as a newly added signer.
        // The rotation must be co-signed by old admin + new admin + new key 7.
        let old = with_admin_and_revocation(&keys, (&[0], 1), (&[4], 1), (&[6], 1));
        let new = with_admin_and_revocation(&keys, (&[0], 1), (&[4], 1), (&[7], 1));
        // First entry: all_signer_keys = {X=0, A=4, R=6}. Sign with [0, 4, 6].
        let entry1 = make_entry(&old, &keys, &[0, 4, 6], &[0, 4, 6], t(10));
        // Rotation needs old admin (A=4) + new admin (A=4) + newly added (R=7). Sign with [4, 7].
        let entry2 = make_entry(&new, &keys, &[4, 7], &[4, 7], t(20));
        scenarios.push(RotationScenario {
            name: "rotation_changes_revocation_key",
            chain: SignersChain {
                history_entries: vec![entry1],
                current_signers_info: current_from_he(entry2),
            },
            expected_valid: true,
        });
    }

    // A8. rotation_three_entry_chain
    {
        let c1 = with_admin(&keys, (&[0], 1), (&[4], 1));
        let c2 = with_admin(&keys, (&[0, 1], 1), (&[4], 1));
        let c3 = with_admin(&keys, (&[0, 1, 2], 1), (&[4], 1));
        let entry1 = make_entry(&c1, &keys, &[0, 4], &[0, 4], t(10));
        // c1 → c2: added Y=1; needs A + Y
        let entry2 = make_entry(&c2, &keys, &[1, 4], &[1, 4], t(20));
        // c2 → c3: added Z=2; needs A + Z
        let entry3 = make_entry(&c3, &keys, &[2, 4], &[2, 4], t(30));
        scenarios.push(RotationScenario {
            name: "rotation_three_entry_chain",
            chain: SignersChain {
                history_entries: vec![entry1, entry2],
                current_signers_info: current_from_he(entry3),
            },
            expected_valid: true,
        });
    }

    // A9. rotation_no_op_same_config
    {
        // Same config across two entries with distinct timestamps. No added
        // signers; only the admin signature is required.
        let cfg = with_admin(&keys, (&[0], 1), (&[4], 1));
        let entry1 = make_entry(&cfg, &keys, &[0, 4], &[0, 4], t(10));
        let entry2 = make_entry(&cfg, &keys, &[4], &[4], t(20));
        scenarios.push(RotationScenario {
            name: "rotation_no_op_same_config",
            chain: SignersChain {
                history_entries: vec![entry1],
                current_signers_info: current_from_he(entry2),
            },
            expected_valid: true,
        });
    }

    // ============================================================
    // Group B — authorization gaps (must fail)
    // ============================================================

    // B1. rotation_missing_old_admin_signature
    {
        // No-op rotation. Only the artifact signer X (not the admin) signs the
        // new entry. Fails the (old admin OR old master) check; nothing else.
        let cfg = with_admin(&keys, (&[0], 1), (&[4], 1));
        let entry1 = make_entry(&cfg, &keys, &[0, 4], &[0, 4], t(10));
        let entry2 = make_entry(&cfg, &keys, &[0], &[0], t(20));
        scenarios.push(RotationScenario {
            name: "rotation_missing_old_admin_signature",
            chain: SignersChain {
                history_entries: vec![entry1],
                current_signers_info: current_from_he(entry2),
            },
            expected_valid: false,
        });
    }

    // B2. rotation_signed_only_by_old_admin_after_admin_change
    {
        // Old admin=[A], new admin=[B]. Rotation is signed only by A (old
        // admin). Fails on BOTH the (new admin OR new master) check AND the
        // newly-added-signer check (B is newly added). Documents that the two
        // failure modes co-occur whenever the admin key itself rotates.
        let old = with_admin(&keys, (&[0], 1), (&[4], 1));
        let new = with_admin(&keys, (&[0], 1), (&[5], 1));
        let entry1 = make_entry(&old, &keys, &[0, 4], &[0, 4], t(10));
        let entry2 = make_entry(&new, &keys, &[4], &[4], t(20));
        scenarios.push(RotationScenario {
            name: "rotation_signed_only_by_old_admin_after_admin_change",
            chain: SignersChain {
                history_entries: vec![entry1],
                current_signers_info: current_from_he(entry2),
            },
            expected_valid: false,
        });
    }

    // B3. rotation_missing_added_signer_signature
    {
        // Old: artifact=[X], admin=[A]. New: artifact=[X, Y], admin=[A].
        // Rotation signed by old admin + new admin (A) but NOT by Y.
        let old = with_admin(&keys, (&[0], 1), (&[4], 1));
        let new = with_admin(&keys, (&[0, 1], 1), (&[4], 1));
        let entry1 = make_entry(&old, &keys, &[0, 4], &[0, 4], t(10));
        let entry2 = make_entry(&new, &keys, &[4], &[4], t(20));
        scenarios.push(RotationScenario {
            name: "rotation_missing_added_signer_signature",
            chain: SignersChain {
                history_entries: vec![entry1],
                current_signers_info: current_from_he(entry2),
            },
            expected_valid: false,
        });
    }

    // B4. rotation_signed_only_by_removed_signer
    {
        // Old: artifact=[X, Y], admin=[A]. New: artifact=[X], admin=[A].
        // Rotation signed by Y (the removed signer) only. Fails old/new
        // admin checks; Y is not authorized to authorize a rotation.
        let old = with_admin(&keys, (&[0, 1], 1), (&[4], 1));
        let new = with_admin(&keys, (&[0], 1), (&[4], 1));
        let entry1 = make_entry(&old, &keys, &[0, 1, 4], &[0, 1, 4], t(10));
        let entry2 = make_entry(&new, &keys, &[1], &[1], t(20));
        scenarios.push(RotationScenario {
            name: "rotation_signed_only_by_removed_signer",
            chain: SignersChain {
                history_entries: vec![entry1],
                current_signers_info: current_from_he(entry2),
            },
            expected_valid: false,
        });
    }

    // B5. rotation_signed_by_unrelated_key
    {
        // No-op rotation, signed by W=3 — a key in neither config.
        let cfg = with_admin(&keys, (&[0], 1), (&[4], 1));
        let entry1 = make_entry(&cfg, &keys, &[0, 4], &[0, 4], t(10));
        let entry2 = make_entry(&cfg, &keys, &[3], &[3], t(20));
        scenarios.push(RotationScenario {
            name: "rotation_signed_by_unrelated_key",
            chain: SignersChain {
                history_entries: vec![entry1],
                current_signers_info: current_from_he(entry2),
            },
            expected_valid: false,
        });
    }

    // ============================================================
    // Group C — chain integrity (must fail unless noted)
    // ============================================================

    // C1. tampered_middle_entry_signers_file
    {
        let c1 = with_admin(&keys, (&[0], 1), (&[4], 1));
        let c2 = with_admin(&keys, (&[0, 1], 1), (&[4], 1));
        let c3 = with_admin(&keys, (&[0, 1, 2], 1), (&[4], 1));
        let entry1 = make_entry(&c1, &keys, &[0, 4], &[0, 4], t(10));
        let mut entry2 = make_entry(&c2, &keys, &[1, 4], &[1, 4], t(20));
        let entry3 = make_entry(&c3, &keys, &[2, 4], &[2, 4], t(30));
        // Mutate entry2.signers_file after the fact: invalidates its hash.
        entry2.signers_file.push(' ');
        scenarios.push(RotationScenario {
            name: "tampered_middle_entry_signers_file",
            chain: SignersChain {
                history_entries: vec![entry1, entry2],
                current_signers_info: current_from_he(entry3),
            },
            expected_valid: false,
        });
    }

    // C2. tampered_middle_entry_signatures_base64
    {
        use signatures::keys::AsfaloadPublicKeyTrait;
        use signatures::signatures_file::TaggedSignature;

        let c1 = with_admin(&keys, (&[0], 1), (&[4], 1));
        let c2 = with_admin(&keys, (&[0, 1], 1), (&[4], 1));
        let c3 = with_admin(&keys, (&[0, 1, 2], 1), (&[4], 1));
        let entry1 = make_entry(&c1, &keys, &[0, 4], &[0, 4], t(10));
        let mut entry2 = make_entry(&c2, &keys, &[1, 4], &[1, 4], t(20));
        let entry3 = make_entry(&c3, &keys, &[2, 4], &[2, 4], t(30));
        // Replace one signature value with non-base64 garbage.
        let pubkey = keys.pub_key(4).unwrap();
        entry2.signatures.entries.insert(
            pubkey.to_base64(),
            TaggedSignature {
                format: pubkey.key_format(),
                signature: "!!!not-base64!!!".to_string(),
            },
        );
        scenarios.push(RotationScenario {
            name: "tampered_middle_entry_signatures_base64",
            chain: SignersChain {
                history_entries: vec![entry1, entry2],
                current_signers_info: current_from_he(entry3),
            },
            expected_valid: false,
        });
    }

    // C3. middle_entry_with_empty_signatures
    {
        use signatures::signatures_file::SignaturesFile;

        let c1 = with_admin(&keys, (&[0], 1), (&[4], 1));
        let c2 = with_admin(&keys, (&[0, 1], 1), (&[4], 1));
        let c3 = with_admin(&keys, (&[0, 1, 2], 1), (&[4], 1));
        let entry1 = make_entry(&c1, &keys, &[0, 4], &[0, 4], t(10));
        let mut entry2 = make_entry(&c2, &keys, &[1, 4], &[1, 4], t(20));
        let entry3 = make_entry(&c3, &keys, &[2, 4], &[2, 4], t(30));
        entry2.signatures = SignaturesFile::new();
        scenarios.push(RotationScenario {
            name: "middle_entry_with_empty_signatures",
            chain: SignersChain {
                history_entries: vec![entry1, entry2],
                current_signers_info: current_from_he(entry3),
            },
            expected_valid: false,
        });
    }

    // C4. middle_entry_invalid_signers_config_json
    {
        let c1 = with_admin(&keys, (&[0], 1), (&[4], 1));
        let c3 = with_admin(&keys, (&[0, 1, 2], 1), (&[4], 1));
        let entry1 = make_entry(&c1, &keys, &[0, 4], &[0, 4], t(10));
        let mut entry2 = make_entry(&c1, &keys, &[4], &[4], t(20));
        entry2.signers_file = "not valid json".to_string();
        let entry3 = make_entry(&c3, &keys, &[2, 4], &[2, 4], t(30));
        scenarios.push(RotationScenario {
            name: "middle_entry_invalid_signers_config_json",
            chain: SignersChain {
                history_entries: vec![entry1, entry2],
                current_signers_info: current_from_he(entry3),
            },
            expected_valid: false,
        });
    }

    // C5. entries_with_decreasing_obsoleted_at
    {
        let c1 = with_admin(&keys, (&[0], 1), (&[4], 1));
        let c2 = with_admin(&keys, (&[0, 1], 1), (&[4], 1));
        let c3 = with_admin(&keys, (&[0, 1, 2], 1), (&[4], 1));
        let entry1 = make_entry(&c1, &keys, &[0, 4], &[0, 4], t(20));
        let entry2 = make_entry(&c2, &keys, &[1, 4], &[1, 4], t(10));
        let entry3 = make_entry(&c3, &keys, &[2, 4], &[2, 4], t(30));
        scenarios.push(RotationScenario {
            name: "entries_with_decreasing_obsoleted_at",
            chain: SignersChain {
                history_entries: vec![entry1, entry2],
                current_signers_info: current_from_he(entry3),
            },
            expected_valid: false,
        });
    }

    // C6. entries_with_equal_obsoleted_at
    {
        // In practice this should never happen, but two entries sharing an
        // obsolescence instant must still be rejected — strict ordering.
        // Both timestamp-clashing entries must live in `history_entries`;
        // `CurrentSignersInfo` carries no `obsoleted_at`.
        let c1 = with_admin(&keys, (&[0], 1), (&[4], 1));
        let c2 = with_admin(&keys, (&[0, 1], 1), (&[4], 1));
        let c3 = with_admin(&keys, (&[0, 1, 2], 1), (&[4], 1));
        let entry1 = make_entry(&c1, &keys, &[0, 4], &[0, 4], t(10));
        let entry2 = make_entry(&c2, &keys, &[1, 4], &[1, 4], t(10));
        let entry3 = make_entry(&c3, &keys, &[2, 4], &[2, 4], t(20));
        scenarios.push(RotationScenario {
            name: "entries_with_equal_obsoleted_at",
            chain: SignersChain {
                history_entries: vec![entry1, entry2],
                current_signers_info: current_from_he(entry3),
            },
            expected_valid: false,
        });
    }

    // C7. valid_prefix_with_invalid_third_entry
    {
        // entry1, entry2 form a valid prefix; entry3 is missing the added
        // signer's signature. Confirms validation does not short-circuit on
        // a valid prefix.
        let c1 = with_admin(&keys, (&[0], 1), (&[4], 1));
        let c2 = with_admin(&keys, (&[0, 1], 1), (&[4], 1));
        let c3 = with_admin(&keys, (&[0, 1, 2], 1), (&[4], 1));
        let entry1 = make_entry(&c1, &keys, &[0, 4], &[0, 4], t(10));
        let entry2 = make_entry(&c2, &keys, &[1, 4], &[1, 4], t(20));
        // entry3 needs to be signed by Z=2 as the newly added signer; omit it.
        let entry3 = make_entry(&c3, &keys, &[4], &[4], t(30));
        scenarios.push(RotationScenario {
            name: "valid_prefix_with_invalid_third_entry",
            chain: SignersChain {
                history_entries: vec![entry1, entry2],
                current_signers_info: current_from_he(entry3),
            },
            expected_valid: false,
        });
    }

    // ============================================================
    // Group D — cross-cutting with first-entry rules
    // ============================================================

    // D1. invalid_first_entry_with_valid_rotations
    {
        // First entry's signers_file is signed by only one of two required
        // signers — fails the all-signers-of-the-first-entry rule. Even
        // though the rotation that follows is itself well-formed, the chain
        // must be rejected.
        let c1 = with_admin(&keys, (&[0, 1], 1), (&[4], 1));
        let c2 = with_admin(&keys, (&[0, 1, 2], 1), (&[4], 1));
        // Sign first entry with [0, 4] only — Y=1 (artifact signer) missing.
        let entry1 = make_entry(&c1, &keys, &[0, 4], &[0, 4], t(10));
        // entry2 itself is a valid rotation from c1 to c2.
        let entry2 = make_entry(&c2, &keys, &[2, 4], &[2, 4], t(20));
        scenarios.push(RotationScenario {
            name: "invalid_first_entry_with_valid_rotations",
            chain: SignersChain {
                history_entries: vec![entry1],
                current_signers_info: current_from_he(entry2),
            },
            expected_valid: false,
        });
    }

    scenarios
}

#[test]
fn validate_history_rotation_scenarios() {
    for sc in rotation_scenarios() {
        let result = validate_chain(&sc.chain);
        assert_eq!(
            result.is_ok(),
            sc.expected_valid,
            "Scenario '{}': expected valid={}, got valid={} (result: {result:?})",
            sc.name,
            sc.expected_valid,
            result.is_ok(),
        );
    }
}
