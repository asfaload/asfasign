//! Run with: cargo run --package test_helpers --example gen_asfaload_fixtures
//!
//! Produces 10 asfaload keypairs in core/test_helpers/fixtures/keys/
//! named asfaload_key_0..asfaload_key_9 (and .pub siblings).

use signatures::keys::asfaload::{AsfaloadKeysBlob, format::Argon2Params};
use signatures::keys::{AsfaloadKeyPair, AsfaloadKeyPairTrait};
use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/keys");
    std::fs::create_dir_all(&dir).unwrap();

    for i in 0..10 {
        let key_path = dir.join(format!("asfaload_key_{}", i));
        let pub_path = dir.join(format!("asfaload_key_{}.pub", i));
        // Delete any previous version so `save` does not refuse to overwrite.
        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_file(&pub_path);
        let kp = AsfaloadKeyPair::<AsfaloadKeysBlob>::new_with_argon2_params(
            "password",
            Argon2Params::TEST,
        )
        .expect("generate");
        kp.save(&key_path).expect("save");
        println!("wrote {}", key_path.display());
    }
}
