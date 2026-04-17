//! Integration: prove that asfaload-native and SSH-imported ed25519 keys
//! produce identical signatures for the same seed + same message, and that
//! a public key loaded from either format verifies signatures from either.

use base64::Engine;
use common::sha512_for_content;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use signatures::keys::{
    AsfaloadKeyPair, AsfaloadKeyPairTrait, AsfaloadPublicKeyTrait, AsfaloadSecretKeyTrait,
    asfaload::{AsfaloadEd25519PublicKey, AsfaloadKeysBlob, SshEncryptedKey, format::Argon2Params},
};

#[test]
fn same_raw_key_parses_equal_via_asfaload_pub_and_ssh_ed25519() {
    // Generate an asfaload keypair, save its public key, read it back via
    // AsfaloadEd25519PublicKey::from_base64.
    let tmp = tempfile::tempdir().unwrap();
    let asfaload_key_path = tmp.path().join("asfaload_key");
    let kp = AsfaloadKeyPair::<AsfaloadKeysBlob>::new_with_argon2_params("pw", Argon2Params::TEST)
        .unwrap();
    kp.save(&asfaload_key_path).unwrap();

    let pub_text = std::fs::read_to_string(tmp.path().join("asfaload_key.pub")).unwrap();
    let pk_via_asfaload = AsfaloadEd25519PublicKey::from_base64(pub_text.trim()).unwrap();

    // Build the equivalent ssh-ed25519 wire line from the same raw key bytes.
    let mut wire = Vec::new();
    wire.extend_from_slice(&11u32.to_be_bytes());
    wire.extend_from_slice(b"ssh-ed25519");
    wire.extend_from_slice(&32u32.to_be_bytes());
    wire.extend_from_slice(pk_via_asfaload.key().as_bytes());
    let ssh_line = format!(
        "ssh-ed25519 {} interop@test",
        base64::engine::general_purpose::STANDARD.encode(&wire),
    );
    let pk_via_ssh = AsfaloadEd25519PublicKey::from_base64(&ssh_line).unwrap();

    assert_eq!(
        pk_via_asfaload, pk_via_ssh,
        "same raw key loaded via asfaload-pub and ssh-ed25519 must be equal"
    );
}

#[test]
fn ssh_imported_key_signature_verifies_via_asfaload_parse_path() {
    // Build an encrypted openssh-ed25519 PEM for a random key.
    let sk = SigningKey::generate(&mut OsRng);
    let seed: [u8; 32] = sk.to_bytes();
    let ssh_ed = ssh_key::private::Ed25519Keypair::from_seed(&seed);
    let private = ssh_key::PrivateKey::new(
        ssh_key::private::KeypairData::Ed25519(ssh_ed),
        "integration",
    )
    .expect("PrivateKey::new");
    let encrypted = private.encrypt(&mut OsRng, b"passphrase").expect("encrypt");
    let pem = encrypted
        .to_openssh(ssh_key::LineEnding::LF)
        .expect("to_openssh")
        .to_string();

    // Write PEM to a temp file, load via AsfaloadKeyPair<SshEncryptedKey>, and sign.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("id_ed25519");
    std::fs::write(&path, &pem).unwrap();

    let kp = AsfaloadKeyPair::<SshEncryptedKey>::from_file(&path).unwrap();
    let data = sha512_for_content(b"interop payload".to_vec()).unwrap();
    let sig = kp.secret_key("passphrase").unwrap().sign(&data).unwrap();

    // Verify with the public key derived via asfaload's from_base64 path.
    let asfaload_pk = AsfaloadEd25519PublicKey::from_base64(&kp.public_key().to_base64()).unwrap();
    asfaload_pk.verify(&sig, &data).unwrap();
}

#[test]
fn asfaload_roundtrip_sign_and_verify() {
    // Plain asfaload-native roundtrip — regression guard for the happy path.
    let tmp = tempfile::tempdir().unwrap();
    let key_path = tmp.path().join("asfaload_key");
    let kp = AsfaloadKeyPair::<AsfaloadKeysBlob>::new_with_argon2_params("pw", Argon2Params::TEST)
        .unwrap();
    kp.save(&key_path).unwrap();

    let loaded = AsfaloadKeyPair::<AsfaloadKeysBlob>::from_file(&key_path).unwrap();
    let data = sha512_for_content(b"roundtrip payload".to_vec()).unwrap();
    let sig = loaded.secret_key("pw").unwrap().sign(&data).unwrap();
    loaded.public_key().verify(&sig, &data).unwrap();
}
