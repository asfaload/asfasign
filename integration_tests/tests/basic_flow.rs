use aggregate_signature::SignatureWithState;
use aggregate_signature::load_for_file;
use anyhow::Result;
use common::SignedFileLoader;
use common::fs::names::PENDING_SIGNERS_DIR;
use common::fs::names::SIGNERS_FILE;
use common::sha512_for_content;
use common::sha512_for_file;
use signatures::keys::AsfaloadPublicKey;
use signatures::keys::AsfaloadSignature;
use signatures::keys::{AsfaloadKeyPairTrait, AsfaloadSecretKeyTrait};
use signers_file::initialize_signers_file;
use signers_file_types::SignersConfig;
use std::fs;
use tempfile::TempDir;
use test_helpers::TestKeys;
use user_lib::SignedFileWithKindTrait;

#[test]
fn basic_flow() -> Result<()> {
    // Create a temporary directory for our test
    let temp_dir = TempDir::new()?;
    let root_dir = temp_dir.path();

    // Create key pairs for two users
    let test_keys = TestKeys::new(2);
    let user1_keypair = test_keys.key_pair(0).unwrap();
    let user2_keypair = test_keys.key_pair(1).unwrap();

    // We create scopes for each operation taking place, to ensure each
    // user has access to the data it needs.

    // User1 initialises the signers file
    {
        // User1 scope for initialising the signers file
        let signers_content = SignersConfig::with_artifact_signers_only(
            1,
            (
                vec![user1_keypair.public_key(), user2_keypair.public_key()],
                2,
            ),
        )
        .expect("Could not build signers config")
        .to_json()
        .expect("Could not serialise Signersconfig to json");

        // It is the sha512 of the content of the file that is signed.
        let signers_file_hash = sha512_for_content(signers_content.as_bytes().to_vec())?;
        // The user1 signs the file
        let signature1 = user1_keypair
            .secret_key("password")?
            .sign(&signers_file_hash)?;

        // And the signers file is initialised for root_dir.
        initialize_signers_file(
            root_dir,
            &signers_content,
            &signature1,
            &user1_keypair.public_key(),
        )?;
    }

    // Second user signs the signers file
    // It reads the content of the signers file proposed by user1
    {
        // Signers2 scope for signing the signers file
        let signers_file = root_dir.join(PENDING_SIGNERS_DIR).join(SIGNERS_FILE);
        let signed_file = SignedFileLoader::load(&signers_file);
        let signers_file_content_read = std::fs::read_to_string(&signers_file)?;
        // It computes the hash of the content
        let signers_file_hash_for_user2 =
            sha512_for_content(signers_file_content_read.as_bytes().to_vec())?;
        // Then it signs it
        let signature2 = user2_keypair
            .secret_key("password")?
            .sign(&signers_file_hash_for_user2)?;
        // And adds it to the signers_file signatures.
        signed_file.add_signature(signature2, user2_keypair.public_key())?;
    }

    // The signers file is now active and can be used.

    // Create a text file in a sibling directory
    let sibling_dir = root_dir.join("sibling");
    fs::create_dir_all(&sibling_dir)?;
    let text_file = sibling_dir.join("test.txt");
    fs::write(&text_file, "This is a test file to be signed")?;

    // User2 signs the text file
    {
        // User2 scope for signing the file
        let text_file_hash = sha512_for_file(&text_file)?;
        let signature2 = user2_keypair
            .secret_key("password")?
            .sign(&text_file_hash)?;
        let signed_file = SignedFileLoader::load(&text_file);
        signed_file.add_signature(signature2, user2_keypair.public_key())?;
    }

    // Check it left the signature as pending
    let is_signed = SignedFileLoader::load(&text_file).is_signed()?;
    assert!(!is_signed);
    match load_for_file::<AsfaloadPublicKey<_>, AsfaloadSignature<_>, _>(&text_file)? {
        SignatureWithState::Pending(_) => Ok(()),
        _ => Err(anyhow::anyhow!("Unexpected signature state")),
    }?;

    // User1 signs the text file
    {
        // User1 scope for signing the file
        let text_file_hash = sha512_for_file(&text_file)?;
        let signature1 = user1_keypair
            .secret_key("password")?
            .sign(&text_file_hash)?;
        SignedFileLoader::load(&text_file).add_signature(signature1, user1_keypair.public_key())?;
    }

    // As both signatures have been collected, the aggregate signature is now complete.
    match load_for_file::<AsfaloadPublicKey<_>, AsfaloadSignature<_>, _>(&text_file)? {
        SignatureWithState::Complete(_) => Ok(()),
        _ => Err(anyhow::anyhow!(
            "Unexpected signature state: should be complete at end of test"
        )),
    }?;

    Ok(())
}
