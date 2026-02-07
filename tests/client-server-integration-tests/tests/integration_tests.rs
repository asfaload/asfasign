#[cfg(test)]
mod tests {
    use client_server_integration_tests::test_harness;
    use common::sha512_for_content;
    use features_lib::AsfaloadPublicKeyTrait;
    use features_lib::AsfaloadSecretKeyTrait;
    use signers_file::initialize_signers_file;
    use signers_file_types::SignersConfig;
    use std::fs;

    // ========================================
    // LIST-PENDING COMMAND TESTS
    // ========================================

    #[tokio::test]
    async fn test_list_pending_empty() {
        let state = test_harness::initialize().await;
        let guard = state.lock().await;
        let secret_key_path = guard.secret_key_path.clone();
        let backend_url = guard.server.base_url();
        drop(guard);

        let result = client_cli::commands::list_pending::handle_list_pending_command(
            &backend_url,
            &secret_key_path,
            test_harness::TEST_PASSWORD,
        )
        .await;

        assert!(result.is_ok(), "list-pending command should succeed");
    }

    // ========================================
    // ADD FILE + LIST-PENDING TESTS
    // ========================================

    #[tokio::test]
    async fn test_add_file_and_list_pending() {
        let state = test_harness::initialize().await;
        let guard = state.lock().await;
        let git_repo_path = guard.server.git_repo_path();
        let secret_key_path = guard.secret_key_path.clone();
        let backend_url = guard.server.base_url();
        drop(guard);

        let secret_key = features_lib::AsfaloadSecretKeys::from_file(
            &secret_key_path,
            test_harness::TEST_PASSWORD,
        )
        .expect("Failed to load secret key");
        let public_key = features_lib::AsfaloadPublicKeys::from_secret_key(&secret_key)
            .expect("Failed to derive public key");

        let (project_dir_sub, file_path) =
            test_harness::unique_test_paths("add_file_list", "test_file.txt");
        let project_dir = git_repo_path.join(&project_dir_sub);
        fs::create_dir_all(&project_dir).expect("Failed to create project dir");

        let signers_config =
            SignersConfig::with_artifact_signers_only(1, (vec![public_key.clone()], 1))
                .expect("Failed to build signers config");
        let signers_content = signers_config
            .to_json()
            .expect("Failed to serialize signers config");

        let signers_hash = sha512_for_content(signers_content.as_bytes().to_vec())
            .expect("Failed to hash signers content");
        let signature = secret_key.sign(&signers_hash).expect("Failed to sign");

        initialize_signers_file(&project_dir, &signers_content, &signature, &public_key)
            .expect("Failed to initialize signers file");

        test_harness::add_file_via_api(
            &file_path,
            "This is a test file.",
            &secret_key_path,
            test_harness::TEST_PASSWORD,
        )
        .await
        .expect("Failed to add file");

        let result = client_cli::commands::list_pending::handle_list_pending_command(
            &backend_url,
            &secret_key_path,
            test_harness::TEST_PASSWORD,
        )
        .await;

        assert!(result.is_ok(), "list-pending should succeed");
    }

    // ========================================
    // SIGN-PENDING COMMAND TESTS
    // ========================================

    #[tokio::test]
    async fn test_sign_pending_file() {
        let state = test_harness::initialize().await;
        let guard = state.lock().await;
        let git_repo_path = guard.server.git_repo_path();
        let secret_key_path = guard.secret_key_path.clone();
        let backend_url = guard.server.base_url();
        drop(guard);

        let secret_key = features_lib::AsfaloadSecretKeys::from_file(
            &secret_key_path,
            test_harness::TEST_PASSWORD,
        )
        .expect("Failed to load secret key");
        let public_key = features_lib::AsfaloadPublicKeys::from_secret_key(&secret_key)
            .expect("Failed to derive public key");

        // Setup signers
        let (project_dir_sub, file_path) =
            test_harness::unique_test_paths("sign_pending", "artifact.txt");
        let project_dir = git_repo_path.join(&project_dir_sub);
        fs::create_dir_all(&project_dir).expect("Failed to create project dir");

        let signers_config =
            SignersConfig::with_artifact_signers_only(1, (vec![public_key.clone()], 1))
                .expect("Failed to build signers config");
        let signers_content = signers_config
            .to_json()
            .expect("Failed to serialize signers config");

        let signers_hash = sha512_for_content(signers_content.as_bytes().to_vec())
            .expect("Failed to hash signers content");
        let signature = secret_key.sign(&signers_hash).expect("Failed to sign");

        initialize_signers_file(&project_dir, &signers_content, &signature, &public_key)
            .expect("Failed to initialize signers file");

        // Add file via API
        test_harness::add_file_via_api(
            &file_path,
            "This is an artifact to be signed.",
            &secret_key_path,
            test_harness::TEST_PASSWORD,
        )
        .await
        .expect("Failed to add file");

        // Verify the file appears in pending list
        let list_result = client_cli::commands::list_pending::handle_list_pending_command(
            &backend_url,
            &secret_key_path,
            test_harness::TEST_PASSWORD,
        )
        .await;
        assert!(list_result.is_ok(), "list-pending should succeed");

        // Sign the pending file
        let sign_result = client_cli::commands::sign_pending::handle_sign_pending_command(
            &file_path,
            &backend_url,
            &secret_key_path,
            test_harness::TEST_PASSWORD,
        )
        .await;
        assert!(
            sign_result.is_ok(),
            "sign-pending should succeed: {:?}",
            sign_result.err()
        );
    }
}
