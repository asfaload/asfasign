#[cfg(test)]
mod tests {
    use client_server_integration_tests::test_harness;
    use common::sha512_for_content;
    use features_lib::constants::PENDING_SIGNERS_DIR;
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
        let secret_key_path = guard.secret_key_paths[0].clone();
        let backend_url = guard.server.base_url();
        drop(guard);

        let file_paths = client_cli::commands::list_pending::handle_list_pending_command(
            &backend_url,
            &secret_key_path,
            test_harness::TEST_PASSWORD,
            false,
        )
        .await
        .expect("list-pending command should succeed");

        assert!(
            file_paths.is_empty(),
            "Expected no pending files, got: {:?}",
            file_paths
        );
    }

    // ========================================
    // ADD FILE + LIST-PENDING TESTS
    // ========================================

    #[tokio::test]
    async fn test_add_file_and_list_pending() {
        let state = test_harness::initialize().await;
        let guard = state.lock().await;
        let git_repo_path = guard.server.git_repo_path();
        let secret_key_path = guard.secret_key_paths[0].clone();
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

        test_harness::create_file_in_repo(&file_path, "This is a test file.")
            .await
            .expect("Failed to create file");

        test_harness::create_pending_signatures_for(&file_path)
            .await
            .expect("Failed to create pending signatures file");

        let file_paths = client_cli::commands::list_pending::handle_list_pending_command(
            &backend_url,
            &secret_key_path,
            test_harness::TEST_PASSWORD,
            false,
        )
        .await
        .expect("list-pending should succeed");

        assert!(
            file_paths.iter().any(|p| p == &file_path),
            "Expected pending list to contain '{}', got: {:?}",
            file_path,
            file_paths
        );
    }

    // ========================================
    // SIGN-PENDING COMMAND TESTS
    // ========================================

    #[tokio::test]
    async fn test_sign_pending_file() {
        let state = test_harness::initialize().await;
        let guard = state.lock().await;
        let git_repo_path = guard.server.git_repo_path();
        let secret_key_path = guard.secret_key_paths[0].clone();
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

        // Create artifact file
        test_harness::create_file_in_repo(&file_path, "This is an artifact to be signed.")
            .await
            .expect("Failed to create file");

        test_harness::create_pending_signatures_for(&file_path)
            .await
            .expect("Failed to create pending signatures file");

        // Verify the file appears in pending list
        let file_paths = client_cli::commands::list_pending::handle_list_pending_command(
            &backend_url,
            &secret_key_path,
            test_harness::TEST_PASSWORD,
            false,
        )
        .await
        .expect("list-pending should succeed");

        assert!(
            file_paths.iter().any(|p| p == &file_path),
            "Expected '{}' in pending list, got: {:?}",
            file_path,
            file_paths
        );

        // Sign the pending file
        let sign_response = client_cli::commands::sign_pending::handle_sign_pending_command(
            &file_path,
            &backend_url,
            &secret_key_path,
            test_harness::TEST_PASSWORD,
            false,
        )
        .await
        .expect("sign-pending should succeed");

        assert!(
            sign_response.is_complete,
            "Expected signature to be complete (threshold=1, signers=1)"
        );
    }

    // ========================================
    // MULTI-SIGNER WORKFLOW TEST
    // ========================================

    #[tokio::test]
    async fn test_multi_signer_workflow() {
        let state = test_harness::initialize().await;
        let guard = state.lock().await;
        let git_repo_path = guard.server.git_repo_path();
        let backend_url = guard.server.base_url();
        let key_paths = guard.secret_key_paths.clone();
        let test_keys = &guard.test_keys;

        // Build 3-key signers config with artifact threshold=2
        let pub_keys: Vec<_> = (0..3)
            .map(|i| test_keys.pub_key(i).expect("key exists").clone())
            .collect();
        let signers_config = SignersConfig::with_artifact_signers_only(1, (pub_keys, 2))
            .expect("Failed to build signers config");
        let signers_json = signers_config.to_json().expect("Failed to serialize");

        // --- Phase 1: Initialize signers (records key[0]'s signature) ---
        let (project_dir_sub, _) = test_harness::unique_test_paths("multi_signer", "dummy");
        let project_dir = git_repo_path.join(&project_dir_sub);
        fs::create_dir_all(&project_dir).expect("Failed to create project dir");

        let secret_key_0 =
            features_lib::AsfaloadSecretKeys::from_file(&key_paths[0], test_harness::TEST_PASSWORD)
                .expect("Failed to load key 0");
        let signers_hash = sha512_for_content(signers_json.as_bytes().to_vec())
            .expect("Failed to hash signers content");
        let signature_0 = secret_key_0.sign(&signers_hash).expect("Failed to sign");
        let pub_key_0 = features_lib::AsfaloadPublicKeys::from_secret_key(&secret_key_0)
            .expect("Failed to derive public key");

        initialize_signers_file(&project_dir, &signers_json, &signature_0, &pub_key_0)
            .expect("Failed to initialize signers file");

        drop(guard);

        // --- Phase 2: Sign signers file with remaining 2 keys ---
        // list-pending for key[1] should show the pending signers file
        let file_paths = client_cli::commands::list_pending::handle_list_pending_command(
            &backend_url,
            &key_paths[1],
            test_harness::TEST_PASSWORD,
            false,
        )
        .await
        .expect("list-pending should succeed for key[1]");

        // Find the signers file in the pending list
        let signers_pending_path = file_paths
            .iter()
            .find(|p| p.contains(PENDING_SIGNERS_DIR))
            .expect("Signers file should be in pending list")
            .clone();

        // sign-pending with key[1]: not yet complete (2 of 3)
        let r1 = client_cli::commands::sign_pending::handle_sign_pending_command(
            &signers_pending_path,
            &backend_url,
            &key_paths[1],
            test_harness::TEST_PASSWORD,
            false,
        )
        .await
        .expect("sign-pending key[1] should succeed");
        assert!(
            !r1.is_complete,
            "Should not be complete after 2 of 3 signatures"
        );

        // sign-pending with key[2]: complete (3 of 3) → signers activate
        let r2 = client_cli::commands::sign_pending::handle_sign_pending_command(
            &signers_pending_path,
            &backend_url,
            &key_paths[2],
            test_harness::TEST_PASSWORD,
            false,
        )
        .await
        .expect("sign-pending key[2] should succeed");
        assert!(r2.is_complete, "Should be complete after all 3 signatures");

        // --- Phase 3: Create artifact file ---
        let (_, artifact_path) = test_harness::unique_test_paths("multi_signer", "artifact.txt");

        test_harness::create_file_in_repo(&artifact_path, "artifact content")
            .await
            .expect("Failed to create artifact file");

        test_harness::create_pending_signatures_for(&artifact_path)
            .await
            .expect("Failed to create pending signatures file");

        // --- Phase 4: Sign artifact (threshold=2) ---
        let file_paths = client_cli::commands::list_pending::handle_list_pending_command(
            &backend_url,
            &key_paths[0],
            test_harness::TEST_PASSWORD,
            false,
        )
        .await
        .expect("list-pending should succeed for key[0]");

        assert!(
            file_paths.iter().any(|p| p == &artifact_path),
            "Expected artifact '{}' in pending list, got: {:?}",
            artifact_path,
            file_paths
        );

        // sign with key[0]: 1 of 2, not complete
        let r3 = client_cli::commands::sign_pending::handle_sign_pending_command(
            &artifact_path,
            &backend_url,
            &key_paths[0],
            test_harness::TEST_PASSWORD,
            false,
        )
        .await
        .expect("sign key[0] for artifact should succeed");
        assert!(
            !r3.is_complete,
            "Should not be complete after 1 of 2 required signatures"
        );

        // sign with key[1]: 2 of 2, complete
        let r4 = client_cli::commands::sign_pending::handle_sign_pending_command(
            &artifact_path,
            &backend_url,
            &key_paths[1],
            test_harness::TEST_PASSWORD,
            false,
        )
        .await
        .expect("sign key[1] for artifact should succeed");
        assert!(
            r4.is_complete,
            "Should be complete after 2 of 2 required signatures"
        );

        // --- Phase 5: Signing after completion should error ---
        let r5 = client_cli::commands::sign_pending::handle_sign_pending_command(
            &artifact_path,
            &backend_url,
            &key_paths[2],
            test_harness::TEST_PASSWORD,
            false,
        )
        .await;
        assert!(r5.is_err(), "Signing after completion should fail");
    }
}
