use std::sync::Arc;
use std::{fs::create_dir_all, path::PathBuf};

use kameo::actor::{ActorRef, Spawn};

use rest_api_types::git_backend::{GitBackend, GitBackendKind, Sha1GitBackend, Sha256GitBackend};

use crate::{
    actors::{
        nonce_cache_actor::{NONCE_CACHE_DB, NonceCacheActor},
        nonce_cleanup_actor::NonceCleanupActor,
    },
    config::GitBackendConfig,
    file_auth::actors::forge_signers_validator::ForgeProjectValidator,
    file_auth::actors::{
        checksums_actor::ChecksumsActor, git_actor::GitActor, release_actor::ReleaseActor,
        signature_collector::SignatureCollector, signers_initialiser::SignersInitialiser,
    },
};

#[derive(Clone)]
pub struct AppState {
    pub git_repo_path: PathBuf,
    pub git_backend: Arc<dyn GitBackend>,
    pub git_actor: ActorRef<GitActor>,
    pub nonce_cache_actor: ActorRef<NonceCacheActor>,
    pub nonce_cleanup_actor: ActorRef<NonceCleanupActor>,
    pub forge_project_validator: ActorRef<ForgeProjectValidator>,
    pub signers_initialiser: ActorRef<SignersInitialiser>,
    pub signature_collector: ActorRef<SignatureCollector>,
    pub release_actor: ActorRef<ReleaseActor>,
    pub checksums_actor: ActorRef<ChecksumsActor>,
}

fn backend_kind_from_config(config: GitBackendConfig) -> GitBackendKind {
    match config {
        GitBackendConfig::Sha1 => GitBackendKind::Sha1,
        GitBackendConfig::Sha256 => GitBackendKind::Sha256,
    }
}

pub fn init_state(git_repo_path: std::path::PathBuf, config: crate::config::AppConfig) -> AppState {
    let git_backend_kind = backend_kind_from_config(config.git_backend);
    let git_backend: Arc<dyn GitBackend> = match git_backend_kind {
        GitBackendKind::Sha1 => Arc::new(Sha1GitBackend::new(&git_repo_path)),
        GitBackendKind::Sha256 => Arc::new(Sha256GitBackend::new(&git_repo_path)),
    };

    if !git_repo_path.join(".git").exists() {
        git_backend
            .init()
            .unwrap_or_else(|e| panic!("git init failed for {}: {}", git_repo_path.display(), e));
    }

    let git_actor = GitActor::spawn(git_backend.clone());

    // Initialize nonce cache with database path
    // FIXME: support taking the dir for the nonce db from env var
    let nonce_db_dir = git_repo_path.join(".app_cache");
    create_dir_all(&nonce_db_dir).unwrap_or_else(|e| {
        panic!(
            "Cannot create nonce db dir at {}:{}",
            nonce_db_dir.display(),
            e
        )
    });
    let nonce_db_path = git_repo_path.join(".app_cache").join(NONCE_CACHE_DB);
    let db = sled::open(nonce_db_path)
        .map_err(|e| {
            tracing::error!(
                error = %e,
                "Problem opening nonce cache"
            );
        })
        .expect("Cannot open nonce cache database");
    let nonce_cache_actor = NonceCacheActor::spawn(db.clone());
    let nonce_cleanup_actor = NonceCleanupActor::spawn(db.clone());

    let forge_project_validator = ForgeProjectValidator::spawn(());
    let signers_initialiser = SignersInitialiser::spawn(());
    let signature_collector = SignatureCollector::spawn(git_actor.clone());

    let release_actor = ReleaseActor::spawn((git_actor.clone(), config.clone()));
    let checksums_actor = ChecksumsActor::spawn((git_actor.clone(), config));

    AppState {
        git_repo_path,
        git_backend,
        git_actor,
        nonce_cache_actor,
        nonce_cleanup_actor,
        forge_project_validator,
        signers_initialiser,
        signature_collector,
        release_actor,
        checksums_actor,
    }
}
