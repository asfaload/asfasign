use std::path::PathBuf;

use kameo::actor::{ActorRef, Spawn};

use crate::{
    actors::{
        nonce_cache_actor::{NONCE_CACHE_DB, NonceCacheActor},
        nonce_cleanup_actor::NonceCleanupActor,
    },
    config::GitBackendConfig,
    file_auth::actors::forge_signers_validator::ForgeProjectValidator,
    file_auth::actors::{
        checksums_actor::ChecksumsActor, git_actor::GitActor, git_backend::GitBackendKind,
        release_actor::ReleaseActor, signature_collector::SignatureCollector,
        signers_initialiser::SignersInitialiser,
    },
};

#[derive(Clone)]
pub struct AppState {
    pub git_repo_path: PathBuf,
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
        #[cfg(feature = "sha256")]
        GitBackendConfig::Sha256 => GitBackendKind::Sha256,
        #[cfg(not(feature = "sha256"))]
        GitBackendConfig::Sha256 => {
            panic!("git_backend=sha256 selected without 'sha256' feature")
        }
    }
}

pub fn init_state(git_repo_path: std::path::PathBuf, config: crate::config::AppConfig) -> AppState {
    let git_backend = backend_kind_from_config(config.git_backend);
    let git_actor = GitActor::spawn((git_repo_path.clone(), git_backend));

    // Initialize nonce cache with database path
    // FIXME: support taking the dir for the nonce db from env var
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
