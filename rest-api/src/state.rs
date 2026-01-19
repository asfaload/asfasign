use std::path::PathBuf;

use kameo::actor::{ActorRef, Spawn};

use crate::{
    actors::{
        git_actor::GitActor,
        nonce_cache_actor::{NONCE_CACHE_DB, NonceCacheActor},
        nonce_cleanup_actor::NonceCleanupActor,
        signature_collector::SignatureCollector,
        signers_initialiser::SignersInitialiser,
    },
    file_auth::actors::forge_signers_validator::ForgeProjectValidator,
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
}

pub fn init_state(git_repo_path: std::path::PathBuf) -> AppState {
    let git_actor = GitActor::spawn(git_repo_path.clone());

    // Initialize nonce cache with database path
    // FIXME: support taking the dir for the nonce db from env var
    let nonce_db_path = git_repo_path.join(".app_cache").join(NONCE_CACHE_DB);
    let nonce_cache_actor = NonceCacheActor::spawn(nonce_db_path.clone());
    let nonce_cleanup_actor = NonceCleanupActor::spawn(nonce_db_path);

    let forge_project_validator = ForgeProjectValidator::spawn(());
    let signers_initialiser = SignersInitialiser::spawn(());
    let signature_collector = SignatureCollector::spawn(git_actor.clone());

    AppState {
        git_repo_path,
        git_actor,
        nonce_cache_actor,
        nonce_cleanup_actor,
        forge_project_validator,
        signers_initialiser,
        signature_collector,
    }
}
