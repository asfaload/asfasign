use std::path::PathBuf;

use kameo::actor::{ActorRef, Spawn};

use crate::{
    actors::{
        git_actor::GitActor,
        nonce_cache_actor::{NONCE_CACHE_DB, NonceCacheActor},
        nonce_cleanup_actor::NonceCleanupActor,
        signers_initialiser::SignersInitialiser,
    },
    file_auth::github::actors::github_project_validator::GitHubProjectValidator,
};

#[derive(Clone)]
pub struct AppState {
    pub git_repo_path: PathBuf,
    pub git_actor: ActorRef<GitActor>,
    pub nonce_cache_actor: ActorRef<NonceCacheActor>,
    pub nonce_cleanup_actor: ActorRef<NonceCleanupActor>,
    pub github_project_validator: ActorRef<GitHubProjectValidator>,
    pub signers_initialiser: ActorRef<SignersInitialiser>,
}

pub async fn init_state(git_repo_path: std::path::PathBuf) -> AppState {
    let git_actor = GitActor::spawn(git_repo_path.clone());

    // Initialize nonce cache with database path
    // FIXME: support taking the dir for the nonce db from env var
    let nonce_db_path = git_repo_path.join(".app_cache").join(NONCE_CACHE_DB);
    let nonce_cache_actor = NonceCacheActor::spawn(nonce_db_path.clone());
    let nonce_cleanup_actor = NonceCleanupActor::spawn(nonce_db_path);

    let github_project_authenticator = GitHubProjectValidator::spawn(());
    let signers_initialiser = SignersInitialiser::spawn(());

    AppState {
        git_repo_path,
        git_actor,
        nonce_cache_actor,
        nonce_cleanup_actor,
        github_project_validator: github_project_authenticator,
        signers_initialiser,
    }
}
