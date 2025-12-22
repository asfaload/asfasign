use std::path::{Path, PathBuf};

use kameo::actor::{ActorRef, Spawn};

use crate::actors::{
    git_actor::GitActor, nonce_cache_actor::NONCE_CACHE_DB, nonce_cache_actor::NonceCacheActor,
    nonce_cleanup_actor::NonceCleanupActor,
};

#[derive(Clone)]
pub struct AppState {
    pub git_repo_path: PathBuf,
    pub git_actor: ActorRef<GitActor>,
    pub nonce_cache_actor: ActorRef<NonceCacheActor>,
    pub nonce_cleanup_actor: ActorRef<NonceCleanupActor>,
}

pub fn init_state<P: AsRef<Path>>(git_repo_path_in: P) -> AppState {
    let git_repo_path = git_repo_path_in.as_ref().to_path_buf();
    let git_actor = GitActor::spawn(git_repo_path.clone());

    // Initialize nonce cache with database path
    // FIXME: support taking the dir for the nonce db from env var
    let nonce_db_path = git_repo_path.join(".app_cache").join(NONCE_CACHE_DB);
    let nonce_cache_actor = NonceCacheActor::spawn(nonce_db_path.clone());
    let nonce_cleanup_actor = NonceCleanupActor::spawn(nonce_db_path);

    AppState {
        git_repo_path,
        git_actor,
        nonce_cache_actor,
        nonce_cleanup_actor,
    }
}
