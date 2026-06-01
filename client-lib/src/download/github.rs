use super::ForgesPathMethods;

pub(super) struct GithubForge;

impl ForgesPathMethods for GithubForge {
    fn translate_download_to_release_path(&self, path: &str) -> String {
        path.replace("/releases/download/", "/releases/tag/")
    }
}
