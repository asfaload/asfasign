use super::ForgeTrait;

pub(super) struct GithubForge;

impl ForgeTrait for GithubForge {
    fn translate_download_to_release_path(path: &str) -> String {
        path.replace("/releases/download/", "/releases/tag/")
    }
}
