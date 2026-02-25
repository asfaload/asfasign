use super::ForgeTrait;

pub(super) struct GitlabForge;

impl ForgeTrait for GitlabForge {
    fn translate_download_to_release_path(&self, path: &str) -> String {
        // GitLab URLs already use the release path directly.
        // Unlike GitHub (/releases/download/ -> /releases/tag/),
        // GitLab stores at /-/releases/tag/ which matches the URL structure.
        path.to_string()
    }
}
