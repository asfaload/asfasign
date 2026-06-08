use core::fmt;

use serde::{Deserialize, Serialize};

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct FileChecksum {
    pub file_name: String,
    pub algo: HashAlgorithm,
    pub source: String,
    pub hash: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AsfaloadIndex {
    pub mirrored_on: chrono::DateTime<chrono::Utc>,
    pub published_on: chrono::DateTime<chrono::Utc>,
    pub version: i32,
    pub published_files: Vec<FileChecksum>,
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
    Sha1,
    Md5,
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            HashAlgorithm::Sha256 => "SHA-256",
            HashAlgorithm::Sha512 => "SHA-512",
            HashAlgorithm::Sha1 => "SHA-1",
            HashAlgorithm::Md5 => "MD5",
        };
        write!(f, "{}", s)
    }
}
