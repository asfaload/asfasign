//! Tests for RegisterAssetsRequest
//!
//! This module tests serialization and deserialization of the RegisterAssetsRequest type,
//! which supports two mutually exclusive modes: github_release_url or csum_files.

use rest_api_types::RegisterAssetsRequest;

#[test]
fn test_deserialize_github_release_url_only() {
    let json = r#"{
        "github_release_url": "https://github.com/owner/repo/releases/tag/v1.0.0"
    }"#;

    let request: RegisterAssetsRequest = serde_json::from_str(json).unwrap();
    assert_eq!(
        request.github_release_url.as_deref(),
        Some("https://github.com/owner/repo/releases/tag/v1.0.0")
    );
    assert!(request.csum_files.is_none());
}

#[test]
fn test_deserialize_csum_files_only() {
    let json = r#"{
        "csum_files": [
            "https://files.example.com/releases/v1.0/SHA256SUMS",
            "https://files.example.com/releases/v1.0/SHA512SUMS"
        ]
    }"#;

    let request: RegisterAssetsRequest = serde_json::from_str(json).unwrap();
    assert!(request.github_release_url.is_none());
    let csum_files = request.csum_files.unwrap();
    assert_eq!(csum_files.len(), 2);
    assert_eq!(
        csum_files[0],
        "https://files.example.com/releases/v1.0/SHA256SUMS"
    );
}

#[test]
fn test_deserialize_both_fields_present() {
    let json = r#"{
        "github_release_url": "https://github.com/owner/repo/releases/tag/v1.0.0",
        "csum_files": ["https://files.example.com/releases/v1.0/SHA256SUMS"]
    }"#;

    // Both fields can be deserialized (mutual exclusivity is enforced at the handler level)
    let request: RegisterAssetsRequest = serde_json::from_str(json).unwrap();
    assert!(request.github_release_url.is_some());
    assert!(request.csum_files.is_some());
}

#[test]
fn test_deserialize_neither_field_present() {
    let json = r#"{}"#;

    let request: RegisterAssetsRequest = serde_json::from_str(json).unwrap();
    assert!(request.github_release_url.is_none());
    assert!(request.csum_files.is_none());
}

#[test]
fn test_deserialize_empty_csum_files_array() {
    let json = r#"{
        "csum_files": []
    }"#;

    let request: RegisterAssetsRequest = serde_json::from_str(json).unwrap();
    assert!(request.github_release_url.is_none());
    assert_eq!(request.csum_files.unwrap().len(), 0);
}

#[test]
fn test_deserialize_single_csum_file() {
    let json = r#"{
        "csum_files": ["https://files.example.com/releases/v1.0/SHA256SUMS"]
    }"#;

    let request: RegisterAssetsRequest = serde_json::from_str(json).unwrap();
    assert!(request.github_release_url.is_none());
    assert_eq!(request.csum_files.unwrap().len(), 1);
}

#[test]
fn test_serialize_github_release_url_only() {
    let request = RegisterAssetsRequest {
        github_release_url: Some("https://github.com/owner/repo/releases/tag/v1.0.0".to_string()),
        csum_files: None,
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("github_release_url"));
    assert!(!json.contains("csum_files"));
}

#[test]
fn test_serialize_csum_files_only() {
    let request = RegisterAssetsRequest {
        github_release_url: None,
        csum_files: Some(vec![
            "https://files.example.com/releases/v1.0/SHA256SUMS".to_string(),
        ]),
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(!json.contains("github_release_url"));
    assert!(json.contains("csum_files"));
    assert!(json.contains("SHA256SUMS"));
}

#[test]
fn test_serialize_neither_field_omits_both() {
    let request = RegisterAssetsRequest {
        github_release_url: None,
        csum_files: None,
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(!json.contains("github_release_url"));
    assert!(!json.contains("csum_files"));
    assert_eq!(json, "{}");
}

#[test]
fn test_roundtrip_github_release_url() {
    let original = RegisterAssetsRequest {
        github_release_url: Some("https://github.com/owner/repo/releases/tag/v1.0.0".to_string()),
        csum_files: None,
    };

    let json = serde_json::to_string(&original).unwrap();
    let deserialized: RegisterAssetsRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(original.github_release_url, deserialized.github_release_url);
    assert_eq!(original.csum_files, deserialized.csum_files);
}

#[test]
fn test_roundtrip_csum_files() {
    let original = RegisterAssetsRequest {
        github_release_url: None,
        csum_files: Some(vec![
            "https://files.example.com/releases/v1.0/SHA256SUMS".to_string(),
            "https://files.example.com/releases/v1.0/SHA512SUMS".to_string(),
        ]),
    };

    let json = serde_json::to_string(&original).unwrap();
    let deserialized: RegisterAssetsRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(original.github_release_url, deserialized.github_release_url);
    assert_eq!(original.csum_files, deserialized.csum_files);
}
