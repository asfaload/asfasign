//! Tests for RegisterReleaseRequest
//!
//! This module tests URL validation and deserialization of GitHub release URLs.

use rest_api_types::models::RegisterReleaseRequest;

#[test]
fn test_deserialize_valid_full_url() {
    let json = r#"{
        "release_url": "https://github.com/owner/repo/releases/tag/v1.0.0"
    }"#;

    let result: Result<RegisterReleaseRequest, _> = serde_json::from_str(json);

    assert!(result.is_ok());
    let request = result.unwrap();
    assert_eq!(
        request.release_url.as_str(),
        "https://github.com/owner/repo/releases/tag/v1.0.0"
    );
}

#[test]
fn test_deserialize_invalid_url_format() {
    let json = r#"{
        "release_url": "not-a-url"
    }"#;

    let result: Result<RegisterReleaseRequest, _> = serde_json::from_str(json);

    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("Invalid URL"));
}

#[test]
fn test_deserialize_non_github_url() {
    let json = r#"{
        "release_url": "https://gitlab.com/owner/repo/releases/tag/v1.0.0"
    }"#;

    let result: Result<RegisterReleaseRequest, _> = serde_json::from_str(json);

    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("github.com"));
}

#[test]
fn test_deserialize_missing_releases() {
    let json = r#"{
        "release_url": "https://github.com/owner/repo/tag/v1.0.0"
    }"#;

    let result: Result<RegisterReleaseRequest, _> = serde_json::from_str(json);

    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("/releases/"));
}

#[test]
fn test_deserialize_missing_all() {
    let json = r#"{
        "release_url": "https://github.com/owner/repo/releases/"
    }"#;

    let result: Result<RegisterReleaseRequest, _> = serde_json::from_str(json);

    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("Invalid"));
}

#[test]
fn test_deserialize_empty_owner() {
    let json = r#"{
        "release_url": "https://github.com//repo/releases/tag/v1.0.0"
    }"#;

    let result: Result<RegisterReleaseRequest, _> = serde_json::from_str(json);

    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("empty"));
}

#[test]
fn test_deserialize_case_sensitivity() {
    let json = r#"{
        "release_url": "https://github.com/owner/repo/releases/TAG/v1.0.0"
    }"#;

    let result: Result<RegisterReleaseRequest, _> = serde_json::from_str(json);

    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("Invalid GitHub release URL structure"));
}

#[test]
fn test_missing_releases_segment() {
    let json = r#"{
        "release_url": "https://github.com/owner/repo/v1.0.0"
    }"#;

    let result: Result<RegisterReleaseRequest, _> = serde_json::from_str(json);

    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("/releases/"));
}

#[test]
fn test_new_method_with_valid_url() {
    let result = RegisterReleaseRequest::new(
        "https://github.com/testowner/testrepo/releases/tag/v2.0.0".to_string(),
    );

    assert!(result.is_ok());
    let request = result.unwrap();
    assert_eq!(
        request.release_url.as_str(),
        "https://github.com/testowner/testrepo/releases/tag/v2.0.0"
    );
}

#[test]
fn test_new_method_with_invalid_url() {
    let result = RegisterReleaseRequest::new("not-a-url".to_string());

    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("Invalid URL"));
}

#[test]
fn test_new_method_with_invalid_github_url() {
    let result =
        RegisterReleaseRequest::new("https://github.com/testowner/releases/tag/v1.0.0".to_string());

    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(!error.is_empty());
}
