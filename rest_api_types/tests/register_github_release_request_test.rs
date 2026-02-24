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

#[test]
fn test_deserialize_with_forge_type_github() {
    let json = r#"{
        "release_url": "https://github.com/owner/repo/releases/tag/v1.0.0",
        "forge_type": "github"
    }"#;

    let result: Result<RegisterReleaseRequest, _> = serde_json::from_str(json);
    assert!(result.is_ok());
    let request = result.unwrap();
    assert_eq!(request.forge_type.as_deref(), Some("github"));
    assert_eq!(
        request.release_url.as_str(),
        "https://github.com/owner/repo/releases/tag/v1.0.0"
    );
}

#[test]
fn test_deserialize_with_forge_type_skips_github_validation() {
    // A non-github URL would normally fail validation, but with forge_type set
    // the GitHub URL validation is skipped
    let json = r#"{
        "release_url": "https://my-gitlab.example.com/group/project/-/releases/v1.0.0",
        "forge_type": "gitlab"
    }"#;

    let result: Result<RegisterReleaseRequest, _> = serde_json::from_str(json);
    assert!(result.is_ok());
    let request = result.unwrap();
    assert_eq!(request.forge_type.as_deref(), Some("gitlab"));
    assert_eq!(
        request.release_url.as_str(),
        "https://my-gitlab.example.com/group/project/-/releases/v1.0.0"
    );
}

#[test]
fn test_deserialize_without_forge_type_still_validates_github() {
    // Without forge_type, the existing GitHub URL validation still applies
    let json = r#"{
        "release_url": "https://my-gitlab.example.com/group/project/-/releases/v1.0.0"
    }"#;

    let result: Result<RegisterReleaseRequest, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn test_deserialize_forge_type_is_none_when_omitted() {
    let json = r#"{
        "release_url": "https://github.com/owner/repo/releases/tag/v1.0.0"
    }"#;

    let result: Result<RegisterReleaseRequest, _> = serde_json::from_str(json);
    assert!(result.is_ok());
    let request = result.unwrap();
    assert!(request.forge_type.is_none());
}

#[test]
fn test_serialize_with_forge_type() {
    let request = RegisterReleaseRequest {
        release_url: url::Url::parse("https://github.com/owner/repo/releases/tag/v1.0.0").unwrap(),
        forge_type: Some("github".to_string()),
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains("forge_type"));
    assert!(json.contains("github"));
}

#[test]
fn test_serialize_without_forge_type_omits_field() {
    let request = RegisterReleaseRequest {
        release_url: url::Url::parse("https://github.com/owner/repo/releases/tag/v1.0.0").unwrap(),
        forge_type: None,
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(!json.contains("forge_type"));
}

#[test]
fn test_deserialize_duplicate_forge_type_rejected() {
    // Manually construct JSON with duplicate forge_type field
    // serde_json by default uses the last value, but our custom deserializer rejects duplicates
    let json = r#"{
        "release_url": "https://github.com/owner/repo/releases/tag/v1.0.0",
        "forge_type": "github",
        "forge_type": "gitlab"
    }"#;

    let result: Result<RegisterReleaseRequest, _> = serde_json::from_str(json);
    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("duplicate"));
}

#[test]
fn test_deserialize_unknown_field_rejected() {
    let json = r#"{
        "release_url": "https://github.com/owner/repo/releases/tag/v1.0.0",
        "unknown_field": "value"
    }"#;

    let result: Result<RegisterReleaseRequest, _> = serde_json::from_str(json);
    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("unknown field"));
}

#[test]
fn test_new_method_sets_forge_type_to_none() {
    let result = RegisterReleaseRequest::new(
        "https://github.com/owner/repo/releases/tag/v1.0.0".to_string(),
    );

    assert!(result.is_ok());
    let request = result.unwrap();
    assert!(request.forge_type.is_none());
}
