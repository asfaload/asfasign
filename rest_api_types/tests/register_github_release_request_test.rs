//! Tests for RegisterGitHubReleaseRequest
//!
//! This module tests URL validation and deserialization of GitHub release URLs.

use rest_api_types::models::RegisterGitHubReleaseRequest;

#[test]
fn test_deserialize_valid_full_url() {
    let json = r#"{
        "release_url": "https://github.com/owner/repo/releases/tag/v1.0.0"
    }"#;

    let result: Result<RegisterGitHubReleaseRequest, _> = serde_json::from_str(json);

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

    let result: Result<RegisterGitHubReleaseRequest, _> = serde_json::from_str(json);

    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("Invalid URL"));
}

#[test]
fn test_deserialize_non_github_url() {
    let json = r#"{
        "release_url": "https://gitlab.com/owner/repo/releases/tag/v1.0.0"
    }"#;

    let result: Result<RegisterGitHubReleaseRequest, _> = serde_json::from_str(json);

    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("github.com"));
}

#[test]
fn test_deserialize_missing_releases() {
    let json = r#"{
        "release_url": "https://github.com/owner/repo/tag/v1.0.0"
    }"#;

    let result: Result<RegisterGitHubReleaseRequest, _> = serde_json::from_str(json);

    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("releases"));
}

#[test]
fn test_deserialize_missing_tag() {
    let json = r#"{
        "release_url": "https://github.com/owner/repo/releases/v1.0.0"
    }"#;

    let result: Result<RegisterGitHubReleaseRequest, _> = serde_json::from_str(json);

    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("tag"), "got {}", error);
}

#[test]
fn test_deserialize_missing_tag_value() {
    let json = r#"{
        "release_url": "https://github.com/owner/repo/releases/tag/"
    }"#;

    let result: Result<RegisterGitHubReleaseRequest, _> = serde_json::from_str(json);

    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("tag"));
}

#[test]
fn test_deserialize_too_short_path() {
    let json = r#"{
        "release_url": "https://github.com/owner/releases/tag/v1.0.0"
    }"#;

    let result: Result<RegisterGitHubReleaseRequest, _> = serde_json::from_str(json);

    assert!(result.is_err());
    let error = result.unwrap_err().to_string();
    assert!(error.contains("Invalid GitHub release URL structure"));
}

#[test]
fn test_serialize_and_roundtrip() {
    let json = r#"{
        "release_url": "https://github.com/owner/repo/releases/tag/v2.5.0"
    }"#;

    let deserialized: RegisterGitHubReleaseRequest = serde_json::from_str(json).unwrap();
    let serialized = serde_json::to_string(&deserialized).unwrap();

    let result: RegisterGitHubReleaseRequest = serde_json::from_str(&serialized).unwrap();
    assert_eq!(result.release_url, deserialized.release_url);
}

#[test]
fn test_new_constructor_valid() {
    let result = RegisterGitHubReleaseRequest::new(
        "https://github.com/owner/repo/releases/tag/v1.0.0".to_string(),
    );

    assert!(result.is_ok());
    let request = result.unwrap();
    assert_eq!(
        request.release_url.as_str(),
        "https://github.com/owner/repo/releases/tag/v1.0.0"
    );
}

#[test]
fn test_new_constructor_invalid_url() {
    let result = RegisterGitHubReleaseRequest::new("not-a-url".to_string());

    assert!(result.is_err());
    match result.unwrap_err() {
        rest_api_types::errors::ApiError::InvalidGitHubUrl(msg) => {
            assert!(msg.contains("Invalid URL"));
        }
        _ => panic!("Expected InvalidGitHubUrl error"),
    }
}

#[test]
fn test_new_constructor_non_github() {
    let result = RegisterGitHubReleaseRequest::new(
        "https://gitlab.com/owner/repo/releases/tag/v1.0.0".to_string(),
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        rest_api_types::errors::ApiError::InvalidGitHubUrl(msg) => {
            assert!(msg.contains("github.com"));
        }
        _ => panic!("Expected InvalidGitHubUrl error"),
    }
}

#[test]
fn test_new_constructor_missing_releases() {
    let result =
        RegisterGitHubReleaseRequest::new("https://github.com/owner/repo/tag/v1.0.0".to_string());

    assert!(result.is_err());
    match result.unwrap_err() {
        rest_api_types::errors::ApiError::InvalidGitHubUrl(msg) => {
            assert!(msg.contains("releases"));
        }
        _ => panic!("Expected InvalidGitHubUrl error"),
    }
}

#[test]
fn test_release_url_with_subdomain() {
    let json = r#"{
        "release_url": "https://github.example.org/owner/repo/releases/tag/v1.0.0"
    }"#;

    let result: Result<RegisterGitHubReleaseRequest, _> = serde_json::from_str(json);

    match result {
        Ok(_v) => panic!("Sholud only accept github.com urls"),
        Err(e) => {
            if !e.to_string().contains("Only github.com URLs are supported") {
                panic!("Expected Only github.com URLs are supported, but got {}", e)
            }
        }
    }
}

#[test]
fn test_release_url_with_nested_namespace() {
    let json = r#"{
        "release_url": "https://github.com/org/team/repo/releases/tag/v1.0.0"
    }"#;

    let result: Result<RegisterGitHubReleaseRequest, _> = serde_json::from_str(json);

    assert!(result.is_ok());
    let request = result.unwrap();
    assert_eq!(
        request.release_url.as_str(),
        "https://github.com/org/team/repo/releases/tag/v1.0.0"
    );
}

#[test]
fn test_release_url_with_query_params() {
    let json = r#"{
        "release_url": "https://github.com/owner/repo/releases/tag/v1.0.0?param=value"
    }"#;

    let result: Result<RegisterGitHubReleaseRequest, _> = serde_json::from_str(json);

    // Should be valid since path segments are correct
    assert!(result.is_ok());
}

#[test]
fn test_release_url_with_trailing_slash() {
    let json = r#"{
        "release_url": "https://github.com/owner/repo/releases/tag/v1.0.0/"
    }"#;

    let result: Result<RegisterGitHubReleaseRequest, _> = serde_json::from_str(json);

    match result {
        Ok(v) => assert_eq!(
            v.release_url.to_string(),
            "https://github.com/owner/repo/releases/tag/v1.0.0/"
        ),
        Err(e) => panic!("{}", e),
    }
}
