//! Tests for RegisterDirectoryRequest and RegisterDirectoryResponse serialization.

use rest_api_types::models::{RegisterDirectoryRequest, RegisterDirectoryResponse};

#[test]
fn test_serialize_register_directory_request() {
    let request = RegisterDirectoryRequest {
        urls: vec![
            "https://files.example.com/v1/app.tar.gz".to_string(),
            "https://files.example.com/v1/app.zip".to_string(),
        ],
    };

    let json = serde_json::to_string(&request).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let urls = parsed["urls"].as_array().unwrap();
    assert_eq!(urls.len(), 2);
    assert_eq!(urls[0], "https://files.example.com/v1/app.tar.gz");
    assert_eq!(urls[1], "https://files.example.com/v1/app.zip");
}

#[test]
fn test_deserialize_register_directory_request() {
    let json = r#"{
        "urls": [
            "https://files.example.com/v1/app.tar.gz",
            "https://files.example.com/v1/app.zip"
        ]
    }"#;

    let request: RegisterDirectoryRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.urls.len(), 2);
    assert_eq!(request.urls[0], "https://files.example.com/v1/app.tar.gz");
    assert_eq!(request.urls[1], "https://files.example.com/v1/app.zip");
}

#[test]
fn test_deserialize_register_directory_request_empty_urls() {
    let json = r#"{"urls": []}"#;
    let request: RegisterDirectoryRequest = serde_json::from_str(json).unwrap();
    assert!(request.urls.is_empty());
}

#[test]
fn test_deserialize_register_directory_request_single_url() {
    let json = r#"{"urls": ["https://files.example.com/v1/app.tar.gz"]}"#;
    let request: RegisterDirectoryRequest = serde_json::from_str(json).unwrap();
    assert_eq!(request.urls.len(), 1);
}

#[test]
fn test_deserialize_register_directory_request_missing_urls() {
    let json = r#"{}"#;
    let result: Result<RegisterDirectoryRequest, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

#[test]
fn test_serialize_register_directory_response_with_path() {
    let response = RegisterDirectoryResponse {
        success: true,
        message: "Directory registered successfully".to_string(),
        index_file_path: Some("files.example.com/v1/asfaload.index.json".to_string()),
    };

    let json = serde_json::to_string(&response).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["success"], true);
    assert_eq!(parsed["message"], "Directory registered successfully");
    assert_eq!(
        parsed["index_file_path"],
        "files.example.com/v1/asfaload.index.json"
    );
}

#[test]
fn test_serialize_register_directory_response_without_path() {
    let response = RegisterDirectoryResponse {
        success: false,
        message: "Registration failed".to_string(),
        index_file_path: None,
    };

    let json = serde_json::to_string(&response).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["success"], false);
    assert!(parsed["index_file_path"].is_null());
}

#[test]
fn test_deserialize_register_directory_response() {
    let json = r#"{
        "success": true,
        "message": "OK",
        "index_file_path": "host/path/asfaload.index.json"
    }"#;

    let response: RegisterDirectoryResponse = serde_json::from_str(json).unwrap();
    assert!(response.success);
    assert_eq!(response.message, "OK");
    assert_eq!(
        response.index_file_path.unwrap(),
        "host/path/asfaload.index.json"
    );
}

#[test]
fn test_roundtrip_register_directory_request() {
    let original = RegisterDirectoryRequest {
        urls: vec![
            "https://a.com/dir/file1.bin".to_string(),
            "https://a.com/dir/file2.bin".to_string(),
            "https://a.com/dir/file3.bin".to_string(),
        ],
    };

    let json = serde_json::to_string(&original).unwrap();
    let deserialized: RegisterDirectoryRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(original.urls, deserialized.urls);
}

#[test]
fn test_roundtrip_register_directory_response() {
    let original = RegisterDirectoryResponse {
        success: true,
        message: "Done".to_string(),
        index_file_path: Some("path/to/index.json".to_string()),
    };

    let json = serde_json::to_string(&original).unwrap();
    let deserialized: RegisterDirectoryResponse = serde_json::from_str(&json).unwrap();

    assert_eq!(original.success, deserialized.success);
    assert_eq!(original.message, deserialized.message);
    assert_eq!(original.index_file_path, deserialized.index_file_path);
}
