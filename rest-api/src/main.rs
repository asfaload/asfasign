use rest_api::config::get_config;
use rest_api::server::run_server;
use rest_api::traces::init_tracing;
use rest_api_types::errors::ApiError;

#[tokio::main]
async fn main() -> Result<(), ApiError> {
    let config = get_config()?;
    init_tracing(&config.log_level);
    run_server(&config).await
}
