use env_logger::Builder;
use log::LevelFilter;
use rest_api::config::get_config;
use rest_api::server::run_server;
use rest_api_types::errors::ApiError;

#[tokio::main]
async fn main() -> Result<(), ApiError> {
    // Initialize logging
    Builder::new().filter_level(LevelFilter::Info).init();

    let config = get_config()?;

    run_server(&config).await
}
