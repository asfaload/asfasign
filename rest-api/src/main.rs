use env_logger::Builder;
use log::LevelFilter;
use rest_api::server::run_server;

use rest_api::environment::init_env;
use rest_api::error::ApiError;

#[tokio::main]
async fn main() -> Result<(), ApiError> {
    // Initialize logging
    Builder::new().filter_level(LevelFilter::Info).init();

    let env = init_env()?;

    run_server(env).await
}
