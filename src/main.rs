use std::net::Ipv4Addr;

use config::Config;
use moidc::{generate_router, settings::Settings};
use tokio::signal;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let settings = read_settings();
    let port = settings.port;

    tracing::info!(port, "starting application...");

    let app = generate_router(settings).await;

    let listener = tokio::net::TcpListener::bind((Ipv4Addr::new(0, 0, 0, 0), port))
        .await
        .unwrap();

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

fn read_settings() -> Settings {
    let settings_path = std::env::var("MOIDC_SETTINGS").unwrap_or("./settings.yaml".to_string());
    let settings = Config::builder()
        .add_source(config::File::with_name(&settings_path))
        .add_source(config::Environment::with_prefix("MOIDC"))
        .build()
        .unwrap();

    settings.try_deserialize().unwrap()
}
