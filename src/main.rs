use moidc::generate_router;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();


    let app = generate_router(moidc::settings::Settings {
        base_url: "http://localhost:3000".to_string(),
    }).await;

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
