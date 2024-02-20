use std::sync::Arc;

use axum::{extract::Query, routing::get, Extension, Router};
use moidc::{generate_router, settings::Settings};
use rand::{distributions::DistString, Rng};
use serde::Deserialize;

#[tokio::test]
async fn test_client() -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = generate_router(Settings {
        base_url: format!("http://localhost:{}", addr.port()),
    })
    .await;

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    #[derive(Debug, Deserialize)]
    struct CodeQuery {
        code: String,
    }

    let user_to_log_in = "bob_the_builder@mailing.com";

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<CodeQuery>();
    let our_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let our_addr = our_listener.local_addr().unwrap();

    async fn handle_it(
        Extension(tx): Extension<Arc<tokio::sync::mpsc::UnboundedSender<CodeQuery>>>,
        Query(code_query): Query<CodeQuery>,
    ) {
        tracing::warn!("RECEIVED!");
        tx.send(code_query).unwrap();
    }

    let router = Router::new()
        .route("/", get(handle_it))
        .layer(Extension(Arc::new(tx)));
    tokio::spawn(async move {
        axum::serve(our_listener, router).await.unwrap();
    });

    use anyhow::anyhow;
    use openidconnect::core::{
        CoreAuthenticationFlow, CoreClient, CoreProviderMetadata, CoreResponseType,
        CoreUserInfoClaims,
    };
    use openidconnect::{
        AccessTokenHash, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
        IssuerUrl, Nonce, PkceCodeChallenge, RedirectUrl, Scope,
    };

    use openidconnect::reqwest::async_http_client;

    // Use OpenID Connect Discovery to fetch the provider metadata.
    use openidconnect::{OAuth2TokenResponse, TokenResponse};
    let provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new(format!("http://localhost:{}", addr.port()))?,
        async_http_client,
    )
    .await?;

    // Create an OpenID Connect client by specifying the client ID, client secret, authorization URL
    // and token URL.
    let client_id = rand::distributions::Alphanumeric.sample_string(&mut rand::thread_rng(), 32);
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(client_id),
        Some(ClientSecret::new("client_secret".to_string())),
    )
    // Set the URL the user will be redirected to after the authorization process.
    .set_redirect_uri(RedirectUrl::new(format!(
        "http://localhost:{}",
        our_addr.port()
    ))?);

    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    let (auth_url, csrf_token, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        // Set the desired scopes.
        .add_scope(Scope::new("read".to_string()))
        .add_scope(Scope::new("write".to_string()))
        // Set the PKCE code challenge.
        .set_pkce_challenge(pkce_challenge)
        .url();

    // This is the URL you should redirect the user to, in order to trigger the authorization
    // process.
    let full_url = format!("{}&login_hint={}", auth_url, user_to_log_in);
    println!("Auth URL: {}", full_url);

    reqwest::get(full_url).await.unwrap();

    let re = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
        .await
        .unwrap()
        .unwrap();

    // Once the user has been redirected to the redirect URL, you'll have access to the
    // authorization code. For security reasons, your code should verify that the `state`
    // parameter returned by the server matches `csrf_state`.

    // Now you can exchange it for an access token and ID token.
    let token_response = client
        .exchange_code(AuthorizationCode::new(re.code))
        // Set the PKCE code verifier.
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await?;

    tracing::warn!(token_response = ?token_response, "Got the token response");

    // Extract the ID token claims after verifying its authenticity and nonce.
    let id_token = token_response
        .id_token()
        .ok_or_else(|| anyhow!("Server did not return an ID token"))?;

    tracing::warn!(id_token = ?id_token, "ID token response");

    let claims = id_token.claims(&client.id_token_verifier(), &nonce)?;
    tracing::warn!(claims = ?claims, "Claims");

    // Verify the access token hash to ensure that the access token hasn't been substituted for
    // another user's.
    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash =
            AccessTokenHash::from_token(token_response.access_token(), &id_token.signing_alg()?)?;
        if actual_access_token_hash != *expected_access_token_hash {
            return Err(anyhow!("Invalid access token"));
        }
    }

    // The authenticated user's identity is now available. See the IdTokenClaims struct for a
    // complete listing of the available claims.
    println!(
        "User {} with e-mail address {} has authenticated successfully",
        claims.subject().as_str(),
        claims
            .email()
            .map(|email| email.as_str())
            .unwrap_or("<not provided>"),
    );

    assert_eq!(claims.email().unwrap().as_str(), user_to_log_in);
    Ok(())
}
