use std::sync::Arc;

use axum::{
    extract::{Query, Request},
    http::StatusCode,
    response::Redirect,
    routing::{any, get, post},
    Extension, Form, Json, Router,
};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;

use chrono::{Duration, Utc};
use openidconnect::{
    core::{
        CoreIdToken, CoreIdTokenClaims, CoreIdTokenFields, CoreJsonWebKey, CoreJsonWebKeySet,
        CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreResponseType, CoreRsaPrivateSigningKey,
        CoreSubjectIdentifierType, CoreTokenResponse, CoreTokenType,
    },
    AccessToken, Audience, AuthUrl, EmptyAdditionalClaims, EmptyAdditionalProviderMetadata,
    EmptyExtraTokenFields, EndUserEmail, IssuerUrl, JsonWebKeyId, JsonWebKeySetUrl, Nonce,
    ResponseTypes, StandardClaims, SubjectIdentifier, TokenUrl,
};
use serde::{Deserialize, Serialize};

pub mod settings;

struct State {
    settings: settings::Settings,
    rsa_private_key: RsaPrivateKey,
}

pub async fn generate_router(settings: settings::Settings) -> Router {

    use tower_http::trace::TraceLayer;

    let private = tokio::fs::read_to_string("./private-key.pem")
        .await
        .unwrap();

    let rsa_private_key = RsaPrivateKey::from_pkcs8_pem(&private).unwrap();

    let state = State {
        settings,
        rsa_private_key,
    };

    let app = Router::new()
        .route("/", get(root))
        .route("/authorize", get(authorize))
        .route("/token", post(token_handler))
        .route("/.well-known/jwks", get(jwks))
        .route(
            "/.well-known/openid-configuration",
            get(well_known_openid_configuration),
        )
        .layer(Extension(Arc::new(state)))
        .layer(TraceLayer::new_for_http());

    app
}

async fn root() -> &'static str {
    "Hello, World!"
}
#[axum::debug_handler]
async fn token_handler(
    Extension(state): Extension<Arc<State>>,
    f: Form<TokenRequest>,
) -> Json<CoreTokenResponse> {
    token_handler_int(&*state, f).await.unwrap()
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    code: String,
    code_verifier: String,
    grant_type: String,
    redirect_uri: String,
}

async fn token_handler_int(
    state: &State,
    Form(token_request): Form<TokenRequest>,
) -> anyhow::Result<Json<CoreTokenResponse>> {
    let secret_document = state
        .rsa_private_key
        .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();

    let base_url = &state.settings.base_url;

    let code_state = CodeState::from_url_query_parameter(&token_request.code);

    let access_token = AccessToken::new("some_secret".to_string());

    let token_claims = CoreIdTokenClaims::new(
        IssuerUrl::new(base_url.to_string())?,
        vec![Audience::new(code_state.client_id)],
        Utc::now() + Duration::seconds(300),
        Utc::now(),
        StandardClaims::new(SubjectIdentifier::new(
            "5f83e0ca-2b8e-4e8c-ba0a-f80fe9bc3632".to_string(),
        ))
        .set_email(Some(EndUserEmail::new(code_state.user_to_log_in)))
        .set_email_verified(Some(true)),
        EmptyAdditionalClaims {},
    );

    let token_claims = token_claims.set_nonce(Some(Nonce::new(code_state.nonce)));

    let id_token = CoreIdToken::new(
        token_claims,
        &CoreRsaPrivateSigningKey::from_pem(&secret_document, None)
            .expect("Invalid RSA private key"),
        CoreJwsSigningAlgorithm::RsaSsaPssSha256,
        Some(&access_token),
        None,
    )?;

    Ok(Json(CoreTokenResponse::new(
        access_token,
        CoreTokenType::Bearer,
        CoreIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
    )))
}

#[derive(Deserialize, Debug)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
    redirect_uri: String,
    scope: String,
    nonce: String,
    login_hint: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CodeState {
    nonce: String,
    user_to_log_in: String,
    client_id: String,
}

impl CodeState {
    fn from_url_query_parameter(s: &str) -> Self {
        use base64::prelude::*;
        let b = BASE64_URL_SAFE.decode(s).unwrap();
        let s = String::from_utf8(b).unwrap();
        serde_json::from_str(&s).unwrap()
    }

    fn to_url_query_parameter(&self) -> String {
        let json = serde_json::to_string(&self).unwrap();
        use base64::prelude::*;
        let b = BASE64_URL_SAFE.encode(json.as_bytes());
        b
    }
}

async fn authorize(Query(auth): Query<AuthorizeQuery>) -> Redirect {
    tracing::warn!("Authorizeing");
    // Do something and redirect back, with a code!
    // In order to be stateless, we must pass some state along here, so we can
    // give a proper response once they call to exchange the token for proper idtoken etc.
    // * Nonce
    // * The login_hint user we're logging in
    // * Code challenge method?

    // We must also pass along some state back immediately here:
    // * State
    let code = CodeState {
        nonce: auth.nonce,
        user_to_log_in: auth.login_hint,
        client_id: auth.client_id,
    }
    .to_url_query_parameter();
    Redirect::to(&format!(
        "{}?state={}&code={}",
        auth.redirect_uri, auth.state, code
    ))
}

async fn jwks(Extension(state): Extension<Arc<State>>) -> Json<CoreJsonWebKeySet> {
    let rsa_private = &state.rsa_private_key;

    let key = CoreJsonWebKey::new_rsa(
        rsa_private.n().to_bytes_be(),
        rsa_private.e().to_bytes_be(),
        None,
    );

    let jwks = CoreJsonWebKeySet::new(vec![key]);

    Json(jwks)
}

async fn well_known_openid_configuration(
    Extension(state): Extension<Arc<State>>,
) -> Json<CoreProviderMetadata> {
    inner_well_known_openid_configuration(&*state)
        .await
        .unwrap()
}
async fn inner_well_known_openid_configuration(
    state: &State,
) -> anyhow::Result<Json<CoreProviderMetadata>> {
    let base_url = &state.settings.base_url;

    let provider_metadata = CoreProviderMetadata::new(
        // Parameters required by the OpenID Connect Discovery spec.
        IssuerUrl::new(format!("{base_url}"))?,
        AuthUrl::new(format!("{base_url}/authorize"))?,
        JsonWebKeySetUrl::new(format!("{base_url}/.well-known/jwks"))?,
        vec![
            // Recommended: support the code flow.
            ResponseTypes::new(vec![CoreResponseType::Code]),
        ],
        vec![CoreSubjectIdentifierType::Pairwise],
        // Support the RS256 signature algorithm.
        vec![CoreJwsSigningAlgorithm::RsaSsaPssSha256],
        EmptyAdditionalProviderMetadata {},
    )
    // Specify the token endpoint (required for the code flow).
    .set_token_endpoint(Some(TokenUrl::new(format!("{base_url}/token"))?));

    Ok(Json(provider_metadata))
}
