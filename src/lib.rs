use std::{collections::HashMap, sync::Arc};

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
        CoreGenderClaim, CoreIdToken, CoreIdTokenClaims, CoreIdTokenFields, CoreJsonWebKey,
        CoreJsonWebKeySet, CoreJsonWebKeyType, CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreResponseType, CoreRsaPrivateSigningKey,
        CoreSubjectIdentifierType, CoreTokenResponse, CoreTokenType,
    },
    AccessToken, Audience, AuthUrl, EmptyAdditionalClaims, EmptyAdditionalProviderMetadata,
    EmptyExtraTokenFields, EndUserEmail, IdToken, IdTokenClaims, IdTokenFields, IssuerUrl,
    JsonWebKeyId, JsonWebKeySetUrl, Nonce, ResponseTypes, StandardClaims, StandardTokenResponse,
    SubjectIdentifier, TokenUrl,
};
use serde::{ser::SerializeMap, Deserialize, Serialize};

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

#[axum::debug_handler]
async fn token_handler(
    Extension(state): Extension<Arc<State>>,
    f: Form<TokenRequest>,
) -> Json<MyTokenResponse> {
    token_handler_int(&*state, f).await.unwrap()
}

#[derive(Debug, Deserialize)]
struct TokenRequest {
    code: String,
    code_verifier: Option<String>,
    grant_type: Option<String>,
    redirect_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MyAdditionalClaims {
    groups: Vec<String>,
}

impl openidconnect::AdditionalClaims for MyAdditionalClaims {}

impl serde::Serialize for MyAdditionalClaims {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry("groups", &self.groups)?;
        map.end()
    }
}

type MyIdTokenClaims = IdTokenClaims<MyAdditionalClaims, CoreGenderClaim>;
type MyIdTokenFields = IdTokenFields<
    MyAdditionalClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;
type MyIdToken = IdToken<
    MyAdditionalClaims,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
    CoreJsonWebKeyType,
>;
type MyTokenResponse = StandardTokenResponse<MyIdTokenFields, CoreTokenType>;

#[tracing::instrument(skip(state))]
async fn token_handler_int(
    state: &State,
    Form(token_request): Form<TokenRequest>,
) -> anyhow::Result<Json<MyTokenResponse>> {
    let secret_document = state
        .rsa_private_key
        .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();

    let base_url = &state.settings.base_url;

    let code_state = CodeState::from_url_query_parameter(&token_request.code);

    let access_token = AccessToken::new("some_secret".to_string());

    let email = code_state.user_to_log_in;
    let (first, domain) = email.split_once('@').unwrap();
    let (normal_email, additional_things) = first.split_once('+').unwrap_or((first, ""));
    let reconstructed_email = format!("{}@{}", normal_email, domain);
    let mut groups = state
        .settings
        .per_user_settings
        .get(&reconstructed_email)
        .map(|pus| pus.groups.clone())
        .unwrap_or(vec![]);
    for additional in additional_things.split('+') {
        if let Some(group_name) = additional.strip_prefix("g.") {
            groups.push(group_name.to_string());
        }
    }

    let token_claims = MyIdTokenClaims::new(
        IssuerUrl::new(base_url.to_string())?,
        vec![Audience::new(code_state.client_id)],
        Utc::now() + Duration::seconds(300),
        Utc::now(),
        StandardClaims::new(SubjectIdentifier::new(
            // TODO: Make this some hash of the username? That way it's constant for the user
            uuid::Uuid::new_v4().as_hyphenated().to_string(),
        ))
        .set_email(Some(EndUserEmail::new(reconstructed_email)))
        .set_email_verified(Some(true)),
        MyAdditionalClaims { groups: vec![] },
    );

    let token_claims = token_claims.set_nonce(Some(Nonce::new(code_state.nonce)));

    let id_token = MyIdToken::new(
        token_claims,
        &CoreRsaPrivateSigningKey::from_pem(&secret_document, None)
            .expect("Invalid RSA private key"),
        CoreJwsSigningAlgorithm::RsaSsaPssSha256,
        Some(&access_token),
        Some(&openidconnect::AuthorizationCode::new(token_request.code)),
    )?;

    let token_response = MyTokenResponse::new(
        access_token,
        CoreTokenType::Bearer,
        MyIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
    );

    tracing::warn!(?token_response, "Sending the token response!");

    Ok(Json(token_response))
}

#[derive(Deserialize, Debug)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    state: String,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
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

#[tracing::instrument]
async fn authorize(Query(auth): Query<AuthorizeQuery>) -> Redirect {
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
        "{}?state={}&code={}&session_state=1234",
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
