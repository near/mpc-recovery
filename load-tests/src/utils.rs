use chrono::Utc;
use goose::prelude::{GooseMethod, GooseRequest, GooseUser, TransactionResult};
use goose_eggs::{validate_and_load_static_assets, Validate};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use near_primitives::utils::generate_random_string;
use reqwest::{header::CONTENT_TYPE, Body};
use std::time::Duration;

use crate::primitives::IdTokenClaims;

// TODO: try using existing function
pub fn create_jwt_token(
    secret_rsa_pem_key: &str,
    aud: &str,
    iss: &str,
    sub: Option<&str>,
) -> String {
    let rnd_sub = generate_random_string(10);
    let sub = sub.unwrap_or_else(|| &rnd_sub);

    let my_claims = IdTokenClaims {
        iss: iss.to_owned(),
        sub: sub.to_owned(),
        aud: aud.to_owned(),
        exp: (Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
    };

    let private_key_der = secret_rsa_pem_key.as_bytes().to_vec();

    let token = encode(
        &Header::new(Algorithm::RS256),
        &my_claims,
        &EncodingKey::from_rsa_pem(&private_key_der).unwrap(),
    )
    .expect("Failed to encode jwt token");

    token.to_string()
}

pub async fn build_send_and_check_request(
    user: &mut GooseUser,
    path: &str,
    body_json: &str,
) -> TransactionResult {
    let body = Body::from(body_json.to_owned());
    let request_builder = user
        .get_request_builder(&GooseMethod::Post, path)?
        .body(body)
        .header(CONTENT_TYPE, "application/json")
        .timeout(Duration::from_secs(10));

    let goose_request = GooseRequest::builder()
        .set_request_builder(request_builder)
        .build();

    let goose_responce = user.request(goose_request).await?;

    let validate = &Validate::builder().status(200).build();
    validate_and_load_static_assets(user, goose_responce, validate).await?;

    Ok(())
}
