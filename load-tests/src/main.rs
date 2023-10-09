use std::time::Duration;

use goose::prelude::*;
use goose_eggs::{validate_and_load_static_assets, Validate};
use reqwest::{header::CONTENT_TYPE, Body};

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    GooseAttack::initialize()?
        .register_scenario(
            scenario!("simple_mpc_public_key").register_transaction(transaction!(mpc_public_key)),
        )
        .execute()
        .await?;

    Ok(())
}

async fn mpc_public_key(user: &mut GooseUser) -> TransactionResult {
    let request_builder = user
        .get_request_builder(&GooseMethod::Post, "mpc_public_key")?
        .body(Body::from("{}"))
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
