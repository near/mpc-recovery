pub mod fastauth;
pub mod multichain;

use fastauth::{
    claim_oidc, mpc_public_key, new_account, prepare_user_credentials, sign, user_credentials,
};
use goose::prelude::*;
use tracing_subscriber::{filter, prelude::*};

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    let stdout_log = tracing_subscriber::fmt::layer().pretty();

    tracing_subscriber::registry()
        .with(stdout_log.with_filter(filter::LevelFilter::INFO))
        .init();

    GooseAttack::initialize()?
        .register_scenario(
            scenario!("fastAuthRegistration")
                .register_transaction(transaction!(prepare_user_credentials).set_sequence(1))
                .register_transaction(transaction!(claim_oidc).set_sequence(2))
                .register_transaction(transaction!(new_account).set_sequence(3)),
        )
        .register_scenario(
            scenario!("fastAuthRegistrationAndSign")
                .register_transaction(transaction!(prepare_user_credentials).set_sequence(1))
                .register_transaction(transaction!(claim_oidc).set_sequence(2))
                .register_transaction(transaction!(new_account).set_sequence(3))
                .register_transaction(transaction!(user_credentials).set_sequence(4))
                .register_transaction(
                    transaction!(sign)
                        .set_sequence(5)
                        .set_weight(1000) // In this scenario we are mostly testing /sign functionality
                        .expect("Failed to set weight"),
                ),
        )
        .register_scenario(
            scenario!("fastAuthSimpleClaimOidc")
                .register_transaction(transaction!(prepare_user_credentials).set_sequence(1))
                .register_transaction(
                    transaction!(claim_oidc)
                        .set_sequence(2)
                        .set_weight(100)
                        .expect("Failed to set weight"),
                ),
        )
        .register_scenario(
            scenario!("fastAuthSimpleUserCredentials")
                .register_transaction(transaction!(prepare_user_credentials).set_sequence(1))
                .register_transaction(transaction!(claim_oidc).set_sequence(2))
                .register_transaction(
                    transaction!(user_credentials)
                        .set_sequence(3)
                        .set_weight(100)
                        .expect("Failed to set weight"),
                ),
        )
        .register_scenario(
            scenario!("fastAuthSimpleMpcPublicKey")
                .register_transaction(transaction!(mpc_public_key)),
        )
        .execute()
        .await?;

    Ok(())
}
