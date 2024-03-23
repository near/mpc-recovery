use std::{str::FromStr, time::Duration};

use goose::goose::{GooseMethod, GooseRequest, GooseUser, TransactionResult};
use goose_eggs::{validate_and_load_static_assets, Validate};
use near_crypto::{InMemorySigner, SecretKey};
use near_jsonrpc_client::JsonRpcClient;
use near_primitives::{
    transaction::{Action, FunctionCallAction, Transaction},
    types::AccountId,
};
use rand::Rng;
use reqwest::header::CONTENT_TYPE;

pub async fn multichain_sign(user: &mut GooseUser) -> TransactionResult {
    tracing::info!("multichain_sign");

    // TODO: for better experience we can create real account in prepare_user_credentials and then get it from session
    let account_id = AccountId::try_from("dev-1660670387515-45063246810397".to_string()).unwrap();
    let secret_key = SecretKey::from_str("ed25519:4hc3qA3nTE8M63DB8jEZx9ZbHVUPdkMjUAoa11m4xtET7F6w4bk51TwQ3RzEcFhBtXvF6NYzFdiJduaGdJUvynAi").unwrap();
    let public_key = secret_key.public_key();
    let multichain_contract_id = AccountId::try_from("multichain0.testnet".to_string()).unwrap(); // TODO: pass in parameters
    let testnet_rpc_url = "https://rpc.testnet.near.org".to_string();

    let signer = InMemorySigner {
        account_id: account_id.clone(),
        public_key: public_key.clone(),
        secret_key,
    };

    let connector = JsonRpcClient::new_client();
    let jsonrpc_client = connector.connect(&testnet_rpc_url);
    let rpc_client = near_fetch::Client::from_client(jsonrpc_client.clone());

    let (nonce, block_hash, _) = rpc_client
        .fetch_nonce(&signer.account_id, &signer.public_key)
        .await
        .unwrap();

    let payload: [u8; 32] = rand::thread_rng().gen();
    let payload_hashed = web3::signing::keccak256(&payload);
    tracing::info!("requesting signature for: {:?}", payload_hashed);

    let transaction = Transaction {
        signer_id: account_id.clone(),
        public_key,
        nonce,
        receiver_id: multichain_contract_id,
        block_hash,
        actions: vec![Action::FunctionCall(FunctionCallAction {
            method_name: "sign".to_string(),
            args: serde_json::to_vec(&serde_json::json!({
                "payload": payload_hashed,
                "path": "test",
                "key_version": 0,
            }))
            .unwrap(),
            gas: 300_000_000_000_000,
            deposit: 0,
        })],
    };

    let signed_transaction = transaction.sign(&signer);

    let encoded_transaction = near_primitives::serialize::to_base64(
        &borsh::BorshSerialize::try_to_vec(&signed_transaction).unwrap(),
    );

    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "dontcare",
        "method": "broadcast_tx_commit",
        "params": [
            encoded_transaction
        ]
    });

    let request_builder = user
        .get_request_builder(&GooseMethod::Post, "")?
        .json(&payload)
        .header(CONTENT_TYPE, "application/json")
        .timeout(Duration::from_secs(50));

    let goose_request = GooseRequest::builder()
        .set_request_builder(request_builder)
        .build();

    let goose_response = user.request(goose_request).await?;

    let rsp = goose_response.response.as_ref().unwrap();

    tracing::info!("goose_response: {:?}", rsp);

    let expected_log = "sign_helper: signature ready";

    let validate = &Validate::builder()
        .status(200)
        .text(expected_log) // Naive check if the request is successful
        .build();
    validate_and_load_static_assets(user, goose_response, validate).await?;

    Ok(())
}
