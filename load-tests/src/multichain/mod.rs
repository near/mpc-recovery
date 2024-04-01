use std::time::Duration;

use goose::goose::{GooseMethod, GooseRequest, GooseUser, TransactionResult};
use goose_eggs::{validate_and_load_static_assets, Validate};
use near_crypto::InMemorySigner;
use near_jsonrpc_client::JsonRpcClient;
use near_primitives::{
    transaction::{Action, FunctionCallAction, Transaction},
    types::AccountId,
};
use rand::Rng;
use reqwest::header::CONTENT_TYPE;

use crate::fastauth::primitives::UserSession;

pub async fn multichain_sign(user: &mut GooseUser) -> TransactionResult {
    tracing::info!("multichain_sign");

    let sesion = user
        .get_session_data::<UserSession>()
        .expect("Session Data must be set");

    let multichain_contract_id =
        AccountId::try_from("v2.multichain-mpc.testnet".to_string()).unwrap();
    let testnet_rpc_url = "https://rpc.testnet.near.org".to_string();

    let signer = InMemorySigner {
        account_id: sesion.near_account_id.clone(),
        public_key: sesion.fa_sk.public_key(),
        secret_key: sesion.fa_sk.clone(),
    };

    let connector = JsonRpcClient::new_client();
    let jsonrpc_client = connector.connect(&testnet_rpc_url);
    let rpc_client = near_fetch::Client::from_client(jsonrpc_client.clone());

    let (nonce, block_hash, _) = rpc_client
        .fetch_nonce(&signer.account_id, &signer.public_key)
        .await
        .unwrap();

    let payload_hashed: [u8; 32] = rand::thread_rng().gen();
    tracing::info!("requesting signature for: {:?}", payload_hashed);

    let transaction = Transaction {
        signer_id: sesion.near_account_id.clone(),
        public_key: sesion.fa_sk.public_key(),
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

    // let text = goose_response.response.unwrap().text().await.unwrap();
    // tracing::info!("goose_response: {:?}", text);

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
