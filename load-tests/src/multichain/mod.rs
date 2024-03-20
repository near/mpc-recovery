use std::str::FromStr;

use goose::goose::{GooseUser, TransactionResult};
use near_crypto::{InMemorySigner, SecretKey};
use near_jsonrpc_client::JsonRpcClient;
use near_primitives::{
    transaction::{Action, FunctionCallAction, Transaction},
    types::AccountId,
};
use rand::Rng;

pub async fn multichain_sign(user: &mut GooseUser) -> TransactionResult {
    tracing::info!("multichain_sign");

    // TODO: for better experience we can create real account in prepare_user_credentials and then get it from session
    let account_id = AccountId::try_from("dev-1660670387515-45063246810397".to_string()).unwrap();
    let secret_key = SecretKey::from_str("ed25519:4hc3qA3nTE8M63DB8jEZx9ZbHVUPdkMjUAoa11m4xtET7F6w4bk51TwQ3RzEcFhBtXvF6NYzFdiJduaGdJUvynAi").unwrap();
    let public_key = secret_key.public_key();
    let multichain_contract_id = AccountId::try_from("multichain.near".to_string()).unwrap(); // TODO: pass in parameters
    let testnet_rpc_url = "https://rpc.testnet.near.org".to_string(); // TODO: pass from parameters

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

    let sign_transaction = Transaction {
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
            }))
            .unwrap(),
            gas: 300_000_000_000_000,
            deposit: 0,
        })],
    };

    Ok(())
}
