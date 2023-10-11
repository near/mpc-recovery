use std::{
    fs::{self, File},
    io::Write,
};

use anyhow::{Context, Ok};
use hyper::{Body, Client, Method, Request, StatusCode, Uri};
use near_workspaces::{types::SecretKey, AccountId};
use serde::{Deserialize, Serialize};
use toml::Value;

use crate::containers::RelayerConfig;

pub async fn post<U, Req: Serialize, Resp>(
    uri: U,
    request: Req,
) -> anyhow::Result<(StatusCode, Resp)>
where
    Uri: TryFrom<U>,
    <Uri as TryFrom<U>>::Error: Into<hyper::http::Error>,
    for<'de> Resp: Deserialize<'de>,
{
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&request).context("failed to serialize the request body")?,
        ))
        .context("failed to build the request")?;

    let client = Client::new();
    let response = client
        .request(req)
        .await
        .context("failed to send the request")?;
    let status = response.status();

    let data = hyper::body::to_bytes(response)
        .await
        .context("failed to read the response body")?;
    let response: Resp =
        serde_json::from_slice(&data).context("failed to deserialize the response body")?;

    Ok((status, response))
}

#[derive(Deserialize, Serialize)]
struct KeyFile {
    account_id: String,
    public_key: String,
    private_key: String,
}

pub fn create_key_file(
    account_id: &AccountId,
    account_sk: &SecretKey,
    key_path: &str,
) -> anyhow::Result<(), anyhow::Error> {
    let key_file = KeyFile {
        account_id: account_id.to_string(),
        public_key: account_sk.public_key().to_string(),
        private_key: account_sk.to_string(),
    };
    let key_json_str = serde_json::to_string(&key_file).expect("Failed to serialize to JSON");
    let key_json_file_path = format!("{key_path}/{account_id}.json");
    let mut json_key_file =
        File::create(key_json_file_path).expect("Failed to create JSON key file");
    json_key_file
        .write_all(key_json_str.as_bytes())
        .expect("Failed to write to JSON key file");
    Ok(())
}

pub fn create_relayer_cofig_file(
    config: RelayerConfig,
    config_path: String,
) -> anyhow::Result<String, anyhow::Error> {
    let mut config_table = Value::Table(toml::value::Table::new());
    let table = config_table.as_table_mut().unwrap();

    table.insert(
        "ip_address".to_string(),
        Value::Array(
            config
                .ip_address
                .iter()
                .map(|ip| Value::Integer(i64::from(*ip)))
                .collect(),
        ),
    );
    table.insert("port".to_string(), Value::Integer(i64::from(config.port)));

    let relayer_account_id = config.relayer_account_id.to_string();

    table.insert(
        "relayer_account_id".to_string(),
        Value::String(relayer_account_id.clone()),
    );
    table.insert(
        "keys_filenames".to_string(),
        Value::Array(
            config
                .keys_filenames
                .iter()
                .map(|filename| Value::String(filename.to_string()))
                .collect(),
        ),
    );

    table.insert(
        "shared_storage_account_id".to_string(),
        Value::String(config.shared_storage_account_id.to_string()),
    );
    table.insert(
        "shared_storage_keys_filename".to_string(),
        Value::String(config.shared_storage_keys_filename),
    );

    table.insert(
        "whitelisted_contracts".to_string(),
        Value::Array(
            config
                .whitelisted_contracts
                .iter()
                .map(|account_id| Value::String(account_id.to_string()))
                .collect(),
        ),
    );
    table.insert(
        "whitelisted_delegate_action_receiver_ids".to_string(),
        Value::Array(
            config
                .whitelisted_delegate_action_receiver_ids
                .iter()
                .map(|account_id| Value::String(account_id.to_string()))
                .collect(),
        ),
    );

    table.insert(
        "redis_url".to_string(),
        Value::String(config.redis_url.to_string()),
    );
    table.insert(
        "social_db_contract_id".to_string(),
        Value::String(config.social_db_contract_id.to_string()),
    );

    table.insert(
        "rpc_url".to_string(),
        Value::String(config.rpc_url.to_string()),
    );
    table.insert(
        "wallet_url".to_string(),
        Value::String(config.wallet_url.to_string()),
    ); // not used
    table.insert(
        "explorer_transaction_url".to_string(),
        Value::String(config.explorer_transaction_url.to_string()),
    ); // not used
    table.insert("rpc_api_key".to_string(), Value::String(config.rpc_api_key)); // not used

    let mut file =
        File::create(&config_path).unwrap_or_else(|_| panic!("Failed to write to {}", config_path));
    let toml_string = toml::to_string(&config_table).expect("Failed to convert to TOML string");
    file.write_all(toml_string.as_bytes())
        .unwrap_or_else(|_| panic!("Failed to write to {}", config_path));

    let config_absolute_path = fs::canonicalize(&config_path)
        .unwrap_or_else(|_| panic!("Failed to get absolute path to {}", config_path));
    Ok(config_absolute_path
        .to_str()
        .expect("Failed to convert config file path to string")
        .to_string())
}
