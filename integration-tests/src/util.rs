use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::Context;
use async_process::{Child, Command, Stdio};
use hyper::{Body, Client, Method, Request, StatusCode, Uri};
use serde::{Deserialize, Serialize};
use toml::Value;
use workspaces::{types::SecretKey, AccountId};

use crate::containers::RelayerConfig;

const EXECUTABLE: &str = "mpc-recovery";

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

pub async fn get<U>(uri: U) -> anyhow::Result<StatusCode>
where
    Uri: TryFrom<U>,
    <Uri as TryFrom<U>>::Error: Into<hyper::http::Error>,
{
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::empty())
        .context("failed to build the request")?;

    let client = Client::new();
    let response = client
        .request(req)
        .await
        .context("failed to send the request")?;
    Ok(response.status())
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

/// Request an unused port from the OS.
pub async fn pick_unused_port() -> anyhow::Result<u16> {
    // Port 0 means the OS gives us an unused port
    // Important to use localhost as using 0.0.0.0 leads to users getting brief firewall popups to
    // allow inbound connections on MacOS.
    let addr = std::net::SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 0);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let port = listener.local_addr()?.port();
    Ok(port)
}

pub async fn ping_until_ok(addr: &str, timeout: u64) -> anyhow::Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(timeout), async {
        loop {
            match get(addr).await {
                Ok(status) if status == StatusCode::OK => break,
                _ => tokio::time::sleep(std::time::Duration::from_millis(500)).await,
            }
        }
    })
    .await?;
    Ok(())
}

pub fn target_dir() -> Option<PathBuf> {
    let mut out_dir = Path::new(std::env!("OUT_DIR"));
    loop {
        if out_dir.ends_with("target") {
            break Some(out_dir.to_path_buf());
        }

        match out_dir.parent() {
            Some(parent) => out_dir = parent,
            None => break None, // We've reached the root directory and didn't find "target"
        }
    }
}

pub fn executable(release: bool) -> Option<PathBuf> {
    let executable = target_dir()?
        .join(if release { "release" } else { "debug" })
        .join(EXECUTABLE);
    Some(executable)
}

pub fn spawn_mpc(release: bool, node: &str, args: &[String]) -> anyhow::Result<Child> {
    let executable = executable(release)
        .with_context(|| format!("could not find target dir while starting {node} node"))?;

    Command::new(&executable)
        .args(args)
        .env("RUST_LOG", "mpc_recovery=INFO")
        .envs(std::env::vars())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("failed to run {node} node: {}", executable.display()))
}
