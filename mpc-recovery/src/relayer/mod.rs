pub mod error;
pub mod msg;

use hyper::{Body, Client, Method, Request};
use near_crypto::PublicKey;
use near_jsonrpc_client::JsonRpcClient;
use near_primitives::hash::CryptoHash;
use near_primitives::types::{AccountId, BlockHeight, Nonce};
use near_primitives::views::AccessKeyList;

use self::error::RelayerError;
use self::msg::{RegisterAccountRequest, SendMetaTxRequest, SendMetaTxResponse};

use crate::nar::{self, CachedAccessKeyNonces};

pub struct NearRpcAndRelayerClient {
    rpc_client: JsonRpcClient,
    relayer_url: String,
    cached_nonces: CachedAccessKeyNonces,
    api_key: Option<String>,
}

impl Clone for NearRpcAndRelayerClient {
    fn clone(&self) -> Self {
        Self {
            rpc_client: self.rpc_client.clone(),
            relayer_url: self.relayer_url.clone(),
            api_key: self.api_key.clone(),
            // all the cached nonces will not get cloned, and instead get invalidated:
            cached_nonces: Default::default(),
        }
    }
}

impl NearRpcAndRelayerClient {
    pub fn connect(near_rpc: &str, relayer_url: String, api_key: Option<String>) -> Self {
        Self {
            rpc_client: JsonRpcClient::connect(near_rpc),
            relayer_url,
            cached_nonces: Default::default(),
            api_key,
        }
    }

    pub async fn access_key_list(
        &self,
        account_id: AccountId,
    ) -> Result<(CryptoHash, BlockHeight, AccessKeyList), RelayerError> {
        let (access_key_list, block_hash, block_height) =
            nar::access_key_list(&self.rpc_client, account_id).await?;

        Ok((block_hash, block_height, access_key_list))
    }

    pub async fn access_key(
        &self,
        account_id: AccountId,
        public_key: PublicKey,
    ) -> Result<(CryptoHash, BlockHeight, Nonce), RelayerError> {
        nar::fetch_tx_nonce(
            &self.cached_nonces,
            &self.rpc_client,
            &(account_id, public_key),
        )
        .await
    }

    #[tracing::instrument(level = "debug", skip_all, fields(account_id = request.account_id.to_string()))]
    pub async fn register_account(&self, request: RegisterAccountRequest) -> anyhow::Result<()> {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri(format!("{}/register_account", self.relayer_url))
            .header("content-type", "application/json");

        if let Some(api_key) = &self.api_key {
            req = req.header("x-api-key", api_key);
        };

        let request = req.body(Body::from(serde_json::to_vec(&request)?)).unwrap();

        tracing::debug!("constructed http request to {}", self.relayer_url);
        let client = Client::new();
        let response = client.request(request).await?;

        if response.status().is_success() {
            let response_body = hyper::body::to_bytes(response.into_body()).await?;
            tracing::debug!("success: {}", std::str::from_utf8(&response_body)?);
            Ok(())
        } else {
            let response_body = hyper::body::to_bytes(response.into_body()).await?;
            Err(anyhow::anyhow!(
                "fail: {}",
                std::str::from_utf8(&response_body)?
            ))
        }
    }

    #[tracing::instrument(level = "debug", skip_all, fields(receiver_id = request.delegate_action.receiver_id.to_string()))]
    pub async fn send_meta_tx(
        &self,
        request: SendMetaTxRequest,
    ) -> anyhow::Result<SendMetaTxResponse> {
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("{}/send_meta_tx", self.relayer_url))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&request)?))
            .map_err(|err| anyhow::anyhow!("Failed to construct send_meta_tx request {err}"))?;

        tracing::debug!("constructed http request to {}", self.relayer_url);
        let client = Client::new();
        let response = client.request(request).await.map_err(|err| {
            anyhow::anyhow!("Failed to send send_meta_tx request to relayer: {err}")
        })?;

        if response.status().is_success() {
            let response_body = hyper::body::to_bytes(response.into_body()).await?;
            tracing::debug!("body: {}", std::str::from_utf8(&response_body)?);
            let response: SendMetaTxResponse = serde_json::from_slice(&response_body)?;
            tracing::debug!("success: {:?}", response);

            Ok(response)
        } else {
            let response_body = hyper::body::to_bytes(response.into_body()).await?;
            Err(anyhow::anyhow!(
                "fail: {}",
                std::str::from_utf8(&response_body)?
            ))
        }
    }

    pub(crate) async fn invalidate_cache_if_tx_failed(
        &self,
        cache_key: &(AccountId, PublicKey),
        err_str: &str,
    ) {
        nar::invalidate_nonce_if_tx_failed(&self.cached_nonces, cache_key, err_str).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAYER_URI: &str = "http://34.70.226.83:3030";
    const TESTNET_URL: &str = "https://rpc.testnet.near.org";

    #[tokio::test]
    async fn test_access_key() -> anyhow::Result<()> {
        let testnet = NearRpcAndRelayerClient::connect(TESTNET_URL, RELAYER_URI.to_string(), None);
        let (block_hash, block_height, nonce) = testnet
            .access_key(
                "dev-1636354824855-78504059330123".parse()?,
                "ed25519:8n5HXTibTDtXKAnEUPFUXXJoKqa5A1c2vWXt6LbRAcGn".parse()?,
            )
            .await?;

        assert_eq!(block_hash.0.len(), 32);
        assert!(block_height > 0);
        // Assuming no one will use this account ever again
        assert_eq!(nonce, 70526114000003);
        Ok(())
    }
}
