// TODO: use NAR in the future.
//! Separated away from client to distinguish functions that are common and
//! need to be moved eventually into their own separate crate. Not necessarily
//! to be used from workspaces directly even though it is imported from there.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use near_crypto::PublicKey;
use near_jsonrpc_client::errors::{JsonRpcError, JsonRpcServerError};
use near_jsonrpc_client::methods::query::RpcQueryError;
use near_jsonrpc_client::{methods, JsonRpcClient};
use near_jsonrpc_primitives::types::query::QueryResponseKind;
use near_primitives::hash::CryptoHash;
use near_primitives::types::{AccountId, BlockHeight, Finality, Nonce};
use near_primitives::views::{AccessKeyView, BlockView, QueryRequest};
use tokio::sync::RwLock;
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::Retry;

use crate::relayer::error::RelayerError;

pub type CachedAccessKeyNonces = RwLock<HashMap<(AccountId, PublicKey), AtomicU64>>;

pub(crate) async fn retry_every<R, E, T, F>(interval: Duration, task: F) -> T::Output
where
    F: FnMut() -> T,
    T: core::future::Future<Output = core::result::Result<R, E>>,
{
    let retry_strategy = std::iter::repeat_with(|| interval);
    let task = Retry::spawn(retry_strategy, task);
    task.await
}

pub(crate) async fn retry<R, E, T, F>(task: F) -> T::Output
where
    F: FnMut() -> T,
    T: core::future::Future<Output = core::result::Result<R, E>>,
{
    // Exponential backoff starting w/ 5ms for maximum retry of 4 times with the following delays:
    //   5, 25, 125, 625 ms
    let retry_strategy = ExponentialBackoff::from_millis(5).map(jitter).take(4);
    Retry::spawn(retry_strategy, task).await
}

pub(crate) async fn access_key(
    rpc_client: &JsonRpcClient,
    account_id: AccountId,
    public_key: near_crypto::PublicKey,
) -> Result<(AccessKeyView, CryptoHash, BlockHeight), RelayerError> {
    let query_resp = rpc_client
        .call(&methods::query::RpcQueryRequest {
            block_reference: Finality::None.into(),
            request: QueryRequest::ViewAccessKey {
                account_id,
                public_key,
            },
        })
        .await
        .map_err(|e| match e {
            JsonRpcError::ServerError(JsonRpcServerError::HandlerError(
                RpcQueryError::UnknownAccount {
                    requested_account_id,
                    ..
                },
            )) => RelayerError::UnknownAccount(requested_account_id),
            JsonRpcError::ServerError(JsonRpcServerError::HandlerError(
                RpcQueryError::UnknownAccessKey { public_key, .. },
            )) => RelayerError::UnknownAccessKey(public_key),
            _ => anyhow::anyhow!(e).into(),
        })?;

    match query_resp.kind {
        QueryResponseKind::AccessKey(access_key) => {
            Ok((access_key, query_resp.block_hash, query_resp.block_height))
        }
        _ => Err(anyhow::anyhow!("query returned invalid data while querying access key").into()),
    }
}

async fn cached_nonce(
    nonce: &AtomicU64,
    rpc_client: &JsonRpcClient,
) -> Result<(CryptoHash, BlockHeight, Nonce), RelayerError> {
    let nonce = nonce.fetch_add(1, Ordering::SeqCst);

    // Fetch latest block_hash since the previous one is now invalid for new transactions:
    let block = latest_block(rpc_client).await?;
    Ok((block.header.hash, block.header.height, nonce + 1))
}

/// Fetches the transaction nonce and block hash associated to the access key. Internally
/// caches the nonce as to not need to query for it every time, and ending up having to run
/// into contention with others.
pub async fn fetch_tx_nonce(
    cached_nonces: &CachedAccessKeyNonces,
    rpc_client: &JsonRpcClient,
    cache_key: &(AccountId, near_crypto::PublicKey),
) -> Result<(CryptoHash, BlockHeight, Nonce), RelayerError> {
    let nonces = cached_nonces.read().await;
    if let Some(nonce) = nonces.get(cache_key) {
        cached_nonce(nonce, rpc_client).await
    } else {
        drop(nonces);
        let mut nonces = cached_nonces.write().await;
        match nonces.entry(cache_key.clone()) {
            // case where multiple writers end up at the same lock acquisition point and tries
            // to overwrite the cached value that a previous writer already wrote.
            Entry::Occupied(entry) => cached_nonce(entry.get(), rpc_client).await,

            // Write the cached value. This value will get invalidated when an InvalidNonce error is returned.
            Entry::Vacant(entry) => {
                let (account_id, public_key) = entry.key();
                let (access_key, block_hash, block_height) =
                    access_key(rpc_client, account_id.clone(), public_key.clone()).await?;
                entry.insert(AtomicU64::new(access_key.nonce + 1));
                Ok((block_hash, block_height, access_key.nonce + 1))
            }
        }
    }
}

pub(crate) async fn invalidate_nonce_if_tx_failed(
    cached_nonces: &CachedAccessKeyNonces,
    cache_key: &(AccountId, near_crypto::PublicKey),
    err_str: &str,
) {
    // InvalidNonce, cached nonce is potentially very far behind, so invalidate it.
    if err_str.contains("InvalidNonce")
        || err_str.contains("DelegateActionInvalidNonce")
        || err_str.contains("must be larger than nonce of the used access key")
    {
        let mut nonces = cached_nonces.write().await;
        nonces.remove(cache_key);
    }
}

pub async fn latest_block(rpc_client: &JsonRpcClient) -> Result<BlockView, RelayerError> {
    rpc_client
        .call(&methods::block::RpcBlockRequest {
            block_reference: Finality::Final.into(),
        })
        .await
        .map_err(|err| anyhow::anyhow!(err).into())
}
