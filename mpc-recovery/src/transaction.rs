use crate::error::{AggregateSigningError, LeaderNodeError};
use crate::msg::{SignNodeRequest, SignShareNodeRequest};
use crate::sign_node::aggregate_signer::{Reveal, SignedCommitment};
use crate::sign_node::oidc::OidcToken;

use anyhow::Context;
use curv::elliptic::curves::{Ed25519, Point};
use ed25519_dalek::Signature;
use futures::{future, FutureExt};
use hyper::StatusCode;
use multi_party_eddsa::protocols::aggsig::KeyAgg;
use multi_party_eddsa::protocols::{self, aggsig};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;

use near_crypto::{InMemorySigner, PublicKey};
use near_primitives::delegate_action::{DelegateAction, NonDelegateAction, SignedDelegateAction};
use near_primitives::signable_message::{SignableMessage, SignableMessageType};
use near_primitives::transaction::{Action, FunctionCallAction};
use near_primitives::types::{AccountId, Nonce};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateAccountOptions {
    pub full_access_keys: Option<Vec<PublicKey>>,
    pub limited_access_keys: Option<Vec<LimitedAccessKey>>,
    pub contract_bytes: Option<Vec<u8>>,
}

impl std::fmt::Display for CreateAccountOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let json_string = serde_json::to_string(self).map_err(|_| std::fmt::Error)?;
        write!(f, "{}", json_string)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Information about any limited access keys that are being added to the account as part of `create_account_advanced`.
pub struct LimitedAccessKey {
    /// The public key of the limited access key.
    pub public_key: PublicKey,
    /// The amount of yoctoNEAR$ that can be spent on Gas by this key.
    pub allowance: String,
    /// Which contract should this key be allowed to call.
    pub receiver_id: AccountId,
    /// Which methods should this key be allowed to call.
    pub method_names: String,
}

#[allow(clippy::too_many_arguments)]
pub fn new_create_account_delegate_action(
    signer: &InMemorySigner,
    new_account_id: &AccountId,
    new_account_options: &CreateAccountOptions,
    near_root_account: &AccountId,
    nonce: Nonce,
    max_block_height: u64,
) -> anyhow::Result<SignedDelegateAction> {
    let create_acc_action = Action::FunctionCall(FunctionCallAction {
        method_name: "create_account_advanced".to_string(),
        args: json!({
            "new_account_id": new_account_id,
            "options": new_account_options,
        })
        .to_string()
        .into_bytes(),
        gas: 300_000_000_000_000,
        deposit: 0,
    });

    let delegate_create_acc_action = NonDelegateAction::try_from(create_acc_action)?;

    let delegate_action = DelegateAction {
        sender_id: signer.account_id.clone(),
        receiver_id: near_root_account.clone(),
        actions: vec![delegate_create_acc_action],
        nonce,
        max_block_height,
        public_key: signer.public_key.clone(),
    };

    let signable_message =
        SignableMessage::new(&delegate_action, SignableMessageType::DelegateAction);
    let signature = signable_message.sign(signer);

    Ok(SignedDelegateAction {
        delegate_action,
        signature,
    })
}

pub async fn get_mpc_signature(
    client: &reqwest::Client,
    sign_nodes: &[String],
    oidc_token: &OidcToken,
    delegate_action: DelegateAction,
    frp_signature: &Signature,
    frp_public_key: &near_crypto::PublicKey,
) -> Result<Signature, LeaderNodeError> {
    let sig_share_request = SignNodeRequest::SignShare(SignShareNodeRequest {
        oidc_token: oidc_token.clone(),
        delegate_action,
        frp_signature: *frp_signature,
        frp_public_key: frp_public_key.clone(),
    });

    let signature = sign_payload_with_mpc(client, sign_nodes, sig_share_request).await?;
    Ok(signature)
}

#[derive(thiserror::Error, Debug)]
#[allow(dead_code)]
pub enum NodeSignError {
    #[error("call error: {0}")]
    CallError(#[from] NodeCallError),
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

pub async fn sign_payload_with_mpc(
    client: &reqwest::Client,
    sign_nodes: &[String],
    sig_share_request: SignNodeRequest,
) -> Result<Signature, LeaderNodeError> {
    let commitments: Vec<SignedCommitment> =
        call_all_nodes(client, sign_nodes, "commit", sig_share_request).await?;

    let reveals: Vec<Reveal> = call_all_nodes(client, sign_nodes, "reveal", commitments).await?;

    let signature_shares: Vec<protocols::Signature> =
        call_all_nodes(client, sign_nodes, "signature_share", reveals).await?;

    let raw_sig = aggsig::add_signature_parts(&signature_shares);

    to_dalek_signature(&raw_sig).map_err(LeaderNodeError::AggregateSigningFailed)
}

#[derive(thiserror::Error, Debug)]
#[allow(dead_code)]
pub enum NodeCallError {
    #[error("client error: {0}")]
    ClientError(String, StatusCode),
    #[error("server error: {0}")]
    ServerError(String),
    #[error("{0}")]
    Other(anyhow::Error),
}

/// Call every node with an identical payload and send the response
pub async fn call_all_nodes<Req: Serialize, Res: DeserializeOwned>(
    client: &reqwest::Client,
    sign_nodes: &[String],
    path: &str,
    request: Req,
) -> Result<Vec<Res>, LeaderNodeError> {
    let responses = sign_nodes.iter().map(|sign_node| {
        client
            .post(format!("{}/{}", sign_node, path))
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .then(|r| async move {
                let ok = r.map_err(LeaderNodeError::NetworkRejection)?;
                let status_code = ok.status();
                let ok = ok
                    .json::<Result<Res, String>>()
                    .await
                    .map_err(|e| LeaderNodeError::DataConversionFailure(e.into()))?;

                match ok {
                    Ok(res) => Ok(res),
                    Err(e) if status_code.is_client_error() => {
                        Err(LeaderNodeError::ClientError(e, status_code))
                    }
                    Err(e) => Err(LeaderNodeError::ServerError(e)),
                }
            })
    });

    future::join_all(responses).await.into_iter().collect()
}

pub fn from_dalek_signature(sig: ed25519_dalek::Signature) -> anyhow::Result<protocols::Signature> {
    let bytes = sig.to_bytes();
    Ok(protocols::Signature {
        R: Point::from_bytes(&bytes[..32])?,
        s: curv::elliptic::curves::Scalar::from_bytes(&bytes[32..])?,
    })
}

pub fn to_dalek_signature(
    sig: &protocols::Signature,
) -> Result<ed25519_dalek::Signature, AggregateSigningError> {
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&sig.R.to_bytes(true));
    sig_bytes[32..].copy_from_slice(&sig.s.to_bytes());

    // let dalek_pub = ed25519_dalek::PublicKey::from_bytes(&*pk.to_bytes(true)).unwrap();
    ed25519_dalek::Signature::from_bytes(&sig_bytes)
        .context("to dalek signature conversion failed")
        .map_err(AggregateSigningError::DataConversionFailure)
}

pub fn to_dalek_combined_public_key(
    public_keys: &[Point<Ed25519>],
) -> Result<ed25519_dalek::PublicKey, AggregateSigningError> {
    let combined = KeyAgg::key_aggregation_n(public_keys, 0).apk;
    to_dalek_public_key(&combined)
}

pub fn to_dalek_public_key(
    public_key: &Point<Ed25519>,
) -> Result<ed25519_dalek::PublicKey, AggregateSigningError> {
    ed25519_dalek::PublicKey::from_bytes(&public_key.to_bytes(true))
        .context("to dalek key conversion failed")
        .map_err(AggregateSigningError::DataConversionFailure)
}
