use anyhow::{anyhow, Context};
use curv::elliptic::curves::{Ed25519, Point};
use ed25519_dalek::Signature;
use futures::{future, FutureExt};
use multi_party_eddsa::protocols::aggsig::KeyAgg;
use multi_party_eddsa::protocols::{self, aggsig};
use near_crypto::{InMemorySigner, PublicKey, SecretKey};
use near_primitives::account::{AccessKey, AccessKeyPermission};
use near_primitives::borsh::BorshSerialize;
use near_primitives::hash::hash;
use near_primitives::transaction::{Action, AddKeyAction, FunctionCallAction};
use near_primitives::types::{AccountId, Nonce};

use near_primitives::delegate_action::{DelegateAction, NonDelegateAction, SignedDelegateAction};
use near_primitives::signable_message::{SignableMessage, SignableMessageType};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::msg::SigShareRequest;
use crate::sign_node::aggregate_signer::{Reveal, SignedCommitment};

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
pub fn get_create_account_delegate_action(
    signer_id: AccountId,
    signer_pk: PublicKey,
    new_account_id: AccountId,
    new_account_options: CreateAccountOptions,
    near_root_account: AccountId,
    nonce: Nonce,
    max_block_height: u64,
) -> anyhow::Result<DelegateAction> {
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
        sender_id: signer_id,
        receiver_id: near_root_account,
        actions: vec![delegate_create_acc_action],
        nonce,
        max_block_height,
        public_key: signer_pk,
    };

    Ok(delegate_action)
}

pub fn get_add_key_delegate_action(
    account_id: AccountId,
    signer_pk: PublicKey,
    new_public_key: PublicKey,
    nonce: Nonce,
    max_block_height: u64,
) -> anyhow::Result<DelegateAction> {
    let add_key_action = Action::AddKey(AddKeyAction {
        public_key: new_public_key,
        access_key: AccessKey {
            nonce: 0,
            permission: AccessKeyPermission::FullAccess,
        },
    });

    let delegate_add_key_action = NonDelegateAction::try_from(add_key_action)?;

    let delegate_action = DelegateAction {
        sender_id: account_id.clone(),
        receiver_id: account_id,
        actions: vec![delegate_add_key_action],
        nonce,
        max_block_height,
        public_key: signer_pk,
    };

    Ok(delegate_action)
}

pub fn get_local_signed_delegated_action(
    delegate_action: DelegateAction,
    signer_id: AccountId,
    signer_sk: SecretKey,
) -> SignedDelegateAction {
    let signer = InMemorySigner::from_secret_key(signer_id, signer_sk);
    let signable_message =
        SignableMessage::new(&delegate_action, SignableMessageType::DelegateAction);
    let signature = signable_message.sign(&signer);

    SignedDelegateAction {
        delegate_action,
        signature,
    }
}

pub async fn get_mpc_signed_delegated_action(
    client: &reqwest::Client,
    sign_nodes: &[String],
    oidc_token: String,
    delegate_action: DelegateAction,
) -> anyhow::Result<SignedDelegateAction> {
    let signable_message =
        SignableMessage::new(&delegate_action, SignableMessageType::DelegateAction);

    let bytes = signable_message.try_to_vec()?;

    let hash = hash(&bytes);

    let signature = sign(client, sign_nodes, oidc_token, hash.as_bytes().to_vec()).await?;

    Ok(SignedDelegateAction {
        delegate_action,
        signature: near_crypto::Signature::ED25519(signature),
    })
}

pub async fn sign(
    client: &reqwest::Client,
    sign_nodes: &[String],
    oidc_token: String,
    payload: Vec<u8>,
) -> anyhow::Result<Signature> {
    let commit_request = SigShareRequest {
        oidc_token,
        payload,
    };

    let commitments: Vec<SignedCommitment> =
        call(client, sign_nodes, "commit", commit_request).await?;

    let reveals: Vec<Reveal> = call(client, sign_nodes, "reveal", commitments).await?;

    let signature_shares: Vec<protocols::Signature> =
        call(client, sign_nodes, "signature_share", reveals).await?;

    let raw_sig = aggsig::add_signature_parts(&signature_shares);

    to_dalek_signature(&raw_sig)
}

/// Call every node with an identical payload and send the response
pub async fn call<Req: Serialize, Res: DeserializeOwned>(
    client: &reqwest::Client,
    sign_nodes: &[String],
    path: &str,
    request: Req,
) -> anyhow::Result<Vec<Res>> {
    let responses = sign_nodes.iter().map(|sign_node| {
        client
            .post(format!("{}/{}", sign_node, path))
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .then(|r| async move {
                match r {
                    // Flatten all errors to strings
                    Ok(ok) => match ok.json::<Result<Res, String>>().await {
                        Ok(ok) => ok.map_err(|e| anyhow!(e)),
                        Err(e) => Err(anyhow!(e)),
                    },
                    Err(e) => Err(anyhow!(e)),
                }
            })
    });

    future::join_all(responses).await.into_iter().collect()
}

pub fn to_dalek_signature(sig: &protocols::Signature) -> anyhow::Result<ed25519_dalek::Signature> {
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&sig.R.to_bytes(true));
    sig_bytes[32..].copy_from_slice(&sig.s.to_bytes());

    // let dalek_pub = ed25519_dalek::PublicKey::from_bytes(&*pk.to_bytes(true)).unwrap();
    ed25519_dalek::Signature::from_bytes(&sig_bytes).context("Signature conversion failed")
}

pub fn to_dalek_combined_public_key(
    public_keys: &[Point<Ed25519>],
) -> anyhow::Result<ed25519_dalek::PublicKey> {
    let combined = KeyAgg::key_aggregation_n(public_keys, 0).apk;
    to_dalek_public_key(&combined)
}

pub fn to_dalek_public_key(
    public_key: &Point<Ed25519>,
) -> anyhow::Result<ed25519_dalek::PublicKey> {
    ed25519_dalek::PublicKey::from_bytes(&public_key.to_bytes(true))
        .context("Key conversion failed")
}
