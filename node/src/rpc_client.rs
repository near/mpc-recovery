use cait_sith::protocol::Participant;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::EncodedPoint;
use near_crypto::{InMemorySigner, Secp256K1PublicKey};
use near_primitives::transaction::{Action, FunctionCallAction};
use near_primitives::types::AccountId;
use near_primitives::views::FinalExecutionStatus;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use url::Url;

use crate::{types::PublicKey, util::serde_participant};

#[derive(Serialize, Deserialize, Debug, Hash, PartialEq, Eq, Clone)]
pub struct ParticipantInfo {
    #[serde(with = "serde_participant")]
    pub id: Participant,
    pub account_id: AccountId,
    pub url: Url,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignerContractState {
    participants: HashSet<ParticipantInfo>,
    public_key: Option<near_crypto::PublicKey>,
    pub threshold: usize,
}

impl SignerContractState {
    pub fn participants(&self) -> HashMap<Participant, Url> {
        self.participants
            .iter()
            .cloned()
            .map(|p| (p.id, p.url))
            .collect()
    }

    pub fn public_key(&self) -> Option<PublicKey> {
        match &self.public_key {
            Some(near_crypto::PublicKey::SECP256K1(pk)) => {
                let mut bytes = vec![0x04];
                bytes.extend_from_slice(pk.as_ref());
                let point = EncodedPoint::from_bytes(bytes).unwrap();
                PublicKey::from_encoded_point(&point).into()
            }
            Some(near_crypto::PublicKey::ED25519(_)) => {
                panic!("ed25519 is not supported")
            }
            None => None,
        }
    }
}

pub async fn fetch_mpc_contract_state(
    rpc_client: &near_fetch::Client,
    mpc_contract_id: &AccountId,
) -> anyhow::Result<SignerContractState> {
    Ok(rpc_client.view(mpc_contract_id, "state", ()).await?)
}

pub async fn vote_for_public_key(
    rpc_client: &near_fetch::Client,
    signer: &InMemorySigner,
    mpc_contract_id: &AccountId,
    public_key: &PublicKey,
) -> anyhow::Result<bool> {
    let public_key = near_crypto::PublicKey::SECP256K1(Secp256K1PublicKey::try_from(
        &public_key.to_encoded_point(false).as_bytes()[1..65],
    )?);
    let args = json!({
        "public_key": public_key
    });
    let result = rpc_client
        .send_tx(
            signer,
            mpc_contract_id,
            vec![Action::FunctionCall(FunctionCallAction {
                method_name: "vote_pk".to_string(),
                args: serde_json::to_vec(&args)?,
                gas: 300_000_000_000_000,
                deposit: 0,
            })],
        )
        .await?;

    match result.status {
        FinalExecutionStatus::SuccessValue(value) => Ok(serde_json::from_slice(&value)?),
        status => anyhow::bail!("unexpected status: {:?}", status),
    }
}
