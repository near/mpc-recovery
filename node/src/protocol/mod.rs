mod consensus;
mod contract;
mod cryptography;
mod presignature;
mod signature;
mod triple;

pub mod message;
pub mod state;

pub use contract::{ParticipantInfo, ProtocolState};
pub use message::MpcMessage;
pub use signature::SignQueue;
pub use signature::SignRequest;
pub use state::NodeState;

use self::consensus::ConsensusCtx;
use self::cryptography::CryptographicCtx;
use self::message::MessageCtx;
use crate::protocol::consensus::ConsensusProtocol;
use crate::protocol::cryptography::CryptographicProtocol;
use crate::protocol::message::{MessageHandler, MpcMessageQueue};
use crate::rpc_client::{self};
use cait_sith::protocol::Participant;
use near_crypto::InMemorySigner;
use near_primitives::types::AccountId;
use reqwest::IntoUrl;
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc::{self, error::TryRecvError};
use tokio::sync::RwLock;
use url::Url;

use mpc_keys::hpke;

struct Ctx {
    me: Participant,
    my_address: Url,
    mpc_contract_id: AccountId,
    signer: InMemorySigner,
    rpc_client: near_fetch::Client,
    http_client: reqwest::Client,
    sign_queue: Arc<RwLock<SignQueue>>,
    cipher_pk: hpke::PublicKey,
    sign_sk: near_crypto::SecretKey,
}

impl ConsensusCtx for &Ctx {
    fn me(&self) -> Participant {
        self.me
    }

    fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }

    fn rpc_client(&self) -> &near_fetch::Client {
        &self.rpc_client
    }

    fn signer(&self) -> &InMemorySigner {
        &self.signer
    }

    fn mpc_contract_id(&self) -> &AccountId {
        &self.mpc_contract_id
    }

    fn my_address(&self) -> &Url {
        &self.my_address
    }

    fn sign_queue(&self) -> Arc<RwLock<SignQueue>> {
        self.sign_queue.clone()
    }

    fn cipher_pk(&self) -> &hpke::PublicKey {
        &self.cipher_pk
    }

    fn sign_pk(&self) -> near_crypto::PublicKey {
        self.sign_sk.public_key()
    }
}

impl CryptographicCtx for &Ctx {
    fn me(&self) -> Participant {
        self.me
    }

    fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }

    fn rpc_client(&self) -> &near_fetch::Client {
        &self.rpc_client
    }

    fn signer(&self) -> &InMemorySigner {
        &self.signer
    }

    fn mpc_contract_id(&self) -> &AccountId {
        &self.mpc_contract_id
    }

    fn sign_sk(&self) -> &near_crypto::SecretKey {
        &self.sign_sk
    }
}

impl MessageCtx for &Ctx {
    fn me(&self) -> Participant {
        self.me
    }
}

pub struct MpcSignProtocol {
    ctx: Ctx,
    receiver: mpsc::Receiver<MpcMessage>,
    state: Arc<RwLock<NodeState>>,
}

impl MpcSignProtocol {
    #![allow(clippy::too_many_arguments)]
    pub fn init<U: IntoUrl>(
        me: Participant,
        my_address: U,
        mpc_contract_id: AccountId,
        rpc_client: near_fetch::Client,
        signer: InMemorySigner,
        receiver: mpsc::Receiver<MpcMessage>,
        sign_queue: Arc<RwLock<SignQueue>>,
        cipher_pk: hpke::PublicKey,
    ) -> (Self, Arc<RwLock<NodeState>>) {
        let state = Arc::new(RwLock::new(NodeState::Starting));
        let ctx = Ctx {
            me,
            my_address: my_address.into_url().unwrap(),
            mpc_contract_id,
            rpc_client,
            http_client: reqwest::Client::new(),
            sign_queue,
            cipher_pk,
            sign_sk: signer.secret_key.clone(),
            signer,
        };
        let protocol = MpcSignProtocol {
            ctx,
            receiver,
            state: state.clone(),
        };
        (protocol, state)
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let _span = tracing::info_span!("running", me = u32::from(self.ctx.me));
        let mut queue = MpcMessageQueue::default();
        loop {
            tracing::debug!("trying to advance mpc recovery protocol");
            let contract_state = match rpc_client::fetch_mpc_contract_state(
                &self.ctx.rpc_client,
                &self.ctx.mpc_contract_id,
            )
            .await
            {
                Ok(contract_state) => contract_state,
                Err(e) => {
                    tracing::error!("could not fetch contract's state: {e}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            tracing::debug!(?contract_state);
            loop {
                let msg_result = self.receiver.try_recv();
                match msg_result {
                    Ok(msg) => {
                        tracing::debug!("received a new message");
                        queue.push(msg);
                    }
                    Err(TryRecvError::Empty) => {
                        tracing::debug!("no new messages received");
                        break;
                    }
                    Err(TryRecvError::Disconnected) => {
                        tracing::debug!("communication was disconnected, no more messages will be received, spinning down");
                        return Ok(());
                    }
                }
            }

            let state = {
                let guard = self.state.read().await;
                guard.clone()
            };
            let state = match state.progress(&self.ctx).await {
                Ok(state) => state,
                Err(err) => {
                    tracing::info!("protocol unable to progress: {err:?}");
                    continue;
                }
            };
            let mut state = match state.advance(&self.ctx, contract_state).await {
                Ok(state) => state,
                Err(err) => {
                    tracing::info!("protocol unable to advance: {err:?}");
                    continue;
                }
            };
            if let Err(err) = state.handle(&self.ctx, &mut queue).await {
                tracing::info!("protocol unable to handle messages: {err:?}");
                continue;
            }

            let mut guard = self.state.write().await;
            *guard = state;
            drop(guard);

            tokio::time::sleep(Duration::from_millis(1000)).await;
        }
    }
}
