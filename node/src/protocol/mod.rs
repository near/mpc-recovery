pub mod contract;
mod cryptography;
pub mod presignature;
mod signature;
pub mod triple;

pub mod consensus;
pub mod message;
pub mod state;

pub use consensus::ConsensusError;
pub use contract::primitives::ParticipantInfo;
pub use contract::ProtocolState;
pub use cryptography::CryptographicError;
pub use message::MpcMessage;
pub use signature::SignQueue;
pub use signature::SignRequest;
pub use state::NodeState;

use self::consensus::ConsensusCtx;
use self::cryptography::CryptographicCtx;
use self::message::MessageCtx;
use self::triple::TripleConfig;
use crate::mesh::Mesh;
use crate::protocol::consensus::ConsensusProtocol;
use crate::protocol::cryptography::CryptographicProtocol;
use crate::protocol::message::{MessageHandler, MpcMessageQueue};
use crate::rpc_client::{self};
use crate::storage::secret_storage::SecretNodeStorageBox;
use crate::storage::triple_storage::LockTripleNodeStorageBox;

use cait_sith::protocol::Participant;
use near_crypto::InMemorySigner;
use near_primitives::types::AccountId;
use reqwest::IntoUrl;
use std::time::Instant;
use std::{sync::Arc, time::Duration};
use tokio::sync::mpsc::{self, error::TryRecvError};
use tokio::sync::RwLock;
use url::Url;

use mpc_keys::hpke;

struct Ctx {
    my_address: Url,
    account_id: AccountId,
    mpc_contract_id: AccountId,
    signer: InMemorySigner,
    rpc_client: near_fetch::Client,
    http_client: reqwest::Client,
    sign_queue: Arc<RwLock<SignQueue>>,
    cipher_pk: hpke::PublicKey,
    sign_sk: near_crypto::SecretKey,
    secret_storage: SecretNodeStorageBox,
    triple_cfg: TripleConfig,
    triple_storage: LockTripleNodeStorageBox,
    mesh: Mesh,
}

impl ConsensusCtx for &mut MpcSignProtocol {
    fn my_account_id(&self) -> &AccountId {
        &self.ctx.account_id
    }

    fn http_client(&self) -> &reqwest::Client {
        &self.ctx.http_client
    }

    fn rpc_client(&self) -> &near_fetch::Client {
        &self.ctx.rpc_client
    }

    fn signer(&self) -> &InMemorySigner {
        &self.ctx.signer
    }

    fn mpc_contract_id(&self) -> &AccountId {
        &self.ctx.mpc_contract_id
    }

    fn my_address(&self) -> &Url {
        &self.ctx.my_address
    }

    fn sign_queue(&self) -> Arc<RwLock<SignQueue>> {
        self.ctx.sign_queue.clone()
    }

    fn cipher_pk(&self) -> &hpke::PublicKey {
        &self.ctx.cipher_pk
    }

    fn sign_pk(&self) -> near_crypto::PublicKey {
        self.ctx.sign_sk.public_key()
    }

    fn sign_sk(&self) -> &near_crypto::SecretKey {
        &self.ctx.sign_sk
    }

    fn secret_storage(&self) -> &SecretNodeStorageBox {
        &self.ctx.secret_storage
    }

    fn triple_cfg(&self) -> TripleConfig {
        self.ctx.triple_cfg
    }

    fn triple_storage(&mut self) -> LockTripleNodeStorageBox {
        self.ctx.triple_storage.clone()
    }
}

#[async_trait::async_trait]
impl CryptographicCtx for &mut MpcSignProtocol {
    async fn me(&self) -> Participant {
        get_my_participant(self).await
    }

    fn http_client(&self) -> &reqwest::Client {
        &self.ctx.http_client
    }

    fn rpc_client(&self) -> &near_fetch::Client {
        &self.ctx.rpc_client
    }

    fn signer(&self) -> &InMemorySigner {
        &self.ctx.signer
    }

    fn mpc_contract_id(&self) -> &AccountId {
        &self.ctx.mpc_contract_id
    }

    fn cipher_pk(&self) -> &hpke::PublicKey {
        &self.ctx.cipher_pk
    }

    fn sign_sk(&self) -> &near_crypto::SecretKey {
        &self.ctx.sign_sk
    }

    fn secret_storage(&mut self) -> &mut SecretNodeStorageBox {
        &mut self.ctx.secret_storage
    }

    fn mesh(&self) -> &Mesh {
        &self.ctx.mesh
    }
}

#[async_trait::async_trait]
impl MessageCtx for &MpcSignProtocol {
    async fn me(&self) -> Participant {
        get_my_participant(self).await
    }

    fn mesh(&self) -> &Mesh {
        &self.ctx.mesh
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
        my_address: U,
        mpc_contract_id: AccountId,
        account_id: AccountId,
        rpc_client: near_fetch::Client,
        signer: InMemorySigner,
        receiver: mpsc::Receiver<MpcMessage>,
        sign_queue: Arc<RwLock<SignQueue>>,
        cipher_pk: hpke::PublicKey,
        secret_storage: SecretNodeStorageBox,
        triple_cfg: TripleConfig,
        triple_storage: LockTripleNodeStorageBox,
    ) -> (Self, Arc<RwLock<NodeState>>) {
        let state = Arc::new(RwLock::new(NodeState::Starting));
        let ctx = Ctx {
            my_address: my_address.into_url().unwrap(),
            account_id,
            mpc_contract_id,
            rpc_client,
            http_client: reqwest::Client::new(),
            sign_queue,
            cipher_pk,
            sign_sk: signer.secret_key.clone(),
            signer,
            secret_storage,
            triple_cfg,
            triple_storage,
            mesh: Mesh::default(),
        };
        let protocol = MpcSignProtocol {
            ctx,
            receiver,
            state: state.clone(),
        };
        (protocol, state)
    }

    pub async fn run(mut self) -> anyhow::Result<()> {
        let my_account_id = self.ctx.account_id.to_string();
        let _span = tracing::info_span!("running", my_account_id);
        crate::metrics::NODE_RUNNING
            .with_label_values(&[&my_account_id])
            .set(1);
        let mut queue = MpcMessageQueue::default();
        let mut last_state_update = Instant::now();
        loop {
            tracing::debug!("trying to advance mpc recovery protocol");
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

            let mut state = match state.progress(&mut self).await {
                Ok(state) => state,
                Err(err) => {
                    tracing::info!("protocol unable to progress: {err:?}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };

            if last_state_update.elapsed() > Duration::from_secs(1) {
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

                // Establish the participants for this current iteration of the protocol loop. This will
                // set which participants are currently active in the protocol and determines who will be
                // receiving messages.
                self.ctx.mesh.establish_participants(&contract_state).await;

                state = match state.advance(&mut self, contract_state).await {
                    Ok(state) => state,
                    Err(err) => {
                        tracing::info!("protocol unable to advance: {err:?}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                last_state_update = Instant::now();
            }

            if let Err(err) = state.handle(&self, &mut queue).await {
                tracing::info!("protocol unable to handle messages: {err:?}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }

            let mut guard = self.state.write().await;
            *guard = state;
            drop(guard);
        }
    }
}

async fn get_my_participant(protocol: &MpcSignProtocol) -> Participant {
    let my_near_acc_id = protocol.ctx.account_id.clone();
    let state = protocol.state.read().await;
    let participant_info = state
        .find_participant_info(&my_near_acc_id)
        .unwrap_or_else(|| {
            tracing::error!("could not find participant info for {my_near_acc_id}");
            panic!("could not find participant info for {my_near_acc_id}");
        });
    participant_info.id.into()
}
