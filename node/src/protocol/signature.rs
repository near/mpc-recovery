use super::message::SignatureMessage;
use super::presignature::{Presignature, PresignatureId, PresignatureManager};
use super::state::RunningState;
use crate::kdf;
use crate::types::{PublicKey, SignatureProtocol};
use crate::util::{AffinePointExt, ScalarExt};
use cait_sith::protocol::{Action, InitializationError, Participant, ProtocolError};
use cait_sith::{FullSignature, PresignOutput};
use k256::{Scalar, Secp256k1};
use near_crypto::Signer;
use near_fetch::signer::ExposeAccountId;
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::FunctionCallAction;
use near_primitives::types::AccountId;
use rand::rngs::StdRng;
use rand::seq::{IteratorRandom, SliceRandom};
use rand::SeedableRng;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::Arc;

pub struct SignRequest {
    pub receipt_id: CryptoHash,
    pub msg_hash: [u8; 32],
    pub epsilon: Scalar,
    pub entropy: [u8; 32],
}

#[derive(Default)]
pub struct SignQueue {
    unorganized_requests: Vec<SignRequest>,
    requests: HashMap<Participant, HashMap<CryptoHash, SignRequest>>,
}

impl SignQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, request: SignRequest) {
        tracing::info!(
            receipt_id = %request.receipt_id,
            payload = hex::encode(request.msg_hash),
            entropy = hex::encode(request.entropy),
            "new sign request"
        );
        self.unorganized_requests.push(request);
    }

    pub fn organize(&mut self, state: &RunningState, me: Participant) {
        for request in self.unorganized_requests.drain(..) {
            let mut rng = StdRng::from_seed(request.entropy);
            let subset = state
                .participants
                .keys()
                .choose_multiple(&mut rng, state.threshold);
            let proposer = **subset.choose(&mut rng).unwrap();
            if subset.contains(&&me) {
                tracing::info!(
                    receipt_id = %request.receipt_id,
                    ?subset,
                    ?proposer,
                    "saving sign request: node is in the signer subset"
                );
                let proposer_requests = self.requests.entry(proposer).or_default();
                proposer_requests.insert(request.receipt_id, request);
            } else {
                tracing::info!(
                    receipt_id = %request.receipt_id,
                    ?subset,
                    ?proposer,
                    "skipping sign request: node is NOT in the signer subset"
                );
            }
        }
    }

    pub fn contains(&self, participant: Participant, receipt_id: CryptoHash) -> bool {
        let Some(participant_requests) = self.requests.get(&participant) else {
            return false;
        };
        participant_requests.contains_key(&receipt_id)
    }

    pub fn my_requests(&mut self, me: Participant) -> &mut HashMap<CryptoHash, SignRequest> {
        self.requests.entry(me).or_default()
    }
}

/// An ongoing signature generator.
pub struct SignatureGenerator {
    pub protocol: SignatureProtocol,
    pub proposer: Participant,
    pub presignature_id: PresignatureId,
    pub msg_hash: [u8; 32],
    pub epsilon: Scalar,
    pub delta: Scalar,
}

pub struct SignatureManager {
    /// Ongoing signature generation protocols.
    generators: HashMap<CryptoHash, SignatureGenerator>,
    /// Generated signatures assigned to the current node that are yet to be published.
    signatures: Vec<(CryptoHash, FullSignature<Secp256k1>)>,

    participants: Vec<Participant>,
    me: Participant,
    public_key: PublicKey,
    epoch: u64,
}

impl SignatureManager {
    pub fn new(
        participants: Vec<Participant>,
        me: Participant,
        public_key: PublicKey,
        epoch: u64,
    ) -> Self {
        Self {
            generators: HashMap::new(),
            signatures: Vec::new(),
            participants,
            me,
            public_key,
            epoch,
        }
    }

    fn generate_internal(
        participants: &[Participant],
        me: Participant,
        public_key: PublicKey,
        proposer: Participant,
        presignature: Presignature,
        msg_hash: [u8; 32],
        epsilon: Scalar,
        delta: Scalar,
    ) -> Result<SignatureGenerator, InitializationError> {
        let PresignOutput { big_r, k, sigma } = presignature.output;
        // TODO: Check whether it is okay to use invert_vartime instead
        let output: PresignOutput<Secp256k1> = PresignOutput {
            big_r: (big_r * delta).to_affine(),
            k: k * delta.invert().unwrap(),
            sigma: (sigma + epsilon * k) * delta.invert().unwrap(),
        };
        let protocol = Arc::new(std::sync::RwLock::new(cait_sith::sign(
            participants,
            me,
            kdf::derive_key(public_key, epsilon),
            output,
            Scalar::from_bytes(&msg_hash),
        )?));
        Ok(SignatureGenerator {
            protocol,
            proposer,
            presignature_id: presignature.id,
            msg_hash,
            epsilon,
            delta,
        })
    }

    /// Starts a new presignature generation protocol.
    pub fn generate(
        &mut self,
        receipt_id: CryptoHash,
        presignature: Presignature,
        public_key: PublicKey,
        msg_hash: [u8; 32],
        epsilon: Scalar,
        delta: Scalar,
    ) -> Result<(), InitializationError> {
        tracing::info!(%receipt_id, "starting protocol to generate a new signature");
        let generator = Self::generate_internal(
            &self.participants,
            self.me,
            public_key,
            self.me,
            presignature,
            msg_hash,
            epsilon,
            delta,
        )?;
        self.generators.insert(receipt_id, generator);
        Ok(())
    }

    /// Ensures that the presignature with the given id is either:
    /// 1) Already generated in which case returns `None`, or
    /// 2) Is currently being generated by `protocol` in which case returns `Some(protocol)`, or
    /// 3) Has never been seen by the manager in which case start a new protocol and returns `Some(protocol)`, or
    /// 4) Depends on triples (`triple0`/`triple1`) that are unknown to the node
    // TODO: What if the presignature completed generation and is already spent?
    pub fn get_or_generate(
        &mut self,
        receipt_id: CryptoHash,
        proposer: Participant,
        presignature_id: PresignatureId,
        msg_hash: [u8; 32],
        epsilon: Scalar,
        delta: Scalar,
        presignature_manager: &mut PresignatureManager,
    ) -> Result<Option<&mut SignatureProtocol>, InitializationError> {
        match self.generators.entry(receipt_id) {
            Entry::Vacant(entry) => {
                tracing::info!(%receipt_id, "joining protocol to generate a new signature");
                let Some(presignature) = presignature_manager.take(presignature_id) else {
                    tracing::warn!(presignature_id, "presignature is missing, can't join");
                    return Ok(None);
                };
                let generator = Self::generate_internal(
                    &self.participants,
                    self.me,
                    self.public_key,
                    proposer,
                    presignature,
                    msg_hash,
                    epsilon,
                    delta,
                )?;
                let generator = entry.insert(generator);
                Ok(Some(&mut generator.protocol))
            }
            Entry::Occupied(entry) => Ok(Some(&mut entry.into_mut().protocol)),
        }
    }

    /// Pokes all of the ongoing generation protocols and returns a vector of
    /// messages to be sent to the respective participant.
    ///
    /// An empty vector means we cannot progress until we receive a new message.
    pub fn poke(&mut self) -> Result<Vec<(Participant, SignatureMessage)>, ProtocolError> {
        let mut messages = Vec::new();
        let mut result = Ok(());
        self.generators.retain(|receipt_id, generator| {
            loop {
                let mut protocol = match generator.protocol.write() {
                    Ok(protocol) => protocol,
                    Err(err) => {
                        tracing::error!(
                            ?err,
                            "failed to acquire lock on signature generation protocol"
                        );
                        break false;
                    }
                };
                let action = match protocol.poke() {
                    Ok(action) => action,
                    Err(e) => {
                        result = Err(e);
                        break false;
                    }
                };
                match action {
                    Action::Wait => {
                        tracing::debug!("waiting");
                        // Retain protocol until we are finished
                        return true;
                    }
                    Action::SendMany(data) => {
                        for p in &self.participants {
                            messages.push((
                                *p,
                                SignatureMessage {
                                    receipt_id: *receipt_id,
                                    proposer: generator.proposer,
                                    presignature_id: generator.presignature_id,
                                    msg_hash: generator.msg_hash,
                                    epsilon: generator.epsilon,
                                    delta: generator.delta,
                                    epoch: self.epoch,
                                    from: self.me,
                                    data: data.clone(),
                                },
                            ))
                        }
                    }
                    Action::SendPrivate(p, data) => messages.push((
                        p,
                        SignatureMessage {
                            receipt_id: *receipt_id,
                            proposer: generator.proposer,
                            presignature_id: generator.presignature_id,
                            msg_hash: generator.msg_hash,
                            epsilon: generator.epsilon,
                            delta: generator.delta,
                            epoch: self.epoch,
                            from: self.me,
                            data: data.clone(),
                        },
                    )),
                    Action::Return(output) => {
                        tracing::info!(
                            ?receipt_id,
                            big_r = ?output.big_r.to_base58(),
                            s = ?output.s,
                            "completed signature generation"
                        );
                        if generator.proposer == self.me {
                            self.signatures.push((*receipt_id, output));
                        }
                        // Do not retain the protocol
                        return false;
                    }
                }
            }
        });
        result.map(|_| messages)
    }

    pub async fn publish<T: Signer + ExposeAccountId>(
        &mut self,
        rpc_client: &near_fetch::Client,
        signer: &T,
        mpc_contract_id: &AccountId,
    ) -> Result<(), near_fetch::Error> {
        for (receipt_id, signature) in self.signatures.drain(..) {
            // TODO: Figure out how to properly serialize the signature
            // let r_s = signature.big_r.x().concat(signature.s.to_bytes());
            // let tag =
            //     ConditionallySelectable::conditional_select(&2u8, &3u8, signature.big_r.y_is_odd());
            // let signature = r_s.append(tag);
            // let signature = Secp256K1Signature::try_from(signature.as_slice()).unwrap();
            // let signature = Signature::SECP256K1(signature);
            tracing::info!(%receipt_id, big_r = signature.big_r.to_base58(), s = ?signature.s, "publishing signature response");
            rpc_client
                .send_tx(
                    signer,
                    mpc_contract_id,
                    vec![near_primitives::transaction::Action::FunctionCall(
                        FunctionCallAction {
                            method_name: "respond".to_string(),
                            args: serde_json::to_vec(&serde_json::json!({
                                "receipt_id": receipt_id.as_bytes(),
                                "big_r": signature.big_r,
                                "s": signature.s
                            }))
                            .unwrap(),
                            gas: 300_000_000_000_000,
                            deposit: 0,
                        },
                    )],
                )
                .await?;
        }
        Ok(())
    }
}
