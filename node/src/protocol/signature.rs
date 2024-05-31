use super::contract::primitives::Participants;
use super::message::SignatureMessage;
use super::presignature::{Presignature, PresignatureId, PresignatureManager};
use crate::indexer::ContractSignRequest;
use crate::kdf::into_eth_sig;
use crate::types::SignatureProtocol;
use crate::util::AffinePointExt;

use cait_sith::protocol::{Action, InitializationError, Participant, ProtocolError};
use cait_sith::{FullSignature, PresignOutput};
use chrono::Utc;
use crypto_shared::{derive_key, PublicKey};
use crypto_shared::{ScalarExt, SerializableScalar};
use k256::{Scalar, Secp256k1};
use mpc_contract::SignatureRequest;
use rand::rngs::StdRng;
use rand::seq::{IteratorRandom, SliceRandom};
use rand::SeedableRng;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use near_account_id::AccountId;
use near_fetch::signer::SignerExt;
use near_primitives::hash::CryptoHash;

/// Duration for which completed signatures are retained.
pub const COMPLETION_EXISTENCE_TIMEOUT: Duration = Duration::from_secs(120 * 60);

pub struct SignRequest {
    pub receipt_id: CryptoHash,
    pub request: ContractSignRequest,
    pub epsilon: Scalar,
    pub delta: Scalar,
    pub entropy: [u8; 32],
    pub time_added: Instant,
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

    pub fn len(&self) -> usize {
        self.unorganized_requests.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn add(&mut self, request: SignRequest) {
        tracing::info!(
            receipt_id = %request.receipt_id,
            payload = hex::encode(request.request.payload),
            entropy = hex::encode(request.entropy),
            "new sign request"
        );
        self.unorganized_requests.push(request);
    }

    pub fn organize(
        &mut self,
        threshold: usize,
        active: &Participants,
        me: Participant,
        my_account_id: &AccountId,
    ) {
        for request in self.unorganized_requests.drain(..) {
            let mut rng = StdRng::from_seed(request.entropy);
            let subset = active.keys().choose_multiple(&mut rng, threshold);
            let proposer = **subset.choose(&mut rng).unwrap();
            if subset.contains(&&me) {
                tracing::info!(
                    receipt_id = %request.receipt_id,
                    ?me,
                    ?subset,
                    ?proposer,
                    "saving sign request: node is in the signer subset"
                );
                let proposer_requests = self.requests.entry(proposer).or_default();
                proposer_requests.insert(request.receipt_id, request);
                crate::metrics::NUM_SIGN_REQUESTS_MINE
                    .with_label_values(&[my_account_id.as_str()])
                    .inc();
            } else {
                tracing::info!(
                    receipt_id = %request.receipt_id,
                    ?me,
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
    pub participants: Vec<Participant>,
    pub proposer: Participant,
    pub presignature_id: PresignatureId,
    pub request: ContractSignRequest,
    pub epsilon: Scalar,
    pub delta: Scalar,
    pub sign_request_timestamp: Instant,
    pub generator_timestamp: Instant,
}

impl SignatureGenerator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol: SignatureProtocol,
        participants: Vec<Participant>,
        proposer: Participant,
        presignature_id: PresignatureId,
        request: ContractSignRequest,
        epsilon: Scalar,
        delta: Scalar,
        sign_request_timestamp: Instant,
    ) -> Self {
        Self {
            protocol,
            participants,
            proposer,
            presignature_id,
            request,
            epsilon,
            delta,
            sign_request_timestamp,
            generator_timestamp: Instant::now(),
        }
    }

    pub fn poke(&mut self) -> Result<Action<FullSignature<Secp256k1>>, ProtocolError> {
        if self.generator_timestamp.elapsed() > crate::types::PROTOCOL_SIGNATURE_TIMEOUT {
            tracing::info!(self.presignature_id, "signature protocol timed out");
            return Err(ProtocolError::Other(
                anyhow::anyhow!("signature protocol timed out").into(),
            ));
        }

        self.protocol.poke()
    }
}

/// Generator for signature thas has failed. Only retains essential information
/// for starting up this failed signature once again.
pub struct GenerationRequest {
    pub proposer: Participant,
    pub request: ContractSignRequest,
    pub epsilon: Scalar,
    pub delta: Scalar,
    pub sign_request_timestamp: Instant,
}

pub struct SignatureManager {
    /// Ongoing signature generation protocols.
    generators: HashMap<CryptoHash, SignatureGenerator>,
    /// Failed signatures awaiting to be retried.
    failed: VecDeque<(CryptoHash, GenerationRequest)>,
    /// Set of completed signatures
    completed: HashMap<PresignatureId, Instant>,
    /// Generated signatures assigned to the current node that are yet to be published.
    /// Vec<(receipt_id, msg_hash, timestamp, output)>
    signatures: Vec<(
        CryptoHash,
        SignatureRequest,
        Instant,
        FullSignature<Secp256k1>,
    )>,
    me: Participant,
    public_key: PublicKey,
    epoch: u64,
}

impl SignatureManager {
    pub fn new(me: Participant, public_key: PublicKey, epoch: u64) -> Self {
        Self {
            generators: HashMap::new(),
            failed: VecDeque::new(),
            completed: HashMap::new(),
            signatures: Vec::new(),
            me,
            public_key,
            epoch,
        }
    }

    pub fn failed_len(&self) -> usize {
        self.failed.len()
    }

    pub fn me(&self) -> Participant {
        self.me
    }

    #[allow(clippy::too_many_arguments)]
    fn generate_internal(
        participants: &Participants,
        me: Participant,
        public_key: PublicKey,
        presignature: Presignature,
        req: GenerationRequest,
    ) -> Result<SignatureGenerator, InitializationError> {
        let participants = participants.keys_vec();
        let GenerationRequest {
            proposer,
            request,
            epsilon,
            delta,
            sign_request_timestamp,
        } = req;
        let PresignOutput { big_r, k, sigma } = presignature.output;
        // TODO: Check whether it is okay to use invert_vartime instead
        let output: PresignOutput<Secp256k1> = PresignOutput {
            big_r: (big_r * delta).to_affine(),
            k: k * delta.invert().unwrap(),
            sigma: (sigma + epsilon * k) * delta.invert().unwrap(),
        };
        let protocol = Box::new(cait_sith::sign(
            &participants,
            me,
            derive_key(public_key, epsilon),
            output,
            Scalar::from_bytes(&request.payload),
        )?);
        Ok(SignatureGenerator::new(
            protocol,
            participants,
            proposer,
            presignature.id,
            request,
            epsilon,
            delta,
            sign_request_timestamp,
        ))
    }

    fn retry_failed_generation(
        &mut self,
        receipt_id: CryptoHash,
        req: GenerationRequest,
        presignature: Presignature,
        participants: &Participants,
    ) -> Result<(), InitializationError> {
        tracing::info!(receipt_id = %receipt_id, participants = ?participants.keys_vec(), "restarting failed protocol to generate signature");
        let generator =
            Self::generate_internal(participants, self.me, self.public_key, presignature, req)?;
        self.generators.insert(receipt_id, generator);
        Ok(())
    }

    /// Starts a new presignature generation protocol.
    #[allow(clippy::too_many_arguments)]
    pub fn generate(
        &mut self,
        participants: &Participants,
        receipt_id: CryptoHash,
        presignature: Presignature,
        request: ContractSignRequest,
        epsilon: Scalar,
        delta: Scalar,
        sign_request_timestamp: Instant,
    ) -> Result<(), InitializationError> {
        tracing::info!(
            %receipt_id,
            me = ?self.me,
            presignature_id = presignature.id,
            participants = ?participants.keys_vec(),
            "starting protocol to generate a new signature",
        );
        let generator = Self::generate_internal(
            participants,
            self.me,
            self.public_key,
            presignature,
            GenerationRequest {
                proposer: self.me,
                request,
                epsilon,
                delta,
                sign_request_timestamp,
            },
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
    #[allow(clippy::too_many_arguments)]
    pub fn get_or_generate(
        &mut self,
        participants: &Participants,
        receipt_id: CryptoHash,
        proposer: Participant,
        presignature_id: PresignatureId,
        request: ContractSignRequest,
        epsilon: Scalar,
        delta: Scalar,
        presignature_manager: &mut PresignatureManager,
    ) -> Result<Option<&mut SignatureProtocol>, InitializationError> {
        match self.generators.entry(receipt_id) {
            Entry::Vacant(entry) => {
                tracing::info!(%receipt_id, me = ?self.me, presignature_id, "joining protocol to generate a new signature");
                let Some(presignature) = presignature_manager.take(presignature_id) else {
                    tracing::warn!(me = ?self.me, presignature_id, "presignature is missing, can't join signature generation protocol");
                    return Ok(None);
                };
                tracing::info!(me = ?self.me, presignature_id, "found presignature: ready to start signature generation");
                let generator = Self::generate_internal(
                    participants,
                    self.me,
                    self.public_key,
                    presignature,
                    GenerationRequest {
                        proposer,
                        request,
                        epsilon,
                        delta,
                        sign_request_timestamp: Instant::now(),
                    },
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
    pub fn poke(&mut self) -> Vec<(Participant, SignatureMessage)> {
        let mut messages = Vec::new();
        self.generators.retain(|receipt_id, generator| {
            loop {
                let action = match generator.poke() {
                    Ok(action) => action,
                    Err(err) => {
                        tracing::warn!(?err, "signature failed to be produced; pushing request back into failed queue");
                        if generator.proposer == self.me {
                            // only retry the signature generation if it was initially proposed by us. We do not
                            // want any nodes to be proposing the same signature multiple times.
                            self.failed.push_back((
                                *receipt_id,
                                GenerationRequest {
                                    proposer: generator.proposer,
                                    request: generator.request.clone(),
                                    epsilon: generator.epsilon,
                                    delta: generator.delta,
                                    sign_request_timestamp: generator.sign_request_timestamp
                                },
                            ));
                        }
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
                        for p in generator.participants.iter() {
                            messages.push((
                                *p,
                                SignatureMessage {
                                    receipt_id: *receipt_id,
                                    proposer: generator.proposer,
                                    presignature_id: generator.presignature_id,
                                    request: generator.request.clone(),
                                    epsilon: generator.epsilon,
                                    delta: generator.delta,
                                    epoch: self.epoch,
                                    from: self.me,
                                    data: data.clone(),
                                    timestamp: Utc::now().timestamp() as u64
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
                            request: generator.request.clone(),
                            epsilon: generator.epsilon,
                            delta: generator.delta,
                            epoch: self.epoch,
                            from: self.me,
                            data,
                            timestamp: Utc::now().timestamp() as u64
                        },
                    )),
                    Action::Return(output) => {
                        tracing::info!(
                            ?receipt_id,
                            me = ?self.me,
                            presignature_id = generator.presignature_id,
                            big_r = ?output.big_r.to_base58(),
                            s = ?output.s,
                            "completed signature generation"
                        );
                        self.completed.insert(generator.presignature_id, Instant::now());
                        let request = SignatureRequest {
                            epsilon: SerializableScalar {scalar: generator.epsilon},
                            payload_hash: generator.request.payload,
                        };
                        if generator.proposer == self.me {
                            self.signatures
                                .push((*receipt_id, request, generator.sign_request_timestamp, output));
                        }
                        // Do not retain the protocol
                        return false;
                    }
                }
            }
        });
        messages
    }

    pub fn handle_requests(
        &mut self,
        threshold: usize,
        active: &Participants,
        my_requests: &mut HashMap<CryptoHash, SignRequest>,
        presignature_manager: &mut PresignatureManager,
    ) -> Result<(), super::CryptographicError> {
        let mut failed_presigs = Vec::new();
        while let Some(mut presignature) = {
            if self.failed.is_empty() && my_requests.is_empty() {
                None
            } else {
                presignature_manager.take_mine()
            }
        } {
            let sig_participants = active.intersection(&[&presignature.participants]);
            if sig_participants.len() < threshold {
                tracing::debug!(
                    participants = ?sig_participants.keys_vec(),
                    "we do not have enough participants to generate a failed signature"
                );
                failed_presigs.push(presignature);
                continue;
            }

            // NOTE: this prioritizes old requests first then tries to do new ones if there's enough presignatures.
            // TODO: we need to decide how to prioritize certain requests over others such as with gas or time of
            // when the request made it into the NEAR network.
            // issue: https://github.com/near/mpc-recovery/issues/596
            if let Some((receipt_id, failed_req)) = self.failed.pop_front() {
                self.retry_failed_generation(
                    receipt_id,
                    failed_req,
                    presignature,
                    &sig_participants,
                )?;

                if let Some(another_presignature) = presignature_manager.take_mine() {
                    presignature = another_presignature;
                } else {
                    break;
                }
            }

            let Some(receipt_id) = my_requests.keys().next().cloned() else {
                failed_presigs.push(presignature);
                continue;
            };
            let Some(my_request) = my_requests.remove(&receipt_id) else {
                failed_presigs.push(presignature);
                continue;
            };
            self.generate(
                &sig_participants,
                receipt_id,
                presignature,
                my_request.request,
                my_request.epsilon,
                my_request.delta,
                my_request.time_added,
            )?;
        }

        // add back the failed presignatures that were incompatible to be made into
        // signatures due to failures or lack of participants.
        for presignature in failed_presigs {
            presignature_manager.insert_mine(presignature);
        }

        Ok(())
    }

    pub async fn publish<T: SignerExt>(
        &mut self,
        rpc_client: &near_fetch::Client,
        signer: &T,
        mpc_contract_id: &AccountId,
        my_account_id: &AccountId,
    ) -> Result<(), near_fetch::Error> {
        for (receipt_id, request, time_added, signature) in self.signatures.drain(..) {
            let expected_public_key = derive_key(self.public_key, request.epsilon.scalar);
            // We do this here, rather than on the client side, so we can use the ecrecover system function on NEAR to validate our signature
            let signature = into_eth_sig(
                &expected_public_key,
                &signature.big_r,
                &signature.s,
                Scalar::from_bytes(&request.payload_hash),
            )
            .map_err(|_| near_fetch::Error::InvalidArgs("Failed to generate a recovery ID"))?;
            let response = rpc_client
                .call(signer, mpc_contract_id, "respond")
                .args_json(serde_json::json!({
                    "request": request,
                    "response": signature,
                }))
                .max_gas()
                .transact()
                .await?;
            crate::metrics::NUM_SIGN_SUCCESS
                .with_label_values(&[my_account_id.as_str()])
                .inc();
            crate::metrics::SIGN_LATENCY
                .with_label_values(&[my_account_id.as_str()])
                .observe(time_added.elapsed().as_secs_f64());
            if time_added.elapsed().as_secs() <= 30 {
                crate::metrics::NUM_SIGN_SUCCESS_30S
                    .with_label_values(&[my_account_id.as_str()])
                    .inc();
            }
            tracing::info!(%receipt_id, big_r = signature.big_r.affine_point.to_base58(), s = ?signature.s, status = ?response.status(), "published signature response");
        }
        Ok(())
    }

    /// Check whether or not the signature has been completed with this presignature_id.
    pub fn has_completed(&mut self, presignature_id: &PresignatureId) -> bool {
        self.completed
            .retain(|_, timestamp| timestamp.elapsed() < COMPLETION_EXISTENCE_TIMEOUT);

        self.completed.contains_key(presignature_id)
    }
}
