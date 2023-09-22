use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use curv::arithmetic::Converter;
use curv::cryptographic_primitives::commitments::{
    hash_commitment::HashCommitment, traits::Commitment,
};
use curv::elliptic::curves::{Ed25519, Point};
use curv::BigInt;
use ed25519_dalek::{Sha512, Signature, Verifier};
use multi_party_eddsa::protocols;
use multi_party_eddsa::protocols::aggsig::{self, KeyAgg, SignSecondMsg};
use rand8::rngs::OsRng;
use rand8::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::AggregateSigningError;
use crate::transaction::{to_dalek_public_key, to_dalek_signature};

pub struct SigningState {
    committed: RwLock<HashMap<AggrCommitment, Committed>>,
    revealed: RwLock<HashMap<Reveal, Revealed>>,
}

impl Default for SigningState {
    fn default() -> Self {
        Self::new()
    }
}

impl SigningState {
    pub fn new() -> Self {
        SigningState {
            committed: RwLock::new(HashMap::new()),
            revealed: RwLock::new(HashMap::new()),
        }
    }

    pub async fn get_commitment(
        &self,
        our_key: &protocols::ExpandedKeyPair,
        node_key: &protocols::ExpandedKeyPair,
        message: Vec<u8>,
    ) -> Result<SignedCommitment, AggregateSigningError> {
        // We use OSRng on it's own instead of thread_random() for commit padding and OsRng
        self.get_commitment_with_rng(our_key, node_key, message, &mut OsRng)
            .await
    }

    /// This is for deterministic testing, don't use it in prod
    /// The whole signing process is deterministic if a deterministic rng is used
    pub(crate) async fn get_commitment_with_rng(
        &self,
        our_key: &protocols::ExpandedKeyPair,
        node_key: &protocols::ExpandedKeyPair,
        message: Vec<u8>,
        rng: &mut impl Rng,
    ) -> Result<SignedCommitment, AggregateSigningError> {
        let (commitment, state) = Committed::commit(our_key, node_key, message, rng)?;
        self.committed
            .write()
            .await
            .insert(commitment.commitment.clone(), state);
        Ok(commitment)
    }

    pub async fn get_reveal(
        &self,
        node_info: NodeInfo,
        recieved_commitments: Vec<SignedCommitment>,
    ) -> Result<Reveal, AggregateSigningError> {
        // TODO Factor this out
        let i = node_info.our_index;
        let our_c = recieved_commitments.get(i).ok_or_else(|| {
            AggregateSigningError::InvalidCommitmentNumbers(
                node_info.our_index,
                recieved_commitments.len(),
            )
        })?;
        // Don't readd this on failure, this commitment is now burnt
        let state = self
            .committed
            .write()
            .await
            .remove(&our_c.commitment)
            .ok_or_else(|| {
                AggregateSigningError::CommitmentNotFound(format!("{:?}", our_c.commitment))
            })?;

        let (reveal, state) = state.reveal(&node_info, recieved_commitments).await?;
        let reveal = Reveal(reveal);
        self.revealed.write().await.insert(reveal.clone(), state);
        Ok(reveal)
    }

    pub async fn get_signature_share(
        &self,
        node_info: NodeInfo,
        signature_parts: Vec<Reveal>,
    ) -> Result<protocols::Signature, AggregateSigningError> {
        let i = node_info.our_index;
        let our_r = signature_parts.get(i).ok_or_else(|| {
            AggregateSigningError::InvalidRevealNumbers(node_info.our_index, signature_parts.len())
        })?;

        // Don't readd this on failure, this commitment is now burnt
        let state = self
            .revealed
            .write()
            .await
            .remove(our_r)
            .ok_or_else(|| AggregateSigningError::RevealNotFound(format!("{:?}", our_r)))?;

        let signature_parts = signature_parts.into_iter().map(|s| s.0).collect();

        state.combine(signature_parts, &node_info)
    }
}

/// This represents the signers view of a single signed transaction
/// We use an minor extention of aggregate signatures to do this.
/// This extension creates a "node key" in addition to the signing keys which allows the key to verify that the information they recieves actually comes from a signer
#[derive(Clone)]
pub struct Committed {
    ephemeral_key: aggsig::EphemeralKey,
    our_signature: aggsig::SignSecondMsg,
    message: Vec<u8>,
    our_key: protocols::ExpandedKeyPair,
}

// TOOD Make this fixed size hash
#[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct AggrCommitment(pub BigInt);

impl Hash for AggrCommitment {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.0.to_bytes().hash(hasher);
    }
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Reveal(pub SignSecondMsg);

impl Hash for Reveal {
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        // TODO fix collision risk
        let SignSecondMsg { R, blind_factor } = self.0.clone();
        R.to_bytes(false).hash(hasher);
        AggrCommitment(blind_factor).hash(hasher)
    }
}

impl Eq for Reveal {}

impl Committed {
    pub fn commit(
        our_key: &protocols::ExpandedKeyPair,
        node_key: &protocols::ExpandedKeyPair,
        message: Vec<u8>,
        rng: &mut impl Rng,
    ) -> Result<(SignedCommitment, Self), AggregateSigningError> {
        let (ephemeral_key, commit, our_signature) =
            aggsig::create_ephemeral_key_and_commit_rng(our_key, &message, rng);
        let s = Committed {
            ephemeral_key,
            our_signature,
            message,
            our_key: our_key.clone(),
        };
        let sc = SignedCommitment::create(AggrCommitment(commit.commitment), node_key, our_key)?;
        Ok((sc, s))
    }

    pub async fn reveal(
        self,
        node_info: &NodeInfo,
        commitments: Vec<SignedCommitment>,
    ) -> Result<(SignSecondMsg, Revealed), AggregateSigningError> {
        let (commitments, signing_public_keys) = node_info
            .signed_by_every_node(commitments)
            .await?
            .into_iter()
            .unzip();
        Ok((
            self.our_signature.clone(),
            Revealed {
                commitments,
                committed: self,
                signing_public_keys,
            },
        ))
    }
}

#[derive(Clone)]
pub struct Revealed {
    commitments: Vec<AggrCommitment>,
    signing_public_keys: Vec<Point<Ed25519>>,
    committed: Committed,
}

impl Revealed {
    pub fn combine(
        self,
        signature_parts: Vec<SignSecondMsg>,
        node_info: &NodeInfo,
    ) -> Result<protocols::Signature, AggregateSigningError> {
        // Check the commitments have the correct signatures
        for (commit, partial_sig) in self.commitments.iter().zip(signature_parts.iter()) {
            check_commitment(&partial_sig.R, &partial_sig.blind_factor, &commit.0)?;
        }
        // TODO less copying
        let rs: Vec<_> = signature_parts.into_iter().map(|s| s.R).collect();
        let r_tot = aggsig::get_R_tot(&rs);

        let key_agg = KeyAgg::key_aggregation_n(&self.signing_public_keys, node_info.our_index);

        let ephemeral_key = self.committed.ephemeral_key;

        let partial_sig = aggsig::partial_sign(
            &ephemeral_key.r,
            &self.committed.our_key,
            &key_agg.hash,
            &r_tot,
            &key_agg.apk,
            &self.committed.message,
        );

        Ok(partial_sig)
    }
}

// Stores info about the other nodes we're interacting with
#[derive(Clone)]
pub struct NodeInfo {
    pub nodes_public_keys: Arc<RwLock<Option<Vec<Point<Ed25519>>>>>,
    pub our_index: usize,
}

impl NodeInfo {
    pub fn new(our_index: usize, nodes_public_keys: Option<Vec<Point<Ed25519>>>) -> Self {
        Self {
            our_index,
            nodes_public_keys: Arc::new(RwLock::new(nodes_public_keys)),
        }
    }

    async fn signed_by_every_node(
        &self,
        signed: Vec<SignedCommitment>,
    ) -> Result<Vec<(AggrCommitment, Point<Ed25519>)>, AggregateSigningError> {
        self.nodes_public_keys
            .read()
            .await
            .as_ref()
            .ok_or(AggregateSigningError::NodeKeysUnavailable)?
            .iter()
            .zip(signed.iter())
            .map(|(public_key, signed)| signed.verify(public_key))
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCommitment {
    pub commitment: AggrCommitment,
    /// This is the public key we're currently signing with,
    /// not the node public key that generated the signature
    pub signing_public_key: Point<Ed25519>,
    /// Signature used to verify the signing public key in case a rogue one is
    /// inserted later on.
    pub signing_public_key_sig: Signature,
    /// This is signed with the node public key
    pub signature: Signature,
}

impl SignedCommitment {
    pub fn create(
        commitment: AggrCommitment,
        node_key: &protocols::ExpandedKeyPair,
        signing_keys: &protocols::ExpandedKeyPair,
    ) -> Result<Self, AggregateSigningError> {
        let to_sign = Self::serialize(&commitment, &signing_keys.public_key)?;
        let signature = aggsig::sign_single(b"", signing_keys);
        let signing_public_key_sig = to_dalek_signature(&signature)?;

        // This is awkward, we should move more stuff over to dalek later on
        let signature = aggsig::sign_single(&to_sign, node_key);
        let signature = to_dalek_signature(&signature)?;
        Ok(SignedCommitment {
            commitment,
            signing_public_key: signing_keys.public_key.clone(),
            signature,
            signing_public_key_sig,
        })
    }

    pub fn verify(
        &self,
        public_key: &Point<Ed25519>,
    ) -> Result<(AggrCommitment, Point<Ed25519>), AggregateSigningError> {
        let public_key = to_dalek_public_key(public_key)?;
        let message = Self::serialize(&self.commitment, &self.signing_public_key)?;
        public_key
            .verify(&message, &self.signature)
            .map_err(|e| AggregateSigningError::SignatureVerificationFailed(anyhow::anyhow!(e)))?;

        let signing_public_key = to_dalek_public_key(&self.signing_public_key)?;
        signing_public_key
            .verify(b"", &self.signing_public_key_sig)
            .map_err(|e| AggregateSigningError::SignatureVerificationFailed(anyhow::anyhow!(e)))?;

        Ok((self.commitment.clone(), self.signing_public_key.clone()))
    }

    fn serialize(
        commitment: &AggrCommitment,
        pk: &Point<Ed25519>,
    ) -> Result<Vec<u8>, AggregateSigningError> {
        let content = serde_json::to_vec(&(commitment, pk))
            .map_err(|e| AggregateSigningError::DataConversionFailure(anyhow::anyhow!(e)))?;
        // Makes signature collisions less likely
        let mut message = b"SignedCommitment::serialize".to_vec();
        message.extend(content);
        Ok(message)
    }
}

pub fn check_commitment(
    r_to_test: &Point<Ed25519>,
    blind_factor: &BigInt,
    comm: &BigInt,
) -> Result<(), AggregateSigningError> {
    let computed_comm = &HashCommitment::<Sha512>::create_commitment_with_user_defined_randomness(
        &r_to_test.y_coord().unwrap(),
        blind_factor,
    );
    if computed_comm != comm {
        // TODO check this is safe to share in case of error
        // Should be because everything is provided by the caller I think
        Err(AggregateSigningError::InvalidCommitment(
            r_to_test.clone(),
            blind_factor.clone(),
            computed_comm.clone(),
            comm.clone(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::transaction::from_dalek_signature;

    use super::*;
    use curv::elliptic::curves::{Ed25519, Point};
    use ed25519_dalek::{SignatureError, Verifier};
    use multi_party_eddsa::protocols::ExpandedKeyPair;

    fn verify_dalek(
        pk: &Point<Ed25519>,
        sig: &protocols::Signature,
        msg: &[u8],
    ) -> Result<(), SignatureError> {
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&sig.R.to_bytes(true));
        sig_bytes[32..].copy_from_slice(&sig.s.to_bytes());

        let dalek_pub = ed25519_dalek::PublicKey::from_bytes(&pk.to_bytes(true)).unwrap();
        let dalek_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes).unwrap();

        dalek_pub.verify(msg, &dalek_sig)
    }

    fn create_rogue_commit(message: &[u8], commitments: &[SignedCommitment]) -> SignedCommitment {
        let ks = || (ExpandedKeyPair::create(), ExpandedKeyPair::create());
        // Also generate a public key for the rogue key
        let (rogue_node_key, rogue_key) = ks();

        // Create rogue commitments to be inserted in to the list
        let rogue_pk = commitments
            .iter()
            .fold(rogue_key.public_key.clone(), |acc, c| {
                acc - &c.signing_public_key
            });

        let rogue_sig = aggsig::sign_single(b"", &rogue_key);
        let rogue_sig = commitments
            .iter()
            .map(|c| from_dalek_signature(c.signing_public_key_sig).unwrap())
            .fold(rogue_sig, |acc, s| protocols::Signature {
                R: acc.R - s.R,
                s: acc.s - s.s,
            });

        let (_ephemeral_key, commit, _our_signature) =
            aggsig::create_ephemeral_key_and_commit_rng(&rogue_key, message, &mut OsRng);
        let mut rogue_commit = SignedCommitment::create(
            AggrCommitment(commit.commitment),
            &rogue_node_key,
            &rogue_key,
        )
        .unwrap();
        rogue_commit.signing_public_key = rogue_pk;
        rogue_commit.signing_public_key_sig = to_dalek_signature(&rogue_sig).unwrap();
        rogue_commit
    }

    #[tokio::test]
    async fn rogue_attack() {
        // Generate node keys and signing keys
        let ks = || (ExpandedKeyPair::create(), ExpandedKeyPair::create());
        let (n1, k1) = ks();
        let (n2, k2) = ks();
        let (n3, k3) = ks();

        let nodes_public_keys = vec![
            n1.public_key.clone(),
            n2.public_key.clone(),
            n3.public_key.clone(),
        ];

        let ni = |n| NodeInfo::new(n, Some(nodes_public_keys.clone()));

        // Set up nodes with that config
        let s1 = SigningState::new();
        let s2 = SigningState::new();
        let s3 = SigningState::new();

        let message = b"message in a bottle".to_vec();

        let mut commitments = vec![
            s1.get_commitment(&k1, &n1, message.clone()).await.unwrap(),
            s2.get_commitment(&k2, &n2, message.clone()).await.unwrap(),
            s3.get_commitment(&k3, &n3, message.clone()).await.unwrap(),
        ];
        // Insert in the rogue key to be detected later.
        commitments.push(create_rogue_commit(&message, &commitments));

        let reveals = vec![
            s1.get_reveal(ni(0), commitments.clone()).await.unwrap(),
            s2.get_reveal(ni(1), commitments.clone()).await.unwrap(),
            s3.get_reveal(ni(2), commitments.clone()).await.unwrap(),
        ];

        let sig_shares = vec![
            s1.get_signature_share(ni(0), reveals.clone()).await.unwrap(),
            s2.get_signature_share(ni(1), reveals.clone()).await.unwrap(),
            s3.get_signature_share(ni(2), reveals).await.unwrap(),
        ];

        let signing_keys: Vec<_> = commitments
            .iter()
            .map(|c| c.signing_public_key.clone())
            .collect();
        let aggrigate_key = KeyAgg::key_aggregation_n(&signing_keys, 0);

        let signature = aggsig::add_signature_parts(&sig_shares);
        let verified = verify_dalek(&aggrigate_key.apk, &signature, &message);
        assert!(
            verified.is_err(),
            "Expected rogue key to be detected and create an invalid proof"
        );
    }

    #[tokio::test]
    async fn aggregate_signatures() {
        // Generate node keys and signing keys
        let ks = || (ExpandedKeyPair::create(), ExpandedKeyPair::create());
        let (n1, k1) = ks();
        let (n2, k2) = ks();
        let (n3, k3) = ks();

        let nodes_public_keys = vec![
            n1.public_key.clone(),
            n2.public_key.clone(),
            n3.public_key.clone(),
        ];

        let ni = |n| NodeInfo::new(n, Some(nodes_public_keys.clone()));

        // Set up nodes with that config
        let s1 = SigningState::new();
        let s2 = SigningState::new();
        let s3 = SigningState::new();

        let message = b"message in a bottle".to_vec();

        let commitments = vec![
            s1.get_commitment(&k1, &n1, message.clone()).await.unwrap(),
            s2.get_commitment(&k2, &n2, message.clone()).await.unwrap(),
            s3.get_commitment(&k3, &n3, message.clone()).await.unwrap(),
        ];

        let reveals = vec![
            s1.get_reveal(ni(0), commitments.clone()).await.unwrap(),
            s2.get_reveal(ni(1), commitments.clone()).await.unwrap(),
            s3.get_reveal(ni(2), commitments.clone()).await.unwrap(),
        ];

        let sig_shares = vec![
            s1.get_signature_share(ni(0), reveals.clone()).await.unwrap(),
            s2.get_signature_share(ni(1), reveals.clone()).await.unwrap(),
            s3.get_signature_share(ni(2), reveals).await.unwrap(),
        ];

        let signing_keys: Vec<_> = commitments
            .iter()
            .map(|c| c.signing_public_key.clone())
            .collect();
        let aggrigate_key = KeyAgg::key_aggregation_n(&signing_keys, 0);

        let signature = aggsig::add_signature_parts(&sig_shares);
        verify_dalek(&aggrigate_key.apk, &signature, &message).unwrap();
    }
}
