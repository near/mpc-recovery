use std::collections::HashMap;
use std::hash::{Hash, Hasher};

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

use crate::transaction::{to_dalek_public_key, to_dalek_signature};

pub struct SigningState {
    committed: HashMap<AggrCommitment, Committed>,
    revealed: HashMap<Reveal, Revealed>,
}

impl Default for SigningState {
    fn default() -> Self {
        Self::new()
    }
}

impl SigningState {
    pub fn new() -> Self {
        SigningState {
            committed: HashMap::new(),
            revealed: HashMap::new(),
        }
    }

    pub fn get_commitment(
        &mut self,
        our_key: &protocols::ExpandedKeyPair,
        node_key: &protocols::ExpandedKeyPair,
        message: Vec<u8>,
    ) -> Result<SignedCommitment, String> {
        // We use OSRng on it's own instead of thread_random() for commit padding and OsRng
        self.get_commitment_with_rng(our_key, node_key, message, &mut OsRng)
    }

    /// This is for deterministic testing, don't use it in prod
    /// The whole signing process is deterministic if a deterministic rng is used
    pub(crate) fn get_commitment_with_rng(
        &mut self,
        our_key: &protocols::ExpandedKeyPair,
        node_key: &protocols::ExpandedKeyPair,
        message: Vec<u8>,
        rng: &mut impl Rng,
    ) -> Result<SignedCommitment, String> {
        let (commitment, state) = Committed::commit(our_key, node_key, message, rng)?;
        self.committed.insert(commitment.commitment.clone(), state);
        Ok(commitment)
    }

    pub fn get_reveal(
        &mut self,
        node_info: NodeInfo,
        recieved_commitments: Vec<SignedCommitment>,
    ) -> Result<Reveal, String> {
        // TODO Factor this out
        let i = node_info.our_index;
        let our_c = recieved_commitments.get(i).ok_or_else(|| {
            format!(
                "This is node index {}, but you only gave us {} commitments",
                i,
                recieved_commitments.len()
            )
        })?;
        // Don't readd this on failure, this commitment is now burnt
        let state = self
            .committed
            .remove(&our_c.commitment)
            .ok_or(format!("Committment {:?} not found", &our_c.commitment))?;

        let (reveal, state) = state.reveal(&node_info, recieved_commitments)?;
        let reveal = Reveal(reveal);
        self.revealed.insert(reveal.clone(), state);
        Ok(reveal)
    }

    pub fn get_signature_share(
        &mut self,
        node_info: NodeInfo,
        signature_parts: Vec<Reveal>,
    ) -> Result<protocols::Signature, String> {
        let i = node_info.our_index;
        let our_r = signature_parts.get(i).ok_or(format!(
            "This is node index {}, but you only gave us {} reveals",
            i,
            signature_parts.len()
        ))?;
        // Don't readd this on failure, this commitment is now burnt
        let state = self
            .revealed
            .remove(our_r)
            .ok_or(format!("Reveal {:?} not found", &our_r))?;

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
    ) -> Result<(SignedCommitment, Self), String> {
        let (ephemeral_key, commit, our_signature) =
            aggsig::create_ephemeral_key_and_commit_rng(our_key, &message, rng);
        let s = Committed {
            ephemeral_key,
            our_signature,
            message,
            our_key: our_key.clone(),
        };
        let sc = SignedCommitment::create(
            AggrCommitment(commit.commitment),
            node_key,
            &our_key.public_key,
        )?;
        Ok((sc, s))
    }

    pub fn reveal(
        self,
        node_info: &NodeInfo,
        commitments: Vec<SignedCommitment>,
    ) -> Result<(SignSecondMsg, Revealed), String> {
        let (commitments, signing_public_keys) = node_info
            .signed_by_every_node(commitments)?
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
    ) -> Result<protocols::Signature, String> {
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
    pub nodes_public_keys: Option<Vec<Point<Ed25519>>>,
    pub our_index: usize,
}

impl NodeInfo {
    fn signed_by_every_node(
        &self,
        signed: Vec<SignedCommitment>,
    ) -> Result<Vec<(AggrCommitment, Point<Ed25519>)>, String> {
        self.nodes_public_keys
            .as_ref()
            .ok_or_else(|| "No nodes public keys available to sign".to_string())?
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
    /// This is signed with the node public key
    pub signature: Signature,
}

impl SignedCommitment {
    pub fn create(
        commitment: AggrCommitment,
        node_private_key: &protocols::ExpandedKeyPair,
        signing_public_key: &Point<Ed25519>,
    ) -> Result<Self, String> {
        let to_sign = Self::serialize(&commitment, signing_public_key)?;
        // This is awkward, we should move more stuff over to dalek later on
        let signature = aggsig::sign_single(&to_sign, node_private_key);
        let signature = to_dalek_signature(&signature).map_err(|e| e.to_string())?;
        Ok(SignedCommitment {
            commitment,
            signing_public_key: signing_public_key.clone(),
            signature,
        })
    }

    pub fn verify(
        &self,
        public_key: &Point<Ed25519>,
    ) -> Result<(AggrCommitment, Point<Ed25519>), String> {
        let public_key = to_dalek_public_key(public_key).map_err(|e| e.to_string())?;
        let message = Self::serialize(&self.commitment, &self.signing_public_key)?;
        public_key
            .verify(&message, &self.signature)
            .map_err(|e| e.to_string())?;
        Ok((self.commitment.clone(), self.signing_public_key.clone()))
    }

    fn serialize(commitment: &AggrCommitment, pk: &Point<Ed25519>) -> Result<Vec<u8>, String> {
        let content = serde_json::to_vec(&(commitment, pk)).map_err(|e| e.to_string())?;
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
) -> Result<(), String> {
    let computed_comm = &HashCommitment::<Sha512>::create_commitment_with_user_defined_randomness(
        &r_to_test.y_coord().unwrap(),
        blind_factor,
    );
    if computed_comm != comm {
        // TODO check this is safe to share in case of error
        // Should be because everything is provided by the caller I think
        Err(format!(
            "In a commitment with r={:?}, with blind={} expected {} but found {}",
            r_to_test, blind_factor, computed_comm, comm
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curv::elliptic::curves::{Ed25519, Point};
    use ed25519_dalek::{SignatureError, Verifier};
    use multi_party_eddsa::protocols::ExpandedKeyPair;

    #[test]
    fn aggregate_signatures() {
        pub fn verify_dalek(
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

        let ni = |n| NodeInfo {
            nodes_public_keys: Some(nodes_public_keys.clone()),
            our_index: n,
        };

        // Set up nodes with that config
        let mut s1 = SigningState::new();
        let mut s2 = SigningState::new();
        let mut s3 = SigningState::new();

        let message = b"message in a bottle".to_vec();

        let commitments = vec![
            s1.get_commitment(&k1, &n1, message.clone()).unwrap(),
            s2.get_commitment(&k2, &n2, message.clone()).unwrap(),
            s3.get_commitment(&k3, &n3, message.clone()).unwrap(),
        ];

        let reveals = vec![
            s1.get_reveal(ni(0), commitments.clone()).unwrap(),
            s2.get_reveal(ni(1), commitments.clone()).unwrap(),
            s3.get_reveal(ni(2), commitments.clone()).unwrap(),
        ];

        let sig_shares = vec![
            s1.get_signature_share(ni(0), reveals.clone()).unwrap(),
            s2.get_signature_share(ni(1), reveals.clone()).unwrap(),
            s3.get_signature_share(ni(2), reveals).unwrap(),
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
