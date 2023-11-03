#[cfg(not(feature = "wasm"))]
pub mod hpke;

#[cfg(feature = "wasm")]
pub mod hpke {
    use borsh::{self, BorshDeserialize, BorshSerialize};
    use serde::{Deserialize, Serialize};

    /// HPKE public key interface for wasm contracts
    #[derive(
        Clone,
        Debug,
        Hash,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Serialize,
        Deserialize,
        BorshSerialize,
        BorshDeserialize,
    )]
    pub struct PublicKey([u8; 32]);
}
