// Find all our documentation at https://docs.near.org
use near_sdk::{AccountId, env, ext_contract, near_bindgen, require, Gas, NearToken, Promise};
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};

// interface for cross contract call to mpc contract
#[ext_contract(mpc)]
trait MPC {
    fn sign(&self, payload: [u8; 32], path: String, key_version: u32);
}

// automatically init the contract
impl Default for Contract {
    fn default() -> Self {
        Self {
            mpc_account: "hello".parse().unwrap()
        }
    }
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, Debug)]
pub struct Contract {
    pub mpc_account: AccountId,
}

#[near_bindgen]
impl Contract {
    #[init]
    #[private] // Public - but only callable by env::current_account_id()
    pub fn init(mpc_account: AccountId) -> Self {
        assert!(!env::state_exists(), "Already initialized");
        Self { mpc_account }
    }

    // proxy to call MPC_CONTRACT_ACCOUNT_ID method sign if COST is deposited
    #[payable]
    pub fn sign(&mut self, payload: [u8; 32], path: String, key_version: u32) -> Promise {
        // call mpc sign and return promise
        mpc::ext(self.mpc_account.clone())
            .with_static_gas(Gas::from_tgas(100))
            .sign(
                    payload, 
                    path, 
                    key_version
        )
    }
}