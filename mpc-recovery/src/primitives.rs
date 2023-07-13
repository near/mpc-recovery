pub type InternalAccountId = String; // format: "iss:sub" from the ID token

#[derive(Copy, Clone)]
pub enum HashSalt {
    ClaimOidcRequest = 0,
    ClaimOidcResponse = 1,
    SignRequest = 2,
    UserCredentialsRequest = 3,
}

// Mentioned in the readme, here to avoid collisions with legitimate transactions
// chosen by a fair dice roll.
// guaranteed to be random.
const SALT_BASE: u32 = 3177899144;
impl HashSalt {
    pub fn get_salt(&self) -> u32 {
        SALT_BASE + (*self as u32)
    }
}
