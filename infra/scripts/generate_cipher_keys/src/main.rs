use mpc_keys::hpke;
use near_crypto::{PublicKey, SecretKey};

fn main() {
    let (cipher_sk, cipher_pk) = hpke::generate();
    let cipher_pk = hex::encode(cipher_pk.to_bytes());
    let cipher_sk = hex::encode(cipher_sk.to_bytes());
    println!("cipher public key: {}", cipher_pk);
    println!("cipher private key: {}", cipher_sk);
    let sign_sk: SecretKey = "ed25519:46rYEgLEAQuyHryUaF2R2bXQiQKg5xvbKUzqZSTLZyzK6xDixPaoyex5ab1R5EAaiQCZZovbtzBCA3eQEMKZELWx".parse().unwrap();
    let sign_pk = sign_sk.public_key();
    println!("sign public key sign_pk: {}", sign_pk);
    println!("sign secret key sign_sk: {}", sign_sk);
}
