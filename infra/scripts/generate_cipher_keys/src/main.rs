use mpc_keys::hpke;

fn main() {
    let (cipher_sk, cipher_pk) = hpke::generate();
    let cipher_pk = hex::encode(cipher_pk.to_bytes());
    let cipher_sk = hex::encode(cipher_sk.to_bytes());
    println!("cipher public key: {}", cipher_pk);
    println!("cipher private key: {}", cipher_sk);
}
