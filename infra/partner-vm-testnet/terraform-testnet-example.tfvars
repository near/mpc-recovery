env          = "testnet"
# These will be specific to your node
node_configs = [
  {
    # Each node has a unique account ID
    account              = "{your_near_account_id}"
    cipher_pk            = "<your_cipher_pk>"
    # These 3 values below should match your secret names in google secrets manager
    account_sk_secret_id = "multichain-account-sk-testnet-{your_entity_name}"
    cipher_sk_secret_id  = "multichain-cipher-sk-testnet-{your_entity_name}"
    sk_share_secret_id   = "multichain-sk-share-testnet-{your_entity_name}"
  },
]