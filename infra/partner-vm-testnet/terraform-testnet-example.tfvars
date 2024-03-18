env          = "testnet"
# These will be specific to your node
node_configs = [
  {
    # Each node has a unique account ID
    account              = "multichain-node-testnet-7.testnet"
    cipher_pk            = "<your_cipher_pk>"
    # These 3 values below should match your secret names in google secrets manager
    account_sk_secret_id = "multichain-account-sk-testnet-0"
    cipher_sk_secret_id  = "multichain-cipher-sk-testnet-0"
    sk_share_secret_id   = "multichain-sk-share-testnet-0"
  },
]