env          = "testnet"
project_id   = "<your-project-id>"
network      = "default"
subnetwork   = "us-central1"
image        = "us-east1-docker.pkg.dev/pagoda-discovery-platform-prod/multichain-public/multichain-testnet:latest"
region       = "<preferred-region>"
zone         = "<preferred-zone>"
# These will be specific to your node
node_configs = [
  {
    # Each node has a unique account ID
    account              = "{your_near_account_id}"
    cipher_pk            = "<your_cipher_pk>"
    # These 3 values below should match your secret names in google secrets manager
    account_sk_secret_id = "multichain-account-sk-testnet"
    cipher_sk_secret_id  = "multichain-cipher-sk-testnet"
    sk_share_secret_id   = "multichain-sk-share-testnet"
  },
]