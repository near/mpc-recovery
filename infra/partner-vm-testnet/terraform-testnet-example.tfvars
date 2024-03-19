env          = "dev"
project_id   = "pagoda-discovery-platform-dev"
network      = "projects/pagoda-shared-infrastructure/global/networks/dev"
subnetwork   = "projects/pagoda-shared-infrastructure/regions/us-central1/subnetworks/dev-us-central1"
# These will be specific to your node
node_configs = [
  {
    # Each node has a unique account ID
    account              = "multichain-node-dev-7.dev"
    cipher_pk            = "5f49047f95ab9705f325d573ea6fcd2bbe681ab1f90b6b0d736669c34b483a07"
    # These 3 values below should match your secret names in google secrets manager
    account_sk_secret_id = "multichain-account-sk-dev-0"
    cipher_sk_secret_id  = "multichain-cipher-sk-dev-0"
    sk_share_secret_id   = "multichain-sk-share-dev-0"
  },
]