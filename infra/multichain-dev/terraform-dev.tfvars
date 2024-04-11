env          = "dev"
project      = "pagoda-discovery-platform-dev"
docker_image = "us-east1-docker.pkg.dev/pagoda-discovery-platform-dev/multichain/multichain-dev:latest"

mpc_contract_id = "multichain0.testnet"
indexer_options = {
  s3_bucket          = "near-lake-data-testnet"
  s3_region          = "eu-central-1"
  s3_url             = null
  start_block_height = 152754054
}

aws_access_key_secret_id = "multichain-indexer-aws-access-key"
aws_secret_key_secret_id = "multichain-indexer-aws-secret-key"
node_configs = [
  {
    account_id           = "multichain-node-dev-0.testnet"
    cipher_pk            = "5a9d1d27fc3c952e7af7a2f1c84f552928eec232c3f2c3e787f4a15d82a82916"
    address              = "https://multichain-dev-0-7tk2cmmtcq-ue.a.run.app"
    account_sk_secret_id = "multichain-account-sk-dev-0"
    cipher_sk_secret_id  = "multichain-cipher-sk-dev-0"
    sign_sk_secret_id    = "multichain-sign-sk-dev-0"
    sk_share_secret_id   = "multichain-sk-share-dev-0"
  },
  {
    account_id           = "multichain-node-dev-1.testnet"
    cipher_pk            = "349f89f6717a02aaf7a649b98ac7af09e6517ffd4cb7ea8a9f6edee8f84a330c"
    address              = "https://multichain-dev-1-7tk2cmmtcq-ue.a.run.app"
    account_sk_secret_id = "multichain-account-sk-dev-1"
    cipher_sk_secret_id  = "multichain-cipher-sk-dev-1"
    sign_sk_secret_id    = "multichain-sign-sk-dev-1"
    sk_share_secret_id   = "multichain-sk-share-dev-1"
  },
  {
    account_id           = "multichain-node-dev-2.testnet"
    cipher_pk            = "78ae67d38afaa6d329bba0175c200a8c248a5a82d78fbb8f71e060e6c186d800"
    address              = "https://multichain-dev-2-7tk2cmmtcq-ue.a.run.app"
    account_sk_secret_id = "multichain-account-sk-dev-2"
    cipher_sk_secret_id  = "multichain-cipher-sk-dev-2"
    sign_sk_secret_id    = "multichain-sign-sk-dev-2"
    sk_share_secret_id   = "multichain-sk-share-dev-2"
  }
]
