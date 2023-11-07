env          = "mainnet"
project      = "pagoda-discovery-platform-dev"
docker_image = "us-east1-docker.pkg.dev/pagoda-discovery-platform-prod/mpc-recovery-mainnet/mpc-recovery-mainnet@sha256:3d2c6d9ab13cfd6ef4b5ea8d6ff03f4373b6d3abd1d12ce91c88034eb5f40548"

account_creator_id           = "account_creator.near"
account_creator_sk_secret_id = "mpc-account-creator-sk-mainnet"
oidc_providers_secret_id     = "mpc-allowed-oidc-providers-mainnet"
fast_auth_partners_secret_id = "mpc-fast-auth-partners-mainnet"
signer_configs = [
  {
    cipher_key_secret_id = "mpc-cipher-0-mainnet"
    sk_share_secret_id   = "mpc-sk-share-0-mainnet"
  },
  {
    cipher_key_secret_id = "mpc-cipher-1-mainnet"
    sk_share_secret_id   = "mpc-sk-share-1-mainnet"
  },
  {
    cipher_key_secret_id = "mpc-cipher-2-mainnet"
    sk_share_secret_id   = "mpc-sk-share-2-mainnet"
  }
]
