env          = "dev"
project      = "pagoda-discovery-platform-dev"
docker_image = "near/mpc-recovery"

account_creator_id           = "mpc-recovery-dev-creator.testnet"
account_creator_sk_secret_id = "mpc-account-creator-sk-dev"
oidc_providers_secret_id     = "mpc-allowed-oidc-providers-dev"
fast_auth_partners_secret_id = "mpc-fast-auth-partners-dev"
signer_configs = [
  {
    cipher_key_secret_id = "mpc-cipher-0-dev"
    sk_share_secret_id   = "mpc-sk-share-0-dev"
  },
  {
    cipher_key_secret_id = "mpc-cipher-1-dev"
    sk_share_secret_id   = "mpc-sk-share-1-dev"
  },
  {
    cipher_key_secret_id = "mpc-cipher-2-dev"
    sk_share_secret_id   = "mpc-sk-share-2-dev"
  }
]
