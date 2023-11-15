# MPC Recovery Infrastructure Overview

There are currently 3 mostly static environments for MPC
 - Mainnet (production)
 - Testnet (production)
 - Dev (development)

 ## Mainnet/Testnet

 Mainnet and Testnet infra code is in the directory `mpc-recovery-prod` and is built off of the `main` GitHub Branch
   - This environment should be deployed via the GHA pipeline `deploy-prod.yml` manually in order to prevent unwanted changes
   - Both Mainnet and Testnet are treated as production environments

 ## Dev

 The Dev environment infra code is located in the `mpc-recovery-dev` directory and is built off of the `develop` GitHub Branch
   - This should be used as the main development environment
   - Every time a pull request is opened up against the `develop` branch, a new, ephemeral environment is created with your changes
     - *Note: These environments will have the associated PR number appended to all resources*
   - When a pull request is approved and merged into the `develop` branch, a new revision is deployed to the static Dev environment with the PRs changes and the PRs ephemeral environment is destroyed