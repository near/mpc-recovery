# Multichain Infrastructure Overview

## Environments:
- Testnet (Production)
- Dev (Development)

## Deployment:

### Development
#### This environment has been automated for deployment, simply make a pull request with your changes to the `develop` branch, get it reviewed, and merge the PR.
  - Deployment steps:
    1. A merged PR triggers the following Github Actions Workflows:
      - [multichain-dev.yml](../.github/workflows/multichain-dev.yml)
      - [deploy-multichain-dev-contract.yml](../.github/workflows/deploy-multichain-dev-contract.yml)
    2. These workflows deploy a new imaged based off of the github SHA tag to the 8 GCP vms and restart the VM
    3. Then, the smart contract for the dev environment is redeployed

### "Break Glass" Deployment of Development environment
#### This should only be used if the environment is completely broken
  - Deployment steps:
    1. Make sure you have [terraform installed](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli) on your local machine
    2. Navigate to the `infra` directory, and then the `multichain-dev` directory
    3. Verify the variables in both `variables.tf` and `terraform-dev.tfvars` are up to date
    4. Verify the environment variables (`main.tf lines 17-61`, `variables.tf lines 87-150`) for the container are as desired
    5. Run the `terraform init` command to initialize the infrastructure
        - *Note: if you run into permissions issues, please reach out to SRE (Kody)*
    6. Run `terraform plan --var-file=terraform-dev.tfvars` and ensure the changes are indeed what you want to change
    7. Run `terraform apply --var-file=terraform-dev.tfvars`, This will replace the instance templates with new changes, and rebuild the VMs from scratch.
        - *Note: This will cause downtime, so make sure you let your team members know whats going on*
    8. Verify that the container has been started by ssh'ing to at least one of the VMs and running `docker ps`
        - *Note: use ```gcloud compute ssh multichain-dev-0``` or similar to ssh into machine, contact SRE if you have IAM issues*

---

### Testnet
#### Please keep in mind that this is a live environment, and any changes you make may also effect our ecosystem partners. Ensure your new changes are rigorously tested, and will not break Testnet. This deployment is semi-automated.

  - Deployment steps:
    1. After verifying these are the changes you would like to make accross all parter environments, publish a new image to the following public image repository: [Public Production Image Repo](https://console.cloud.google.com/artifacts/docker/pagoda-discovery-platform-prod/us-east1/multichain-public/multichain-testnet?project=pagoda-discovery-platform-prod&supportedpurview=project)
    2. This can be done 2 different ways:
        1. Utilize [Github Actions pipeline](https://github.com/near/mpc-recovery/actions/workflows/multichain-prod.yml)
        2. Manually push a docker image with the `latest` tag to the public image repository
    3. Track updates accross network using [this grafana dashboard](https://nearinc.grafana.net/d/bdg2srektjy0wd/chain-signatures?orgId=1&tab=query&var-node_account_id=All&var-environment=testnet) (this will take 1-2 hours to propogate)

### "Break Glass" Deployment of Production environment
#### **This should only be used if the environment is completely broken**
  - Deployment steps:
    1. Make sure you have [terraform installed](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli) on your local machine
    2. Navigate to the `infra` directory, and then the `multichain-testnet` directory
    3. Verify the variables in both `variables.tf` and `terraform-testnet.tfvars` are up to date
    4. Verify the environment variables (`main.tf lines 17-61`, `variables.tf lines 87-150`) for the container are as desired
    5. Run the `terraform init` command to initialize the infrastructure
      - *Note: if you run into permissions issues, please reach out to SRE (Kody)*
    6. Run `terraform plan --var-file=terraform-testnet.tfvars` and ensure the changes are indeed what you want to change
    7. Run `terraform apply --var-file=terraform-testnet.tfvars`, This will replace the instance templates with new changes, and rebuild the VMs from scratch.
      - *Note: This will cause downtime, **MAKE SURE YOU ACTUALLY WANT TO DO THIS AND NOTIFY PARTNERS IN TELEGRAM CHANNEL "NEAR MPC Node Operators" If you don't have access to that telegram channel, you should probably not be doing this***
    8. Verify that the container has been started by ssh'ing to at least one of the VMs and running `docker ps`
    - *Note: use ```gcloud compute ssh multichain-testnet-partner-0``` or similar to ssh into machine, contact SRE if you have IAM issues*

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