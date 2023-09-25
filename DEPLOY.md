# Manually Deploying mpc-recovery to GCP

## Requirements

This guide assumes you have access to GCP console and the administrative ability to enable services, create service accounts and grant IAM roles if necessary.

It is assumed that you have chosen a region to use throughout this guide. This can be any region, but we recommend something close to our leader node in `us-east1` if you are deploying production nodes. This region of your choosing will be referred to as `GCP_REGION`.

[TODO]: <> (Rewrite below to use gcloud CLI instead of GCP Console UI)

Make sure that:
* You have a GCP Project (its ID will be referred to as `GCP_PROJECT_ID` below, should look something like `pagoda-discovery-platform-dev`)
* `GCP_PROJECT_ID` has the following services enabled:
    * `Artifact Registry`
    * `Cloud Run Admin API` (can be enabled by trying to create a Cloud Run instance, no need to proceed with creation after you pressed the `CREATE SERVICE` button)
    * `Datastore` (should also be initialized with the `default` database)
    * `Secret Manager`
* You have a service account dedicated to mpc-recovery (will be referred to as `GCP_SERVICE_ACCOUNT` below, should look something like `mpc-recovery@pagoda-discovery-platform-dev.iam.gserviceaccount.com`).
* `GCP_SERVICE_ACCOUNT` should have the following roles granted to it (change in `https://console.cloud.google.com/iam-admin/iam?project=<GCP_PROJECT_ID>`):
    * `Artifact Registry Administrator`
    * `Cloud Datastore Owner`
    * `Cloud Run Admin`
    * `Secret Manager Admin`
    * `Security Admin`
    * `Service Account Admin`
* JSON service account keys for `GCP_SERVICE_ACCOUNT`. If you don't have any, then follow the steps below:
    1. Go to the service account page (`https://console.cloud.google.com/iam-admin/serviceaccounts?project=<GCP_PROJECT_ID>`)
    2. Select your `GCP_SERVICE_ACCOUNT` in the list
    3. Open `KEYS` tab
    4. Press `ADD KEY` and then `Create new key`.
    5. Choose `JSON` and press `CREATE`.
    6. Save the keys somewhere to your filesystem, we will refer to its location as `GCP_SERVICE_ACCOUNT_KEY_PATH`.

## Requirements

⚠️ **Warning: You must use an x86 machine, M1 will not work**

You need Rust 1.68 or later. Update your `rustc` by running:

```
$ rustup install stable
```

## Create Secrets
### Secret Key Share

[TODO]: <> (Change key serialization format to a more conventional format so that users can generate it outside of mpc-recovery)

You need a Ed25519 key pair that you can generate by running `RUST_LOG=info cargo run --bin mpc-recovery -- generate 1` in this directory. Grab JSON object after `Secret key share 0:`; it should look like this:
```json
{"public_key":{"curve":"ed25519","point":[120,153,87,73,144,228,107,221,163,76,41,132,123,208,73,71,110,235,204,191,174,106,225,69,38,145,165,76,132,201,55,152]},"expanded_private_key":{"prefix":{"curve":"ed25519","scalar":[180,110,118,232,35,24,127,100,6,137,244,195,8,154,150,22,214,43,134,73,234,67,255,249,99,157,120,6,163,88,178,12]},"private_key":{"curve":"ed25519","scalar":[160,85,170,73,186,103,158,30,156,142,160,162,253,246,210,214,173,162,39,244,145,241,58,148,63,211,218,241,11,70,235,89]}}}
```

Now save it to GCP Secret Manager under the name of your choosing (e.g. `mpc-recovery-key-prod`). This name will be referred to as `GCP_SK_SHARE_SECRET_ID`.

### Cipher

You also need to grab the AES cipher key that was printed after `Cipher 0:`; it should like this:

```
23855bcee709c32e98fdbf2a44f0e86fb122b87774394f77ed31c1875244dcd7
```

Save it to GCP Secret Manager under the name of your choosing (e.g. `mpc-recovery-cipher-prod`). This name will be referred to as `GCP_CIPHER_SECRET_ID`.

### OIDC Providers
Create one more secret secret under the name of your choosing (e.g. `mpc-recovery-oidc-providers-prod`). This name will be referred to as `GCP_OIDC_PROVIDERS_SECRET_ID`.

Populate it with whatever your Pagoda point of contact told you to use, it should look similar to below:

```
[
  {
    issuer   = "https://securetoken.google.com/near-fastauth-prod",
    audience = "near-fastauth-prod"
  }
]
```

## Building Docker Image

Build the mpc-recovery docker image from this folder and make sure to tag it for convenience:

```bash
$ docker build . -t near/mpc-recovery
```

## Configure Terraform Variables

Go to `infra/partner` and copy `template.tfvars` as `prod.tfvars`. Edit `prod.tfvars` to match your environment:

* Set `env` to `prod`
* Set `project` to `<GCP_PROJECT_ID>`
* Set `node_id` to whatever your point of contact with Pagoda has given you (ask them if they did not). It is very important you use this specific ID for your node's configuration
* Set `oidc_providers_secret_id` to `<GCP_OIDC_PROVIDERS_SECRET_ID>`
* Set `cipher_key_secret_id` to `<GCP_CIPHER_SECRET_ID>`
* Set `sk_share_secret_id` to `<GCP_SK_SHARE_SECRET_ID>`

## Apply Terraform Configuration

Run `terraform apply -var-file prod.tfvars -var credentials_file=<GCP_SERVICE_ACCOUNT_KEY_PATH>` and if deploy ends successfully it will give you your node's URL, share it with your Pagoda point of contact.
