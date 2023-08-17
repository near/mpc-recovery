# Manually Deploying mpc-recovery to GCP

## Requirements

This guide assumes you have access to GCP console and the administrative ability to enable services, create service accounts and grant IAM roles if necessary.

It is assumed that you have chosen a region to use throughout this guide. This can be any region, but we recommend something close to our leader node in `us-east1` if you are deploying production nodes. This region of your choosing will be referred to as `GCP_REGION`.

Make sure that:
* You have a GCP Project (its ID will be referred to as `GCP_PROJECT_ID` below, should look something like `pagoda-discovery-platform-dev`)
* `GCP_PROJECT_ID` has the following services enabled:
    * `Artifact Registry`
    * `Cloud Run Admin API` (can be enabled by trying to create a Cloud Run instance, no need to proceed with creation after you pressed the `CREATE SERVICE` button)
    * `Datastore` (should also be initialized with the default database)
    * `Secret Manager`
* You have a service account dedicated to mpc-recovery (will be referred to as `GCP_SERVICE_ACCOUNT` below, should look something like `mpc-recovery@pagoda-discovery-platform-dev.iam.gserviceaccount.com`).
* `GCP_SERVICE_ACCOUNT` should have the following roles granted to it (change in `https://console.cloud.google.com/iam-admin/iam?project=<GCP_PROJECT_ID>`):
    * `Artifact Registry Writer`
    * `Cloud Datastore User`
    * `Secret Manager Secret Accessor`
    * `Cloud Run Admin` (TODO: might be able to downgrade to `Cloud Run Developer`)
* JSON service account keys for `GCP_SERVICE_ACCOUNT`. If you don't, then follow the steps below:
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

## Configuration

Your point of contact with Pagoda must have given you your Node ID (ask them if not). It is very important you use this specific ID for your node's configuration, we will refer to this value as `MPC_NODE_ID`.

[TODO]: <> (Change key serialization format to a more conventional format so that users can generate it outside of mpc-recovery)

You also need a Ed25519 key pair that you can generate by running `cargo run -- generate 1` in this directory. Grab JSON object after `Secret key share 0:`; it should look like this:
```json
{"public_key":{"curve":"ed25519","point":[120,153,87,73,144,228,107,221,163,76,41,132,123,208,73,71,110,235,204,191,174,106,225,69,38,145,165,76,132,201,55,152]},"expanded_private_key":{"prefix":{"curve":"ed25519","scalar":[180,110,118,232,35,24,127,100,6,137,244,195,8,154,150,22,214,43,134,73,234,67,255,249,99,157,120,6,163,88,178,12]},"private_key":{"curve":"ed25519","scalar":[160,85,170,73,186,103,158,30,156,142,160,162,253,246,210,214,173,162,39,244,145,241,58,148,63,211,218,241,11,70,235,89]}}}
```

Now save it to GCP Secret Manager under the name of your choosing (e.g. `mpc-recovery-key-prod`). This name will be referred to as `GCP_SM_KEY_NAME`.

You also need to grab the AES cipher key that was printed after `Cipher 0:`; it should like this:

```
23855bcee709c32e98fdbf2a44f0e86fb122b87774394f77ed31c1875244dcd7
```

Save it to GCP Secret Manager under the name of your choosing (e.g. `mpc-recovery-cipher-prod`). This name will be referred to as `GCP_SM_CIPHER_NAME`.

## Uploading Docker Image

First, let's create a new repository in GCP Artifact Registry. Go to `https://console.cloud.google.com/artifacts?project=<GCP_PROJECT_ID>`, press `CREATE REPOSITORY` and follow the form to create a new repository with **Docker** format and **Standard** mode. Name can be anything we will refer to it as `GCP_ARTIFACT_REPO`.

Now, you need to log into the GCP Artifact Registry on your machine:

```bash
$ cat <GCP_SERVICE_ACCOUNT_KEY_PATH> | docker login -u _json_key --password-stdin https://<GCP_REGION>-docker.pkg.dev
```

Build the mpc-recovery docker image from this folder and make sure to tag it with this image name:

```bash
$ docker build . -t <GCP_REGION>-docker.pkg.dev/<GCP_PROJECT_ID>/<GCP_ARTIFACT_REPO>/mpc-recovery
```

Push the image to GCP Artifact Registry:

```bash
$ docker push <GCP_REGION>-docker.pkg.dev/<GCP_PROJECT_ID>/<GCP_ARTIFACT_REPO>/mpc-recovery
```

You can check that the image has been successfully uploaded on the GCP Artifact Registry dashboard.

## Running on Cloud Run

Pick a name for your Cloud Run service, we will refer to it as `GCP_CLOUD_RUN_SERVICE`. For example `mpc-signer-pagoda-prod`.

Run:

```bash
$ gcloud run deploy <GCP_CLOUD_RUN_SERVICE> \
    --image=<GCP_REGION>-docker.pkg.dev/<GCP_PROJECT_ID>/<GCP_ARTIFACT_REPO>/mpc-recovery \
    --allow-unauthenticated \
    --port=3000 \
    --args=start-sign \
    --service-account=<GCP_SERVICE_ACCOUNT> \
    --cpu=2 \
    --memory=2Gi \
    --min-instances=1 \
    --max-instances=1 \
    --set-env-vars=MPC_RECOVERY_NODE_ID=<MPC_NODE_ID>,MPC_RECOVERY_GCP_PROJECT_ID=<GCP_PROJECT_ID>,MPC_RECOVERY_WEB_PORT=3000,RUST_LOG=mpc_recovery=debug,PAGODA_ALLOWLIST='{"entries":[{"issuer":"https://securetoken.google.com/near-fastauth-prod","audience":"near-fastauth-prod"}]}' \
    --set-secrets=MPC_RECOVERY_SK_SHARE=<GCP_SM_KEY_NAME>:latest,MPC_RECOVERY_CIPHER_KEY=<GCP_SM_CIPHER_NAME>:latest \
    --no-cpu-throttling \
    --region=<GCP_REGION> \
    --project=<GCP_PROJECT_ID>
```

If deploy ends successfully it will give you a Service URL, share it with your Pagoda point of contact.
