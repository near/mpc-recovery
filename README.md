# MPC Account Recovery (WIP)
The aim of this project is to offer NEAR users the opportunity to create and restore their accounts by utilizing OIDC protocol. By linking their NEAR account to `near.org` or other authentication provider, they can then add a new Full Access key, which will be managed by the trusted network of servers. Should they lose all the keys they possess, they can reauthorize themselves, create a new key, and add it into their NEAR account using a transaction that will be signed by MPC servers through their recovery key. All the transaction cost will be covered by a relayer server and metatransactions.

## How the MPC system will work
- The system consists of 3 trusted signing nodes and a leader node
- Each node holds a unique secret key
- Each action must be signed by all 3 nodes
- Nodes signatures are then combined into a single signature on the leader node

In the future we are planning to get rid  of the leader node to make the system more decentralized.

## External API

The recovery service is currently hosted at https://near.org

### Claim OIDC Id Token ownership

    URL: /claim_oidc
    Request parameters: {
        oidc_token_hash: [u8; 32],
        frp_public_key: String,
        frp_signature: [u8; 64],
    }
    Response: Ok {
        mpc_signature: String,
    } / Err {
        msg: String
    }

The frp_signature you send must be an Ed22519 signature of the hash:

    SALT = 3177899144
    sha256.hash(Borsh.serialize<u32>(SALT + 0) ++ Borsh.serialize<[u8]>(oidc_token_hash) ++ [0] ++ Borsh.serialize<[u8]>(frp_public_key))

signed with your on device public key.

The constant 3177899144 is a random number between 2^31 and 2^32 which as described [here](https://github.com/gutsyphilip/NEPs/blob/8b0b05c3727f0a90b70c6f88791152f54bf5b77f/neps/nep-0413.md#example) prevents collisions with legitimate on chain transactions.

If you successfully claim the token you will receive a signature in return of:

    sha256.hash(Borsh.serialize<u32>(SALT + 1) ++ Borsh.serialize<[u8]>(signature))

This will be signed by the nodes combined Ed22519 signature.

### MPC Public Key

    URL: /mpc_public_key
    Request parameters: {}
    Response: Ok {
        mpc_pk: String,
    } / Err {
        msg: String
    }

Returns the MPC public key that is used to sign the OIDC claiming response. Should not be used in production environment, as the MPC PK should be hardcoded in the client.

### User Credentials

    URL: /user_credentials
    Request parameters: {
        oidc_token: String,
        frp_signature: Signature,
        frp_public_key: String,
    }
    Response: Ok {
        public_key: String,
    } / Err {
        msg: String
    }

Returns the recovery public key associated with the provided OIDC token.
The frp_signature you send must be an Ed22519 signature of the hash:

    sha256.hash(Borsh.serialize<u32>(SALT + 2) ++ Borsh.serialize<[u8]>(oidc_token) ++ [0] ++ Borsh.serialize<[u8]>(frp_public_key))

### Create New Account

    URL: /new_account
    Request parameters: {
        near_account_id: String,
        create_account_options: CreateAccountOptions,
        oidc_token: String,
        user_credentials_frp_signature: Signature,
        frp_public_key: String,
    }
    Response:
    Ok {
        create_account_options: CreateAccountOptions,
        recovery_public_key: String,
        near_account_id: String,
    } /
    Err {
        msg: String
    }

This creates an account with account Id provided in `near_account_id`. If this name is already taken then this operation will fail with no action having been taken.

This service will send a `create_account` transaction to the relayer signed by `account_creator.near` account. If this operation is successful relayer will make an allowance for the created account.

Newly created NEAR account will have two full access keys. One that was provided by the user, and the recovery one that is controlled by the MPC system.

In the future, MPC Service will disallow creating account with ID Tokes that were not claimed first. It is expected, that PK that client wants to use for the account creation is the same as the one that was used to claim the ID Token.

The user_credentials_frp_signature you send must be an Ed22519 signature of the hash:

    sha256.hash(Borsh.serialize<u32>(SALT + 2) ++ Borsh.serialize<[u8]>(oidc_token) ++ [0] ++ Borsh.serialize<[u8]>(frp_public_key))

signed by the key you used to claim the oidc token. This does not have to be the same as the key in the public key field. This digest is the same as the one used in the user_credentials endpoint, because new_account request needs to get the recovery public key of the user that is creating the account.

### Sign

    URL: /sign
    Request parameters: {
        delegate_action: DelegateAction,
        oidc_token: String,
        frp_signature: Signature,
        user_credentials_frp_signature: Signature,
        frp_public_key: String,
    }
    Response:
    Ok {
        signature: Signature,
    } /
    Err {
        msg: String
    }

This endpoint can be used to sign a delegate action that can then be sent to the relayer. The delegate action is signed by user recovery key.

The frp_signature you send must be an Ed22519 signature of the hash:

    sha256.hash(Borsh.serialize<u32>(SALT + 3) ++ Borsh.serialize<[u8]>(
        delegate_action,
        oidc_token_hash,
    ) ++ [0] ++ Borsh.serialize<[u8]>(frp_public_key))

The user_credentials_frp_signature is needed to get user recovery PK. It is the same as in user_credentials endpoint.

## OIDC (OAuth 2.0) authentication

We are using OpenID Connect (OIDC) standard to authenticate users (built on top of OAuth 2.0).
Check OIDC standard docs [here](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) and Google OIDC docs [here](https://developers.google.com/identity/protocols/oauth2/openid-connect)

## Front-runnig protection flow
Before transmitting your OIDC Id Token to the recovery service you must first claim the ownership of the token. This prevents a rogue node from taking your Id Token and using it to sign another request.

The expected flow for the client is next:
1. Client-side developer hardcodes the MPC PK in the client code. It should be provided by MPC Recovery service developers and compared to the one that is returned by `/mpc_public_key` endpoint. You MUST NOT fetch the MPC PK from the nodes themselves in production env.
2. Client generates a key pair that is stored in their device. It can be same key pair that is used to sign the transactions.
3. Client recieves an OIDC Id Token from the authentication provider.
4. Client claims the ownership of the token by sending a request to the `/claim_oidc_token` endpoint.
5. In reponce to the claim request, user recieves a signature that is signed by the MPC system.
6. User verifies that the signature is valid. It garantees that each node in the system has seen the token and will not accept it again with another key.
7. Now client can safely send their Id Token with `/sign` or other requests.
8. Once the token is expaired, client can claim a new one and continue using the MPC Recovery service.

Check our integration tests to see how it works in practice.

Registered ID Token will be added to the persistent DB on each Signing node and saved until expiration. Registered Id Tokens are tied to the provided PK.

## Sign flow
The expected flow for the client is next:
1. Client uses `/user_credentials` endpoint to get the recovery PK.
2. Client fetches latest nonce, block hash using obtained recovery PK.
3. Client creates a delegate action with desired actions, such as add or delete key.
4. Client gets the signature from the MPC system using `/sign` endpoint.
5. Client sends the same delegate action to the relayer with obtained signature.

### Client integration

There are several ways to get and use the ID token. The flow that we are using is called the "server" flow, you can find more info [here](https://developers.google.com/identity/openid-connect/openid-connect#authenticatingtheuser). The system will be able to process any token that is following the core OpenID Connect standard. In order to receive the ID token from OpenID provider you will need to include the `openid` scope value to the Authorization Request.

### Server integration

Internally, we are identifying users by their issuer id (iss) and their unique ID (sub) retrieved form the ID token and separated by a colon: `<issuer_iss>:<user_sub>`. It means that each recovery method (like GitHub and Google) is separated from one another even if they have the same email.

### Contribute

In order to build the project, you will need to have `protoc` and `gmp` installed. Refer to your system's package manager on how to do this.

If you have [nix](https://nixos.org/) and [direnv](https://direnv.net/) installed, you can set up a development environment by running:

```BASH
direnv allow
```

Run unit tests with:
```BASH
cargo test -p mpc-recovery
```
