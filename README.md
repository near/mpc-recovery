# NEAR MPC

This repo hosts all the code for MPC related services on NEAR, which includes but is not limited to FastAuth and Chain Signatures.


## Chain Signatures

An MPC service that generates signatures based on a payload. These are a set of N nodes operating as a sort of L2 (maybe L0) where users (developers or clients) can talk to a smart contract on NEAR to generate a signature. This signature can then be used for multiple purposes such as managing an account located on a foreign chain (BTC, ETH, ...)

Most of this code is located in `chain-signatures/` folder and for more information on how most of this work or its design, refer to [ARCHITECTURE.md](ARCHITECTURE.md).

## FastAuth (aka MPC recovery)

An MPC service that allows users to create NEAR accounts based on an identity provider. The secret key belonging to these accounts are stored partially on an MPC node, where the full key is never recreated. For more info on, look at the [mpc-recovery/README.md](mpc-recovery/README.md)

## Notes

- Not to be confused, but FastAuth and Chain Signatures are separate services. This can change in the future but they remain separate for now.
- FastAuth also has an equivalent [UI repo](https://github.com/near/fast-auth-signer) which is used in [near.org](near.org)
