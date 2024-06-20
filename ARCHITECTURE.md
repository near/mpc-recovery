# Architecture

This doc outlines the architecture for NEAR's Multi-Party Computation (MPC) related services which powers FastAuth and Chain Signatures.

## FastAuth (aka mpc-recovery)

FastAuth allows a user to store their login details for their NEAR wallet in a set amount of MPC nodes. Each node contains a share of the user's credentials. Note, this will likely change in the future as we resdesign the system to utilize chain signatures instead of having to purely rely on a standalone MPC service for NEAR accounts.

## Chain Signatures

Chain signature is an MPC service that facilitates the ability to sign arbitrary payloads by calling into a smart contract and eventually getting back a signature. This signature can be used for various purposes such as deriving new public keys associated to foreign chains.

There are several components that make up chain-signatures. This includes but is not limited to the following:

- NEAR Smart Contract
- NEAR Lake Indexer
- MPC nodes

Note that this list only includes components vital to creating signatures and not the components required to do foreign chain interactions like sending the signature over to ethereum or any other chain. Each of these will be explained further in the following sections.

### NEAR Smart Contract

The contract is simple in terms of functionality. It provides two main functions for users or developers to call into.

- The most common of which is `sign`, which when called will yield back a signature for the user to consume however they wish to. For example, this signature can be used to sign into arbitrary chains given the derivation path of the account of that chain. For more info on how the MPC node picks these `sign` request, refer to the NEAR Lake Indexer section.
- The second method (and should realistically only be used by the MPC nodes themselves), are the `vote_*` methods. These allow the MPC nodes to each individually act as voters into the MPC network, and facilitates the way new nodes join or current nodes get kicked out.

#### MPC State

Note that each MPC node does not maintain its own state, but rather queries the contract for the contract's state and then directly switch to the corresponding MPC node state. This is how state transitions also happen -- whenever the contract determines it is time to reshare or refresh the shares of the keys, the nodes themselves will properly transition to these corresponding states.

The contract also circumvents many possibilities such as going below the threshold amount of nodes in the network. This keeps it simple such that the MPC nodes only needs to keep track of very little things like the beaver triples it stockpiles.

### NEAR Lake Indexer

How does the MPC network pick up sign requests even though users are mainly interacting with the multichain NEAR smart contract?

The answer is the indexer. Each node would ideally run an indexer to listen to a specific contract's address with a method `"sign"` being called. Note that currently each node does not run its own indexer, but rather uses the NEAR Lake Indexer; which is a bit different but saves us the resource cost of having to run our own NEAR Node where the indexer's blocks can be streamed from. This has its tradeoffs with whoever that's running the NEAR Lake ends up being compromised since it is a service that runs on AWS s3 buckets. To circumvent this, we can include ZK light client proofs to verify that the block are indeed correct.

### MPC Node

The MPC node is the central piece to the operation of the network itself. These nodes will listen to requests from the NEAR smart contract, utilizing an `Indexer`, eventually forwarding the request over to the signature pipeline to be signed by each node. Most of the computation for this is pre-calculated ahead of time (i.e. beaver triple stockpiling) to save time on the signature being returned. If the network is congested, the bottleneck here would be a new set of triples being generated. One signature would require two owned triples per node. To generate a singular triple takes about 30-50 seconds in the best case with our default hardware configurations.

#### Networking

Each of the MPC nodes needs to keep track of who is alive in the connective mesh. This is to ensure that messages for things like signature generation and triple generation are routed correctly; and done in a reasonable amount of time.
