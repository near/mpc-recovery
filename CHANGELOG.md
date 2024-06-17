# Changelog

## 0.3.0

- Payload hash scalars are now big endian where previously they were little endian. In general this means that clients of the contract should no longer reverse their hashed payload before sending it to the MPC contract.
- The sha256 scalar used to derive the epsilon value is now big endian where previously it was little endian. In general this means clients should no longer reverse the bytes generated when hashing the epsilon derivation path. These new derivation paths will result in all testnet keys being lost.

