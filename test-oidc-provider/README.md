# Test OIDC Provider
Simplistic server that can return a public key in RSA PEM format for JWT Roken validation.

## Usage
1. Build Dcoker image
```bash
docker build -t near/test-oidc-provider .
```
2. Run Integration or other type of tests