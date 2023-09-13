env     = "dev"
project = "pagoda-discovery-platform-dev"

account_creator_id = "tmp_acount_creator.serhii.testnet"
account_creator_sk = "ed25519:5pFJN3czPAHFWHZYjD4oTtnJE7PshLMeTkSU7CmWkvLaQWchCLgXGF1wwcJmh2AQChGH85EwcL5VW7tUavcAZDSG"
cipher_keys        = ["ea28abd17cb76924f62c99f6fd240985c16b9dc85187760c1487e64689d447f5", "cc7a448b28b2a58bada59770b6418ae75ade177abad216385e012805b9cfc8f9", "78be23c9400f4414c043aa966b51e44b3fa3ab790a1779d370d40589a7b02dd2"]
sk_shares = [
  "{\"public_key\":{\"curve\":\"ed25519\",\"point\":[44,250,33,208,230,210,1,232,218,250,54,239,72,81,92,99,10,169,178,160,155,203,106,27,68,188,121,148,143,199,6,241]},\"expanded_private_key\":{\"prefix\":{\"curve\":\"ed25519\",\"scalar\":[102,223,208,90,184,101,17,59,89,36,9,226,244,136,59,225,17,226,66,187,72,197,17,71,28,28,128,125,122,248,32,105]},\"private_key\":{\"curve\":\"ed25519\",\"scalar\":[240,196,61,168,214,169,50,27,103,54,246,131,195,119,194,74,24,183,7,164,92,165,213,35,130,63,118,52,70,141,108,97]}}}",
  "{\"public_key\":{\"curve\":\"ed25519\",\"point\":[46,181,130,13,164,112,16,130,63,196,212,83,38,63,120,124,0,35,238,100,212,32,46,7,233,221,2,16,20,189,198,167]},\"expanded_private_key\":{\"prefix\":{\"curve\":\"ed25519\",\"scalar\":[35,145,79,79,99,72,33,94,114,179,89,56,252,168,145,28,195,10,230,89,247,39,194,127,202,75,119,182,59,120,144,83]},\"private_key\":{\"curve\":\"ed25519\",\"scalar\":[88,71,177,97,38,226,233,158,49,168,14,146,117,128,240,16,97,35,56,137,0,69,150,237,4,210,81,35,0,44,233,98]}}}",
  "{\"public_key\":{\"curve\":\"ed25519\",\"point\":[226,221,12,58,210,76,171,11,139,88,242,44,18,207,126,120,5,90,208,108,4,93,19,188,24,172,130,61,51,94,10,34]},\"expanded_private_key\":{\"prefix\":{\"curve\":\"ed25519\",\"scalar\":[72,32,251,204,100,91,164,82,140,231,84,166,176,30,167,99,107,71,71,195,83,40,241,205,6,89,122,227,140,146,82,4]},\"private_key\":{\"curve\":\"ed25519\",\"scalar\":[8,248,184,114,40,88,141,189,156,115,215,171,36,210,85,189,12,217,176,9,208,28,141,207,18,18,57,230,231,14,118,116]}}}"
]

// For leader node
fast_auth_partners = [
  {
    oidc_provider = {
      issuer   = "https://securetoken.google.com/pagoda-oboarding-dev",
      audience = "pagoda-oboarding-dev"
    },
    relayer = {
      url     = "http://34.70.226.83:3030",
      api_key = null,
    },
  }
]

// For signing nodes
oidc_providers = [
  {
    issuer   = "https://securetoken.google.com/pagoda-oboarding-dev",
    audience = "pagoda-oboarding-dev"
  }
]
