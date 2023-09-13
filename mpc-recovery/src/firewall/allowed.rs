use std::collections::HashSet;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct OidcProvider {
    pub issuer: String,
    pub audience: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AllowedOidcProviders {
    pub entries: HashSet<OidcProvider>,
}

impl AllowedOidcProviders {
    pub fn contains(&self, issuer: &str, audience: &str) -> bool {
        self.entries.contains(&OidcProvider {
            issuer: issuer.into(),
            audience: audience.into(),
        })
    }

    #[cfg(test)]
    pub(crate) fn insert(&mut self, entry: OidcProvider) {
        self.entries.insert(entry);
    }
}
