use std::collections::HashSet;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct OidcProvider {
    pub issuer: String,
    pub audience: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct DelegateActionRelayer {
    pub url: String,
    pub api_key: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct FastAuthPartner {
    pub oidc_provider: OidcProvider,
    pub relayer: DelegateActionRelayer,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OidcProviderList {
    pub entries: HashSet<OidcProvider>,
}

impl OidcProviderList {
    pub fn contains(&self, issuer: &str, audience: &str) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.issuer == issuer && entry.audience == audience)
    }

    pub fn insert(&mut self, entry: OidcProvider) {
        self.entries.insert(entry);
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PartnerList {
    pub entries: HashSet<FastAuthPartner>,
}

impl PartnerList {
    pub fn contains(&self, issuer: &str, audience: &str) -> bool {
        self.entries.iter().any(|entry| {
            entry.oidc_provider.issuer == issuer && entry.oidc_provider.audience == audience
        })
    }

    pub fn find(&self, issuer: &str, audience: &str) -> anyhow::Result<FastAuthPartner> {
        match self
            .entries
            .iter()
            .find(|entry| {
                entry.oidc_provider.issuer == issuer && entry.oidc_provider.audience == audience
            })
            .cloned()
        {
            Some(partner) => Ok(partner),
            None => Err(anyhow::anyhow!(
                "Failed to find relayer for given partner. Issuer: {}, Audience: {}",
                issuer,
                audience,
            )),
        }
    }

    pub fn oidc_providers(&self) -> OidcProviderList {
        let mut oidc_providers = OidcProviderList::default();
        for entry in self.entries.iter() {
            oidc_providers.insert(entry.oidc_provider.clone());
        }
        oidc_providers
    }
}
