use std::collections::HashSet;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct Entry {
    pub issuer: String,
    pub audience: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AllowList {
    pub entries: HashSet<Entry>,
}

impl AllowList {
    pub fn contains(&self, issuer: &str, audience: &str) -> bool {
        self.entries.contains(&Entry {
            issuer: issuer.into(),
            audience: audience.into(),
        })
    }

    #[cfg(test)]
    pub(crate) fn insert(&mut self, entry: Entry) {
        self.entries.insert(entry);
    }
}
