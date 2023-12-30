use serde::Deserialize;
use std::{collections::HashMap, path::Path};

#[derive(Debug, Deserialize, Default, Clone)]
pub(crate) struct UserAccess {
    #[serde(default)]
    pub(crate) read: bool,
    #[serde(default)]
    pub(crate) write: bool,
}

type CollectionConfig = HashMap<String, UserAccess>;

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct Configuration {
    #[serde(default)]
    pub(crate) users: HashMap<String, String>,
    #[serde(default)]
    pub(crate) collections: HashMap<String, CollectionConfig>,
}

pub(crate) fn load_config<P: AsRef<Path>>(path: P) -> Configuration {
    let content = std::fs::read_to_string(path).expect("could not read config file");

    toml::from_str(&content).expect("could not parse config file")
}
