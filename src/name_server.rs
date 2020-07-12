use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NameServer {
    pub name: String,
    pub host: String,
}

pub fn parse_name_servers_json(path: &Path) -> Vec<NameServer> {
    serde_json::from_reader(File::open(path).expect("Name servers file not found"))
        .expect("JSON file parse error")
}
