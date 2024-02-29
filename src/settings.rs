use std::collections::HashMap;

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Settings {
    pub base_url: String,
    pub port: u16,
    #[serde(default)]
    pub per_user_settings: HashMap<String, PerUserSettings>
}

#[derive(Deserialize)]
pub struct PerUserSettings {
    pub groups: Vec<String>
}

