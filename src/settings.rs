use std::collections::HashMap;

use serde::Deserialize;

#[derive(Deserialize)]
pub struct Settings {
    pub base_url: openidconnect::url::Url,
    pub port: u16,
    pub allow_setting_edits: bool,
    #[serde(default)]
    pub per_user_settings: HashMap<String, PerUserSettings>,
}

#[derive(Clone, Deserialize)]
pub struct PerUserSettings {
    pub groups: Vec<String>,
}
