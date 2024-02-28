use serde::Deserialize;

#[derive(Deserialize)]
pub struct Settings {
    pub base_url: String,
    pub port: u16,
}


