use config::Config;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Settings {
    pub base_url: String
}


pub fn read_settings() -> Settings {
 let settings = Config::builder()
    .add_source(config::File::with_name("examples/simple/Settings"))
    .build()
    .unwrap();

 settings.try_deserialize().unwrap()
}

