use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use serde_derive::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    block_after_times: i32
}

impl Config {
    pub fn from_file<T: AsRef<Path>>(filename: T) -> io::Result<Config> {
        let mut content = String::new();
        File::open(filename)?.read_to_string(&mut content)?;

        Config::parse(content)
    }


    fn parse<S: ToString>(content: S) -> io::Result<Config> {
        match toml::from_str(&content.to_string()) {
            Ok(value) => {
                Ok(value)
            }
            Err(e) => {
                Err(io::Error::from(e))
            }
        }
    }
}
