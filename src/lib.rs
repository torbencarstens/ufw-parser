#[macro_use]
extern crate ini;
extern crate regex;
extern crate serde_derive;
extern crate thiserror;
extern crate toml;

use std::convert::TryInto;
use std::num::ParseIntError;
use std::path::{Path, PathBuf};

use thiserror::Error;

pub use config::Config;
pub use ufw::UfwCommand;

pub use crate::application::{Application, ApplicationEntry, parse_applications};
use crate::ufw::Protocol;

mod config;
mod ufw;
mod application;

#[derive(Clone, Debug, Error)]
pub enum ParseError {
    #[error("port range must have a protocol attached")]
    InvalidPortRange(String),
    #[error("port must be a number")]
    PortNotANumber(String),
    #[error("ufw ini file not found")]
    FileNotFound,
    #[error("all port numbers must appear before the protocol")]
    NumberAfterProtocol(String),
    #[error("not a valid protocol")]
    InvalidProtocol(String),
    #[error("an IO error has occured")]
    IOError(String),
    #[error("ports section is empty")]
    PortsSectionEmpty,
    #[error("")]
    MissingTitle,
    #[error("")]
    MissingDescroption,
}

pub type ParseResult<V> = Result<V, ParseError>;
