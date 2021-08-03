#![feature(str_split_once)]
#[macro_use]
extern crate anyhow;
extern crate bitstring;
#[macro_use]
extern crate ini;
extern crate pest;
#[macro_use]
extern crate pest_derive;
extern crate regex;
extern crate serde_derive;
extern crate thiserror;
extern crate toml;


use thiserror::Error;

pub use config::Config;
pub use numbered::*;
pub use ufw::UfwCommand;

pub use crate::application::{Application, ApplicationEntry, parse_applications};

mod config;
mod ufw;
mod application;
mod numbered;

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
    MissingDescription,
    #[error("")]
    MissingPorts,
    #[error("")]
    EmptyPortsSection,
    #[error("")]
    InvalidLoggingLevel(String),
    #[error("")]
    WrongRuleDirection(String),
    #[error("")]
    WrongRuleType(String),
    #[error("")]
    InvalidDefaults(String),
}

pub type ParseResult<V> = Result<V, ParseError>;
