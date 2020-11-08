use std::convert::TryFrom;
use std::io;
use std::io::Error;
use std::net::IpAddr;
use std::ops::Index;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::str;
use std::str::Utf8Error;

use regex::{Captures, Match, Regex};

use crate::{ParseError, ParseResult};

#[derive(Clone, Debug)]
pub enum Protocol {
    TCP,
    UDP,
    AH,
    ESP,
    GRE,
    IPV6,
    IGMP,
}

impl TryFrom<&str> for Protocol {
    type Error = ParseError;

    fn try_from(v: &str) -> Result<Self, Self::Error> {
        Ok(match v {
            "tcp" => Protocol::TCP,
            "udp" => Protocol::UDP,
            _ => Err(ParseError::InvalidProtocol(v.to_string()))?
        })
    }
}

pub enum IpVersion {
    V4,
    V6,
}

pub struct RuleEntry {
    source_address: Option<IpAddr>,
    destination_address: Option<IpAddr>,
    source_port: Option<i16>,
    destination_port: Option<i16>,
    proto: Option<Protocol>,
    ip_version: Option<IpVersion>,
}

impl RuleEntry {
    fn source_address_string(&self) -> String {
        match self.source_address {
            None => {
                "any".into()
            }
            Some(val) => {
                val.to_string()
            }
        }
    }
}

pub enum RuleType {
    ALLOW,
    DENY,
    REJECT,
    LIMIT,
}

pub enum ReportFormats {
    Raw,
    Builtins,
    BeforeRules,
    UserRules,
    AfterRules,
    LoggingRules,
    Listening,
    Added,
}

pub enum LoggingLevel {
    Off,
    Low,
    Medium,
    High,
    Full,
}

pub struct Ufw {
    enabled: bool,
    logging: LoggingLevel,
    entries: Vec<RuleEntry>,
}

impl Ufw {
    pub fn add_rule(&mut self, entry: RuleEntry) {
        self.entries.push(entry)
    }

    pub fn delete_rule(&mut self, entry_index: u16) -> Option<RuleEntry> {
        if entry_index > self.entries.len() as u16 {
            None
        } else {
            Some(self.entries.remove(entry_index.into()))
        }
    }

    pub fn submit(self) -> io::Result<()> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub(crate) struct UfwPort {
    pub(crate) number: u16,
    pub(crate) end_number: Option<u16>,
    pub(crate) protocols: Vec<ParseResult<Protocol>>,
}

pub struct UfwCommand {
    executable: PathBuf
}

pub type UfwCommandOutput = Output;

impl UfwCommand {
    pub fn new() -> UfwCommand {
        UfwCommand::with_executable(PathBuf::from("/usr/bin/ufw"))
    }

    pub fn with_executable<P: Into<PathBuf>>(executable_path: P) -> UfwCommand {
        UfwCommand {
            executable: executable_path.into()
        }
    }

    pub fn info(&self) -> io::Result<()> {
        let output = self.exec(vec!["status", "numbered"]);
        match output {
            Ok(out) => {
                Ok(())
            }
            Err(err) => {
                Err(err)
            }
        }
    }

    /// e.g.: [ 1] Anywhere on eth0           ALLOW FWD   10.6.0.0/24 on wg0
    fn parse_numbered_output(stdout: String) {}

    pub fn version(&self) -> io::Result<String> {
        let output = self.exec(vec!["version"])?;

        if output.status.success() {
            let text = match str::from_utf8(&*output.stdout) {
                Ok(val) => {
                    Ok(val)
                }
                Err(err) => {
                    Err(io::Error::new(io::ErrorKind::Other, err.to_string()))
                }
            }?;
            match Regex::new(r"ufw (\d+\.\d+(?:\.\d+)?)")
                .unwrap()
                .captures(text) {
                None => {
                    let error_message = format!("Couldn't find a valid ufw version in {}", text);
                    Err(io::Error::new(io::ErrorKind::InvalidInput, error_message))
                }
                Some(captures) => {
                    match captures.get(1) {
                        None => {
                            let error_message = format!("Couldn't find a valid ufw version in {}", text);
                            Err(io::Error::new(io::ErrorKind::InvalidInput, error_message))
                        }
                        Some(capture) => {
                            Ok(capture.as_str().to_string())
                        }
                    }
                }
            }
        } else {
            Err(io::Error::new(io::ErrorKind::Other, format!("ufw execution unsuccessful: {:?}", str::from_utf8(&output.stderr))))
        }
    }

    fn exec(&self, args: Vec<&str>) -> io::Result<UfwCommandOutput> {
        // Command::new("sudo")
        //     .arg("-n")
        Command::new("ufw")
            .args(args)
            .output()
    }
}
