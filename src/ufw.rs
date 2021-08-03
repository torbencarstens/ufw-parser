use std::convert::TryFrom;
use std::io;
use std::net::IpAddr;
use std::num::ParseIntError;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::str;
use std::str::FromStr;

use anyhow::{Context, Error, Result};
use regex::{Captures, Regex};

use crate::{ParseError, ParseResult};
use crate::ParseError::{InvalidLoggingLevel, IOError};

#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    TCP,
    UDP,
    AH,
    ESP,
    GRE,
    IPV6,
    IGMP,
    ANY,
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

#[derive(Debug)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Debug)]
pub struct UfwAction {
    typ: RuleType,
    direction: RuleDirection,
}

#[derive(Clone, Copy, Debug)]
pub struct Address {
    addr: IpAddr,
    cidr: u8,
}

impl From<IpAddr> for Address {
    fn from(ip: IpAddr) -> Self {
        Address {
            addr: ip,
            cidr: 32,
        }
    }
}

impl ToString for Address {
    fn to_string(&self) -> String {
        if self.cidr == 32 {
            self.addr.to_string()
        } else {
            vec![self.addr.to_string(), self.cidr.to_string()].join("/")
        }
    }
}

impl TryFrom<&str> for Address {
    type Error = anyhow::Error;

    fn try_from(s: &str) -> Result<Self> {
        Ok(match s.rfind('/') {
            None => Address::from(IpAddr::from_str(s)?),
            Some(pos) => {
                Address {
                    addr: IpAddr::from_str(&s[0..pos])?,
                    cidr: u8::from_str(&s[pos + 1..])?,
                }
            }
        })
    }
}

#[derive(Debug)]
pub struct RuleEntry {
    interface: Option<String>,
    source_address: Option<Address>,
    destination_address: Option<Address>,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    proto: Protocol,
    ip_version: Option<IpVersion>,
    number: u16,
    action: UfwAction,
}

impl RuleEntry {
    fn source_address_string(&self) -> String {
        match &self.source_address {
            None => {
                "any".into()
            }
            Some(val) => {
                val.to_string()
            }
        }
    }
}

impl ToString for RuleEntry {
    fn to_string(&self) -> String {
        unimplemented!()
    }
}

#[derive(Debug)]
pub enum RuleDirection {
    IN,
    OUT,
    FWD,
}

#[derive(Debug)]
pub enum RuleDirectionDefaults {
    INCOMING,
    OUTGOING,
    ROUTED,
}

#[derive(Debug)]
pub enum RuleType {
    ALLOW,
    DENY,
    REJECT,
    LIMIT,
}

impl TryFrom<&str> for RuleDirectionDefaults {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value.to_ascii_lowercase().as_str() {
            "incoming" => RuleDirectionDefaults::INCOMING,
            "outgoing" => RuleDirectionDefaults::OUTGOING,
            "routed" => RuleDirectionDefaults::ROUTED,
            &_ => Err(ParseError::WrongRuleDirection(value.to_string()))?,
        })
    }
}

impl TryFrom<&str> for RuleType {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value.to_ascii_lowercase().as_str() {
            "allow" => RuleType::ALLOW,
            "deny" => RuleType::DENY,
            "reject" => RuleType::REJECT,
            "limit" => RuleType::LIMIT,
            &_ => Err(ParseError::WrongRuleType(value.to_string()))?,
        })
    }
}

impl TryFrom<&str> for RuleDirection {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value.to_ascii_lowercase().as_str() {
            "fwd" => RuleDirection::FWD,
            "out" => RuleDirection::OUT,
            "in" => RuleDirection::IN,
            &_ => Err(ParseError::WrongRuleDirection(value.to_string()))?,
        })
    }
}

#[derive(Debug)]
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

#[derive(Debug)]
pub enum LoggingLevel {
    Off,
    Low,
    Medium,
    High,
    Full,
}

impl TryFrom<(&str, &str)> for LoggingLevel {
    type Error = ParseError;

    fn try_from(value: (&str, &str)) -> Result<Self, Self::Error> {
        let (onoff, level) = value;

        match onoff {
            "on" => {
                match level {
                    "low" => Ok(LoggingLevel::Low),
                    "medium" => Ok(LoggingLevel::Medium),
                    "high" => Ok(LoggingLevel::High),
                    "full" => Ok(LoggingLevel::Full),
                    &_ => Err(ParseError::InvalidLoggingLevel(level.to_string())),
                }
            }
            "off" => {
                Ok(LoggingLevel::Off)
            }
            &_ => Err(ParseError::InvalidLoggingLevel(onoff.to_string())),
        }
    }
}

#[derive(Debug)]
pub struct Ufw {
    enabled: bool,
    logging: LoggingLevel,
    entries: Vec<(RuleEntry, bool)>,
}

// keep old rules until submitting
impl Ufw {
    pub fn add_rule(&mut self, entry: RuleEntry) {
        self.entries.push((entry, true))
    }

    pub fn delete_rule(&mut self, entry_index: u16) -> Option<(RuleEntry, bool)> {
        if entry_index > self.entries.len() as u16 {
            None
        } else {
            Some(self.entries.remove(entry_index.into()))
        }
    }

    pub fn submit(self) -> io::Result<Vec<Output>> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(index, (entry, commit_status))|
                if !commit_status {
                    Some(UfwCommand::new().exec(vec!["insert", &index.to_string(), &entry.to_string()]))
                } else {
                    None
                })
            .collect()
    }
}

#[derive(Debug)]
pub(crate) struct UfwPort {
    pub(crate) number: u16,
    pub(crate) end_number: Option<u16>,
    pub(crate) protocols: Vec<ParseResult<Protocol>>,
}

pub struct UfwCommand {
    executable: PathBuf,
}

pub type UfwCommandOutput = Output;

struct LineNumberRuleEntry {}

struct LineNumberField {
    name: String,
    value: Vec<ParseResult<UfwPort>>, // TOOD correct type?
}

impl UfwCommand {
    pub fn new() -> UfwCommand {
        UfwCommand {
            executable: PathBuf::from("/usr/bin/ufw")
        }
    }

    pub fn with_executable<P: Into<PathBuf>>(&mut self, executable_path: P) -> &mut UfwCommand {
        self.executable = executable_path.into();

        self
    }

    fn parse_action(arguments: Vec<&str>) -> ParseResult<UfwAction> {
        let rule_type = arguments.get(0)
            .ok_or(ParseError::WrongRuleType(String::from("couldn't get rule type")))?.to_owned();
        let rule_direction = arguments.get(1)
            .ok_or(ParseError::WrongRuleType(String::from("couldn't get rule direction")))?.to_owned();

        Ok(UfwAction {
            typ: RuleType::try_from(rule_type)?,
            direction: RuleDirection::try_from(rule_direction)?,
        })
    }

    fn parse_stdout(o: Vec<u8>) -> io::Result<String> {
        match str::from_utf8(&o) {
            Ok(val) => {
                Ok(val.to_string())
            }
            Err(err) => {
                Err(io::Error::new(io::ErrorKind::Other, err.to_string()))
            }
        }
    }

    pub fn version(&self) -> io::Result<String> {
        let output = self.exec(vec!["version"])?;

        if output.status.success() {
            let text = UfwCommand::parse_stdout(output.stdout)?;
            match Regex::new(r"ufw (\d+\.\d+(?:\.\d+)?)")
                .unwrap()
                .captures(&text) {
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
            Err(io::Error::new(io::ErrorKind::Other, format!("ufw execution unsuccessful: {:?}", str::from_utf8(&output.stderr))))?
        }
    }

    pub fn info(&self) -> ParseResult<(bool, LoggingLevel)> {
        let output = self.exec(vec!["status", "verbose"]).map_err(|e| IOError(e.to_string()))?;

        if output.status.success() {
            let text = match str::from_utf8(&*output.stdout) {
                Ok(val) => {
                    Ok(val)
                }
                Err(err) => {
                    Err(IOError(err.to_string()))
                }
            }?;

            let enabled = match Regex::new(r"Status:\s*((:?in)?active)")
                .unwrap()
                .captures(text) {
                None => {
                    let error_message = format!("Couldn't find a valid ufw version in {}", text);
                    Err(IOError(error_message))
                }
                Some(captures) => {
                    match captures.get(1) {
                        None => {
                            let error_message = format!("Couldn't find a valid logging level in: {}", text);
                            Err(IOError(error_message))
                        }
                        Some(capture) => {
                            Ok(capture.as_str().to_string())
                        }
                    }
                }
            }? == "active";
            let logging_level = match Regex::new(r"Logging:\s*(on|off)\s*(:?\((\w+)\))?")
                .unwrap()
                .captures(text) {
                None => {
                    let error_message = format!("Couldn't find a valid logging level {}", text);
                    Err(InvalidLoggingLevel(text.to_string()))
                }
                Some(captures) => {
                    let (state, level) = (captures.get(1), captures.get(2));
                    if state.is_some() && level.is_some() {
                        let level = level.unwrap().as_str().replace("(", "").replace(")", "");
                        LoggingLevel::try_from((state.unwrap().as_str(), level.as_str()))
                    } else {
                        let message = format!("Invalid logging level ({}) found.\
                            Valid logging levels are: `low`, `medium`, `high`.\
                            \nBeware that ufw has no checks on what you're setting the value to and allows anything.",
                                              text.to_string());
                        Err(InvalidLoggingLevel(message))
                    }
                }
            }?;

            Ok((enabled, logging_level))
        } else {
            Err(IOError(format!("ufw execution unsuccessful: {:?}", str::from_utf8(&output.stderr))))
        }
    }

    pub fn defaults(&self) -> ParseResult<Vec<(ParseResult<RuleDirectionDefaults>, ParseResult<RuleType>)>> {
        let output = self.exec(vec!["status", "verbose"]).map_err(|e| IOError(e.to_string()))?;
        if output.status.success() {
            let text = match str::from_utf8(&*output.stdout) {
                Ok(val) => {
                    Ok(val)
                }
                Err(err) => {
                    Err(IOError(err.to_string()))
                }
            }?;

            let defaults_regex = Regex::new(r"^Default:\s*.+").unwrap();
            let single_default_regex = Regex::new(r"(\w+)\s+\((\w+)\)").unwrap();
            Ok(text
                .split("\n")
                .filter(|text| defaults_regex.is_match(text))
                .map(|text|
                    text
                        .split(": ")
                        .last()
                        // this is impossible since we match against the defaults_regex beforehand which assures that something is behind the colon
                        .unwrap_or("")
                        .split(", ")
                        .map(|x| {
                            let default = single_default_regex.captures(x).unwrap();

                            let rule_type = default.get(1);
                            let rule_direction = default.get(2);

                            if rule_direction.is_some() & &rule_type.is_some() {
                                let rule_direction: String = rule_direction.unwrap().as_str().into();
                                let rule_type: String = rule_type.unwrap().as_str().into();

                                let direction = RuleDirectionDefaults::try_from(&*rule_direction);
                                let rtype = RuleType::try_from(&*rule_type);

                                (direction, rtype)
                            } else {
                                (Err(ParseError::WrongRuleDirection(text.to_string())), Err(ParseError::WrongRuleDirection(text.to_string())))
                            }
                        })
                        .collect::<Vec<(ParseResult<RuleDirectionDefaults>, ParseResult<RuleType>)>>()
                ).flatten()
                .collect())
        } else {
            Err(ParseError::InvalidDefaults(format!("{:?}\n\n{:?}", str::from_utf8(&*output.stdout), str::from_utf8(&*output.stderr))))
        }
    }

    fn exec(&self, args: Vec<&str>) -> io::Result<UfwCommandOutput> {
        Command::new(&self.executable)
            .args(args)
            .output()
    }
}
