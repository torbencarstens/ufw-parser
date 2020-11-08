use std::convert::TryFrom;
use std::io;
use std::net::IpAddr;
use std::num::ParseIntError;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::slice::SliceIndex;
use std::str;

use regex::{Captures, Match, Regex};

use crate::{ParseError, ParseResult};
use crate::ufw::ReportFormats::LoggingRules;

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

#[derive(Debug)]
pub struct RuleEntry {
    interface: Option<String>,
    source_address: Option<IpAddr>,
    destination_address: Option<IpAddr>,
    source_port: Option<i16>,
    destination_port: Option<i16>,
    proto: Option<Protocol>,
    ip_version: Option<IpVersion>,
    number: u16,
    action: UfwAction,
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

#[derive(Debug)]
pub enum RuleDirection {
    IN,
    OUT,
    FWD,
}

#[derive(Debug)]
pub enum RuleType {
    ALLOW,
    DENY,
    REJECT,
    LIMIT,
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

impl LoggingLevel {
    fn from(onoff: &str, level: &str) -> ParseResult<LoggingLevel> {
        match onoff {
            "on" => {
                match level {
                    "low" => Ok(LoggingLevel::Low),
                    "medium" => Ok(LoggingLevel::Medium),
                    "high" => Ok(LoggingLevel::High),
                    &_ => Err(ParseError::InvalidLoggingLevel),
                }
            }
            "off" => {
                Ok(LoggingLevel::Off)
            }
            &_ => Err(ParseError::InvalidLoggingLevel),
        }
    }
}

#[derive(Debug)]
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

    pub fn numbered_output(&self) -> io::Result<Vec<RuleEntry>> {
        let output = self.exec(vec!["status", "numbered"])?;
        let regex = Regex::new(r"\[\s*(\d+)](.*)").unwrap();

        if output.status.success() {
            let stdout = UfwCommand::parse_stdout(output.stdout)?;
            stdout
                .lines()
                .filter_map(|line| if regex.is_match(line) { Some(line) } else { None })
                .map(|s|
                    match regex
                        .captures(s) {
                        None => {
                            Err(io::Error::new(io::ErrorKind::InvalidInput, format!("can't parse entry: {}", s)))
                        }
                        Some(value) => {
                            let number = match value.get(1) {
                                None => {
                                    Err(io::Error::new(io::ErrorKind::InvalidInput, format!("can't parse entry: {}", s)))
                                }
                                Some(capture) => {
                                    capture
                                        .as_str()
                                        .parse::<u16>()
                                        .map_err(|e: ParseIntError| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
                                }
                            }?;
                            let fields = match value.get(2) {
                                None => {
                                    println!("no capture: {}", stdout)
                                }
                                Some(capture) => {
                                    let text = capture.as_str().trim();
                                    let fields: Vec<&str> = Regex::new(r"\s+")
                                        .unwrap()
                                        .split(text)
                                        .map(|x|
                                            x
                                                .trim()
                                                .split_whitespace()
                                                .collect::<Vec<&str>>())
                                        .flatten()
                                        .collect();

                                    let to: Vec<&&str> = fields
                                        .iter()
                                        .by_ref()
                                        .take_while(|v| {
                                            RuleType::try_from(**v).is_err()
                                        }).collect();
                                    let modifier = to.len();

                                    let action = UfwCommand::parse_action(fields[modifier..modifier + 2].to_vec());
                                    let from = &fields[modifier + 2..];

                                    println!("==========================\n{:#?}", action);
                                    println!("{:#?}", from);

                                    action;
                                }
                            };

                            Ok(RuleEntry {
                                interface: None,
                                source_address: None,
                                destination_address: None,
                                source_port: None,
                                destination_port: None,
                                proto: None,
                                ip_version: None,
                                number,
                                action: UfwAction { typ: RuleType::ALLOW, direction: RuleDirection::IN },
                            })
                        }
                    }).collect()
        } else {
            Err(io::Error::new(io::ErrorKind::Other, format!("ufw execution unsuccessful: {:?}", str::from_utf8(&output.stderr))))
        }
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
            Err(io::Error::new(io::ErrorKind::Other, format!("ufw execution unsuccessful: {:?}", str::from_utf8(&output.stderr))))
        }
    }

    pub fn info(&self) -> io::Result<(bool, LoggingLevel)> {
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

            let enabled = match Regex::new(r"Status:\s*((:?in)?active)")
                .unwrap()
                .captures(text) {
                None => {
                    let error_message = format!("Couldn't find a valid ufw version in {}", text);
                    Err(io::Error::new(io::ErrorKind::InvalidInput, error_message))
                }
                Some(captures) => {
                    match captures.get(1) {
                        None => {
                            let error_message = format!("Couldn't find a valid logging level in: {}", text);
                            Err(io::Error::new(io::ErrorKind::InvalidInput, error_message))
                        }
                        Some(capture) => {
                            Ok(capture.as_str().to_string())
                        }
                    }.map_err(|_| io::Error::new(io::ErrorKind::Other, format!("couldn't find enabled status in: {:?}", str::from_utf8(&output.stderr))))
                }
            }? == "active";
            let logging = match Regex::new(r"Logging:\s*(on|off)\s*(:?\((\w+)\))?")
                .unwrap()
                .captures(text) {
                None => {
                    let error_message = format!("Couldn't find a valid logging level {}", text);
                    Err(io::Error::new(io::ErrorKind::InvalidInput, error_message))
                }
                Some(captures) => {
                    match captures.get(1) {
                        None => {
                            let error_message = format!("Couldn't find a valid logging level in: {}", text);
                            Err(io::Error::new(io::ErrorKind::InvalidInput, error_message))
                        }
                        Some(capture) => {
                            Ok(capture.as_str().to_string())
                        }
                    }.map_err(|_| io::Error::new(io::ErrorKind::Other, format!("couldn't find enabled status in: {:?}", str::from_utf8(&output.stderr))))
                }
            }?;

            Ok((enabled, LoggingLevel::Full))
        } else {
            Err(io::Error::new(io::ErrorKind::Other, format!("ufw execution unsuccessful: {:?}", str::from_utf8(&output.stderr))))
        }
    }

    fn exec(&self, args: Vec<&str>) -> io::Result<UfwCommandOutput> {
        Command::new(&self.executable)
            .args(args)
            .output()
    }
}
