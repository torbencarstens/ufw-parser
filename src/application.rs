use std::collections::HashMap;
use std::convert::TryInto;
use std::fs;
use std::io::{self};
use std::num::ParseIntError;
use std::path::{Path, PathBuf};

use crate::{ParseError, ParseResult};
use crate::ufw::{Protocol, UfwPort};

#[derive(Debug)]
pub struct ApplicationEntry {
    pub(crate) name: String,
    pub(crate) title: String,
    pub(crate) description: String,
    pub(crate) ports: Vec<ParseResult<UfwPort>>,
}

impl ApplicationEntry {
    fn parse(entry_key: &String, values: &HashMap<String, Option<String>>) -> ParseResult<Self> {
        let title: String = values
            .get("title")
            .ok_or(ParseError::MissingTitle)?.to_owned()
            .ok_or(ParseError::MissingTitle)?;
        let description: String = values
            .get("description")
            .ok_or(ParseError::MissingDescription)?.to_owned()
            .ok_or(ParseError::MissingDescription)?;

        let ports = values
            .get("ports")
            .ok_or(ParseError::MissingPorts)?.to_owned()
            .ok_or(ParseError::MissingPorts)?
            .split("|")
            .map(ApplicationEntry::parse_ports)
            .flatten()
            .collect::<Vec<ParseResult<UfwPort>>>();
        if ports.is_empty() {
            Err(ParseError::EmptyPortsSection)?
        }

        Ok(ApplicationEntry {
            name: entry_key.to_owned(),
            title,
            description,
            ports,
        })
    }

    fn parse_ports(entry: &str) -> Vec<ParseResult<UfwPort>> {
        let mut ports_protocol = entry.split("/");
        let s = ports_protocol.next();
        if s.is_none() {
            return vec![Err(ParseError::PortsSectionEmpty)];
        }

        let protocols = match ports_protocol.next() {
            None => {
                vec![Ok(Protocol::TCP), Ok(Protocol::UDP)]
            }
            Some(val) => {
                let p: ParseResult<Protocol> = val.try_into();

                vec![p]
            }
        };

        s.unwrap()
            .split(",")
            .map(|p| {
                Ok(match p.contains(":") {
                    true => {
                        let mut ranges = p.split(":");
                        // Check that both sides of the range have a value (x:y)
                        let start = ranges
                            .next()
                            .ok_or(ParseError::InvalidPortRange("number before colon hasn't been specified".to_string()))?;
                        let end = ranges
                            .next()
                            .ok_or(ParseError::InvalidPortRange("number after colon hasn't been specified".to_string()))?;

                        UfwPort {
                            number: start
                                .parse()
                                .map_err(|x: ParseIntError|
                                    ParseError::PortNotANumber(format!("Cannot parse first number in range: {}", x.to_string()))
                                )?,
                            end_number: Some(end
                                .parse()
                                .map_err(|x: ParseIntError|
                                    ParseError::PortNotANumber(format!("Cannot parse second number in range: {}", x.to_string()))
                                )?),
                            protocols: protocols.to_vec(),
                        }
                    }
                    false => {
                        UfwPort {
                            number: p
                                .parse()
                                .map_err(|x: ParseIntError|
                                    ParseError::PortNotANumber(x.to_string())
                                )?,
                            end_number: None,
                            protocols: protocols.to_vec(),
                        }
                    }
                })
            }).collect()
    }
}

#[derive(Debug)]
pub struct Application {
    pub(crate) filepath: PathBuf,
    pub(crate) entries: Vec<ParseResult<ApplicationEntry>>,
}

impl Application {
    pub fn parse_file<P: Into<PathBuf> + Clone>(path: P) -> ParseResult<Application> {
        let inipath = path.clone().into().to_str().unwrap().to_owned();
        if !Path::new(&inipath).exists() {
            return Err(ParseError::FileNotFound);
        }
        let map = ini!(&inipath);

        let entries = map
            .iter()
            .map(|(k, v)|
                ApplicationEntry::parse(k, v)
            ).collect();

        Ok(Application {
            filepath: path.into(),
            entries,
        })
    }
}

pub fn parse_applications<P: Into<PathBuf>>(applications_directory: Option<P>) -> io::Result<Vec<ParseResult<Application>>> {
    let path: PathBuf = applications_directory.and_then(|p| Some(p.into())).unwrap_or("/etc/ufw/applications.d/".into());

    match fs::read_dir(path) {
        Ok(iter) => {
            iter
                .filter_map(|file| {
                    let file = file.ok()?;
                    if file
                        .file_type().ok()?
                        .is_file() {
                        Some(Ok(Application::parse_file(file.path())))
                    } else {
                        None
                    }
                }).collect()
        }
        Err(err) => {
            Ok(vec![Err(ParseError::IOError(err.to_string()))])
        }
    }
}
