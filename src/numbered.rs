use std::convert::TryFrom;
use std::fmt::Formatter;
use std::net::IpAddr;
use std::str::{FromStr, Split};

use anyhow::{Context, Error, Result};
use pest::iterators::Pair;
use pest::Parser;

#[derive(Parser)]
#[grammar = "address.pest"]
pub struct AddressParser;

#[derive(Debug, Eq, PartialOrd, PartialEq)]
pub enum Protocol {
    TCP,
    UDP,
    ANY,
}

#[derive(Debug, Eq, PartialOrd, PartialEq)]
pub enum Modifier {
    ALLOW,
    DENY,
}

#[derive(Debug, Eq, PartialOrd, PartialEq)]
pub enum Direction {
    IN,
    OUT,
    BOTH,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Protocol::TCP => { "tcp" }
            Protocol::UDP => { "udp" }
            Protocol::ANY => { "ANY" }
        };

        write!(f, "{}", s)
    }
}

impl TryFrom<&str> for Protocol {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "tcp" => Ok(Protocol::TCP),
            "udp" => Ok(Protocol::UDP),
            "" => Ok(Protocol::ANY),
            _ => Err(anyhow!("unknown protocol"))
        }
    }
}

impl TryFrom<Option<&str>> for Direction {
    type Error = Error;

    fn try_from(value: Option<&str>) -> Result<Self> {
        match value {
            None => {
                Ok(Direction::BOTH)
            }
            Some(value) => {
                match value {
                    "OUT" => Ok(Direction::OUT),
                    "IN" => Ok(Direction::IN),
                    "" => Ok(Direction::BOTH),
                    _ => Err(anyhow!("unknown direction"))
                }
            }
        }
    }
}

impl TryFrom<&str> for Modifier {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "ALLOW" => Ok(Modifier::ALLOW),
            "DENY" => Ok(Modifier::DENY),
            _ => Err(anyhow!("unknown modifier"))
        }
    }
}

#[derive(Debug)]
pub struct Address {
    addr: Option<IpAddr>,
    cidr: Option<u8>,
    port: Option<u16>,
    protocol: Protocol,
}

impl From<(Option<IpAddr>, Option<u16>, Option<u8>, Option<Protocol>)> for Address {
    fn from(v: (Option<IpAddr>, Option<u16>, Option<u8>, Option<Protocol>)) -> Self {
        let (mut addr, port, cidr, proto) = v;
        if addr.is_none() && port.is_some() {
            addr = Some(IpAddr::from([0, 0, 0, 0]))
        }

        Address {
            addr,
            cidr,
            port,
            protocol: proto.unwrap_or(Protocol::ANY),
        }
    }
}

fn parse_index(s: Pair<Rule>) -> Result<u16> {
    let s = s.as_str();
    // pest checks the validity beforehand
    let s = s[1..s.len() - 1].split_whitespace().next().unwrap();

    Ok(s.parse()?)
}

fn parse_portp(mut s: Split<&str>) -> Result<(u16, Protocol)> {
    // all unwraps are ensured to be there by pest
    // port validity is ensured by parsing it to u16 (>= 0 && <= 65535)
    let port = s.next().unwrap().parse::<u16>().context("port must be >= 0 && <= 65535")?;

    // no protocol specified -> ANY
    let proto = Protocol::try_from(s.next().unwrap_or(""))?;

    Ok((port, proto))
}

fn parse_cidr(s: &str) -> Result<u8> {
    let x: u8 = s.parse::<u8>().map_err(|e| anyhow::Error::from(e))?;

    if x > 32 {
        Err(anyhow!("cidr must be >= 0 && <= 32"))?
    }

    Ok(x)
}

#[derive(Debug)]
pub struct Line {
    index: u16,
    to: Address,
    v6: bool,
    action: Element,
    device: Option<String>,
    from: Address,
}

impl Line {
    fn new(index: u16, to: Address, v6: bool, action: Element, device: Option<String>, from: Address) -> Line {
        Line {
            index,
            to,
            v6,
            action,
            device,
            from,
        }
    }
}

impl TryFrom<Vec<Element>> for Line {
    type Error = Error;

    fn try_from(es: Vec<Element>) -> Result<Self> {
        let mut toblock = true;
        let mut index = 0;
        let mut to = (None, None, None, None);
        let mut action = Element::V6;
        let mut v6 = false;
        let mut device = String::new();
        let mut from = (None, None, None, None);

        for e in es {
            match e {
                Element::Index(i) => {
                    index = i
                }
                Element::ToFrom(val) => {
                    for x in val {
                        match x {
                            Element::Address(addr) => {
                                if toblock {
                                    to = (Some(addr?), to.1, to.2, to.3)
                                } else {
                                    from = (Some(addr?), from.1, from.2, from.3)
                                }
                            }
                            Element::PortProtocol(res) => {
                                let (port, proto) = res?;
                                if toblock {
                                    to = (to.0, Some(port), to.2, Some(proto))
                                } else {
                                    from = (from.0, Some(port), from.2, Some(proto))
                                }
                            }
                            Element::CIDR(cidr) => {
                                if toblock {
                                    to = (to.0, to.1, Some(cidr?), to.3)
                                } else {
                                    from = (from.0, from.1, Some(cidr?), from.3)
                                }
                            }
                            Element::Protocol(proto) => {
                                if toblock {
                                    to = (to.0, to.1, to.2, Some(proto?))
                                } else {
                                    from = (from.0, from.1, from.2, Some(proto?))
                                }
                            }
                            Element::CIDRProto(cidr, proto) => {
                                if toblock {
                                    to = (to.0, to.1, Some(cidr?), Some(proto?))
                                } else {
                                    from = (from.0, from.1, Some(cidr?), Some(proto?))
                                }
                            }
                            Element::Port(port) => {
                                if toblock {
                                    to = (to.0, Some(port?), to.2, to.3)
                                } else {
                                    from = (from.0, Some(port?), from.2, from.3)
                                }
                            }
                            _ => unimplemented!("{:#?}", x)
                        }
                    }
                }
                Element::Port(_) => {}
                Element::Device(dev) => {
                    device = dev;
                    toblock = false
                }
                Element::V6 => {
                    v6 = true;
                    toblock = false
                }
                Element::Action(port, proto) => {
                    action = Element::Action(Ok(port?), Ok(proto?));
                    toblock = false
                }
                Element::Modifier(_) => {}
                Element::Direction(_) => {}
                Element::CIDR(_) => {}
                _ => {}
            }
        }

        let (toaddr, topp, tocidr, toproto) = to;
        let to = Address::try_from((toaddr, topp, tocidr, toproto));
        let (fromaddr, fromp, fromcidr, fromproto) = from;
        let from = Address::try_from((fromaddr, fromp, fromcidr, fromproto));

        Ok(Line::new(index, to?, v6, action, Some(device), from?))
    }
}

#[derive(Debug)]
pub enum Element {
    Index(u16),
    Ipv4Address(Result<IpAddr>),
    Address(Result<IpAddr>),
    Protocol(Result<Protocol>),
    PortProtocol(Result<(u16, Protocol)>),
    ToFrom(Vec<Element>),
    Port(Result<u16>),
    Device(String),
    V6,
    Action(Result<Modifier>, Result<Direction>),
    Modifier(Result<Modifier>),
    Direction(Result<Direction>),
    CIDR(Result<u8>),
    CIDRProto(Result<u8>, Result<Protocol>),
    END,
}

pub fn parse(line: &str) -> Result<Line> {
    let elements = AddressParser::parse(Rule::line, &(line.to_owned() + " "))?.next().unwrap()
        .into_inner()
        .into_iter()
        .map(parse_line)
        .collect::<Vec<Element>>();
    Line::try_from(elements)
}

pub fn parse_line(r: Pair<Rule>) -> Element {
    match r.as_rule() {
        Rule::index => {
            let index = parse_index(r).unwrap();

            Element::Index(index)
        }
        Rule::ipv4_address => {
            let s = r.as_str();
            let ipv4_address = IpAddr::from_str(s).map_err(|e| anyhow::Error::from(e).context(format!("Rule::ipv4_address: {:?}", s)));

            Element::Ipv4Address(ipv4_address)
        }
        Rule::address => {
            let inner = r.into_inner().next();
            let address = if inner.is_some() {
                let s = inner.unwrap().as_str();
                IpAddr::from_str(s).context(format!("Rule::address: {}", s))
            } else {
                // needs to be ::/0 for ipv6
                Ok(IpAddr::from([0, 0, 0, 0]))
            }.map_err(|e| anyhow::Error::from(e).context("Rule::address"));

            Element::Address(address)
        }
        Rule::protosuffix => {
            // pest ensures a slash at the start -> empty first element in iterator
            let proto = Protocol::try_from(r.as_str().split("/").next().unwrap_or("")).context("Rule::protosuffix");

            Element::Protocol(proto)
        }
        Rule::portp => {
            let s = r.as_str();
            let res = parse_portp(s.split("/")).map_err(|e| anyhow::Error::from(e).context(format!("Rule::portp {}", s)));

            Element::PortProtocol(res)
        }
        Rule::proto => {
            let proto = Protocol::try_from(r.as_str()).map_err(|e| anyhow::Error::from(e).context(format!("Rule::proto {:?}", r)));

            Element::Protocol(proto)
        }
        Rule::portsuffpr => {
            let s = r.as_str();
            let mut split = s.split("/");
            split.next(); // pest makes sure that the portsuffpr starts with a string -> empty first v

            let res = parse_portp(split).map_err(|e| anyhow::Error::from(e).context(format!("Rule::portsuffpr {}", s)));

            Element::PortProtocol(res)
        }
        Rule::tofrom => {
            let inner = r.into_inner();
            Element::ToFrom(inner.map(parse_line).collect())
        }
        Rule::port => {
            let port = r.as_str().parse::<u16>().map_err(|e| anyhow::Error::from(e).context(format!("Rule::port {:?}", r)));

            Element::Port(port)
        }
        Rule::device => {
            let device = r.as_str();

            Element::Device(device.to_string())
        }
        Rule::ondevice => {
            let mut split = r.as_str().split_whitespace();
            split.next();

            let device = split.next().unwrap();
            Element::Device(device.to_string())
        }
        Rule::v6 => {
            Element::V6
        }
        Rule::action => {
            let mut i = r.into_inner();
            let m = i.next().unwrap().as_str();
            let d = i.next().and_then(|s| Some(s.as_str()));
            let modifier = Modifier::try_from(m).map_err(|e| anyhow::Error::from(e).context(format!("Rule::action: {}", m)));
            let direction = Direction::try_from(d).map_err(|e| anyhow::Error::from(e).context(format!("Rule::action: {:?}", d)));

            Element::Action(modifier, direction)
        }
        Rule::modifier => {
            let s = r.as_str();
            Element::Modifier(Modifier::try_from(s).context(format!("Rule::modifier: {}", s)))
        }
        Rule::direction => {
            let s = r.as_str();
            Element::Direction(Direction::try_from(Some(s)).context(format!("Rule::direction: {}", s)))
        }
        Rule::cidr => {
            let s = r.as_str();
            Element::CIDR(parse_cidr(s).context(format!("Rule::cidr: {}", s)))
        }
        Rule::cidrprot => {
            let mut inner = r.into_inner();
            let cidr = inner.next().context("cidr must be there in cidrproto").and_then(|x| x.as_str().parse::<u8>().map_err(|e| anyhow::Error::from(e)));
            let proto = Protocol::try_from(inner.next().unwrap().as_str()).map_err(|e| anyhow::Error::from(e));

            Element::CIDRProto(cidr, proto)
        }
        Rule::line => unimplemented!("can't parse another line in `parse_line`"),
        Rule::hex => unimplemented!("can't parse hex in `parse_line`"),
        Rule::ipv6_address => unimplemented!("can't parse another ipv6_address in `parse_line`"),
        Rule::EOI => {
            Element::END
        }
    }
}
