extern crate toml;
extern crate ufw_auto_block;

use regex::Regex;

use ufw_auto_block::{parse, ParseResult};

fn main() -> ParseResult<()> {
    let x: Option<&str> = None;
    let applications = ufw_auto_block::parse_applications(x).unwrap();
    println!("{:#?}", applications.first());
    let regex = Regex::new(r"\[\s*(\d+)](.*)").unwrap();

    // let rule = "[ 5] 192.168.1.0/24 22/udp on tun0 ALLOW IN    192.168.1.0/24 22/udp";
    // println!("{}", rule);
    // println!("{:#?}", ufw_auto_block::parse(rule));
    // println!("{:#?}", ufw_auto_block::UfwCommand::new().info());
    // println!("{:#?}", ufw_auto_block::UfwCommand::new().version());
    Ok(())
}
