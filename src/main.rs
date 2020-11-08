extern crate toml;
extern crate ufw_auto_block;

use ufw_auto_block::ParseResult;

fn main() -> ParseResult<()> {
    // let x: Option<&str> = None;
    // ufw_auto_block::parse_applications(x)
    //     .iter()
    //     .for_each(|x|
    //         println!("{:#?}", x));

    // println!("{:#?}", ufw_auto_block::UfwCommand::new().numbered_output());
    ufw_auto_block::UfwCommand::new().numbered_output();
    Ok(())
}
