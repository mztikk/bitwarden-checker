use std::{fs, path::PathBuf};

use bitwarden_data::Export;
use structopt::StructOpt;

#[derive(StructOpt)]
struct Cli {
    /// Input file
    #[structopt(parse(from_os_str))]
    input: PathBuf,
}
struct BitwardenItem {
    name: String,
    username: String,
    password: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::from_args();

    let bitwarden_json = fs::read_to_string(&cli.input).expect("Failed to read input file");

    let bitwarden_data: Export =
        serde_json::from_str(&bitwarden_json).expect("Failed to parse JSON");

    let client = reqwest::Client::builder().brotli(true).gzip(true).build()?;
    for item in bitwarden_data.items.iter().filter_map(|x| match &x.login {
        Some(login) => match (&login.username, &login.password) {
            (Some(username), Some(password)) => Some(BitwardenItem {
                name: x.name.clone(),
                username: username.clone(),
                password: password.clone(),
            }),
            _ => None,
        },
        _ => None,
    }) {
        let password_breach_count =
            haveibeenrusted::get_password_count(&client, &item.password).await?;
        if password_breach_count == 0 {
            continue;
        }

        println!(
            "Password of user \"{}\" on \"{}\" has {} breaches.",
            &item.username, item.name, password_breach_count
        );
    }

    Ok(())
}
