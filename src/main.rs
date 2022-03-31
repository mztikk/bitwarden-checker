use bitwarden_data::{Export, Item};
use haveibeenrusted::Hibr;
use std::{fs, path::PathBuf};
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

impl TryFrom<Item> for BitwardenItem {
    type Error = ();
    fn try_from(item: Item) -> Result<Self, Self::Error> {
        if let Some(login) = item.login {
            if let (Some(username), Some(password)) = (login.username, login.password) {
                return Ok(BitwardenItem {
                    name: item.name,
                    username,
                    password,
                });
            }
        }

        Err(())
    }
}

struct BreachedItem {
    name: String,
    username: String,
    password: String,
    breaches: u32,
}

async fn get_breached_item(
    hibr: &Hibr,
    bitwarden_item: BitwardenItem,
) -> reqwest::Result<BreachedItem> {
    match hibr.get_password_count(&bitwarden_item.password).await {
        Ok(count) => Ok(BreachedItem {
            name: bitwarden_item.name,
            username: bitwarden_item.username,
            password: bitwarden_item.password,
            breaches: count,
        }),
        Err(err) => Err(err),
    }
}

impl BreachedItem {
    fn print_info(&self) {
        println!(
            "Password of user \"{}\" on \"{}\" has {} breaches.",
            self.username, self.name, self.breaches
        );
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::from_args();

    let bitwarden_json = fs::read_to_string(&cli.input).expect("Failed to read input file");
    let bitwarden_data: Export =
        serde_json::from_str(&bitwarden_json).expect("Failed to parse JSON");

    let client = reqwest::Client::builder().brotli(true).gzip(true).build()?;
    let hibr = Hibr::new(client);

    for item in bitwarden_data
        .items
        .into_iter()
        .flat_map(|x| -> Result<BitwardenItem, _> { x.try_into() })
        .map(|x| get_breached_item(&hibr, x))
    {
        let breached_item = item.await?;

        if breached_item.breaches > 0 {
            breached_item.print_info();
        }
    }

    Ok(())
}
