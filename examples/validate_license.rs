//! Validates a license by key against a running Tamga server and interprets
//! the resulting `ValidationCode`.
//!
//! ```bash
//! TAMGA_ACCOUNT_ID=... TAMGA_HOST=api.tamga.sh TAMGA_LICENSE_KEY=... \
//!     cargo run --example validate_license
//! ```

use tamga::models::validation::ValidationCode;
use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let account_id = std::env::var("TAMGA_ACCOUNT_ID")?;
    let host = std::env::var("TAMGA_HOST").unwrap_or_else(|_| "api.tamga.sh".to_string());
    let license_key = std::env::var("TAMGA_LICENSE_KEY")?;

    // `AuthTransport::License` is the primary transport for embedded/client
    // SDKs validating against a raw license key — see the `tamga::transport`
    // module docs for the other three.
    let config = ClientConfig::builder(account_id, host)
        .auth(AuthTransport::License(license_key.clone()))
        .build();
    let client = Client::new(config)?;

    let result = client.validate_by_key(&license_key, None).await?;

    // Only 16 of the 24 modeled ValidationCode variants are reachable
    // today — see the enum's own doc comment for the full ✅/⛔ breakdown.
    // The catch-all arm below therefore has to stay: it absorbs both the
    // 8 unreachable codes and any future server-side addition, which
    // deserializes to `ValidationCode::Unknown`.
    match result.meta.code {
        ValidationCode::Valid => {
            println!("✅ license is valid");
        }
        ValidationCode::Suspended => println!("❌ license is suspended"),
        ValidationCode::Expired => println!("❌ license has expired"),
        ValidationCode::Overdue => println!("❌ license is overdue for check-in"),
        ValidationCode::TooManyMachines
        | ValidationCode::TooManyCores
        | ValidationCode::TooMuchMemory
        | ValidationCode::TooMuchDisk
        | ValidationCode::TooManyProcesses => {
            println!(
                "❌ license is over a resource limit: {:?}",
                result.meta.code
            );
        }
        ValidationCode::TooManyUses => println!("❌ license has reached its use limit"),
        other => println!(
            "❌ license is not valid: {other:?} ({})",
            result.meta.detail
        ),
    }

    println!("server detail: {}", result.meta.detail);
    Ok(())
}
