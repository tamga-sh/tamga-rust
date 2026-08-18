//! Checks out an encrypted `.lic` file and verifies it fully offline (no
//! further network access past the initial checkout call).
//!
//! ```bash
//! TAMGA_ACCOUNT_ID=... TAMGA_HOST=api.tamga.sh TAMGA_LICENSE_ID=... \
//!     TAMGA_LICENSE_KEY=... TAMGA_ED25519_PUBKEY_B64=... \
//!     cargo run --example verify_license_file
//! ```
//!
//! `TAMGA_ED25519_PUBKEY_B64` is your account's public Ed25519 key
//! (base64), used to verify the checkout signature completely offline —
//! this is the core value proposition of this SDK over hand-rolling HTTP
//! calls.

use tamga::checkout::license_file::verify_license_file;
use tamga::crypto::ed25519::public_key_from_base64;
use tamga::transport::AuthTransport;
use tamga::{Client, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let account_id = std::env::var("TAMGA_ACCOUNT_ID")?;
    let host = std::env::var("TAMGA_HOST").unwrap_or_else(|_| "api.tamga.sh".to_string());
    let license_id: uuid::Uuid = std::env::var("TAMGA_LICENSE_ID")?.parse()?;
    let license_key = std::env::var("TAMGA_LICENSE_KEY")?;
    let pubkey = public_key_from_base64(&std::env::var("TAMGA_ED25519_PUBKEY_B64")?)?;

    let config = ClientConfig::builder(account_id, host)
        .auth(AuthTransport::License(license_key.clone()))
        .build();
    let client = Client::new(config)?;

    // Check out an encrypted, 1-hour-metadata-TTL license file.
    let pem = client
        .check_out_license(license_id, /* encrypt */ true, Some(3600))
        .await?;

    // --- Everything below this point requires no network access at all. ---

    let license = verify_license_file(&pem, &pubkey, Some(&license_key))?;
    println!(
        "verified offline: license {} (key: {:?}, status: {})",
        license.id, license.attributes.key, license.attributes.status
    );

    // The `ttl`/`expiry` fields on the JSON:API checkout envelope are
    // metadata only and must not be trusted — whoever holds the file can
    // edit them. The authoritative expiry is the signed `meta.exp` claim
    // inside the certificate, which `verify_license_file` enforces (60s
    // clock-skew tolerance); an expired file fails with
    // `CheckoutError::Expired`. Use `verify_license_file_at` to supply a
    // server-derived timestamp instead of trusting the local clock.
    println!("expiry was enforced from the file's signed `exp` claim");

    Ok(())
}
