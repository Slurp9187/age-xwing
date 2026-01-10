use age_recipient_pq::HybridRecipient;
use secrecy::ExposeSecret;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Generating X-Wing keypair...");
    let (recipient, identity) = HybridRecipient::generate()?;

    println!("Writing recipient to examples/pq-recipient.key");
    fs::write("examples/pq-recipient.key", recipient.to_string())?;

    println!("Writing identity to examples/pq-identity.key");
    fs::write(
        "examples/pq-identity.key",
        identity.to_string().expose_secret(),
    )?;

    println!("Keypair generated successfully.");
    Ok(())
}
