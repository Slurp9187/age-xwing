//! Interoperability tests for age-xwing with age-go's post-quantum implementation.
//!
//! These tests verify:
//! - Key generation and serialization match age-go formats.
//! - Encryption/decryption roundtrips work.
//! - Decryption of hardcoded age-go generated PQ-encrypted data succeeds.
//! - Error handling for invalid cases.
//! - Label enforcement prevents mixing with non-PQ recipients.
//!
//! Note: For full interop, run these alongside age-go binaries or use real files from age-go/testdata.
//! Hardcoded vectors here are illustrative; replace with actual age-go outputs for production testing.

use age::{Decryptor, Encryptor};
use age_core::format::{FileKey, Stanza};
use age_xwing::pq::{HybridIdentity, HybridRecipient};
use std::io::{Read, Write};

#[test]
fn test_key_generation_and_serialization() {
    let (recipient, identity) = HybridRecipient::generate();

    let pub_str = recipient.to_string();
    assert!(pub_str.starts_with("age1pq"));
    assert!(pub_str.len() > 100); // Long PQ keys

    let priv_str = identity.to_string();
    assert!(priv_str.starts_with("AGE-SECRET-KEY-PQ-1"));
    assert!(priv_str.len() > 50);

    // Parse back
    let parsed_recipient = HybridRecipient::parse(&pub_str).unwrap();
    assert_eq!(
        recipient.pub_key.to_bytes(),
        parsed_recipient.pub_key.to_bytes()
    );

    let parsed_identity = HybridIdentity::parse(&priv_str).unwrap();
    assert_eq!(
        identity.secret_key.expose_secret(),
        parsed_identity.secret_key.expose_secret()
    );
}

#[test]
fn test_encryption_decryption_roundtrip() {
    let (recipient, identity) = HybridRecipient::generate();
    let plaintext = b"Hello, post-quantum world!";

    // Encrypt
    let encryptor = Encryptor::with_recipient(Box::new(recipient)).unwrap();
    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();

    // Decrypt
    let decryptor = Decryptor::new(&encrypted[..]).unwrap();
    let mut reader = decryptor.decrypt(Box::new(identity)).unwrap();
    let mut decrypted = Vec::new();
    reader.read_to_end(&mut decrypted).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_decrypt_age_go_generated_data() {
    // Hardcoded example: Replace with actual age-go generated values.
    // Assume this is a stanza from age-go encrypting file_key [1,2,3,...,16] to a known PQ identity.
    // In practice, extract from age-go/testdata or generate via age-go CLI.
    let known_file_key: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let known_priv =
        "AGE-SECRET-KEY-PQ-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ"; // Placeholder; use real
    let stanza = Stanza {
        tag: "mlkem768x25519".to_string(),
        args: vec!["base64_encoded_ciphertext_from_age_go".to_string()], // Placeholder base64
        body: vec![/* encrypted file key bytes from age-go */],
    };

    let identity = HybridIdentity::parse(known_priv).unwrap();

    // Simulate unwrap (as in age Decryptor)
    if let Some(result) = identity.unwrap_stanzas(&[stanza]) {
        let decrypted_key = result.unwrap();
        assert_eq!(decrypted_key.as_ref(), &known_file_key);
    } else {
        panic!("Failed to unwrap age-go stanza");
    }
}

#[test]
fn test_invalid_stanza_no_match() {
    let (_, identity) = HybridRecipient::generate();
    let invalid_stanza = Stanza {
        tag: "invalid_tag".to_string(),
        args: vec![],
        body: vec![],
    };

    let result = identity.unwrap_stanzas(&[invalid_stanza]);
    assert!(result.is_none()); // Should not match
}

#[test]
fn test_malformed_ciphertext() {
    let (_, identity) = HybridRecipient::generate();
    let malformed_stanza = Stanza {
        tag: "mlkem768x25519".to_string(),
        args: vec!["invalid_base64".to_string()],
        body: vec![0; 32],
    };

    let result = identity.unwrap_stanzas(&[malformed_stanza]);
    assert!(result.is_none()); // Should fail gracefully
}

#[test]
fn test_label_enforcement_prevents_mixing() {
    let (pq_recipient, _) = HybridRecipient::generate();
    let non_pq_recipient = age::x25519::Recipient::generate(); // Assuming x25519 from age

    // Try mixing PQ and non-PQ
    let encryptor =
        Encryptor::with_recipients(vec![Box::new(pq_recipient), Box::new(non_pq_recipient)]);

    // Should fail due to label mismatch ("postquantum" vs none)
    assert!(encryptor.is_err());
}

#[test]
fn test_multiple_pq_recipients() {
    let (recipient1, identity1) = HybridRecipient::generate();
    let (recipient2, identity2) = HybridRecipient::generate();
    let plaintext = b"Multi-recipient test";

    // Encrypt to both
    let encryptor = Encryptor::with_recipient(Box::new(recipient1))
        .add_recipient(Box::new(recipient2))
        .unwrap();
    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();

    // Decrypt with first identity
    let decryptor = Decryptor::new(&encrypted[..]).unwrap();
    let mut reader = decryptor.decrypt(Box::new(identity1)).unwrap();
    let mut decrypted = Vec::new();
    reader.read_to_end(&mut decrypted).unwrap();
    assert_eq!(decrypted, plaintext);

    // Decrypt with second identity
    let decryptor = Decryptor::new(&encrypted[..]).unwrap();
    let mut reader = decryptor.decrypt(Box::new(identity2)).unwrap();
    let mut decrypted = Vec::new();
    reader.read_to_end(&mut decrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}
