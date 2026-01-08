/// # age-recipient-pq
///
/// This crate implements a post-quantum hybrid recipient and identity for the [`age`] encryption
/// tool, designed for potential integration into the official `rage` CLI and libraries.
///
/// ## Overview
///
/// The age encryption format supports pluggable recipients and identities for different
/// cryptographic primitives. This crate provides an [`HybridRecipient`] and [`HybridIdentity`]
/// that combine post-quantum key encapsulation mechanisms (ML-KEM-768) with traditional
/// elliptic-curve cryptography (X25519) for enhanced security against quantum attacks.
///
/// The implementation is based on the pq-xwing-hpke crate, which provides HPKE (Hybrid Public Key
/// Encryption) primitives, and uses the same cryptographic parameters as the age-go plugin for
/// compatibility.
///
/// ## Security
///
/// - **Post-Quantum Security**: Leverages ML-KEM-768 (formerly Kyber-768), a lattice-based KEM
///   standardized by NIST, to resist attacks from large-scale quantum computers.
/// - **Hybrid Design**: Combines PQ security with X25519 for efficiency and backward compatibility.
/// - **Zeroization**: Sensitive secrets (like private keys) are wrapped in `SecretBox` from the
///   `secrecy` crate, ensuring they are zeroized when dropped.
/// - **Secret Management**: Uses `secrecy` for compatibility with the `age` ecosystem, where
///   secrets are exposed only when necessary and zeroized promptly.
///
/// ## Compatibility
///
/// - **Age Format**: Fully compatible with the age file format and stanza structure.
/// - **Rage Integration**: Designed to align with Rage's use of `secrecy` for secret handling,
///   avoiding external dependencies like `secure-gate` to maximize adoption chances.
/// - **Legacy Support**: Supports both new and legacy stanza formats for backward compatibility
///   with older PQ implementations.
///
/// ## Usage
///
/// ```rust,no_run
/// use age_recipient_pq::{HybridRecipient, HybridIdentity};
/// use age::secrecy::ExposeSecret;
/// use std::str::FromStr;
/// // Generate a new recipient and identity pair
/// let (recipient, identity) = HybridRecipient::generate().unwrap();
///
/// // Serialize to strings for storage
/// let recipient_str = recipient.to_string();
/// let secret_str = identity.to_string();
/// let identity_str = secret_str.expose_secret().clone();
///
/// // Parse back
/// let recipient = HybridRecipient::from_str(&recipient_str).unwrap();
/// let identity = HybridIdentity::from_str(&identity_str).unwrap();
/// ```
///
/// See the documentation for [`HybridRecipient`] and [`HybridIdentity`] for more details.
///
/// [`age`]: https://docs.rs/age/
/// [`rage`]: https://github.com/str4d/rage
///
/// ## Post-Quantum Module
///
/// This module contains the core implementation of the hybrid post-quantum recipient and identity.
pub mod pq;

/// Re-exports the main types for convenience.
///
/// This allows users to import `HybridRecipient` and `HybridIdentity` directly from the crate root.
pub use pq::{HybridIdentity, HybridRecipient};
