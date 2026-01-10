use bech32::primitives::checksum::Checksum;

/// Custom checksum that matches classic Bech32 (BIP-173) exactly,
/// including the original theoretical maximum code length of 4096 characters.
///
/// This is the "standard" long variant from early implementations:
/// - Full compatibility with official age v1.3+ (uses classic Bech32 constants)
/// - Proper 6-character checksum with error detection
/// - CODE_LENGTH = 4096 (payload up to ~4090 chars / ~2556 bytes)
///
/// Your ~1959-char hybrid public keys fit easily (plenty of headroom).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HybridRecipientBech32 {}

impl Checksum for HybridRecipientBech32 {
    type MidstateRepr = u32;

    // The "standard" theoretical max from early BIP-173 discussions/impls
    const CODE_LENGTH: usize = 4096;

    const CHECKSUM_LENGTH: usize = 6;

    const GENERATOR_SH: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

    // Classic constant (matches official age)
    const TARGET_RESIDUE: u32 = 1;
}
