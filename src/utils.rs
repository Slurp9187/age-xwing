use chacha20poly1305::aead::rand_core;
// use rand_core::TryRngCore;
use rand_core::{CryptoRng, Error, OsRng, RngCore};
// use std::convert::Infallible; // For completeness, though not strictly needed

#[derive(Debug, Clone, Copy)]
pub struct InfallibleOsRng(OsRng);

impl RngCore for InfallibleOsRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0
            .try_fill_bytes(dest)
            .unwrap_or_else(|e| panic!("OsRng failed: {e}"));
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for InfallibleOsRng {}
