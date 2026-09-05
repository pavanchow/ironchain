//! Deterministic pseudo-random generator, no external crates.
//!
//! This is a `SplitMix64` generator. It is used only for test data and for the
//! demo. Wallet key material is derived from SHA-256, not from this generator.

/// A small deterministic PRNG (`SplitMix64`).
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        // Golden-gamma and mixing constants are transcribed verbatim from the
        // SplitMix64 reference, so no digit separators.
        #[allow(clippy::unreadable_literal)]
        const GOLDEN_GAMMA: u64 = 0x9e3779b97f4a7c15;
        #[allow(clippy::unreadable_literal)]
        const MIX1: u64 = 0xbf58476d1ce4e5b9;
        #[allow(clippy::unreadable_literal)]
        const MIX2: u64 = 0x94d049bb133111eb;
        self.state = self.state.wrapping_add(GOLDEN_GAMMA);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(MIX1);
        z = (z ^ (z >> 27)).wrapping_mul(MIX2);
        z ^ (z >> 31)
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Uniform-ish value in `0..bound`. Bound must be non-zero.
    pub fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&bytes[..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_differ() {
        let mut a = Rng::new(1);
        let mut b = Rng::new(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }
}
