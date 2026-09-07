//! The red genome's deterministic pseudo-random source (OPFOR-03).
//!
//! An adversary the blue detectors are scored against has to be reproducible: a
//! plan must replay to the same bytes on any machine, in any process, at any
//! time, or a regression cannot be told from noise. So the red lane draws from
//! this generator and this generator alone, and the generator has no path to
//! operating-system entropy or the wall clock -- it is constructed only from an
//! explicit seed, and `no_entropy_path_exists_in_the_red_lane` fails the build
//! if any forbidden source appears in the module tree.
//!
//! The algorithm is xoshiro256** seeded through SplitMix64, both public-domain
//! generators by Blackman and Vigna. SplitMix64 expands a 64-bit seed into the
//! 256-bit xoshiro state (the reference implementation recommends exactly this),
//! and xoshiro256** is the output generator. Constants and structure follow the
//! reference sources:
//!   - <https://prng.di.unimi.it/splitmix64.c>
//!   - <https://prng.di.unimi.it/xoshiro256starstar.c>
//!
//! Streams fork by label: `fork` mixes the parent's next draw with the FNV-1a
//! hash of a label, so each operator gets an independent stream and one
//! operator's draws never perturb another's.

use rand_core::{RngCore, SeedableRng};

/// SplitMix64, used only to expand a 64-bit seed into xoshiro256**'s 256-bit
/// state. It is a full generator in its own right, but the red lane wants
/// xoshiro256**'s statistical quality for its draws and SplitMix64 purely for
/// seeding, which is the split the reference sources recommend.
///
/// Reference: <https://prng.di.unimi.it/splitmix64.c>.
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// 64-bit rotate left, xoshiro256**'s only non-trivial word operation.
#[inline]
fn rotl(x: u64, k: u32) -> u64 {
    x.rotate_left(k)
}

/// FNV-1a over a label's bytes, used to give each forked stream a distinct,
/// order-independent identity. 64-bit offset basis and prime from the reference
/// (<http://www.isthe.com/chongo/tech/comp/fnv/>).
fn fnv1a_64(label: &str) -> u64 {
    let mut hash = 0xCBF2_9CE4_8422_2325;
    for byte in label.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

/// The red genome's deterministic PRNG (OPFOR-03): xoshiro256** seeded through
/// SplitMix64, with no path to OS entropy or the wall clock.
///
/// It implements [`rand_core::RngCore`] and [`rand_core::SeedableRng`] so it
/// composes with code written against those traits, but it exposes no
/// entropy-seeded constructor of its own: it is built only from an explicit
/// `u64` seed ([`RedGenomeRng::from_u64`]) or a 32-byte seed
/// ([`SeedableRng::from_seed`]). There is deliberately no `Default` and no
/// `new()` without a seed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedGenomeRng {
    state: [u64; 4],
}

impl RedGenomeRng {
    /// Seed the generator from a 64-bit value, expanding it into the full
    /// 256-bit xoshiro256** state through SplitMix64 as the reference source
    /// recommends. Every distinct seed gives a distinct, reproducible stream.
    pub fn from_u64(seed: u64) -> Self {
        let mut expander = SplitMix64::new(seed);
        Self {
            state: [
                expander.next(),
                expander.next(),
                expander.next(),
                expander.next(),
            ],
        }
    }

    /// Derive a child stream identified by `label`.
    ///
    /// The child is seeded from the parent's next draw XORed with the FNV-1a
    /// hash of the label, so two forks of the same parent state with different
    /// labels diverge, and each operator that forks with its own label gets a
    /// stream independent of every other. Forking advances the parent by one
    /// draw; drawing from the child never touches the parent again.
    pub fn fork(&mut self, label: &str) -> Self {
        let draw = self.next_u64();
        Self::from_u64(draw ^ fnv1a_64(label))
    }

    /// A uniform draw in `0..n`, unbiased by rejection sampling.
    ///
    /// The modulo of a raw 64-bit draw is biased toward the low residues; this
    /// rejects the small band of values that would cause that bias, so every
    /// value in range is equally likely. `n == 0` names an empty range and
    /// yields `0` rather than dividing by zero -- there is no in-range value to
    /// return, and the runtime contract forbids a panic.
    pub fn next_below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        // The number of low values to reject so the accepted band is an exact
        // multiple of `n`: `2^64 mod n`, computed without a 128-bit type.
        let reject = n.wrapping_neg() % n;
        loop {
            let draw = self.next_u64();
            if draw >= reject {
                return draw % n;
            }
        }
    }

    /// Choose one element uniformly, or `None` when the slice is empty.
    pub fn choose<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            return None;
        }
        let index = self.next_below(items.len() as u64) as usize;
        items.get(index)
    }
}

impl RngCore for RedGenomeRng {
    fn next_u64(&mut self) -> u64 {
        // xoshiro256** (<https://prng.di.unimi.it/xoshiro256starstar.c>).
        let s = &mut self.state;
        let result = rotl(s[1].wrapping_mul(5), 7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = rotl(s[3], 45);
        result
    }

    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_core::impls::fill_bytes_via_next(self, dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl SeedableRng for RedGenomeRng {
    type Seed = [u8; 32];

    /// Read the 32-byte seed as four little-endian words used directly as the
    /// xoshiro256** state. xoshiro256** must not be seeded all-zero (it would
    /// then only ever emit zero), so an all-zero seed falls back to the
    /// SplitMix64 expansion of zero, keeping every seed valid.
    fn from_seed(seed: Self::Seed) -> Self {
        let mut state = [0u64; 4];
        for (word, chunk) in state.iter_mut().zip(seed.chunks_exact(8)) {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(chunk);
            *word = u64::from_le_bytes(bytes);
        }
        if state == [0, 0, 0, 0] {
            return Self::from_u64(0);
        }
        Self { state }
    }

    /// Seed from a 64-bit value the same way [`RedGenomeRng::from_u64`] does, so
    /// the two entry points agree and neither reaches for entropy.
    fn seed_from_u64(state: u64) -> Self {
        Self::from_u64(state)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{RedGenomeRng, SplitMix64, fnv1a_64};
    use rand_core::{RngCore, SeedableRng};
    use std::path::{Path, PathBuf};

    fn state_seed(words: [u64; 4]) -> [u8; 32] {
        let mut seed = [0u8; 32];
        for (i, word) in words.iter().enumerate() {
            seed[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
        }
        seed
    }

    #[test]
    fn the_prng_matches_the_reference_vectors() {
        // SplitMix64, seed 0 -- the published vector from the reference
        // implementation (prng.di.unimi.it/splitmix64.c).
        let mut sm = SplitMix64::new(0);
        assert_eq!(sm.next(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(sm.next(), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(sm.next(), 0x06C4_5D18_8009_454F);
        assert_eq!(sm.next(), 0xF88B_B8A8_724C_81EC);

        // SplitMix64, seed 1.
        let mut sm = SplitMix64::new(1);
        assert_eq!(sm.next(), 0x910A_2DEC_8902_5CC1);
        assert_eq!(sm.next(), 0xBEEB_8DA1_658E_EC67);

        // xoshiro256**, from the known state [1, 2, 3, 4] -- vectors computed by
        // hand from the reference algorithm (prng.di.unimi.it/xoshiro256starstar.c)
        // and pinned. `from_seed` reads the four little-endian words as the
        // state directly, so this exercises xoshiro256** in isolation.
        let mut rng = RedGenomeRng::from_seed(state_seed([1, 2, 3, 4]));
        assert_eq!(rng.next_u64(), 0x0000_0000_0000_2D00);
        assert_eq!(rng.next_u64(), 0x0000_0000_0000_0000);
        assert_eq!(rng.next_u64(), 0x0000_0000_5A00_7080);
        assert_eq!(rng.next_u64(), 0x10E0_0000_0000_9D80);

        // The full SplitMix64 -> xoshiro256** path, `from_u64(0)`.
        let mut rng = RedGenomeRng::from_u64(0);
        assert_eq!(rng.next_u64(), 0x99EC_5F36_CB75_F2B4);
        assert_eq!(rng.next_u64(), 0xBF6E_1F78_4956_452A);
    }

    #[test]
    fn two_rngs_from_one_seed_agree_and_a_fork_diverges_without_disturbing_the_parent() {
        const SEED: u64 = 0x5EED;

        // The same seed yields the same stream.
        let mut a = RedGenomeRng::from_u64(SEED);
        let mut b = RedGenomeRng::from_u64(SEED);
        for _ in 0..8 {
            assert_eq!(a.next_u64(), b.next_u64());
        }

        // Forking consumes one draw from the parent, so a forked parent diverges
        // from an unforked twin.
        let mut forked = RedGenomeRng::from_u64(SEED);
        let mut unforked = RedGenomeRng::from_u64(SEED);
        let _child = forked.fork("recon");
        assert_ne!(forked.next_u64(), unforked.next_u64());

        // The parent's post-fork stream is deterministic: seed and fork the same
        // way and it reproduces byte for byte.
        let mut p1 = RedGenomeRng::from_u64(SEED);
        let _ = p1.fork("recon");
        let mut p2 = RedGenomeRng::from_u64(SEED);
        let _ = p2.fork("recon");
        for _ in 0..8 {
            assert_eq!(p1.next_u64(), p2.next_u64());
        }

        // The child stream is reproducible.
        let mut pa = RedGenomeRng::from_u64(SEED);
        let mut ca = pa.fork("recon");
        let mut pb = RedGenomeRng::from_u64(SEED);
        let mut cb = pb.fork("recon");
        for _ in 0..8 {
            assert_eq!(ca.next_u64(), cb.next_u64());
        }

        // Draining the child does not disturb the parent's own stream.
        let mut pc = RedGenomeRng::from_u64(SEED);
        let mut cc = pc.fork("recon");
        for _ in 0..128 {
            let _ = cc.next_u64();
        }
        let mut pd = RedGenomeRng::from_u64(SEED);
        let _cd = pd.fork("recon");
        for _ in 0..8 {
            assert_eq!(pc.next_u64(), pd.next_u64());
        }

        // A different fork label yields a different child stream.
        let mut pe = RedGenomeRng::from_u64(SEED);
        let mut recon_child = pe.fork("recon");
        let mut pf = RedGenomeRng::from_u64(SEED);
        let mut inject_child = pf.fork("injection");
        assert_ne!(recon_child.next_u64(), inject_child.next_u64());

        // FNV-1a of the empty label is the published offset basis.
        assert_eq!(fnv1a_64(""), 0xCBF2_9CE4_8422_2325);
    }

    #[test]
    fn next_below_is_unbiased_enough_and_never_out_of_range() {
        let mut rng = RedGenomeRng::from_u64(0xA11CE);
        let n: u64 = 7;
        let draws: usize = 100_000;
        let mut buckets = [0usize; 7];
        for _ in 0..draws {
            let value = rng.next_below(n);
            assert!(value < n, "draw {value} is out of range");
            buckets[value as usize] += 1;
        }
        let expected = draws as f64 / n as f64;
        for (bucket, &count) in buckets.iter().enumerate() {
            let deviation = (count as f64 - expected).abs() / expected;
            assert!(
                deviation < 0.05,
                "bucket {bucket} deviated {deviation:.4} ({count} vs ~{expected:.0})"
            );
        }

        // An empty range yields zero and never panics.
        assert_eq!(rng.next_below(0), 0);

        // `choose` maps onto `next_below`: always in range, `None` when empty.
        let items = ['a', 'b', 'c', 'd'];
        for _ in 0..1_000 {
            let picked = rng.choose(&items).unwrap();
            assert!(items.contains(picked));
        }
        let empty: [char; 0] = [];
        assert!(rng.choose(&empty).is_none());
    }

    fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    fn strip_comments(source: &str) -> String {
        let mut out = String::with_capacity(source.len());
        let mut chars = source.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '/' && chars.peek() == Some(&'/') {
                for n in chars.by_ref() {
                    if n == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            } else if c == '/' && chars.peek() == Some(&'*') {
                chars.next();
                let mut prev = ' ';
                for n in chars.by_ref() {
                    if prev == '*' && n == '/' {
                        break;
                    }
                    prev = n;
                }
                out.push(' ');
            } else {
                out.push(c);
            }
        }
        out
    }

    /// Production code only: comments stripped, and everything from the first
    /// `#[cfg(test)]` gate onward removed. Every file in this module keeps its
    /// tests in a single trailing `#[cfg(test)] mod tests`, so that cut isolates
    /// the production text exactly.
    fn production_code(source: &str) -> String {
        let without_comments = strip_comments(source);
        match without_comments.find("#[cfg(test)]") {
            Some(idx) => without_comments[..idx].to_string(),
            None => without_comments,
        }
    }

    #[test]
    fn no_entropy_path_exists_in_the_red_lane() {
        let red_swarm_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/red_swarm");
        let forbidden = [
            "getrandom",
            "OsRng",
            "thread_rng",
            "SystemTime",
            "Instant::now",
            "Utc::now",
            "Local::now",
        ];

        let mut files = Vec::new();
        collect_rs_files(&red_swarm_dir, &mut files);
        assert!(
            files.len() >= 3,
            "expected mod.rs, graph.rs and rng.rs under {}",
            red_swarm_dir.display()
        );

        for file in files {
            let source = std::fs::read_to_string(&file).unwrap();
            let production = production_code(&source);
            for needle in forbidden {
                assert!(
                    !production.contains(needle),
                    "forbidden entropy identifier `{needle}` in production code of {}",
                    file.display()
                );
            }
        }
    }
}
