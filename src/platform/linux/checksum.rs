#![expect(
    unsafe_code,
    reason = "runtime-dispatched SIMD intrinsics require target-feature unsafe functions"
)]

use byteorder::{BigEndian, ByteOrder};

/// A pure Rust scalar (non-SIMD) implementation for the checksum accumulation.
///
/// It uses a simple loop instead of manual unrolling for better clarity and maintainability.
fn checksum_no_fold_scalar(mut b: &[u8], initial: u64) -> u64 {
    let mut accumulator = initial;

    // Process the slice in 4-byte (u32) chunks.
    while b.len() >= 4 {
        accumulator += u64::from(BigEndian::read_u32(&b[0..4]));
        b = &b[4..];
    }

    // Handle the remaining 1-3 bytes.
    if b.len() >= 2 {
        accumulator += u64::from(BigEndian::read_u16(&b[0..2]));
        b = &b[2..];
    }
    if let Some(&byte) = b.first() {
        // For odd-length inputs, the last byte is treated as the high byte
        // of a 16-bit word (e.g., [0xAB] becomes 0xAB00), as per RFC 1071.
        accumulator += u64::from(byte) << 8;
    }

    accumulator
}

/// A SIMD-accelerated (AVX2) implementation for the checksum accumulation.
///
/// # Safety
/// Caller must ensure this function is called only on CPUs that support AVX2.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
#[expect(
    clippy::cast_ptr_alignment,
    reason = "unaligned AVX2 load explicitly accepts an unaligned pointer"
)]
unsafe fn checksum_no_fold_avx2(mut b: &[u8], initial: u64) -> u64 {
    use std::arch::x86_64::{
        __m256i, _mm256_add_epi64, _mm256_cvtepu32_epi64, _mm256_extract_epi64,
        _mm256_extracti128_si256, _mm256_loadu_si256, _mm256_set_epi8, _mm256_setzero_si256,
        _mm256_shuffle_epi8,
    };

    const CHUNK_SIZE: usize = 32;
    let mut accumulator = initial; // AVX2 processes 32 bytes (256 bits) at a time.

    if b.len() >= CHUNK_SIZE {
        // Use a 256-bit vector to hold four 64-bit partial sums.
        let mut sums = _mm256_setzero_si256();

        // Shuffle mask to reverse byte order from Big Endian to Little Endian for each 32-bit integer.
        let shuffle_mask = _mm256_set_epi8(
            12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11, 4,
            5, 6, 7, 0, 1, 2, 3,
        );

        while b.len() >= CHUNK_SIZE {
            // Load 32 bytes of data.
            // SAFETY: the AVX2 caller contract is active and b.len() >= CHUNK_SIZE, so
            // the unaligned load reads exactly 32 initialized bytes from the slice.
            let data = unsafe { _mm256_loadu_si256(b.as_ptr().cast::<__m256i>()) };
            // Swap byte order from BE to LE.
            let swapped = _mm256_shuffle_epi8(data, shuffle_mask);

            // Widen the lower 4 u32s to u64s and add them to the accumulator.
            let lower_u64 = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(swapped, 0));
            sums = _mm256_add_epi64(sums, lower_u64);

            // Widen the upper 4 u32s to u64s and add them to the accumulator.
            let upper_u64 = _mm256_cvtepu32_epi64(_mm256_extracti128_si256(swapped, 1));
            sums = _mm256_add_epi64(sums, upper_u64);

            b = &b[CHUNK_SIZE..];
        }

        // Perform a horizontal sum to combine the partial sums in the vector.
        accumulator += u64::from_ne_bytes(_mm256_extract_epi64(sums, 0).to_ne_bytes());
        accumulator += u64::from_ne_bytes(_mm256_extract_epi64(sums, 1).to_ne_bytes());
        accumulator += u64::from_ne_bytes(_mm256_extract_epi64(sums, 2).to_ne_bytes());
        accumulator += u64::from_ne_bytes(_mm256_extract_epi64(sums, 3).to_ne_bytes());
    }

    // Process any remaining data using the scalar implementation.
    checksum_no_fold_scalar(b, accumulator)
}

/// A SIMD-accelerated (SSE4.1) implementation for the checksum accumulation.
///
/// # Safety
/// Caller must ensure this function is called only on CPUs that support SSE4.1.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.1")]
#[expect(
    clippy::cast_ptr_alignment,
    reason = "unaligned SSE load explicitly accepts an unaligned pointer"
)]
unsafe fn checksum_no_fold_sse41(mut b: &[u8], initial: u64) -> u64 {
    use std::arch::x86_64::{
        __m128i, _mm_add_epi64, _mm_bsrli_si128, _mm_cvtepu32_epi64, _mm_cvtsi128_si64,
        _mm_extract_epi64, _mm_loadu_si128, _mm_set_epi8, _mm_setzero_si128, _mm_shuffle_epi8,
    };

    const CHUNK_SIZE: usize = 16;
    let mut accumulator = initial; // SSE processes 16 bytes (128 bits) at a time.

    if b.len() >= CHUNK_SIZE {
        // Use a 128-bit vector to hold two 64-bit partial sums.
        let mut sums = _mm_setzero_si128();

        // Shuffle mask to reverse byte order from Big Endian to Little Endian for each 32-bit integer.
        let shuffle_mask = _mm_set_epi8(12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);

        while b.len() >= CHUNK_SIZE {
            // Load 16 bytes of data.
            // SAFETY: the SSE4.1 caller contract is active and b.len() >= CHUNK_SIZE, so
            // the unaligned load reads exactly 16 initialized bytes from the slice.
            let data = unsafe { _mm_loadu_si128(b.as_ptr().cast::<__m128i>()) };
            // Swap byte order from BE to LE.
            let swapped = _mm_shuffle_epi8(data, shuffle_mask);

            // Widen the lower 2 u32s to u64s and add them to the accumulator.
            let lower_u64 = _mm_cvtepu32_epi64(swapped);
            sums = _mm_add_epi64(sums, lower_u64);

            // Widen the upper 2 u32s to u64s and add them to the accumulator.
            let upper_u64 = _mm_cvtepu32_epi64(_mm_bsrli_si128(swapped, 8));
            sums = _mm_add_epi64(sums, upper_u64);

            b = &b[CHUNK_SIZE..];
        }

        // Horizontal sum of the two 64-bit lanes.
        accumulator += u64::from_ne_bytes(_mm_cvtsi128_si64(sums).to_ne_bytes());
        accumulator += u64::from_ne_bytes(_mm_extract_epi64(sums, 1).to_ne_bytes());
    }

    // Process any remaining data using the scalar implementation.
    checksum_no_fold_scalar(b, accumulator)
}

/// AVX2 fast path for a *final* Internet checksum.
///
/// Unlike `checksum_no_fold_avx2()`, this intentionally accumulates 16-bit
/// Internet-checksum words rather than preserving the raw u32-based no-fold
/// representation. That lets us use VPSADBW to sum the high and low bytes of
/// each network-order word independently, then combine them as
/// `(sum(high) << 8) + sum(low)`.
///
/// The result after one's-complement folding is identical, but the intermediate
/// accumulator is not part of the `checksum_no_fold()` contract and therefore
/// this implementation is only used by `checksum()`.
///
/// A single accumulator pair is fastest on the measured Zen 2 target.
/// The dispatch threshold stays conservative because short remainders can make
/// the setup cost dominate even when nearby lengths benefit.
///
/// # Safety
/// Caller must ensure AVX2 is available.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn checksum_folded_avx2(mut b: &[u8], initial: u64) -> u16 {
    use std::arch::x86_64::{
        _mm256_add_epi64, _mm256_and_si256, _mm256_extract_epi64, _mm256_loadu_si256,
        _mm256_sad_epu8, _mm256_set1_epi16, _mm256_setzero_si256, _mm256_slli_epi64,
        _mm256_srli_epi16,
    };

    let zero = _mm256_setzero_si256();
    let low_byte_mask = _mm256_set1_epi16(0x00ff);

    let mut even = zero;
    let mut odd = zero;

    while b.len() >= 32 {
        // SAFETY: this loop only runs with at least 32 bytes remaining, so the
        // unaligned 32-byte load is entirely within the initialized slice.
        let data = unsafe { _mm256_loadu_si256(b.as_ptr().cast()) };
        let low = _mm256_and_si256(data, low_byte_mask);
        let high = _mm256_srli_epi16(data, 8);

        even = _mm256_add_epi64(even, _mm256_sad_epu8(low, zero));
        odd = _mm256_add_epi64(odd, _mm256_sad_epu8(high, zero));

        b = &b[32..];
    }

    let sums = _mm256_add_epi64(_mm256_slli_epi64(even, 8), odd);

    let mut accumulator = initial;
    accumulator += u64::from_ne_bytes(_mm256_extract_epi64(sums, 0).to_ne_bytes());
    accumulator += u64::from_ne_bytes(_mm256_extract_epi64(sums, 1).to_ne_bytes());
    accumulator += u64::from_ne_bytes(_mm256_extract_epi64(sums, 2).to_ne_bytes());
    accumulator += u64::from_ne_bytes(_mm256_extract_epi64(sums, 3).to_ne_bytes());

    // The SIMD prefix ends on a 16-bit boundary, so the tail can be added
    // directly as network-order 16-bit words.
    while b.len() >= 2 {
        accumulator += u64::from(u16::from_be_bytes([b[0], b[1]]));
        b = &b[2..];
    }
    if let Some(&byte) = b.first() {
        accumulator += u64::from(byte) << 8;
    }

    while accumulator > 0xffff {
        accumulator = (accumulator >> 16) + (accumulator & 0xffff);
    }

    let folded = accumulator.to_be_bytes();
    u16::from_be_bytes([folded[6], folded[7]])
}

/// Calculates a checksum accumulator over a byte slice without the final fold.
///
/// This function dispatches to the optimal implementation at runtime (AVX2, SSE4.1,
/// or scalar) based on CPU feature detection. The algorithm is consistent with the
/// WireGuard-Go implementation: it treats the input as a sequence of big-endian u32s,
/// accumulates them as u64s, and handles the remainder.
#[inline]
#[must_use]
pub fn checksum_no_fold(b: &[u8], initial: u64) -> u64 {
    // Dispatch to the best available implementation based on runtime CPU feature detection.
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            // SAFETY: We have just checked that the CPU supports AVX2.
            return unsafe { checksum_no_fold_avx2(b, initial) };
        }
        if is_x86_feature_detected!("sse4.1") {
            // SAFETY: We have just checked that the CPU supports SSE4.1.
            return unsafe { checksum_no_fold_sse41(b, initial) };
        }
    }

    // TODO: AArch64 (ARM) NEON SIMD optimization could be added here.
    // #[cfg(target_arch = "aarch64")] { ... }

    // Fall back to the scalar implementation if no SIMD features are available.
    checksum_no_fold_scalar(b, initial)
}

/// Calculates the final 16-bit internet checksum.
///
/// This performs the standard one's complement sum fold-down of a 64-bit accumulator
/// into a 16-bit value. The loop ensures correctness regardless of the initial magnitude
/// of the accumulator.
#[must_use]
#[expect(
    clippy::cast_possible_truncation,
    reason = "the fold loop guarantees the accumulator is at most u16::MAX"
)]
pub fn checksum(b: &[u8], initial: u64) -> u16 {
    #[cfg(target_arch = "x86_64")]
    {
        // VPSADBW is substantially faster for packet-sized payloads, but
        // short inputs have remainder-dependent setup costs. Benchmarks show
        // 256 bytes is a conservative crossover with no sampled regressions.
        if b.len() >= 256 && is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 support was checked immediately above.
            return unsafe { checksum_folded_avx2(b, initial) };
        }
    }

    let mut accumulator = checksum_no_fold(b, initial);

    // Fold the 64-bit accumulator into 16 bits.
    while accumulator > 0xFFFF {
        accumulator = (accumulator >> 16) + (accumulator & 0xFFFF);
    }

    accumulator as u16
}

/// Calculates the checksum accumulator for a TCP/UDP pseudo-header.
///
/// This function also benefits from the `checksum_no_fold` optimizations.
#[must_use]
pub fn pseudo_header_checksum_no_fold(
    protocol: u8,
    src_addr: &[u8],
    dst_addr: &[u8],
    total_len: u16,
) -> u64 {
    // Accumulate the source and destination addresses.
    let sum = checksum_no_fold(src_addr, 0);
    let sum = checksum_no_fold(dst_addr, sum);

    // The pseudo-header trailer consists of {0, protocol, total_len}.
    // We construct this 4-byte sequence and add its checksum to the sum.
    let len_bytes = total_len.to_be_bytes();
    let trailer = [0, protocol, len_bytes[0], len_bytes[1]];
    checksum_no_fold(&trailer, sum)
}

#[cfg(test)]
mod tests {
    use rand::RngExt;
    // Assuming these paths are correct for your project structure
    use crate::platform::linux::checksum::{
        checksum_folded_avx2, checksum_no_fold_avx2, checksum_no_fold_scalar,
        checksum_no_fold_sse41,
    };

    #[test]
    fn test_checksum_avx2_vs_scalar_output() {
        // Only run this test on x86/x64 architectures if AVX2 feature is detected
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        if !is_x86_feature_detected!("avx2") {
            println!("AVX2 feature not detected. Skipping AVX2 checksum output comparison tests.");
            return;
        }

        // Initialize random number generator
        let mut rng = rand::rng(); // Changed from rand::rng() to rand::thread_rng() for correctness

        // Test data lengths, including boundary cases and lengths larger than CHUNK_SIZE
        let test_lengths = [31, 32, 33, 63, 64, 65, 100, 1024, 4096];
        // Different initial accumulator values
        let initial_values = [0u64, 1u64, 12345u64];

        println!(
            "\n--- Comparing checksum_no_fold_avx2 output with checksum_no_fold_scalar output ---"
        );
        println!("Note: These two functions perform different types of summations (u32 vs u8).");
        println!("If this test fails, it's likely due to this fundamental difference in calculation logic,");
        println!(
            "not necessarily an 'error' in implementation, but a mismatch in expected behavior."
        );

        for &len in &test_lengths {
            for &initial in &initial_values {
                // Generate random data
                let mut data = vec![0u8; len];
                rng.fill(&mut data[..]);

                // Calculate the expected value using the scalar benchmark function
                let expected = checksum_no_fold_scalar(&data, initial);
                if is_x86_feature_detected!("avx2") {
                    // Calculate the actual value using the AVX2 function
                    // SAFETY: the immediately preceding runtime feature check proves AVX2 is available on this CPU.
                    let actual = unsafe { checksum_no_fold_avx2(&data, initial) };

                    // Assert that the results are equal
                    assert_eq!(
                        actual,
                        expected,
                        "Output Mismatch! Length: {len}, Initial: {initial}, Data: {data:?}\nAVX2 Result: {actual}\nScalar Result: {expected}",
                    );
                }
                if is_x86_feature_detected!("sse4.1") {
                    // SAFETY: the immediately preceding runtime feature check proves SSE4.1 is available on this CPU.
                    let actual = unsafe { checksum_no_fold_sse41(&data, initial) };

                    // Assert that the results are equal
                    assert_eq!(
                        actual,
                        expected,
                        "Output Mismatch! Length: {len}, Initial: {initial}, Data: {data:?}\nsse41 Result: {actual}\nScalar Result: {expected}",
                    );
                }
            }
        }
        println!("\nAll output comparison tests passed (assuming expected mismatch is handled by design).");
    }

    #[test]
    fn test_folded_avx2_checksum_matches_scalar() {
        #[cfg(target_arch = "x86_64")]
        if !is_x86_feature_detected!("avx2") {
            return;
        }

        let mut rng = rand::rng();
        let lengths = [
            0usize, 1, 2, 3, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513,
            1200, 1500, 4096, 16384, 65535,
        ];
        let initial_values = [0u64, 1, 0xffff, 0x12345, 0x1234_5678, 0xffff_ffff];

        for len in lengths {
            let mut data = vec![0u8; len];
            rng.fill(&mut data[..]);

            for initial in initial_values {
                let mut expected = checksum_no_fold_scalar(&data, initial);
                while expected > 0xffff {
                    expected = (expected >> 16) + (expected & 0xffff);
                }

                // SAFETY: the runtime feature check above proves AVX2 is available.
                let actual = unsafe { checksum_folded_avx2(&data, initial) };
                let expected_bytes = expected.to_be_bytes();
                let expected = u16::from_be_bytes([expected_bytes[6], expected_bytes[7]]);
                assert_eq!(actual, expected, "length={len}, initial={initial:#x}");
            }
        }
    }
}
