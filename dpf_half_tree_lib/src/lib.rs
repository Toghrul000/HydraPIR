#![allow(non_snake_case)]
use std::collections::HashSet;
use std::time::Instant;

use aes::cipher::{generic_array::GenericArray, BlockEncrypt};
use aes::Aes128;
use aes::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
use rand::seq::SliceRandom;
use rand::RngCore;
use rayon::prelude::*;


type Aes128Ctr = Ctr128BE<Aes128>;

const AES_BLOCK_SIZE: usize = 16;
pub type Entry<const ENTRY_U64_SIZE: usize> = [u64; ENTRY_U64_SIZE];


/// HS: H_S(x) = AES_fixed(σ(S ⊕ x)) ⊕ σ(S ⊕ x)
pub fn hs(key: &[u8; AES_BLOCK_SIZE], x: &[u8; AES_BLOCK_SIZE], aes: &Aes128, out: &mut [u8; AES_BLOCK_SIZE]) {
    // tmp = S ⊕ x
    let mut tmp = [0u8; AES_BLOCK_SIZE];
    for i in 0..AES_BLOCK_SIZE {
        tmp[i] = key[i] ^ x[i];
    }
    // σ: (xL⊕xR || xL)
    let mut sigma = [0u8; AES_BLOCK_SIZE];
    let half = AES_BLOCK_SIZE / 2;
    for i in 0..half {
        sigma[i] = tmp[i] ^ tmp[i + half];
    }
    for i in half..AES_BLOCK_SIZE {
        sigma[i] = tmp[i - half];
    }
    // π(σ)
    let mut block = GenericArray::clone_from_slice(&sigma);
    aes.encrypt_block(&mut block);
    // H_S(x)
    for i in 0..AES_BLOCK_SIZE {
        out[i] = block[i] ^ sigma[i];
    }
}

/// PRF-based ConvertG: AES_fixed(s) -> 128-bit, truncate to i64
pub fn convert_g(s: &[u8; AES_BLOCK_SIZE], aes: &Aes128) -> i64 {
    let mut block = GenericArray::clone_from_slice(s);
    aes.encrypt_block(&mut block);
    // take first 8 bytes as little-endian u64
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&block[0..8]);
    i64::from_le_bytes(arr)
}

/// PRF-based ConvertG for final output: Only uses s_n (ignores t_n bit)
pub fn convert_g_final(s: &[u8; AES_BLOCK_SIZE], aes: &Aes128) -> i64 {
    // Create a copy where we zero out the last bit (t_n)
    let mut s_only = *s;
    // Zero out the entire last byte except for bit 0 (t_n)
    s_only[AES_BLOCK_SIZE - 1] = s_only[AES_BLOCK_SIZE - 1] & 1;
    
    // Use the regular convert_g function on the modified input
    convert_g(&s_only, aes)
}


/// PRF-based ConvertG for M i64 values using AES-CTR.
/// Depends only on the s_n part of the input seed s = (s_n || t_n).
pub fn convert_g_bytes<const M: usize>(
    s: &[u8; AES_BLOCK_SIZE], // Input is (s_n || t_n)
    aes_cipher: &Aes128, // The fixed key bytes for the main AES instance
) -> [i64; M] {
    // 1. Normalize the seed s to s_only (zero out the t_n bit)
    // This ensures the PRF output depends only on s_n.
    let mut s_only = *s;
    // Zero out the entire last byte except for bit 0 (t_n)
    s_only[AES_BLOCK_SIZE - 1] = s_only[AES_BLOCK_SIZE - 1] & 1;

    // 2. Generate M * 8 pseudorandom bytes using s_only and the fixed AES key.
    // We'll use AES-CTR. We need a key and nonce for CTR mode.
    // Let's derive them from s_only using the fixed AES instance.

    // Derive CTR key: Encrypt s_only with the fixed key
    // This provides a unique key for CTR based on the s_n seed part.
    let mut ctr_key_block = GenericArray::clone_from_slice(&s_only);
    aes_cipher.encrypt_block(&mut ctr_key_block);
    let ctr_key = ctr_key_block; // Use the full 16 bytes as the CTR key

    // Derive CTR nonce: Use a fixed nonce (e.g., all zeros) or derive one.
    // Using a fixed nonce is generally safe in CTR mode as long as the KEY is unique,
    // which it is here (derived from s_only). Let's use a zero nonce.
    let ctr_nonce = GenericArray::from([0u8; AES_BLOCK_SIZE]); // 16-byte zero nonce

    // Initialize CTR mode cipher
    // Note: The key for Ctr128BE::new is the derived ctr_key.
    let mut cipher = Aes128Ctr::new(&ctr_key, &ctr_nonce);

    // Generate the required number of pseudorandom bytes
    let mut output_bytes = vec![0u8; M * 8];
    // apply_keystream generates pseudorandom bytes (XORs with zeros)
    cipher.apply_keystream(&mut output_bytes);

    // 3. Convert bytes to [i64; M]
    let mut result = [0i64; M];
    for k in 0..M {
        let start = k * 8;
        let end = start + 8;
        // Ensure we don't panic if output_bytes is somehow too short (shouldn't happen)
        if end > output_bytes.len() {
             // Handle error appropriately, maybe return Err or panic
             panic!("Generated insufficient bytes for ConvertG_M");
        }
        let chunk: [u8; 8] = output_bytes[start..end]
            .try_into()
            .expect("Slice conversion failed: incorrect length");

        // Interpret bytes as u64 in little-endian format, then cast to i64
        // (Matches the original convert_g logic)
        result[k] = u64::from_le_bytes(chunk) as i64;
    }

    result
}


// fn get_bit(n: u32, pos: u32, bit_size: u32) -> u8 {
//     assert!(pos < bit_size);
//     let shifted = n << (32 - bit_size);
//     ((shifted >> (31 - pos)) & 1) as u8
// }

pub fn get_bit(n: u32, pos: u32, bit_size: u32) -> u8 {
    assert!(pos < bit_size);
    ((n >> (bit_size - 1 - pos)) & 1) as u8
}


pub fn sample_delta() -> [u8; AES_BLOCK_SIZE] {
    let mut delta = [0u8; AES_BLOCK_SIZE];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut delta);
    delta[AES_BLOCK_SIZE - 1] |= 1; // force LSB=1
    delta
}

pub fn share_delta(delta: &[u8; AES_BLOCK_SIZE]) -> ([u8; AES_BLOCK_SIZE], [u8; AES_BLOCK_SIZE]) {
    let mut rng = rand::rng();
    let mut share0 = [0u8; AES_BLOCK_SIZE];
    rng.fill_bytes(&mut share0);
    let mut share1 = [0u8; AES_BLOCK_SIZE];
    for i in 0..AES_BLOCK_SIZE {
        share1[i] = delta[i] ^ share0[i];
    }
    (share0, share1)
}

// Helper for XORing byte arrays
#[inline(always)]
pub fn xor_bytes(a: &mut [u8; AES_BLOCK_SIZE], b: &[u8; AES_BLOCK_SIZE]) {
    // #[cfg(target_arch = "x86_64")]
    // {
    //     if is_x86_feature_detected!("sse2") {
    //         unsafe {
    //             use std::arch::x86_64::*;
    //             let a_ptr = a.as_ptr() as *const __m128i;
    //             let b_ptr = b.as_ptr() as *const __m128i;
    //             let result = _mm_xor_si128(_mm_loadu_si128(a_ptr), _mm_loadu_si128(b_ptr));
    //             _mm_storeu_si128(a.as_mut_ptr() as *mut __m128i, result);
    //             return;
    //         }
    //     }
    // }

    for i in 0..AES_BLOCK_SIZE {
        a[i] ^= b[i];
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Struct for a DPF key share
pub struct DPFKey {
    pub n: usize,
    pub seed: [u8; AES_BLOCK_SIZE], // (s_0 || t_0)
    pub cw_levels: Vec<[u8; AES_BLOCK_SIZE]>, // CW_1..CW_{n-1}
    pub cw_n: ([u8; AES_BLOCK_SIZE - 1], u8, u8), // CW_n represented as a tuple: (HCW, LCW^0, LCW^1)
    pub cw_np1: i64,                          // CW_{n+1}
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Struct for a DPF key share
pub struct DPFKey_Bytes<const ENTRY_U64_SIZE: usize> {
    pub n: usize,
    pub seed: [u8; AES_BLOCK_SIZE], // (s_0 || t_0)
    pub cw_levels: Vec<[u8; AES_BLOCK_SIZE]>, // CW_1..CW_{n-1}
    pub cw_n: ([u8; AES_BLOCK_SIZE - 1], u8, u8), // CW_n represented as a tuple: (HCW, LCW^0, LCW^1)
    pub cw_np1: [i64; ENTRY_U64_SIZE],                          // CW_{n+1} for beta with byte array
}

pub fn dpf_gen(
    alpha: u32,
    beta: u64,
    n: usize,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128,
) -> (DPFKey, DPFKey) {
    // 1) sample Δ with LSB=1 and share
    let delta = sample_delta(); 
    let (s0_initial, s1_initial) = share_delta(&delta); 

    let mut cw_levels = Vec::with_capacity(n - 1);

    // Initialize current_s0, s1, for the loop
    let mut current_s0 = s0_initial;
    let mut current_s1 = s1_initial;

    // Buffers reused in the loop
    let mut h0 = [0u8; AES_BLOCK_SIZE];
    let mut h1 = [0u8; AES_BLOCK_SIZE];
    let mut cwi = [0u8; AES_BLOCK_SIZE]; // Reuse buffer for cwi

    // Levels 0..n-2 (equivalent to 1..n-1 for indices)
    for i in 0..(n - 1) {
        // Keep copies of seeds *before* they are potentially modified by HS output
        let prev0 = current_s0;
        let prev1 = current_s1;

        // Compute HS directly into h0, h1 buffers
        hs(hs_key, &prev0, aes, &mut h0); // h0 = HS(prev0)
        hs(hs_key, &prev1, aes, &mut h1); // h1 = HS(prev1)

        let ai = get_bit(alpha, i as u32, n as u32);
        let alpha_bar_i = 1 - ai; // Complement bit ᾱ_i

        // Calculate CW_i = H0 ⊕ H1 ⊕ (ᾱ_i * Δ) in place
        // Start cwi with h0, then XOR others in.
        cwi = h0;
        xor_bytes(&mut cwi, &h1); // cwi = H0 ⊕ H1 
        if alpha_bar_i == 1 {
            xor_bytes(&mut cwi, &delta); // cwi = H0 ⊕ H1 ⊕ (ᾱ_i * Δ)
        }
        // Store the final CW_i for this level
        cw_levels.push(cwi); 

        // Update seeds for next level (modify h0 and h1 in place to become next seeds)
        let t0 = prev0[AES_BLOCK_SIZE - 1] & 1;
        let t1 = prev1[AES_BLOCK_SIZE - 1] & 1;

        // Calculate next s0 = h0 ⊕  (a_i * prev0) ⊕  (t0 * cwi)
        // h0 already contains HS(prev0)
        if ai == 1 {
            xor_bytes(&mut h0, &prev0); // h0 ⊕ = prev0
        }
        if t0 == 1 {
            // Use the cwi we just calculated and pushed
            xor_bytes(&mut h0, &cw_levels[i]); // h0 ⊕ = cwi
        }
        current_s0 = h0; // Update current_s0 with the final value for this level

        // Calculate next s1 = h1 ⊕  (a_i * prev1) ⊕  (t1 * cwi)
        // h1 already contains HS(prev1)
        if ai == 1 {
            xor_bytes(&mut h1, &prev1); // h1 ⊕= prev1
        }
        if t1 == 1 {
            // Use the cwi we just calculated and pushed
            xor_bytes(&mut h1, &cw_levels[i]); // h1 ⊕= cwi
        }
        current_s1 = h1; // Update current_s1 with the final value for this level
    }

    // Level n processing - uses current_s0, current_s1 (which are last0, last1)
    let last0 = current_s0;
    let last1 = current_s1;
    let alpha_n = get_bit(alpha, (n - 1) as u32, n as u32);
    let alpha_n_bar = 1 - alpha_n; // ᾱ_n

    // Compute HS(s_{n-1}^b ⊕ σ) for σ ∈ {0,1}
    let mut hi0 = [[0u8; AES_BLOCK_SIZE]; 2]; 
    let mut hi1 = [[0u8; AES_BLOCK_SIZE]; 2];
    for sigma in 0..2 {
        // Normalize the inputs for consistent hashing
        let mut inp0 = last0; 
        let mut inp1 = last1; 

        inp0[AES_BLOCK_SIZE - 1] =
            (inp0[AES_BLOCK_SIZE - 1] & 1) ^ sigma as u8;
        inp1[AES_BLOCK_SIZE - 1] =
            (inp1[AES_BLOCK_SIZE - 1] & 1) ^ sigma as u8;

        hs(hs_key, &inp0, aes, &mut hi0[sigma]);
        hs(hs_key, &inp1, aes, &mut hi1[sigma]);
    }

    // Build HCW (high control word)
    let mut hcw = [0u8; AES_BLOCK_SIZE - 1];

     // HCW = high(hi0[ᾱ_n]) ⊕ high(hi1[ᾱ_n])
    let alpha_n_bar_idx = alpha_n_bar as usize;
    for j in 0..(AES_BLOCK_SIZE - 1) {
        hcw[j] = hi0[alpha_n_bar_idx][j] ^ hi1[alpha_n_bar_idx][j];
    }

    // Compute LCW^0 and LCW^1
    // LCW^0 = low(hi0[0]) ⊕ low(hi1[0]) ⊕ ᾱ_n
    let lcw0 = (hi0[0][AES_BLOCK_SIZE - 1] & 1)
        ^ (hi1[0][AES_BLOCK_SIZE - 1] & 1)
        ^ alpha_n_bar; 

    // LCW^1 = low(hi0[1]) ⊕ low(hi1[1]) ⊕ α_n
    let lcw1 = (hi0[1][AES_BLOCK_SIZE - 1] & 1)
        ^ (hi1[1][AES_BLOCK_SIZE - 1] & 1)
        ^ alpha_n; 

    // Create final seeds s_n
    // Get the branch we're programming for alpha_n
    let alpha_n_idx = alpha_n as usize;
    let mut final0 = hi0[alpha_n_idx]; // (high || low)_0
    let mut final1 = hi1[alpha_n_idx]; // (high || low)_1

    // Get t values from s_{n-1}
    let t_n_minus_1_0 = last0[AES_BLOCK_SIZE - 1] & 1;
    let t_n_minus_1_1 = last1[AES_BLOCK_SIZE - 1] & 1;

    // Create correction values
    let lcw_alpha_n = if alpha_n == 0 { lcw0 } else { lcw1 };

    // Apply t_{n-1} * (HCW || LCW^{alpha_n}) correction
    if t_n_minus_1_0 == 1 {
        // Apply HCW to high part of final0
        for j in 0..(AES_BLOCK_SIZE - 1) {
            final0[j] ^= hcw[j];
        }
        // Apply LCW^{alpha_n} to low part of final0
        final0[AES_BLOCK_SIZE - 1] ^= lcw_alpha_n;
    }

    if t_n_minus_1_1 == 1 {
        // Apply HCW to high part of final1
        for j in 0..(AES_BLOCK_SIZE - 1) {
            final1[j] ^= hcw[j];
        }
        // Apply LCW^{alpha_n} to low part of final1
        final1[AES_BLOCK_SIZE - 1] ^= lcw_alpha_n;
    }

    // Get final t bits and normalize the seeds
    let t_n0 = final0[AES_BLOCK_SIZE - 1] & 1;
    let t_n1 = final1[AES_BLOCK_SIZE - 1] & 1;

    // Normalize final seeds - ensure only t_n bit remains in last byte
    final0[AES_BLOCK_SIZE - 1] = t_n0; 
    final1[AES_BLOCK_SIZE - 1] = t_n1;

    // Compute ConvertG on the final seeds (only using s_n, not t_n)
    let sg0 = convert_g_final(&final0, aes);
    let sg1 = convert_g_final(&final1, aes);

    // Calculate CW_{n+1}
    // Use wrapping arithmetic explicitly for clarity and correctness
    let diff_t = (t_n0 as i64).wrapping_sub(t_n1 as i64); // More robust way to get -1, 0, or 1
    let term2 = sg1.wrapping_sub(sg0).wrapping_add(beta as i64);
    let cw_np1 = diff_t.wrapping_mul(term2);

    // --- Return key shares ---
    //println!("Generated keys");
    // println!("DEBUG: alpha={}, t_n0={}, t_n1={}, diff_t={}", 
    //          alpha, t_n0, t_n1, diff_t);
    // println!("DEBUG: sg0={}, sg1={}, cw_np1={}", sg0, sg1, cw_np1);

    (
        DPFKey {
            n,
            seed: s0_initial,
            cw_levels: cw_levels.clone(), // Clone here
            cw_n: (hcw, lcw0, lcw1),
            cw_np1,
        },
        DPFKey {
            n,
            seed: s1_initial,
            cw_levels, // Move original vector here
            cw_n: (hcw, lcw0, lcw1),
            cw_np1,
        },
    )
}



pub fn dpf_gen_bytes<const ENTRY_U64_SIZE: usize>(
    alpha: u32,
    beta: [u64; ENTRY_U64_SIZE],
    n: usize,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128,
) -> (DPFKey_Bytes<ENTRY_U64_SIZE>, DPFKey_Bytes<ENTRY_U64_SIZE>) {
    // 1) sample Δ with LSB=1 and share
    let delta = sample_delta(); 
    let (s0_initial, s1_initial) = share_delta(&delta); 

    let mut cw_levels = Vec::with_capacity(n - 1);

    // Initialize current_s0, s1, for the loop
    let mut current_s0 = s0_initial;
    let mut current_s1 = s1_initial;

    // Buffers reused in the loop
    let mut h0 = [0u8; AES_BLOCK_SIZE];
    let mut h1 = [0u8; AES_BLOCK_SIZE];
    let mut cwi = [0u8; AES_BLOCK_SIZE]; // Reuse buffer for cwi

    // Levels 0..n-2 (equivalent to 1..n-1 for indices)
    for i in 0..(n - 1) {
        // Keep copies of seeds *before* they are potentially modified by HS output
        let prev0 = current_s0;
        let prev1 = current_s1;

        // Compute HS directly into h0, h1 buffers
        hs(hs_key, &prev0, aes, &mut h0); // h0 = HS(prev0)
        hs(hs_key, &prev1, aes, &mut h1); // h1 = HS(prev1)

        let ai = get_bit(alpha, i as u32, n as u32);
        let alpha_bar_i = 1 - ai; // Complement bit ᾱ_i

        // Calculate CW_i = H0 ⊕ H1 ⊕ (ᾱ_i * Δ) in place
        // Start cwi with h0, then XOR others in.
        cwi = h0;
        xor_bytes(&mut cwi, &h1); // cwi = H0 ⊕ H1 
        if alpha_bar_i == 1 {
            xor_bytes(&mut cwi, &delta); // cwi = H0 ⊕ H1 ⊕ (ᾱ_i * Δ)
        }
        // Store the final CW_i for this level
        cw_levels.push(cwi); 

        // Update seeds for next level (modify h0 and h1 in place to become next seeds)
        let t0 = prev0[AES_BLOCK_SIZE - 1] & 1;
        let t1 = prev1[AES_BLOCK_SIZE - 1] & 1;

        // Calculate next s0 = h0 ⊕  (a_i * prev0) ⊕  (t0 * cwi)
        // h0 already contains HS(prev0)
        if ai == 1 {
            xor_bytes(&mut h0, &prev0); // h0 ⊕ = prev0
        }
        if t0 == 1 {
            // Use the cwi we just calculated and pushed
            xor_bytes(&mut h0, &cw_levels[i]); // h0 ⊕ = cwi
        }
        current_s0 = h0; // Update current_s0 with the final value for this level

        // Calculate next s1 = h1 ⊕  (a_i * prev1) ⊕  (t1 * cwi)
        // h1 already contains HS(prev1)
        if ai == 1 {
            xor_bytes(&mut h1, &prev1); // h1 ⊕= prev1
        }
        if t1 == 1 {
            // Use the cwi we just calculated and pushed
            xor_bytes(&mut h1, &cw_levels[i]); // h1 ⊕= cwi
        }
        current_s1 = h1; // Update current_s1 with the final value for this level
    }

    // Level n processing - uses current_s0, current_s1 (which are last0, last1)
    let last0 = current_s0;
    let last1 = current_s1;
    let alpha_n = get_bit(alpha, (n - 1) as u32, n as u32);
    let alpha_n_bar = 1 - alpha_n; // ᾱ_n

    // Compute HS(s_{n-1}^b ⊕ σ) for σ ∈ {0,1}
    let mut hi0 = [[0u8; AES_BLOCK_SIZE]; 2]; 
    let mut hi1 = [[0u8; AES_BLOCK_SIZE]; 2];
    for sigma in 0..2 {
        // Normalize the inputs for consistent hashing
        let mut inp0 = last0; 
        let mut inp1 = last1; 

        inp0[AES_BLOCK_SIZE - 1] =
            (inp0[AES_BLOCK_SIZE - 1] & 1) ^ sigma as u8;
        inp1[AES_BLOCK_SIZE - 1] =
            (inp1[AES_BLOCK_SIZE - 1] & 1) ^ sigma as u8;

        hs(hs_key, &inp0, aes, &mut hi0[sigma]);
        hs(hs_key, &inp1, aes, &mut hi1[sigma]);
    }

    // Build HCW (high control word)
    let mut hcw = [0u8; AES_BLOCK_SIZE - 1];

     // HCW = high(hi0[ᾱ_n]) ⊕ high(hi1[ᾱ_n])
    let alpha_n_bar_idx = alpha_n_bar as usize;
    for j in 0..(AES_BLOCK_SIZE - 1) {
        hcw[j] = hi0[alpha_n_bar_idx][j] ^ hi1[alpha_n_bar_idx][j];
    }

    // Compute LCW^0 and LCW^1
    // LCW^0 = low(hi0[0]) ⊕ low(hi1[0]) ⊕ ᾱ_n
    let lcw0 = (hi0[0][AES_BLOCK_SIZE - 1] & 1)
        ^ (hi1[0][AES_BLOCK_SIZE - 1] & 1)
        ^ alpha_n_bar; 

    // LCW^1 = low(hi0[1]) ⊕ low(hi1[1]) ⊕ α_n
    let lcw1 = (hi0[1][AES_BLOCK_SIZE - 1] & 1)
        ^ (hi1[1][AES_BLOCK_SIZE - 1] & 1)
        ^ alpha_n; 

    // Create final seeds s_n
    // Get the branch we're programming for alpha_n
    let alpha_n_idx = alpha_n as usize;
    let mut final0 = hi0[alpha_n_idx]; // (high || low)_0
    let mut final1 = hi1[alpha_n_idx]; // (high || low)_1

    // Get t values from s_{n-1}
    let t_n_minus_1_0 = last0[AES_BLOCK_SIZE - 1] & 1;
    let t_n_minus_1_1 = last1[AES_BLOCK_SIZE - 1] & 1;

    // Create correction values
    let lcw_alpha_n = if alpha_n == 0 { lcw0 } else { lcw1 };

    // Apply t_{n-1} * (HCW || LCW^{alpha_n}) correction
    if t_n_minus_1_0 == 1 {
        // Apply HCW to high part of final0
        for j in 0..(AES_BLOCK_SIZE - 1) {
            final0[j] ^= hcw[j];
        }
        // Apply LCW^{alpha_n} to low part of final0
        final0[AES_BLOCK_SIZE - 1] ^= lcw_alpha_n;
    }

    if t_n_minus_1_1 == 1 {
        // Apply HCW to high part of final1
        for j in 0..(AES_BLOCK_SIZE - 1) {
            final1[j] ^= hcw[j];
        }
        // Apply LCW^{alpha_n} to low part of final1
        final1[AES_BLOCK_SIZE - 1] ^= lcw_alpha_n;
    }

    // Get final t bits and normalize the seeds
    let t_n0 = final0[AES_BLOCK_SIZE - 1] & 1;
    let t_n1 = final1[AES_BLOCK_SIZE - 1] & 1;

    // Normalize final seeds - ensure only t_n bit remains in last byte
    final0[AES_BLOCK_SIZE - 1] = t_n0; 
    final1[AES_BLOCK_SIZE - 1] = t_n1;


    // Calculate CW_{n+1} but for byte array beta

    // Compute ConvertG on the final seeds (only using s_n, not t_n)
    let sg0 = convert_g_bytes::<ENTRY_U64_SIZE>(&final0, &aes);
    let sg1 = convert_g_bytes::<ENTRY_U64_SIZE>(&final1, &aes);

    // Use wrapping arithmetic explicitly for clarity and correctness
    let mut cw_np1 = [0i64; ENTRY_U64_SIZE];
    let diff_t = (t_n0 as i64).wrapping_sub(t_n1 as i64); // -1, 0, or 1
    for k in 0..ENTRY_U64_SIZE {
        // beta[k] needs to be cast to i64 for the calculation
        let term2 = sg1[k].wrapping_sub(sg0[k]).wrapping_add(beta[k] as i64);
        cw_np1[k] = diff_t.wrapping_mul(term2);
    }


    (
        DPFKey_Bytes {
            n,
            seed: s0_initial,
            cw_levels: cw_levels.clone(), // Clone here
            cw_n: (hcw, lcw0, lcw1),
            cw_np1,
        },
        DPFKey_Bytes {
            n,
            seed: s1_initial,
            cw_levels, // Move original vector here
            cw_n: (hcw, lcw0, lcw1),
            cw_np1,
        },
    )
}



pub fn dpf_eval(
    b: u8,
    key: &DPFKey,
    hs_key: &[u8; AES_BLOCK_SIZE],
    x: u32,
    aes: &Aes128,
) -> i64 {
    // Step 1: Parse k_b components
    let mut current_seed = key.seed; // Start with the initial seed
    let n = key.n;

    // Buffer for hs output, reused in the loop
    let mut hs_out = [0u8; AES_BLOCK_SIZE];

    // Step 2: Tree traversal for i ∈ [0, n-2] (equivalent to 1..n-1)
    for i in 0..(n - 1) {
        let x_i = get_bit(x, i as u32, n as u32);
        // Extract t bit *before* current_seed is potentially modified by hs_out
        let current_t = current_seed[AES_BLOCK_SIZE - 1] & 1;

        // Compute H_S(current_seed) directly into hs_out
        hs(hs_key, &current_seed, aes, &mut hs_out);
        // hs_out now contains H_S(...)

        // Conditionally XOR with current_seed if x_i is 1
        // seed = HS(...) ^ (x_i * current_seed)
        if x_i == 1 {
            xor_bytes(&mut hs_out, &current_seed);
        }

        // Conditionally XOR with the correction word if t is 1
        // seed = HS(...) ^ (x_i * current_seed) ^ (t * CW_i)
        if current_t == 1 {
            xor_bytes(&mut hs_out, &key.cw_levels[i]);
        }

        // Update current_seed for the next iteration *without* extra copy
        current_seed = hs_out;
    }

    // Step 3: Final level processing (i = n-1)
    let x_n = get_bit(x, (n - 1) as u32, n as u32);
    let current_t = current_seed[AES_BLOCK_SIZE - 1] & 1; // t_{n-1}

    // Prepare input for the final HS call
    // Need a copy here because we modify it before hashing
    let mut hash_input = current_seed;
    // Normalize: keep only t_{n-1}, then XOR with x_n
    hash_input[AES_BLOCK_SIZE - 1] = current_t ^ x_n;

    // Compute final HS(normalized seed ⊕ x_n) -> hs_out reused
    hs(hs_key, &hash_input, aes, &mut hs_out);
    // hs_out now contains H_S(...) for the final level

    // Compute final seed: (high || low) = HS(...) ⊕ t_{n-1} * (HCW || LCW^{x_n})
    if current_t == 1 {
        let hcw = &key.cw_n.0;
        let lcw = if x_n == 0 { key.cw_n.1 } else { key.cw_n.2 };

        // Apply HCW to high bits (modifies hs_out in place)
        for j in 0..(AES_BLOCK_SIZE - 1) {
            hs_out[j] ^= hcw[j];
        }
        // Apply appropriate LCW to low bit (modifies hs_out in place)
        hs_out[AES_BLOCK_SIZE - 1] ^= lcw;
    }

    // hs_out now holds the final seed (s_n || t_n') before normalization

    // Normalize final seed - ensure only t_n bit remains in last byte
    let t_n = hs_out[AES_BLOCK_SIZE - 1] & 1;
    hs_out[AES_BLOCK_SIZE - 1] = t_n; // hs_out is now the normalized (s_n || t_n)

    // ConvertG for final output (only using s_n part of hs_out)
    let convert_out = convert_g_final(&hs_out, aes);

    // Calculate y_b = (-1)^b * (ConvertG(s_n) + t_n * CW_{n+1})
    let sign = if b == 0 { 1i64 } else { -1i64 };
    // Use wrapping arithmetic for the final calculation as well
    let t_term = if t_n == 1 { key.cw_np1 } else { 0 };
    let result = sign.wrapping_mul(convert_out.wrapping_add(t_term));

    result
}


pub fn dpf_eval_bytes<const ENTRY_U64_SIZE: usize>(
    b: u8,
    key: &DPFKey_Bytes<ENTRY_U64_SIZE>,
    hs_key: &[u8; AES_BLOCK_SIZE],
    x: u32,
    aes: &Aes128,
) -> [i64; ENTRY_U64_SIZE] {
    // Step 1: Parse k_b components
    let mut current_seed = key.seed; // Start with the initial seed
    let n = key.n;

    // Buffer for hs output, reused in the loop
    let mut hs_out = [0u8; AES_BLOCK_SIZE];

    // Step 2: Tree traversal for i ∈ [0, n-2] (equivalent to 1..n-1)
    for i in 0..(n - 1) {
        let x_i = get_bit(x, i as u32, n as u32);
        // Extract t bit *before* current_seed is potentially modified by hs_out
        let current_t = current_seed[AES_BLOCK_SIZE - 1] & 1;

        // Compute H_S(current_seed) directly into hs_out
        hs(hs_key, &current_seed, aes, &mut hs_out);
        // hs_out now contains H_S(...)

        // Conditionally XOR with current_seed if x_i is 1
        // seed = HS(...) ^ (x_i * current_seed)
        if x_i == 1 {
            xor_bytes(&mut hs_out, &current_seed);
        }

        // Conditionally XOR with the correction word if t is 1
        // seed = HS(...) ^ (x_i * current_seed) ^ (t * CW_i)
        if current_t == 1 {
            xor_bytes(&mut hs_out, &key.cw_levels[i]);
        }

        // Update current_seed for the next iteration *without* extra copy
        current_seed = hs_out;
    }

    // Step 3: Final level processing (i = n-1)
    let x_n = get_bit(x, (n - 1) as u32, n as u32);
    let current_t = current_seed[AES_BLOCK_SIZE - 1] & 1; // t_{n-1}

    // Prepare input for the final HS call
    // Need a copy here because we modify it before hashing
    let mut hash_input = current_seed;
    // Normalize: keep only t_{n-1}, then XOR with x_n
    hash_input[AES_BLOCK_SIZE - 1] = current_t ^ x_n;

    // Compute final HS(normalized seed ⊕ x_n) -> hs_out reused
    hs(hs_key, &hash_input, aes, &mut hs_out);
    // hs_out now contains H_S(...) for the final level

    // Compute final seed: (high || low) = HS(...) ⊕ t_{n-1} * (HCW || LCW^{x_n})
    if current_t == 1 {
        let hcw = &key.cw_n.0;
        let lcw = if x_n == 0 { key.cw_n.1 } else { key.cw_n.2 };

        // Apply HCW to high bits (modifies hs_out in place)
        for j in 0..(AES_BLOCK_SIZE - 1) {
            hs_out[j] ^= hcw[j];
        }
        // Apply appropriate LCW to low bit (modifies hs_out in place)
        hs_out[AES_BLOCK_SIZE - 1] ^= lcw;
    }

    // hs_out now holds the final seed (s_n || t_n') before normalization

    // Normalize final seed - ensure only t_n bit remains in last byte
    let t_n = hs_out[AES_BLOCK_SIZE - 1] & 1;
    hs_out[AES_BLOCK_SIZE - 1] = t_n; // hs_out is now the normalized (s_n || t_n)

    // ConvertG for final output (only using s_n part of hs_out)
    let convert_out = convert_g_bytes::<ENTRY_U64_SIZE>(&hs_out, aes);

    // Calculate y_b = (-1)^b * (ConvertG(s_n) + t_n * CW_{n+1}) for bytes array beta cw_np1
    let mut result = [0i64; ENTRY_U64_SIZE];
    let sign = if b == 0 { 1i64 } else { -1i64 };
    
    for k in 0..ENTRY_U64_SIZE {
        let t_term = if t_n == 1 { key.cw_np1[k] } else { 0 };
        result[k] = sign.wrapping_mul(convert_out[k].wrapping_add(t_term));
    }

    result
}





/// Precomputes the state after the main loop for all 2^(n-1) paths using Rayon.
/// Returns a Vec containing the final `current_seed` for each path prefix.
pub fn dpf_full_eval_precompute_parallel(
    key: &DPFKey,
    hs_key: &[u8; AES_BLOCK_SIZE], 
    aes: &Aes128, 
) -> Vec<[u8; AES_BLOCK_SIZE]> {
    let n = key.n;
    if n == 0 {
        return Vec::new();
    }
    if n == 1 {
        return vec![key.seed];
    }

    // Start with the initial seed at level 0
    let mut current_level_seeds = vec![key.seed];

    // Iterate through levels i = 0 to n-2 (computing seeds for levels 1 to n-1)
    for i in 0..(n - 1) {
        let cw_i = key.cw_levels[i]; // Correction word for this level (Copy)

        // Use Rayon to parallelize the computation for the next level
        let next_level_seeds = current_level_seeds
            .par_iter() // Parallel iterator over seeds from the previous level
            .flat_map(|&prev_seed| {
                // This closure runs in parallel for each prev_seed
                let mut hs_out = [0u8; AES_BLOCK_SIZE]; // Local buffer per task
                let mut next_seed_0 = [0u8; AES_BLOCK_SIZE];
                let mut next_seed_1 = [0u8; AES_BLOCK_SIZE];

                let current_t = prev_seed[AES_BLOCK_SIZE - 1] & 1;

                // Compute H_S(prev_seed) - aes is Sync+Send, hs_key is Copy
                hs(hs_key, &prev_seed, aes, &mut hs_out);

                // Calculate seed for the 'left' branch (x_{i+1} = 0)
                next_seed_0 = hs_out;
                if current_t == 1 {
                    xor_bytes(&mut next_seed_0, &cw_i); // cw_i is Copy
                }

                // Calculate seed for the 'right' branch (x_{i+1} = 1)
                next_seed_1 = hs_out;
                xor_bytes(&mut next_seed_1, &prev_seed);
                if current_t == 1 {
                    xor_bytes(&mut next_seed_1, &cw_i);
                }

                // Return the two computed seeds for this branch
                // flat_map will flatten these into the collection
                vec![next_seed_0, next_seed_1]
            })
            .collect::<Vec<[u8; AES_BLOCK_SIZE]>>(); // Collect results into a new Vec

        // Update current_level_seeds for the next iteration
        current_level_seeds = next_level_seeds;
    }

    // After the loop, current_level_seeds contains the seeds for level n-1
    current_level_seeds
}


/// Evaluates the DPF key using the precomputed loop results.
pub fn dpf_eval_fast(
    b: u8,
    key: &DPFKey,
    hs_key: &[u8; AES_BLOCK_SIZE],
    x: u32,
    aes: &Aes128,
    precomputed_seeds: &[[u8; AES_BLOCK_SIZE]], 
) -> i64 {
    let n = key.n;
    if n == 0 {
        // Handle error or return default
        return 0;
    }

    // --- O(1) Lookup ---
    // Calculate the index corresponding to the path prefix x_1...x_{n-1}
    // This assumes x < 2^n. The first n-1 bits are obtained by shifting right by 1.
    let prefix_index = (x >> 1) as usize;

    // Handle n=1 case where table size is 1 and index should be 0
    let current_seed = if n == 1 {
        precomputed_seeds[0]
    } else {
        // Bounds check might be wise in production code if n is dynamic
        // assert!(prefix_index < precomputed_seeds.len());
        precomputed_seeds[prefix_index]
    };
    // current_seed now holds the state s_{n-1} (equivalent to the state after the loop)

    // --- Step 3: Final level processing (identical to original dpf_eval) ---
    let x_n = get_bit(x, (n - 1) as u32, n as u32); // Gets the last bit x_n
    let current_t = current_seed[AES_BLOCK_SIZE - 1] & 1; // t_{n-1}

    // Buffer for hs output (can be reused)
    let mut hs_out = [0u8; AES_BLOCK_SIZE];

    // Prepare input for the final HS call
    let mut hash_input = current_seed; // Need a copy to modify
    hash_input[AES_BLOCK_SIZE - 1] = current_t ^ x_n; // Normalize: t_{n-1} ^ x_n

    // Compute final HS
    hs(hs_key, &hash_input, aes, &mut hs_out);
    // hs_out now contains HS(...) for the final level

    // Compute final seed: (high || low) = HS(...) ⊕ t_{n-1} * (HCW || LCW^{x_n})
    if current_t == 1 {
        let hcw = &key.cw_n.0;
        let lcw = if x_n == 0 { key.cw_n.1 } else { key.cw_n.2 };

        // Apply HCW to high bits (modifies hs_out in place)
        for j in 0..(AES_BLOCK_SIZE - 1) {
            hs_out[j] ^= hcw[j];
        }
        // Apply appropriate LCW to low bit (modifies hs_out in place)
        hs_out[AES_BLOCK_SIZE - 1] ^= lcw;
    }

    // hs_out now holds the final seed (s_n || t_n') before normalization

    // Normalize final seed - ensure only t_n bit remains in last byte
    let t_n = hs_out[AES_BLOCK_SIZE - 1] & 1;
    hs_out[AES_BLOCK_SIZE - 1] = t_n; // hs_out is now the normalized (s_n || t_n)

    // ConvertG for final output (only using s_n part of hs_out)
    let convert_out = convert_g_final(&hs_out, aes);

    // Calculate y_b = (-1)^b * (ConvertG(s_n) + t_n * CW_{n+1})
    let sign = if b == 0 { 1i64 } else { -1i64 };
    let t_term = if t_n == 1 { key.cw_np1 } else { 0 };
    let result = sign.wrapping_mul(convert_out.wrapping_add(t_term));

    result
}


/// Evaluates the DPF key using the precomputed loop results.
pub fn dpf_eval_fast_bytes<const ENTRY_U64_SIZE: usize>(
    b: u8,
    key: &DPFKey_Bytes<ENTRY_U64_SIZE>,
    hs_key: &[u8; AES_BLOCK_SIZE],
    x: u32,
    aes: &Aes128,
    precomputed_seeds: &[[u8; AES_BLOCK_SIZE]], // Reference to the precomputed table
) -> [i64; ENTRY_U64_SIZE] {
    let n = key.n;
    // --- O(1) Lookup ---
    // Calculate the index corresponding to the path prefix x_1...x_{n-1}
    // This assumes x < 2^n. The first n-1 bits are obtained by shifting right by 1.
    let prefix_index = (x >> 1) as usize;

    // Handle n=1 case where table size is 1 and index should be 0
    let current_seed = if n == 1 {
        precomputed_seeds[0]
    } else {
        // Bounds check might be wise in production code if n is dynamic
        // assert!(prefix_index < precomputed_seeds.len());
        precomputed_seeds[prefix_index]
    };
    // current_seed now holds the state s_{n-1} (equivalent to the state after the loop)

    // --- Step 3: Final level processing (identical to original dpf_eval) ---
    let x_n = get_bit(x, (n - 1) as u32, n as u32); // Gets the last bit x_n
    let current_t = current_seed[AES_BLOCK_SIZE - 1] & 1; // t_{n-1}

    // Buffer for hs output (can be reused)
    let mut hs_out = [0u8; AES_BLOCK_SIZE];

    // Prepare input for the final HS call
    let mut hash_input = current_seed; // Need a copy to modify
    hash_input[AES_BLOCK_SIZE - 1] = current_t ^ x_n; // Normalize: t_{n-1} ^ x_n

    // Compute final HS
    hs(hs_key, &hash_input, aes, &mut hs_out);
    // hs_out now contains HS(...) for the final level

    // Compute final seed: (high || low) = HS(...) ⊕ t_{n-1} * (HCW || LCW^{x_n})
    if current_t == 1 {
        let hcw = &key.cw_n.0;
        let lcw = if x_n == 0 { key.cw_n.1 } else { key.cw_n.2 };

        // Apply HCW to high bits (modifies hs_out in place)
        for j in 0..(AES_BLOCK_SIZE - 1) {
            hs_out[j] ^= hcw[j];
        }
        // Apply appropriate LCW to low bit (modifies hs_out in place)
        hs_out[AES_BLOCK_SIZE - 1] ^= lcw;
    }

    // hs_out now holds the final seed (s_n || t_n') before normalization

    // Normalize final seed - ensure only t_n bit remains in last byte
    let t_n = hs_out[AES_BLOCK_SIZE - 1] & 1;
    hs_out[AES_BLOCK_SIZE - 1] = t_n; // hs_out is now the normalized (s_n || t_n)

    // ConvertG for final output (only using s_n part of hs_out)
    let convert_out = convert_g_bytes::<ENTRY_U64_SIZE>(&hs_out, aes);

    // Calculate y_b = (-1)^b * (ConvertG(s_n) + t_n * CW_{n+1}) for bytes array beta cw_np1
    let mut result = [0i64; ENTRY_U64_SIZE];
    let sign = if b == 0 { 1i64 } else { -1i64 };
    
    for k in 0..ENTRY_U64_SIZE {
        let t_term = if t_n == 1 { key.cw_np1[k] } else { 0 };
        result[k] = sign.wrapping_mul(convert_out[k].wrapping_add(t_term));
    }

    result
}


/// Precomputes the state after the main loop for all 2^(n-1) paths using Rayon.
/// Returns a Vec containing the final `current_seed` for each path prefix.
pub fn dpf_full_eval_precompute_parallel_bytes<const ENTRY_U64_SIZE: usize>(
    key: &DPFKey_Bytes<ENTRY_U64_SIZE>,
    hs_key: &[u8; AES_BLOCK_SIZE], 
    aes: &Aes128,
) -> Vec<[u8; AES_BLOCK_SIZE]> {
    let n = key.n;
    if n == 0 {
        return Vec::new();
    }
    if n == 1 {
        return vec![key.seed];
    }

    // Start with the initial seed at level 0
    let mut current_level_seeds = vec![key.seed];

    // Iterate through levels i = 0 to n-2 (computing seeds for levels 1 to n-1)
    for i in 0..(n - 1) {
        let cw_i = key.cw_levels[i]; // Correction word for this level (Copy)

        // Use Rayon to parallelize the computation for the next level
        let next_level_seeds = current_level_seeds
            .par_iter() // Parallel iterator over seeds from the previous level
            .flat_map(|&prev_seed| {
                // This closure runs in parallel for each prev_seed
                let mut hs_out = [0u8; AES_BLOCK_SIZE]; // Local buffer per task
                let mut next_seed_0 = [0u8; AES_BLOCK_SIZE];
                let mut next_seed_1 = [0u8; AES_BLOCK_SIZE];

                let current_t = prev_seed[AES_BLOCK_SIZE - 1] & 1;

                // Compute H_S(prev_seed) - aes is Sync+Send, hs_key is Copy
                hs(hs_key, &prev_seed, aes, &mut hs_out);

                // Calculate seed for the 'left' branch (x_{i+1} = 0)
                next_seed_0 = hs_out;
                if current_t == 1 {
                    xor_bytes(&mut next_seed_0, &cw_i); // cw_i is Copy
                }

                // Calculate seed for the 'right' branch (x_{i+1} = 1)
                next_seed_1 = hs_out;
                xor_bytes(&mut next_seed_1, &prev_seed);
                if current_t == 1 {
                    xor_bytes(&mut next_seed_1, &cw_i);
                }

                // Return the two computed seeds for this branch
                // flat_map will flatten these into the collection
                vec![next_seed_0, next_seed_1]
            })
            .collect::<Vec<[u8; AES_BLOCK_SIZE]>>(); // Collect results into a new Vec

        // Update current_level_seeds for the next iteration
        current_level_seeds = next_level_seeds;
    }

    // After the loop, current_level_seeds contains the seeds for level n-1
    current_level_seeds
}


#[derive(Debug, Clone)] // Added Clone derive
pub enum Slot<const ENTRY_U64_SIZE: usize> {
    Single(Entry<ENTRY_U64_SIZE>), // For buckets with 0 or 1 target points
    Many(Vec<Entry<ENTRY_U64_SIZE>>), // For buckets with multiple target points
}


/// Calculates optimal PIR configuration based on DB size exponent N.
///
/// Finds the largest power-of-2 number of buckets (`NUM_BUCKETS`)
/// such that `NUM_BUCKETS * N <= floor(sqrt(1 << N))`.
/// It then derives the corresponding `DB_SIZE`, `BUCKET_SIZE`, and `BUCKET_BITS`.
///
/// # Arguments
///
/// * `n`: The exponent for the database size (DB_SIZE = 1 << n). Must be > 0.
///
/// # Returns
///
/// A tuple `(DB_SIZE, NUM_BUCKETS, BUCKET_SIZE, BUCKET_BITS)`.
///
/// # Panics
///
/// Panics if `n` is 0.
/// Panics if `n` is large enough that `1 << n` overflows `usize`.
/// Panics if intermediate floating-point calculations result in non-finite values.
pub fn calculate_pir_config(n: usize) -> (usize, usize, usize, u32) {
    if n == 0 {
        panic!("N must be greater than 0 to calculate PIR configuration.");
    }

    // Calculate DB_SIZE, checking for potential overflow if n is very large
    let db_size = 1usize.checked_shl(n as u32).unwrap_or_else(|| {
        panic!("N ({}) is too large, 1 << N overflowed usize", n)
    });

    // Calculate the constraint threshold
    let sqrt_db_size = (db_size as f64).sqrt();
    if !sqrt_db_size.is_finite() {
        panic!(
            "Square root calculation resulted in non-finite value for N={}",
            n
        );
    }
    let sqrt_db_floor = sqrt_db_size.floor();

    // Calculate the maximum allowed value for k (NUM_BUCKETS) based on the formula
    // k * N <= floor(sqrt(DB_SIZE))  => k <= floor(sqrt(DB_SIZE)) / N
    let max_k_float = sqrt_db_floor / (n as f64);
    if !max_k_float.is_finite() {
        panic!("Max k calculation resulted in non-finite value for N={}", n);
    }

    // We need the largest *power of 2* for NUM_BUCKETS that is <= max_k_float
    let max_k_allowed = max_k_float.floor() as usize;

    let num_buckets = if max_k_allowed == 0 {
        // If even k=1 doesn't satisfy the condition (or N is huge),
        // the largest power of 2 <= 0 doesn't make sense.
        // Default to 1 bucket, as it's the smallest possible power-of-2 division.
        if (n as f64) > sqrt_db_floor {
            println!(
                "Warning: For N={}, even 1 bucket violates the condition ({} > {}). \
                 Defaulting to 1 bucket anyway.",
                n, n, sqrt_db_floor
            );
        }
        1 // Smallest power-of-2 division
    } else {
        // Find the greatest power of 2 less than or equal to max_k_allowed.
        // Equivalent to 2^(floor(log2(max_k_allowed)))
        1usize << max_k_allowed.ilog2()
    };

    // Calculate BUCKET_SIZE and BUCKET_BITS
    // These divisions/logs are safe because db_size and num_buckets are powers of 2.
    let bucket_size = db_size / num_buckets;
    let bucket_bits = bucket_size.ilog2(); // log2 of bucket_size

    (db_size, num_buckets, bucket_size, bucket_bits)
}




pub fn dpf_priv_update_gen_buckets<const ENTRY_U64_SIZE: usize>(
    target_points: &[(u32, [u64; ENTRY_U64_SIZE])],
    num_buckets: usize,
    bucket_size: usize,
    bucket_bits: u32,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128, 
) -> (Vec<Vec<Vec<DPFKey_Bytes<ENTRY_U64_SIZE>>>>, Vec<usize>) {
    // client_keys[server_id][bucket_id] -> Vec<DPFKey>
    let mut client_keys: Vec<Vec<Vec<DPFKey_Bytes<ENTRY_U64_SIZE>>>> =
        vec![vec![Vec::new(); num_buckets]; 2];
    // Track how many *actual* target points are in each bucket
    let mut points_per_bucket: Vec<usize> = vec![0; num_buckets];

    println!("Generating DPF keys per bucket...");
    for bucket_idx in 0..num_buckets {
        let bucket_start_idx = (bucket_idx * bucket_size) as u32;
        let bucket_end_idx = bucket_start_idx + bucket_size as u32;
        let mut current_bucket_point_count = 0;

        // Find points belonging to the current bucket
        for (global_idx, value) in target_points {
            if *global_idx >= bucket_start_idx && *global_idx < bucket_end_idx {
                let local_idx = global_idx - bucket_start_idx;
                println!(
                    "  Found point {} in bucket {} (local index {})",
                    global_idx, bucket_idx, local_idx
                );
                // Generate keys for this specific point
                let (k0, k1) = dpf_gen_bytes(
                    local_idx,
                    *value, // DPF usually encodes the value directly
                    bucket_bits as usize,
                    hs_key,
                    aes, 
                );
                client_keys[0][bucket_idx].push(k0);
                client_keys[1][bucket_idx].push(k1);
                current_bucket_point_count += 1;
            }
        }
        points_per_bucket[bucket_idx] = current_bucket_point_count; // Store count

        // If no points found in this bucket, generate keys for a zero function
        if current_bucket_point_count == 0 {
            println!(
                "  No target points in bucket {}. Generating zero function keys.",
                bucket_idx
            );
            let (k0, k1) = dpf_gen_bytes(
                0, // Arbitrary index for zero function
                [0u64; ENTRY_U64_SIZE], // Value is zero
                bucket_bits as usize,
                hs_key,
                aes,
            );
            // Still add the keys, but the count remains 0
            client_keys[0][bucket_idx].push(k0);
            client_keys[1][bucket_idx].push(k1);
        }
    }
    println!("DPF key generation complete.");
    (client_keys, points_per_bucket)
}


pub fn dpf_priv_update_eval_buckets<const ENTRY_U64_SIZE: usize>(
    server_id: usize,
    server_keys: &[Vec<DPFKey_Bytes<ENTRY_U64_SIZE>>], 
    db: &mut[[i64; ENTRY_U64_SIZE]],
    bucket_size: usize,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128,
) {
    println!("Server {} starting evaluation...", server_id);
    let start = Instant::now();

    // Process buckets in parallel using par_iter_mut
    db.par_chunks_mut(bucket_size)
        .enumerate()
        .for_each(|(bucket_idx, bucket)| {
            let keys = &server_keys[bucket_idx]; // Keys for this server, this bucket
            let num_keys_in_bucket = keys.len();

            // Outer loop over keys for this bucket
            for key_idx in 0..num_keys_in_bucket {
                let key = &keys[key_idx];

                // Precompute seeds for the current key
                let precomputed_seeds =
                    dpf_full_eval_precompute_parallel_bytes(key, hs_key, aes);

                // Inner loop over DB entries in the bucket
                for (local_idx, db_entry) in bucket.iter_mut().enumerate() {
                    // Evaluate the key quickly using precomputed data
                    let eval_share = dpf_eval_fast_bytes::<ENTRY_U64_SIZE>(
                        server_id as u8,
                        key,
                        hs_key,
                        local_idx as u32,
                        aes,
                        &precomputed_seeds,
                    );

                    // Update the database entry
                    for k in 0..ENTRY_U64_SIZE {
                        db_entry[k] = db_entry[k].wrapping_add(eval_share[k]);
                    }
                }
            }
        });

    let duration = start.elapsed();
    println!(
        "Server {} evaluation complete,",
        server_id
    );
    println!("Time taken: {:?}", duration);
    println!("In seconds: {:.2}s", duration.as_secs_f64());
    println!("In milliseconds: {}ms", duration.as_millis());
}



pub fn dpf_priv_update_additive<const ENTRY_U64_SIZE: usize>(
    server_id: u8,
    server_key: &DPFKey_Bytes<ENTRY_U64_SIZE>,
    db: &mut[[i64; ENTRY_U64_SIZE]],
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128,
) {
    println!("Starting evaluation and update...");
    let start_eval = Instant::now();

    let precomputed_seeds = dpf_full_eval_precompute_parallel_bytes(server_key, hs_key, aes);
    
    let duration = start_eval.elapsed();
    println!("Precomputation Evaluation and update took: {:?}s ({}ms)", duration.as_secs_f64(), duration.as_millis());

    // for i in 0..db.len(){
    //     for k in 0..ENTRY_U64_SIZE{
    //         db[i][k] = db[i][k].wrapping_add(dpf_eval_fast_bytes::<ENTRY_U64_SIZE>(server_id, server_key, hs_key, i as u32, aes, &precomputed_seeds)[k]);
    //     }
    // }

    // --- Parallelized Loop ---
    db.par_iter_mut()
        .enumerate()
        .for_each(|(i, db_entry)| {
            let eval_result = dpf_eval_fast_bytes::<ENTRY_U64_SIZE>(
                server_id,
                server_key,
                hs_key,
                i as u32,
                aes,
                &precomputed_seeds,
            );

            // Ensure values stay within bounds using modulo arithmetic
            for k in 0..ENTRY_U64_SIZE {
                // Use modulo to keep values within i64 bounds
                db_entry[k] = db_entry[k].wrapping_add(eval_result[k]);
            }
        });
    // --- End of Parallelized Loop ---

    let duration = start_eval.elapsed();
    println!("Evaluation and update took: {:?}s ({}ms)", duration.as_secs_f64(), duration.as_millis());
} 




/// Generates DPF keys for the client based on target points and bucketing.
///
/// # Arguments
/// * `target_points`: Vec of (global_index, value_to_encode) tuples.
/// * `num_buckets`: Total number of buckets.
/// * `bucket_size`: Number of database elements per bucket.
/// * `bucket_bits`: Number of bits needed for a local index within a bucket (log2(bucket_size)).
/// * `hs_key`: Hash seed key for DPF generation.
/// * `aes`: AES cipher instance for DPF generation.
///
/// # Returns
/// A tuple containing:
/// * `client_keys`: Vec<Vec<Vec<DPFKey>>> where client_keys[server_id][bucket_id] holds keys for that server/bucket.
/// * `points_per_bucket`: Vec<usize> tracking the number of actual target points per bucket.
pub fn dmpf_pir_query_gen(
    target_points: &[(u32, u32)],
    num_buckets: usize,
    bucket_size: usize,
    bucket_bits: u32,
    hs_key: [u8; AES_BLOCK_SIZE],
    aes: &Aes128,
) -> (Vec<Vec<Vec<DPFKey>>>, Vec<usize>) {
    // client_keys[server_id][bucket_id] -> Vec<DPFKey>
    let mut client_keys: Vec<Vec<Vec<DPFKey>>> =
        vec![vec![Vec::new(); num_buckets]; 2];
    // Track how many *actual* target points are in each bucket
    let mut points_per_bucket: Vec<usize> = vec![0; num_buckets];

    println!("Generating DPF keys per bucket...");
    for bucket_idx in 0..num_buckets {
        let bucket_start_idx = (bucket_idx * bucket_size) as u32;
        let bucket_end_idx = bucket_start_idx + bucket_size as u32;
        let mut current_bucket_point_count = 0;

        // Find points belonging to the current bucket
        for (global_idx, value) in target_points {
            if *global_idx >= bucket_start_idx && *global_idx < bucket_end_idx {
                let local_idx = global_idx - bucket_start_idx;
                println!(
                    "  Found point {} in bucket {} (local index {})",
                    global_idx, bucket_idx, local_idx
                );
                // Generate keys for this specific point
                let (k0, k1) = dpf_gen(
                    local_idx,
                    *value as u64, // DPF usually encodes the value directly
                    bucket_bits as usize,
                    &hs_key,
                    &aes, 
                );
                client_keys[0][bucket_idx].push(k0);
                client_keys[1][bucket_idx].push(k1);
                current_bucket_point_count += 1;
            }
        }
        points_per_bucket[bucket_idx] = current_bucket_point_count; // Store count

        // If no points found in this bucket, generate keys for a zero function
        if current_bucket_point_count == 0 {
            println!(
                "  No target points in bucket {}. Generating zero function keys.",
                bucket_idx
            );
            let (k0, k1) = dpf_gen(
                0, // Arbitrary index for zero function
                0, // Value is zero
                bucket_bits as usize,
                &hs_key,
                &aes,
            );
            // Still add the keys, but the count remains 0
            client_keys[0][bucket_idx].push(k0);
            client_keys[1][bucket_idx].push(k1);
        }
    }
    println!("DPF key generation complete.");
    (client_keys, points_per_bucket)
}



/// Generates DPF keys for the client. Unique keys are stored, and a layout
/// maps buckets to indices of these keys. Keys generated for target points
/// are reused and distributed to leftover buckets.
///
/// # Returns
/// A tuple containing:
/// * `server0_data`: A tuple `(Vec<DPFKey>, Vec<Vec<usize>>)` for server 0.
///   - The first element is a flat list of unique DPFKey shares.
///   - The second element is the layout: `layout[bucket_id]` gives a `Vec<usize>`
///     of indices into the flat list of keys for that bucket.
/// * `server1_data`: Similar tuple for server 1.
/// * `points_per_bucket`: `Vec<usize>` where `points_per_bucket[i]` is the
///   count of DPF key evaluations assigned to bucket `i`.
pub fn dmpf_pir_query_gen_optimized_layout(
    target_points: &[(u32, u32)],
    num_buckets: usize,
    bucket_size: usize,
    bucket_bits: u32,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128,
) -> (
    (Vec<DPFKey>, Vec<Vec<usize>>), // Server 0 (keys, layout)
    (Vec<DPFKey>, Vec<Vec<usize>>), // Server 1 (keys, layout)
    Vec<usize>,                     // points_per_bucket
) {
    if bucket_size == 0 {
        panic!("bucket_size cannot be zero.");
    }
    if num_buckets == 0 {
        if target_points.is_empty() {
            println!("No target points and no buckets. Returning empty structures.");
            return ((Vec::new(), Vec::new()), (Vec::new(), Vec::new()), vec![]);
        } else {
            panic!("num_buckets is zero but target_points are provided.");
        }
    }
    if target_points.is_empty() {
        println!("No target points. No DPF keys will be generated. All buckets will be empty in layout.");
        let empty_layout = vec![Vec::new(); num_buckets];
        return (
            (Vec::new(), empty_layout.clone()),
            (Vec::new(), empty_layout),
            vec![0; num_buckets],
        );
    }

    // --- Initialization ---
    // For Server 0
    let mut server0_unique_keys: Vec<DPFKey> = Vec::new();
    let mut server0_layout: Vec<Vec<usize>> = vec![Vec::new(); num_buckets];

    // For Server 1
    let mut server1_unique_keys: Vec<DPFKey> = Vec::new();
    let mut server1_layout: Vec<Vec<usize>> = vec![Vec::new(); num_buckets];

    // This will store the count of DPF key evaluations assigned to each bucket.
    let mut points_per_bucket: Vec<usize> = vec![0; num_buckets];

    // Stores (index_in_server0_keys, index_in_server1_keys) for generated pairs.
    let mut generated_key_pair_indices: Vec<(usize, usize)> = Vec::new();
    let mut primary_assigned_buckets: HashSet<usize> = HashSet::new();

    // 1. Generate DPF keys for actual target points, store them uniquely, and build initial layout.
    println!("Generating DPF keys for primary target points...");
    for (global_idx, value) in target_points {
        let target_bucket_idx = (*global_idx / bucket_size as u32) as usize;

        if target_bucket_idx >= num_buckets {
            eprintln!(
                "Warning: Target point global_idx {} (value {}) maps to bucket_idx {}, which is out of range (0-{}). Skipping.",
                global_idx, value, target_bucket_idx, num_buckets - 1
            );
            continue;
        }

        let local_idx = global_idx % bucket_size as u32;
        println!(
            "  Found point {} (value {}) in bucket {} (local index {})",
            global_idx, value, target_bucket_idx, local_idx
        );

        let (k0, k1) = dpf_gen(
            local_idx,
            *value as u64,
            bucket_bits as usize,
            hs_key,
            aes,
        );

        // Store k0 uniquely and get its index
        let k0_idx = server0_unique_keys.len();
        server0_unique_keys.push(k0);
        server0_layout[target_bucket_idx].push(k0_idx);

        // Store k1 uniquely and get its index
        let k1_idx = server1_unique_keys.len();
        server1_unique_keys.push(k1);
        server1_layout[target_bucket_idx].push(k1_idx);

        generated_key_pair_indices.push((k0_idx, k1_idx));
        primary_assigned_buckets.insert(target_bucket_idx);
    }

    // 2. Identify leftover buckets.
    let mut leftover_buckets: Vec<usize> = (0..num_buckets)
        .filter(|b_idx| !primary_assigned_buckets.contains(b_idx))
        .collect();

    // 3. Distribute indices of already generated key pairs to the leftover buckets.
    if !generated_key_pair_indices.is_empty() && !leftover_buckets.is_empty() {
        println!(
            "Distributing indices of {} generated key pairs to {} leftover buckets...",
            generated_key_pair_indices.len(),
            leftover_buckets.len()
        );
        let mut rng = rand::rng();
        leftover_buckets.shuffle(&mut rng);

        for (i, &leftover_bucket_idx) in leftover_buckets.iter().enumerate() {
            // Select a key pair's indices round-robin
            let (k0_idx_to_reuse, k1_idx_to_reuse) =
                generated_key_pair_indices[i % generated_key_pair_indices.len()];

            // Add the index of the reused k0 to server 0's layout for this leftover bucket
            server0_layout[leftover_bucket_idx].push(k0_idx_to_reuse);
            // Add the index of the reused k1 to server 1's layout for this leftover bucket
            server1_layout[leftover_bucket_idx].push(k1_idx_to_reuse);
            println!(
                "  Assigned reused key indices (s0:{}, s1:{}) to leftover bucket {}",
                k0_idx_to_reuse, k1_idx_to_reuse, leftover_bucket_idx
            );
        }
    } else if generated_key_pair_indices.is_empty() && !leftover_buckets.is_empty() {
        println!("Warning: No DPF keys were generated (no valid target points?), so leftover buckets cannot be assigned key indices.");
    } else if !generated_key_pair_indices.is_empty() && leftover_buckets.is_empty() {
        println!("All buckets had primary target points. No leftover buckets to assign reused key indices to.");
    }

    // 4. Calculate points_per_bucket: the number of DPF key evaluations assigned to each bucket.
    // This should be the same for server 0 and server 1 based on their layouts.
    for bucket_idx in 0..num_buckets {
        points_per_bucket[bucket_idx] = server0_layout[bucket_idx].len();
        if server1_layout[bucket_idx].len() != points_per_bucket[bucket_idx] {
            eprintln!(
                "Warning: Mismatch in key assignment count for bucket {} between servers (s0: {}, s1: {}). This should not happen.",
                bucket_idx, points_per_bucket[bucket_idx], server1_layout[bucket_idx].len()
            );
        }
    }

    println!("DPF key generation and layout construction complete.");
    (
        (server0_unique_keys, server0_layout),
        (server1_unique_keys, server1_layout),
        points_per_bucket,
    )
}


/// Evaluates DPF keys for a single server against the database, using the
/// optimized key layout and performing DPF seed precomputation only once per unique key.
///
/// # Arguments
/// * `server_id`: The ID of the server (0 or 1).
/// * `server_data`: A tuple `&(Vec<DPFKey>, Vec<Vec<usize>>)` for this server.
///   - `.0`: Flat list of unique DPFKey shares.
///   - `.1`: Layout where `layout[bucket_id]` gives `Vec<usize>` of indices
///           into the flat list of keys for that bucket.
/// * `db`: A slice representing the entire database.
/// * `num_buckets`: Total number of buckets (should match `server_data.1.len()`).
/// * `bucket_size`: Number of database elements per bucket.
/// * `hs_key`: Hash seed key for DPF evaluation.
/// * `aes`: AES cipher instance for DPF evaluation.
///
/// # Returns
/// `Vec<Vec<[i64; ENTRY_U64_SIZE]>>` where `result[bucket_id]` contains the
/// accumulated evaluation results for each key evaluation in that bucket.
pub fn dmpf_pir_query_eval_optimized_layout<const ENTRY_U64_SIZE: usize>(
    server_id: usize,
    server_data: &(Vec<DPFKey>, Vec<Vec<usize>>), // Optimized server data
    db: &[Entry<ENTRY_U64_SIZE>],
    num_buckets: usize,
    bucket_size: usize,
    hs_key: &[u8; 16], 
    aes: &Aes128,
) -> Vec<Vec<[i64; ENTRY_U64_SIZE]>> {
    println!(
        "Server {} starting evaluation with optimized layout and one-time precomputation...",
        server_id
    );
    let overall_start_time = Instant::now();

    let (unique_keys, layout) = server_data;

    // Validate that the layout matches the expected number of buckets
    if layout.len() != num_buckets {
        panic!(
            "Layout size ({}) does not match num_buckets ({}).",
            layout.len(),
            num_buckets
        );
    }

    // Handle cases where there are no keys to process
    if unique_keys.is_empty() {
        println!("Server {}: No unique DPF keys to process. Returning empty results for {} buckets.", server_id, num_buckets);
        // Ensure the output structure is consistent: a Vec of empty Vecs for each bucket
        let empty_results_per_bucket = vec![Vec::new(); num_buckets];
        let duration = overall_start_time.elapsed();
        println!("Server {} evaluation (no keys) complete in {:?}", server_id, duration);
        return empty_results_per_bucket;
    }
     // Further consistency check: if layout expects keys but unique_keys is empty
    if layout.iter().any(|v| !v.is_empty()) && unique_keys.is_empty() {
        panic!("Layout expects DPF keys for some buckets, but the unique_keys list is empty. Inconsistent state.");
    }


    // 1. Precompute seeds for ALL unique keys ONCE and in parallel.
    //    The resulting Vec will have its indices aligned with `unique_keys`.
    let precomputation_start_time = Instant::now();
    println!(
        "Server {}: Starting precomputation for {} unique DPF keys...",
        server_id,
        unique_keys.len()
    );
    let all_globally_precomputed_seeds: Vec<Vec<[u8; AES_BLOCK_SIZE]>> = unique_keys
        .par_iter() // Parallel iterator over the unique DPFKey objects
        .map(|key| {
            // This closure runs in parallel for each unique key.
            // hs_key and aes are captured by reference (they must be Sync).
            dpf_full_eval_precompute_parallel(key, hs_key, aes)
        })
        .collect(); // Collects Vec<[u8; AES_BLOCK_SIZE]> for each key

    let precomputation_duration = precomputation_start_time.elapsed();
    println!(
        "Server {}: Precomputation for {} unique keys took: {:?}",
        server_id,
        unique_keys.len(),
        precomputation_duration
    );

    // 2. Process buckets in parallel, using the globally precomputed seeds.
    let bucket_evaluation_start_time = Instant::now();
    println!(
        "Server {}: Starting parallel evaluation for {} buckets...",
        server_id, num_buckets
    );

    let collected_results: Vec<Vec<[i64; ENTRY_U64_SIZE]>> = (0..num_buckets)
        .into_par_iter()
        .map(|bucket_idx| {
            let bucket_start_idx = bucket_idx * bucket_size;
            // Get the list of key *indices* for this server and this bucket_idx
            let key_indices_for_this_bucket = &layout[bucket_idx];
            let num_key_evals_in_bucket = key_indices_for_this_bucket.len();

            // Initialize result vector local to this parallel task.
            let mut bucket_results: Vec<[i64; ENTRY_U64_SIZE]> =
                vec![[0i64; ENTRY_U64_SIZE]; num_key_evals_in_bucket];

            // Outer loop over the *indices* of keys assigned to this bucket.
            for (eval_idx_in_bucket, &actual_key_idx) in
                key_indices_for_this_bucket.iter().enumerate()
            {
                // Validate actual_key_idx against both unique_keys and precomputed_seeds
                if actual_key_idx >= unique_keys.len() || actual_key_idx >= all_globally_precomputed_seeds.len() {
                    eprintln!(
                        "Error: Key index {} is out of bounds (unique_keys_len: {}, precomputed_seeds_len: {}). Skipping eval for bucket {}.",
                        actual_key_idx, unique_keys.len(), all_globally_precomputed_seeds.len(), bucket_idx
                    );
                    bucket_results[eval_idx_in_bucket] = [0i64; ENTRY_U64_SIZE]; // Fill with zeros
                    continue;
                }

                let key = &unique_keys[actual_key_idx];
                // Retrieve the globally precomputed seeds for this specific key
                let current_key_precomputed_seeds = &all_globally_precomputed_seeds[actual_key_idx];

                // Inner loop over DB entries in the current bucket
                for local_db_idx in 0..bucket_size {
                    let global_db_idx = bucket_start_idx + local_db_idx;

                    if global_db_idx >= db.len() {
                        continue; // Bucket might extend beyond actual DB size
                    }

                    let db_item_u64: &Entry<ENTRY_U64_SIZE> = &db[global_db_idx];

                    // Evaluate the key quickly using its globally precomputed seeds.
                    let eval_share = dpf_eval_fast(
                        server_id as u8,
                        key, // The actual DPFKey object
                        hs_key,
                        local_db_idx as u32, // DPF eval uses local index within bucket
                        aes,
                        current_key_precomputed_seeds, // Pass the precomputed seeds
                    );

                    // Accumulate the result
                    for k_comp in 0..ENTRY_U64_SIZE {
                        bucket_results[eval_idx_in_bucket][k_comp] = bucket_results
                            [eval_idx_in_bucket][k_comp]
                            .wrapping_add(eval_share.wrapping_mul(db_item_u64[k_comp] as i64));
                    }
                }
            }
            bucket_results
        })
        .collect();

    let bucket_evaluation_duration = bucket_evaluation_start_time.elapsed();
    let overall_duration = overall_start_time.elapsed();

    println!("Server {} evaluation complete.", server_id);
    println!("  Total time:      {:?}", overall_duration);
    println!("  Precomputation:  {:?} (for {} unique keys)", precomputation_duration, unique_keys.len());
    println!("  Bucket Eval:     {:?} (for {} buckets)", bucket_evaluation_duration, num_buckets);

    collected_results
}

/// Evaluates DPF keys for a single server against the database.
///
/// This function processes all buckets assigned to this server, potentially in parallel.
///
/// # Arguments
/// * `server_id`: The ID of the server (0 or 1).
/// * `server_keys`: The DPF keys assigned to this server (`Vec<Vec<DPFKey>>` where outer vec is by bucket).
/// * `db`: A slice representing the entire database or the relevant portion.
/// * `num_buckets`: Total number of buckets.
/// * `bucket_size`: Number of database elements per bucket.
/// * `hs_key`: Hash seed key for DPF evaluation.
/// * `aes`: AES cipher instance for DPF evaluation.
///
/// # Returns
/// `Vec<Vec<ENTRY>>` where result[bucket_id] contains the accumulated evaluation results
/// (shares) for each key corresponding to that bucket.
pub fn dmpf_pir_query_eval<const ENTRY_U64_SIZE: usize>(
    server_id: usize,
    server_keys: &[Vec<DPFKey>], 
    db: &[Entry<ENTRY_U64_SIZE>],
    num_buckets: usize,
    bucket_size: usize,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128, // Pass AES by reference
) -> Vec<Vec<[i64; ENTRY_U64_SIZE]>> {
    println!("Server {} starting evaluation...", server_id);
    let start = Instant::now();

    // Process buckets in parallel
    let collected_results: Vec<Vec<[i64; ENTRY_U64_SIZE]>> = (0..num_buckets)
        .into_par_iter()
        .map(|bucket_idx| {
            let bucket_start_idx = bucket_idx * bucket_size;
            let keys = &server_keys[bucket_idx]; // Keys for this server, this bucket
            let num_keys_in_bucket = keys.len();

            // Initialize result vector local to this parallel task
            let mut bucket_results: Vec<[i64; ENTRY_U64_SIZE]> = vec![[0i64; ENTRY_U64_SIZE]; num_keys_in_bucket];

            // Outer loop over keys for this bucket
            for key_idx in 0..num_keys_in_bucket {
                let key = &keys[key_idx];

                // Precompute seeds for the current key
                // Note: Cloning AES here if precompute needs its own instance
                let precomputed_seeds =
                    dpf_full_eval_precompute_parallel(key, hs_key, aes);

                // Inner loop over DB entries in the bucket
                for local_idx in 0..bucket_size {
                    let global_idx = bucket_start_idx + local_idx;

                    if global_idx >= db.len() {
                        continue; // Skip if out of DB bounds
                    }
                    
                    let db_item_u64: &Entry<ENTRY_U64_SIZE> = &db[global_idx];

                    // Evaluate the key quickly using precomputed data
                    let eval_share = dpf_eval_fast(
                        server_id as u8,
                        key,
                        hs_key,
                        local_idx as u32,
                        aes,
                        &precomputed_seeds,
                    );

                    // Accumulate the result: share * db_value
                    for k in 0..ENTRY_U64_SIZE {
                        bucket_results[key_idx][k] = bucket_results[key_idx][k].wrapping_add(eval_share.wrapping_mul(db_item_u64[k] as i64));
                    }

                }
            }
            // Return the computed results (shares) for this bucket
            bucket_results
        })
        .collect(); // Collect the Vec<i64> results from all parallel bucket tasks

    let duration = start.elapsed();
    println!(
        "Server {} evaluation complete,",
        server_id
    );
    println!("Time taken: {:?}", duration);
    println!("In seconds: {:.2}s", duration.as_secs_f64());
    println!("In milliseconds: {}ms", duration.as_millis());

    collected_results // This is already Vec<Vec<[i64; ENTRY_U64_SIZE]>> indexed by bucket_idx
}


pub fn dmpf_pir_query_eval_additive<const ENTRY_U64_SIZE: usize>(
    server_id: usize,
    server_keys: &[Vec<DPFKey>], 
    db: &[[i64; ENTRY_U64_SIZE]],
    num_buckets: usize,
    bucket_size: usize,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128,
) -> Vec<Vec<[i64; ENTRY_U64_SIZE]>> {
    println!("Server {} starting evaluation...", server_id);
    let start = Instant::now();

    // Process buckets in parallel
    let collected_results: Vec<Vec<[i64; ENTRY_U64_SIZE]>> = (0..num_buckets)
        .into_par_iter()
        .map(|bucket_idx| {
            let bucket_start_idx = bucket_idx * bucket_size;
            let keys = &server_keys[bucket_idx]; // Keys for this server, this bucket
            let num_keys_in_bucket = keys.len();

            // Initialize result vector local to this parallel task
            let mut bucket_results: Vec<[i64; ENTRY_U64_SIZE]> = vec![[0i64; ENTRY_U64_SIZE]; num_keys_in_bucket];

            // Outer loop over keys for this bucket
            for key_idx in 0..num_keys_in_bucket {
                let key = &keys[key_idx];

                // Precompute seeds for the current key
                // Note: Cloning AES here if precompute needs its own instance
                let precomputed_seeds =
                    dpf_full_eval_precompute_parallel(key, hs_key, aes);

                // Inner loop over DB entries in the bucket
                for local_idx in 0..bucket_size {
                    let global_idx = bucket_start_idx + local_idx;

                    if global_idx >= db.len() {
                        continue; // Skip if out of DB bounds
                    }
                    
                    let db_item_u64 = &db[global_idx];

                    // Evaluate the key quickly using precomputed data
                    let eval_share = dpf_eval_fast(
                        server_id as u8,
                        key,
                        hs_key,
                        local_idx as u32,
                        aes,
                        &precomputed_seeds,
                    );

                    // Accumulate the result: share * db_value
                    for k in 0..ENTRY_U64_SIZE {
                        bucket_results[key_idx][k] = bucket_results[key_idx][k].wrapping_add(eval_share.wrapping_mul(db_item_u64[k] as i64));
                    }

                }
            }
            // Return the computed results (shares) for this bucket
            bucket_results
        })
        .collect(); // Collect the Vec<i64> results from all parallel bucket tasks

    let duration = start.elapsed();
    println!(
        "Server {} evaluation complete,",
        server_id
    );
    println!("Time taken: {:?}", duration);
    println!("In seconds: {:.2}s", duration.as_secs_f64());
    println!("In milliseconds: {}ms", duration.as_millis());

    collected_results // This is already Vec<Vec<[i64; ENTRY_U64_SIZE]>> indexed by bucket_idx
}

/// Reconstructs the final results (vectors) from server shares and formats them into Slots.
///
/// # Arguments
/// * `results0`: Result shares from server 0 (`Vec<Vec<[i64; ENTRY_U64_SIZE]>>`).
/// * `results1`: Result shares from server 1 (`Vec<Vec<[i64; ENTRY_U64_SIZE]>>`).
/// * `points_per_bucket`: Tracks the number of actual target points per bucket.
/// * `num_buckets`: Total number of buckets.
/// * `ENTRY_U64_SIZE`: The dimension of the entry vectors (e.g., 32 for 256 bytes).
///
/// # Returns
/// `Vec<Slot<ENTRY_U64_SIZE>>` containing the reconstructed vector results.
pub fn dmpf_pir_reconstruct<const ENTRY_U64_SIZE: usize>(
    results0: &[Vec<[i64; ENTRY_U64_SIZE]>], 
    results1: &[Vec<[i64; ENTRY_U64_SIZE]>], 
    points_per_bucket: &[usize],            
    num_buckets: usize,
) -> Vec<Slot<ENTRY_U64_SIZE>> {
    println!("\n--- Client-Side Reconstruction (Vector) ---");
    let mut reconstructed_slots: Vec<Slot<ENTRY_U64_SIZE>> =
        Vec::with_capacity(num_buckets);

    // Basic validation
    if results0.len() != num_buckets || results1.len() != num_buckets {
        panic!(
            "Mismatched number of buckets in results ({} vs {} vs {})",
            results0.len(),
            results1.len(),
            num_buckets
        );
    }
    if points_per_bucket.len() != num_buckets {
         panic!(
            "Mismatched number of buckets in points_per_bucket ({} vs {})",
            points_per_bucket.len(),
            num_buckets
        );
    }


    for bucket_idx in 0..num_buckets {
        let bucket_res0 = &results0[bucket_idx]; // &Vec<[i64; ENTRY_U64_SIZE]>
        let bucket_res1 = &results1[bucket_idx]; // &Vec<[i64; ENTRY_U64_SIZE]>

        if bucket_res0.len() != bucket_res1.len() {
            panic!(
                "Mismatched number of results in bucket {} ({} vs {})",
                bucket_idx,
                bucket_res0.len(),
                bucket_res1.len()
            );
        }
        let num_results_in_bucket = bucket_res0.len(); // Num keys for this bucket

        // Combine result vectors element-wise for each key result in the bucket
        let mut combined_results_i64: Vec<[i64; ENTRY_U64_SIZE]> =
            vec![[0i64; ENTRY_U64_SIZE]; num_results_in_bucket];

        for i in 0..num_results_in_bucket { // Iterate through key results
            for k in 0..ENTRY_U64_SIZE { // Iterate through vector components
                combined_results_i64[i][k] =
                    bucket_res0[i][k].wrapping_add(bucket_res1[i][k]);
            }
        }

        // Determine the Slot type based on the number of *actual* points requested
        match points_per_bucket[bucket_idx] {
            0 => {
                // Bucket had no target points (used zero key). Result should be zero vector.
                if combined_results_i64.len() != 1 {
                    eprintln!(
                        "Warning: Expected 1 result vector for empty bucket {}, got {}",
                        bucket_idx,
                        combined_results_i64.len()
                    );
                    // Handle error or push default? Pushing default zero.
                }
                // Create an explicit zero entry
                let zero_entry: Entry<ENTRY_U64_SIZE> = [0u64; ENTRY_U64_SIZE];
                reconstructed_slots.push(Slot::Single(zero_entry));
            }
            1 => {
                // Bucket had exactly one target point.
                if combined_results_i64.len() != 1 {
                     eprintln!(
                        "Warning: Expected 1 result vector for single-point bucket {}, got {}",
                        bucket_idx,
                        combined_results_i64.len()
                    );
                     // Handle error or push default? Pushing default zero.
                     reconstructed_slots.push(Slot::Single([0u64; ENTRY_U64_SIZE]));
                     continue; // Skip to next bucket
                }

                // Convert the single combined i64 vector to a u64 vector (Entry)
                let result_i64 = &combined_results_i64[0];
                let mut result_u64: Entry<ENTRY_U64_SIZE> = [0u64; ENTRY_U64_SIZE];
                for k in 0..ENTRY_U64_SIZE {
                    // Direct cast assumes PIR correctly reconstructs non-negative values
                    result_u64[k] = result_i64[k] as u64;
                }
                reconstructed_slots.push(Slot::Single(result_u64));
            }
            _ => {
                // Bucket had multiple target points.
                // Convert each combined i64 vector to a u64 vector (Entry)
                let mut results_u64: Vec<Entry<ENTRY_U64_SIZE>> =
                    Vec::with_capacity(num_results_in_bucket);

                for result_i64 in combined_results_i64.iter() {
                    let mut result_u64: Entry<ENTRY_U64_SIZE> = [0u64; ENTRY_U64_SIZE];
                    for k in 0..ENTRY_U64_SIZE {
                        result_u64[k] = result_i64[k] as u64;
                    }
                    results_u64.push(result_u64);
                }
                reconstructed_slots.push(Slot::Many(results_u64));
            }
        }
    }

    println!("Reconstruction complete.");
    reconstructed_slots
}




/// Reconstructs the final results (vectors) from shares provided by multiple servers
/// and formats them into Slots.
///
/// # Arguments
/// * `all_server_results`: A slice where each element contains the results from one server.
///   The structure is `&[Vec<Vec<[i64; ENTRY_U64_SIZE]>>]`.
///   - Outer slice: Index corresponds to the server ID.
///   - First `Vec`: Index corresponds to the `bucket_id`.
///   - Second `Vec`: Index corresponds to the specific DPF key result within that bucket.
///   - `[i64; ENTRY_U64_SIZE]`: The vector share for that key from that server for that bucket.
/// * `points_per_bucket`: Tracks the number of actual target points per bucket.
/// * `num_buckets`: Total number of buckets.
/// * `ENTRY_U64_SIZE`: The dimension of the entry vectors (e.g., 32 for 256 bytes).
///
/// # Returns
/// `Vec<Slot<ENTRY_U64_SIZE>>` containing the reconstructed vector results.
///
/// # Panics
/// Panics if:
/// * `all_server_results` is empty.
/// * The number of servers is inconsistent with the results structure.
/// * The number of buckets reported by servers is inconsistent.
/// * The number of results within a specific bucket is inconsistent across servers.
/// * `points_per_bucket` length doesn't match `num_buckets`.
pub fn dmpf_pir_reconstruct_servers<const ENTRY_U64_SIZE: usize>(
    all_server_results: &[Vec<Vec<[i64; ENTRY_U64_SIZE]>>],
    points_per_bucket: &[usize],
    num_buckets: usize,
) -> Vec<Slot<ENTRY_U64_SIZE>> {
    println!("\n--- Client-Side Reconstruction (Multi-Server Vector) ---");

    // --- Initial Validation ---
    if all_server_results.is_empty() {
        panic!("Received results from zero servers.");
    }
    let num_servers = all_server_results.len();
    println!("Reconstructing from {} servers.", num_servers);

    // Check if all servers reported results for the expected number of buckets
    for (server_id, results) in all_server_results.iter().enumerate() {
        if results.len() != num_buckets {
            panic!(
                "Server {} reported results for {} buckets, expected {}",
                server_id,
                results.len(),
                num_buckets
            );
        }
    }

    if points_per_bucket.len() != num_buckets {
        panic!(
            "points_per_bucket length ({}) does not match num_buckets ({})",
            points_per_bucket.len(),
            num_buckets
        );
    }

    // --- Reconstruction Loop ---
    let mut reconstructed_slots: Vec<Slot<ENTRY_U64_SIZE>> =
        Vec::with_capacity(num_buckets);

    for bucket_idx in 0..num_buckets {
        // Determine the expected number of results (keys) in this bucket from the first server
        let num_results_in_bucket = if let Some(first_server_bucket) =
            all_server_results.get(0).and_then(|res| res.get(bucket_idx))
        {
            first_server_bucket.len()
        } else {
            // This case should ideally not happen due to earlier checks, but defensively:
            panic!("Could not access results for bucket {} from server 0", bucket_idx);
        };

        // Validate that all other servers have the same number of results for this bucket
        for server_id in 1..num_servers {
             if let Some(current_server_bucket) =
                all_server_results.get(server_id).and_then(|res| res.get(bucket_idx))
             {
                 if current_server_bucket.len() != num_results_in_bucket {
                     panic!(
                        "Mismatched number of results in bucket {} between server 0 ({}) and server {} ({})",
                        bucket_idx,
                        num_results_in_bucket,
                        server_id,
                        current_server_bucket.len()
                    );
                 }
             } else {
                 panic!("Could not access results for bucket {} from server {}", bucket_idx, server_id);
             }
        }


        // Combine result vectors element-wise across all servers for each key result
        let mut combined_results_i64: Vec<[i64; ENTRY_U64_SIZE]> =
            vec![[0i64; ENTRY_U64_SIZE]; num_results_in_bucket];

        for i in 0..num_results_in_bucket { // Iterate through key results
            for k in 0..ENTRY_U64_SIZE { // Iterate through vector components
                // Sum the k-th component of the i-th result across all servers
                let mut component_sum = 0i64;
                for server_id in 0..num_servers {
                    // Access is safe due to previous checks
                    let server_share = all_server_results[server_id][bucket_idx][i][k];
                    component_sum = component_sum.wrapping_add(server_share);
                }
                combined_results_i64[i][k] = component_sum;
            }
        }

        // Determine the Slot type based on the number of *actual* points requested
        match points_per_bucket[bucket_idx] {
             0 => {
                // Bucket had no target points (used zero key). Result should be zero vector.
                if num_results_in_bucket != 1 {
                    eprintln!(
                        "Warning: Expected 1 result vector for empty bucket {}, got {}",
                        bucket_idx,
                        num_results_in_bucket
                    );
                    // Decide on error handling: push default zero or panic? Pushing default.
                }
                // Create an explicit zero entry
                let zero_entry: Entry<ENTRY_U64_SIZE> = [0u64; ENTRY_U64_SIZE];
                reconstructed_slots.push(Slot::Single(zero_entry));
            }
            1 => {
                // Bucket had exactly one target point.
                if num_results_in_bucket != 1 {
                     eprintln!(
                        "Warning: Expected 1 result vector for single-point bucket {}, got {}",
                        bucket_idx,
                        num_results_in_bucket
                    );
                     // Push default zero and continue
                     reconstructed_slots.push(Slot::Single([0u64; ENTRY_U64_SIZE]));
                     continue; // Skip to next bucket
                }

                // Convert the single combined i64 vector to a u64 vector (Entry)
                let result_i64 = &combined_results_i64[0];
                let mut result_u64: Entry<ENTRY_U64_SIZE> = [0u64; ENTRY_U64_SIZE];
                for k in 0..ENTRY_U64_SIZE {
                    // Direct cast assumes PIR correctly reconstructs non-negative values
                    // or that the underlying field handles potential negative wraps correctly.
                    result_u64[k] = result_i64[k] as u64;
                }
                reconstructed_slots.push(Slot::Single(result_u64));
            }
            _ => {
                // Bucket had multiple target points.
                // Convert each combined i64 vector to a u64 vector (Entry)
                let mut results_u64: Vec<Entry<ENTRY_U64_SIZE>> =
                    Vec::with_capacity(num_results_in_bucket);

                for result_i64 in combined_results_i64.iter() {
                    let mut result_u64: Entry<ENTRY_U64_SIZE> = [0u64; ENTRY_U64_SIZE];
                    for k in 0..ENTRY_U64_SIZE {
                        result_u64[k] = result_i64[k] as u64;
                    }
                    results_u64.push(result_u64);
                }
                reconstructed_slots.push(Slot::Many(results_u64));
            }
        }
    }

    println!("Reconstruction complete.");
    reconstructed_slots
}