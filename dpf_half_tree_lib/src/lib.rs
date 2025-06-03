#![allow(non_snake_case)]
use std::time::Instant;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt};
use aes::Aes128;
use aes::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;
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

// Helper for XORing byte arrays (most likely optimization happens automatically since i didnt notice difference, thus no manual SIMD needed)
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
    // Fallback to scalar implementation
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
pub struct DPFKeyBytes<const ENTRY_U64_SIZE: usize> {
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
            cw_levels: cw_levels.clone(), 
            cw_n: (hcw, lcw0, lcw1),
            cw_np1,
        },
        DPFKey {
            n,
            seed: s1_initial,
            cw_levels, 
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
) -> (DPFKeyBytes<ENTRY_U64_SIZE>, DPFKeyBytes<ENTRY_U64_SIZE>) {
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
        DPFKeyBytes {
            n,
            seed: s0_initial,
            cw_levels: cw_levels.clone(), // Clone here
            cw_n: (hcw, lcw0, lcw1),
            cw_np1,
        },
        DPFKeyBytes {
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


pub fn dpf_eval_full_optimized(
    b: u8,
    key: &DPFKey,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128,
) -> Vec<i64> {
    let n = key.n;
    if n == 0 {
        return vec![];
    }

    let num_cw_levels = key.cw_levels.len();
    let total_outputs = 1 << n;
    let mut result = vec![0i64; total_outputs];

    // Pre-allocate all buffers once
    let mut hs_out_buffer = [0u8; AES_BLOCK_SIZE];
    let mut hash_input_buffer = [0u8; AES_BLOCK_SIZE];
    let mut temp_buffer = [0u8; AES_BLOCK_SIZE];

    // Pre-compute HCW with LCW values to avoid repeated work
    let mut hcw_with_lcw0 = [0u8; AES_BLOCK_SIZE];
    let mut hcw_with_lcw1 = [0u8; AES_BLOCK_SIZE];
    hcw_with_lcw0[..AES_BLOCK_SIZE - 1].copy_from_slice(&key.cw_n.0);
    hcw_with_lcw0[AES_BLOCK_SIZE - 1] = key.cw_n.1;
    hcw_with_lcw1[..AES_BLOCK_SIZE - 1].copy_from_slice(&key.cw_n.0);
    hcw_with_lcw1[AES_BLOCK_SIZE - 1] = key.cw_n.2;

    // Pre-compute sign multiplier
    let sign = if b == 0 { 1i64 } else { -1i64 };

    let mut current_seeds = vec![key.seed];
    let mut next_seeds = Vec::new();

    // Phase 1: Tree expansion for levels 0 to n-2
    for i in 0..num_cw_levels {
        let cw_i = &key.cw_levels[i];
        next_seeds.clear();
        next_seeds.reserve(current_seeds.len() * 2);

        for prev_seed in &current_seeds {
            let current_t = prev_seed[AES_BLOCK_SIZE - 1] & 1;
            hs(hs_key, prev_seed, aes, &mut hs_out_buffer);

            // Path for x_i = 0
            let mut next_seed_0 = hs_out_buffer;
            if current_t == 1 {
                xor_bytes(&mut next_seed_0, cw_i);
            }
            next_seeds.push(next_seed_0);

            // Path for x_i = 1 (reuse hs_out_buffer)
            xor_bytes(&mut hs_out_buffer, prev_seed);
            if current_t == 1 {
                xor_bytes(&mut hs_out_buffer, cw_i);
            }
            next_seeds.push(hs_out_buffer);
        }
        std::mem::swap(&mut current_seeds, &mut next_seeds);
    }

    // Phase 2: Final level processing (level n-1)
    let mut output_index = 0;

    for current_seed in current_seeds {
        let t_for_final = current_seed[AES_BLOCK_SIZE - 1] & 1;

        // Process both final branches (x_n = 0 and x_n = 1)
        for x_bit in 0u8..2u8 {
            // Prepare hash input
            hash_input_buffer = current_seed;
            hash_input_buffer[AES_BLOCK_SIZE - 1] = t_for_final ^ x_bit;
            
            hs(hs_key, &hash_input_buffer, aes, &mut temp_buffer);

            // Apply correction word if needed
            if t_for_final == 1 {
                let hcw_to_use = if x_bit == 0 { &hcw_with_lcw0 } else { &hcw_with_lcw1 };
                xor_bytes(&mut temp_buffer, hcw_to_use);
            }

            // Normalize final seed - ensure only t_n bit remains in last byte
            let t_n = temp_buffer[AES_BLOCK_SIZE - 1] & 1;
            temp_buffer[AES_BLOCK_SIZE - 1] = t_n;

            // ConvertG for final output (only using s_n part)
            let convert_out = convert_g_final(&temp_buffer, aes);

            // Calculate y_b = (-1)^b * (ConvertG(s_n) + t_n * CW_{n+1})
            let t_term = if t_n == 1 { key.cw_np1 } else { 0 };
            let final_result = sign.wrapping_mul(convert_out.wrapping_add(t_term));

            if output_index < result.len() {
                result[output_index] = final_result;
                output_index += 1;
            }
        }
    }

    result
}



pub fn dpf_eval_bytes<const ENTRY_U64_SIZE: usize>(
    b: u8,
    key: &DPFKeyBytes<ENTRY_U64_SIZE>,
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


pub fn dpf_eval_bytes_full_optimized<const ENTRY_U64_SIZE: usize>(
    b: u8,
    key: &DPFKeyBytes<ENTRY_U64_SIZE>,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128,
) -> Vec<[i64; ENTRY_U64_SIZE]> {
    let n = key.n;
    if n == 0 {
        return vec![];
    }

    let num_cw_levels = key.cw_levels.len();
    let total_outputs = 1 << n;
    let mut result = vec![[0i64; ENTRY_U64_SIZE]; total_outputs];

    // Pre-allocate all buffers once
    let mut hs_out_buffer = [0u8; AES_BLOCK_SIZE];
    let mut hash_input_buffer = [0u8; AES_BLOCK_SIZE];
    let mut temp_buffer = [0u8; AES_BLOCK_SIZE];

    // Pre-compute HCW with LCW values to avoid repeated work
    let mut hcw_with_lcw0 = [0u8; AES_BLOCK_SIZE];
    let mut hcw_with_lcw1 = [0u8; AES_BLOCK_SIZE];
    hcw_with_lcw0[..AES_BLOCK_SIZE - 1].copy_from_slice(&key.cw_n.0);
    hcw_with_lcw0[AES_BLOCK_SIZE - 1] = key.cw_n.1;
    hcw_with_lcw1[..AES_BLOCK_SIZE - 1].copy_from_slice(&key.cw_n.0);
    hcw_with_lcw1[AES_BLOCK_SIZE - 1] = key.cw_n.2;

    // Pre-compute sign multiplier
    let sign = if b == 0 { 1i64 } else { -1i64 };

    let mut current_seeds = vec![key.seed];
    let mut next_seeds = Vec::new();

    // Phase 1: Tree expansion for levels 0 to n-2
    for i in 0..num_cw_levels {
        let cw_i = &key.cw_levels[i];
        next_seeds.clear();
        next_seeds.reserve(current_seeds.len() * 2);

        for prev_seed in &current_seeds {
            let current_t = prev_seed[AES_BLOCK_SIZE - 1] & 1;
            hs(hs_key, prev_seed, aes, &mut hs_out_buffer);

            // Path for x_i = 0
            let mut next_seed_0 = hs_out_buffer;
            if current_t == 1 {
                xor_bytes(&mut next_seed_0, cw_i);
            }
            next_seeds.push(next_seed_0);

            // Path for x_i = 1 (reuse hs_out_buffer)
            xor_bytes(&mut hs_out_buffer, prev_seed);
            if current_t == 1 {
                xor_bytes(&mut hs_out_buffer, cw_i);
            }
            next_seeds.push(hs_out_buffer);
        }
        std::mem::swap(&mut current_seeds, &mut next_seeds);
    }

    // Phase 2: Final level processing (level n-1)
    let mut output_index = 0;

    for current_seed in current_seeds {
        let t_for_final = current_seed[AES_BLOCK_SIZE - 1] & 1;

        // Process both final branches (x_n = 0 and x_n = 1)
        for x_bit in 0u8..2u8 {
            // Prepare hash input
            hash_input_buffer = current_seed;
            hash_input_buffer[AES_BLOCK_SIZE - 1] = t_for_final ^ x_bit;
            
            hs(hs_key, &hash_input_buffer, aes, &mut temp_buffer);

            // Apply correction word if needed
            if t_for_final == 1 {
                let hcw_to_use = if x_bit == 0 { &hcw_with_lcw0 } else { &hcw_with_lcw1 };
                xor_bytes(&mut temp_buffer, hcw_to_use);
            }

            // Normalize final seed - ensure only t_n bit remains in last byte
            let t_n = temp_buffer[AES_BLOCK_SIZE - 1] & 1;
            temp_buffer[AES_BLOCK_SIZE - 1] = t_n;

            // ConvertG for final output (only using s_n part)
            let convert_out = convert_g_bytes::<ENTRY_U64_SIZE>(&temp_buffer, aes);

            // Calculate y_b = (-1)^b * (ConvertG(s_n) + t_n * CW_{n+1}) for each entry
            if output_index < result.len() {
                for k in 0..ENTRY_U64_SIZE {
                    let t_term = if t_n == 1 { key.cw_np1[k] } else { 0 };
                    result[output_index][k] = sign.wrapping_mul(
                        convert_out[k].wrapping_add(t_term)
                    );
                }
                output_index += 1;
            }
        }
    }

    result
}



pub fn dpf_priv_update_gen_buckets<const ENTRY_U64_SIZE: usize>(
    target_points: &[(u32, [u64; ENTRY_U64_SIZE])],
    num_buckets: usize,
    bucket_size: usize,
    bucket_bits: u32,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128, 
) -> Vec<Vec<DPFKeyBytes<ENTRY_U64_SIZE>>> {
    // client_keys[server_id][bucket_id] -> DPFKey
    let mut client_keys: Vec<Vec<DPFKeyBytes<ENTRY_U64_SIZE>>> =
        vec![Vec::with_capacity(num_buckets); 2];

    for server_id in 0..2 {
        for _ in 0..num_buckets {
            // Initialize with dummy values that will be overwritten
            // This ensures proper length so we can index into client_keys[server_id][bucket_idx]
            client_keys[server_id].push(DPFKeyBytes {
                n: 0,
                seed: [0u8; AES_BLOCK_SIZE],
                cw_levels: Vec::new(),
                cw_n: ([0u8; AES_BLOCK_SIZE - 1], 0, 0),
                cw_np1: [0i64; ENTRY_U64_SIZE],
            });
        }
    }

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
                client_keys[0][bucket_idx] = k0;
                client_keys[1][bucket_idx] = k1;
                current_bucket_point_count += 1;
            }
        }

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
            client_keys[0][bucket_idx] = k0;
            client_keys[1][bucket_idx] = k1;
        }
    }
    println!("DPF key generation complete.");
    client_keys
}


pub fn dpf_priv_update_additive_buckets<const ENTRY_U64_SIZE: usize>(
    server_id: u8,
    server_keys: &[DPFKeyBytes<ENTRY_U64_SIZE>], 
    db: &mut[[i64; ENTRY_U64_SIZE]],
    bucket_size: &usize,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128,
) {
    println!("Server {} starting evaluation...", server_id);
    let start = Instant::now();

    // Process buckets in parallel using par_iter_mut
    db.par_chunks_mut(*bucket_size)
        .enumerate()
        .for_each(|(bucket_idx, bucket)| {
            let server_key = &server_keys[bucket_idx]; // Keys for this server, this bucket
            let precomputed_seeds = dpf_eval_bytes_full_optimized(server_id, server_key, hs_key, aes);

            // Inner loop over DB entries in the bucket
            for (local_idx, db_entry) in bucket.iter_mut().enumerate() {

                let eval_result = precomputed_seeds[local_idx];
                for k in 0..ENTRY_U64_SIZE {
                    db_entry[k] = db_entry[k].wrapping_add(eval_result[k]);
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
    server_key: &DPFKeyBytes<ENTRY_U64_SIZE>,
    db: &mut[[i64; ENTRY_U64_SIZE]],
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128,
) {
    println!("Starting evaluation and update...");
    let start_eval = Instant::now();

    let precomputed_seeds = dpf_full_eval_precompute_parallel_bytes(server_key, hs_key, aes);
    //let precomputed_seeds = dpf_eval_bytes_full_optimized(server_id, server_key, hs_key, aes);
    
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

            // let eval_result = precomputed_seeds[i];
            // for k in 0..ENTRY_U64_SIZE {
            //     db_entry[k] = db_entry[k].wrapping_add(eval_result[k]);
            // }


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
/// * `client_keys`: Vec<Vec<DPFKey>> where client_keys[server_id][bucket_id] holds key for that server/bucket.
pub fn dmpf_pir_query_gen(
    target_points: &[(u32, u32)],
    num_buckets: usize,
    bucket_size: usize,
    bucket_bits: u32,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128,
) -> Vec<Vec<DPFKey>> {
    // client_keys[server_id][bucket_id] -> DPFKey
    let mut client_keys: Vec<Vec<DPFKey>> =
        vec![Vec::with_capacity(num_buckets); 2];

    for server_id in 0..2 {
        for _ in 0..num_buckets {
            // Initialize with dummy values that will be overwritten
            // This ensures proper length so we can index into client_keys[server_id][bucket_idx]
            client_keys[server_id].push(DPFKey {
                n: 0,
                seed: [0u8; AES_BLOCK_SIZE],
                cw_levels: Vec::new(),
                cw_n: ([0u8; AES_BLOCK_SIZE - 1], 0, 0),
                cw_np1: 0,
            });
        }
    }

    //println!("Generating DPF keys per bucket...");
    for bucket_idx in 0..num_buckets {
        let bucket_start_idx = (bucket_idx * bucket_size) as u32;
        let bucket_end_idx = bucket_start_idx + bucket_size as u32;
        let mut current_bucket_point_count = 0;

        // Find points belonging to the current bucket
        for (global_idx, value) in target_points {
            if *global_idx >= bucket_start_idx && *global_idx < bucket_end_idx {
                let local_idx = global_idx - bucket_start_idx;
                // println!(
                //     "  Found point {} in bucket {} (local index {})",
                //     global_idx, bucket_idx, local_idx
                // );
                // Generate keys for this specific point
                let (k0, k1) = dpf_gen(
                    local_idx,
                    *value as u64, // DPF usually encodes the value directly
                    bucket_bits as usize,
                    hs_key,
                    aes, 
                );
                client_keys[0][bucket_idx] = k0;
                client_keys[1][bucket_idx] = k1;
                current_bucket_point_count += 1;
            }
        }
        // If no points found in this bucket, generate keys for a zero function
        if current_bucket_point_count == 0 {
            // println!(
            //     "  No target points in bucket {}. Generating zero function keys.",
            //     bucket_idx
            // );
            let (k0, k1) = dpf_gen(
                0, // Arbitrary index for zero function
                0, // Value is zero
                bucket_bits as usize,
                &hs_key,
                &aes,
            );
            // Still add the keys, but the count remains 0
            client_keys[0][bucket_idx] = k0;
            client_keys[1][bucket_idx] = k1;
        }
    }
    //println!("DPF key generation complete.");
    client_keys
}


/// Evaluates DPF keys for a single server against the database.
///
/// This function processes all buckets assigned to this server, potentially in parallel.
///
/// # Arguments
/// * `server_id`: The ID of the server (0 or 1).
/// * `server_keys`: The DPF keys assigned to this server (`Vec<DPFKey>` where outer vec is by bucket).
/// * `db`: A slice representing the entire database or the relevant portion.
/// * `num_buckets`: Total number of buckets.
/// * `bucket_size`: Number of database elements per bucket.
/// * `hs_key`: Hash seed key for DPF evaluation.
/// * `aes`: AES cipher instance for DPF evaluation.
///
/// # Returns
/// `Vec<ENTRY>` where result[bucket_id] contains the accumulated evaluation results
/// (shares) for each key corresponding to that bucket.
pub fn dmpf_pir_query_eval<const ENTRY_U64_SIZE: usize>(
    server_id: usize,
    server_keys: &[DPFKey], 
    db: &[Entry<ENTRY_U64_SIZE>],
    num_buckets: usize,
    bucket_size: usize,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128, // Pass AES by reference
) -> Vec<[i64; ENTRY_U64_SIZE]> {
    println!("Server {} starting evaluation...", server_id);
    let start = Instant::now();

    // Preallocate the results vector
    let mut collected_results = vec![[0i64; ENTRY_U64_SIZE]; num_buckets];

    // Process buckets in parallel with mutable access
    collected_results.par_iter_mut().enumerate().for_each(|(bucket_idx, bucket_result)| {
            let bucket_start_idx = bucket_idx * bucket_size;
            let key = &server_keys[bucket_idx];

            // Precompute seeds for the current key
            // let precomputed_seeds =
            // dpf_full_eval_precompute_parallel_full_final_step(key, hs_key, aes);
            let precomputed_seeds = dpf_eval_full_optimized(server_id as u8, key, hs_key, aes);

            // Inner loop over DB entries in the bucket
            for local_idx in 0..bucket_size {
                let global_idx = bucket_start_idx + local_idx;

                if global_idx >= db.len() {
                    continue; // Skip if out of DB bounds
                }
                
                let db_item_u64: &Entry<ENTRY_U64_SIZE> = &db[global_idx];

                // // Evaluate the key quickly using precomputed data
                // let eval_share = dpf_eval_fast_with_full_final_step(
                //     server_id as u8,
                //     key,
                //     hs_key,
                //     local_idx as u32,
                //     aes,
                //     &precomputed_seeds,
                // );

                // // Accumulate the result: share * db_value
                // for k in 0..ENTRY_U64_SIZE {
                //     bucket_result[k] = bucket_result[k].wrapping_add(eval_share.wrapping_mul(db_item_u64[k] as i64));
                // }

                let eval_share = precomputed_seeds[local_idx];
                for k in 0..ENTRY_U64_SIZE {
                    bucket_result[k] = bucket_result[k].wrapping_add(eval_share.wrapping_mul(db_item_u64[k] as i64));
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

    collected_results
}


pub fn dmpf_pir_query_eval_additive<const ENTRY_U64_SIZE: usize>(
    server_id: usize,
    server_keys: &[DPFKey], 
    db: &[[i64; ENTRY_U64_SIZE]],
    num_buckets: usize,
    bucket_size: usize,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128, // Pass AES by reference
) -> Vec<[i64; ENTRY_U64_SIZE]> {
    println!("Server {} starting evaluation...", server_id);
    let start = Instant::now();

    // Preallocate the results vector
    let mut collected_results = vec![[0i64; ENTRY_U64_SIZE]; num_buckets];

    // Process buckets in parallel with mutable access
    collected_results.par_iter_mut().enumerate().for_each(|(bucket_idx, bucket_result)| {
            let bucket_start_idx = bucket_idx * bucket_size;
            let key = &server_keys[bucket_idx];
            // Precompute seeds for the current key
            // let precomputed_seeds =
            // dpf_full_eval_precompute_parallel_full_final_step(key, hs_key, aes);
            let precomputed_seeds = dpf_eval_full_optimized(server_id as u8, key, hs_key, aes);

            // Inner loop over DB entries in the bucket
            for local_idx in 0..bucket_size {
                let global_idx = bucket_start_idx + local_idx;

                if global_idx >= db.len() {
                    continue; // Skip if out of DB bounds
                }
                
                let db_item_u64= &db[global_idx];

                // // Evaluate the key quickly using precomputed data
                // let eval_share = dpf_eval_fast_with_full_final_step(
                //     server_id as u8,
                //     key,
                //     hs_key,
                //     local_idx as u32,
                //     aes,
                //     &precomputed_seeds,
                // );

                // // Accumulate the result: share * db_value
                // for k in 0..ENTRY_U64_SIZE {
                //     bucket_result[k] = bucket_result[k].wrapping_add(eval_share.wrapping_mul(db_item_u64[k] as i64));
                // }

                let eval_share = precomputed_seeds[local_idx];
                for k in 0..ENTRY_U64_SIZE {
                    bucket_result[k] = bucket_result[k].wrapping_add(eval_share.wrapping_mul(db_item_u64[k] as i64));
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

    collected_results
}


/// Reconstructs the final results (vectors) from shares provided by multiple servers
/// and formats them into Slots.
///
/// # Arguments
/// * `all_server_results`: A slice where each element contains the results from one server.
/// * `num_buckets`: Total number of buckets.
/// * `ENTRY_U64_SIZE`: The dimension of the entry vectors (e.g., 32 for 256 bytes).
///
/// # Returns
/// `Vec<Entry<ENTRY_U64_SIZE>>` containing the reconstructed vector results.
pub fn dmpf_pir_reconstruct_servers<const ENTRY_U64_SIZE: usize>(
    all_server_results: &[Vec<[i64; ENTRY_U64_SIZE]>],
    num_buckets: usize,
) -> Vec<Entry<ENTRY_U64_SIZE>> {
    //println!("\n--- Client-Side Reconstruction (Multi-Server Vector) ---");

    // --- Initial Validation ---
    if all_server_results.is_empty() {
        panic!("Received results from zero servers.");
    }
    let num_servers = all_server_results.len();
    //println!("Reconstructing from {} servers.", num_servers);

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

    // --- Reconstruction Loop ---
    let mut reconstructed_entries: Vec<Entry<ENTRY_U64_SIZE>> = Vec::with_capacity(num_buckets);

    for bucket_idx in 0..num_buckets {
        // Initialize a zero entry for this bucket
        let mut result_u64: Entry<ENTRY_U64_SIZE> = [0u64; ENTRY_U64_SIZE];
        
        // Combine results from all servers for this bucket
        for k in 0..ENTRY_U64_SIZE {
            // Sum the k-th component across all servers for this bucket
            let mut component_sum = 0i64;
            for server_id in 0..num_servers {
                // Access the result from each server
                component_sum = component_sum.wrapping_add(all_server_results[server_id][bucket_idx][k]);
            }
            // Convert the combined i64 result to u64
            result_u64[k] = component_sum as u64;
        }
        
        // Add the reconstructed entry for this bucket
        reconstructed_entries.push(result_u64);
    }

    //println!("Reconstruction complete.");
    reconstructed_entries
}



/// Calculates optimal PIR configuration based on DB size exponent N and bucket number option.
///
/// Finds the largest power-of-2 number of buckets (`NUM_BUCKETS`)
/// such that `NUM_BUCKETS * N <= floor(sqrt(1 << N))`, then optionally increases
/// the number of buckets based on `BUCKET_NUM_OPTION`.
///
/// # Arguments
///
/// * `n`: The exponent for the database size (DB_SIZE = 1 << n). Must be > 0.
/// * `bucket_num_option`: Multiplier for number of buckets. Must be a power of 2.
///   - 1: Use optimal number of buckets (original behavior)
///   - 2: Double the number of buckets
///   - 4: Quadruple the number of buckets
///   - etc. (must be a power of 2)
///
/// # Returns
///
/// A tuple `(DB_SIZE, NUM_BUCKETS, BUCKET_SIZE, BUCKET_BITS)`.
///
/// # Panics
///
/// Panics if `n` is 0.
/// Panics if `bucket_num_option` is not a power of 2.
/// Panics if `n` is large enough that `1 << n` overflows `usize`.
/// Panics if intermediate floating-point calculations result in non-finite values.
/// Panics if `bucket_num_option` results in more buckets than database entries.
pub fn calculate_pir_config(n: usize, bucket_num_option: usize) -> (usize, usize, usize, u32) {
    if n == 0 {
        panic!("N must be greater than 0 to calculate PIR configuration.");
    }

    // Check if bucket_num_option is a power of 2
    if bucket_num_option == 0 || (bucket_num_option & (bucket_num_option - 1)) != 0 {
        panic!(
            "BUCKET_NUM_OPTION ({}) must be a power of 2.",
            bucket_num_option
        );
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

    let base_num_buckets = if max_k_allowed == 0 {
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

    // Apply bucket number option multiplier
    let num_buckets = base_num_buckets.checked_mul(bucket_num_option).unwrap_or_else(|| {
        panic!(
            "BUCKET_NUM_OPTION ({}) causes overflow when multiplied with base_num_buckets ({})",
            bucket_num_option, base_num_buckets
        )
    });

    // Check feasibility: number of buckets cannot exceed database size
    if num_buckets > db_size {
         // Calculate valid power-of-2 BUCKET_NUM_OPTION values
        let max_feasible_option = db_size / base_num_buckets;
        let mut valid_options = Vec::new();
        let mut option = 1;
        while option <= max_feasible_option {
            valid_options.push(option.to_string());
            option *= 2;
        }

        panic!(
            "BUCKET_NUM_OPTION ({}) results in too many buckets ({}). \
             Cannot have more buckets than database entries ({}). \
             Valid power-of-2 BUCKET_NUM_OPTION values for N={} are: {}",
            bucket_num_option,
            num_buckets,
            db_size,
            n,
            valid_options.join(", ")
        );
    }

    // Calculate BUCKET_SIZE. Since num_buckets and db_size are powers of 2,
    // bucket_size will also be a power of 2 if num_buckets <= db_size.
    let bucket_size = db_size / num_buckets;
    
    // Check that bucket_size is a power of 2 (required for efficient operations)
    if bucket_size == 0 || (bucket_size & (bucket_size - 1)) != 0 {
        panic!(
            "BUCKET_NUM_OPTION ({}) results in bucket_size ({}) that is not a power of 2. \
             This occurs when num_buckets ({}) doesn't divide db_size ({}) into power-of-2 chunks. \
             Try a different BUCKET_NUM_OPTION value.",
            bucket_num_option, bucket_size, num_buckets, db_size
        );
    }

    let bucket_bits = bucket_size.ilog2(); // log2 of bucket_size

    (db_size, num_buckets, bucket_size, bucket_bits)
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

    // Each level seeds are the paralellism part, going from one level to another is sequential
    //               [S_initial] (Level 0)
    //              /        \
    //    (x_0=0)  /          \ (x_0=1)
    //           /            \
    //        [S_0]          [S_1] (Level 1 seeds)
    //          /  \         /  \
    //  (x_1=0)/    \(x_1=1) (x_1=0)/    \(x_1=1)
    //         /      \       /      \
    //      [S_00]  [S_01]  [S_10]  [S_11] (Level 2 seeds)
    //      / \     / \     / \     / \
    //     /   \   /   \   /   \   /   \
    // [S_000] [S_001] ... [S_110] [S_111]  (Level 3 seeds, which is Level n-1 for n=4)
    // .......


    // Start with the initial seed at level 0
    let mut current_level_seeds = vec![key.seed];

    // Iterate through levels i = 0 to n-2 (computing seeds for levels 1 to n-1)
    for i in 0..(n - 1) {
        let cw_i = key.cw_levels[i]; // Correction word for this level (Copy)
        let mut next_level_seeds = Vec::with_capacity(current_level_seeds.len() * 2);

        // Use Rayon to parallelize the computation for the next level
        let new_seeds_iter = current_level_seeds
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
            }); 
        next_level_seeds.par_extend(new_seeds_iter);
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
    key: &DPFKeyBytes<ENTRY_U64_SIZE>,
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
    key: &DPFKeyBytes<ENTRY_U64_SIZE>,
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
        let mut next_level_seeds = Vec::with_capacity(current_level_seeds.len() * 2);

        // Use Rayon to parallelize the computation for the next level
        let new_seeds_iter = current_level_seeds
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
            }); // Collect results into a new Vec
        next_level_seeds.par_extend(new_seeds_iter);
        // Update current_level_seeds for the next iteration
        current_level_seeds = next_level_seeds;
    }

    // After the loop, current_level_seeds contains the seeds for level n-1
    current_level_seeds
}


#[derive(Clone, Copy, Debug)]
pub struct PrecomputedFinalStep {
    pub hs_output: [u8; AES_BLOCK_SIZE],
    pub t_n_minus_1: u8,
}

/// Precomputes states including the final HS call for all 2^n paths.
/// Returns a Vec of PrecomputedFinalStep.
pub fn dpf_full_eval_precompute_parallel_full_final_step(
    key: &DPFKey,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128,
) -> Vec<PrecomputedFinalStep> {
    let n = key.n;
    if n == 0 {
        return Vec::new();
    }

    // Phase 1: Compute seeds up to level n-1 (s_{n-1} || t_{n-1})
    // These are the inputs to the final HS step that depends on x_n.
    let mut level_n_minus_1_seeds = vec![key.seed];
    if n > 1 {
        for i in 0..(n - 1) {
            let cw_i = key.cw_levels[i];
            let mut next_level_seeds =
                Vec::with_capacity(level_n_minus_1_seeds.len() * 2);

            let new_seeds_producer = level_n_minus_1_seeds
                .par_iter()
                .flat_map(|&prev_seed| {
                    let mut hs_out = [0u8; AES_BLOCK_SIZE];
                    let mut next_seed_0 = [0u8; AES_BLOCK_SIZE];
                    let mut next_seed_1 = [0u8; AES_BLOCK_SIZE];
                    let current_t_from_prev =
                        prev_seed[AES_BLOCK_SIZE - 1] & 1;

                    hs(hs_key, &prev_seed, aes, &mut hs_out);

                    next_seed_0 = hs_out;
                    if current_t_from_prev == 1 {
                        xor_bytes(&mut next_seed_0, &cw_i);
                    }

                    next_seed_1 = hs_out;
                    xor_bytes(&mut next_seed_1, &prev_seed);
                    if current_t_from_prev == 1 {
                        xor_bytes(&mut next_seed_1, &cw_i);
                    }
                    vec![next_seed_0, next_seed_1]
                });
            next_level_seeds.par_extend(new_seeds_producer);
            level_n_minus_1_seeds = next_level_seeds;
        }
    }
    // level_n_minus_1_seeds now contains 2^(n-1) seeds, each is (s_{n-1} || t_{n-1})

    // Phase 2: For each seed from Phase 1, compute the final HS output
    // for both x_n = 0 and x_n = 1.
    let mut final_precomputed_values =
        Vec::with_capacity(level_n_minus_1_seeds.len() * 2);

    let final_results_producer = level_n_minus_1_seeds
        .par_iter()
        .flat_map(|&s_prev_full_seed| {
            // s_prev_full_seed is (s_{n-1} || t_{n-1})
            let t_n_minus_1 = s_prev_full_seed[AES_BLOCK_SIZE - 1] & 1;
            let mut results = Vec::with_capacity(2);

            // Case x_n = 0
            let mut hs_out_for_xn0 = [0u8; AES_BLOCK_SIZE];
            let mut hash_input_0 = s_prev_full_seed; // Copy
            hash_input_0[AES_BLOCK_SIZE - 1] = t_n_minus_1 ^ 0; // Normalize for HS
            hs(hs_key, &hash_input_0, aes, &mut hs_out_for_xn0);
            results.push(PrecomputedFinalStep {
                hs_output: hs_out_for_xn0,
                t_n_minus_1,
            });

            // Case x_n = 1
            let mut hs_out_for_xn1 = [0u8; AES_BLOCK_SIZE];
            let mut hash_input_1 = s_prev_full_seed; // Copy
            hash_input_1[AES_BLOCK_SIZE - 1] = t_n_minus_1 ^ 1; // Normalize for HS
            hs(hs_key, &hash_input_1, aes, &mut hs_out_for_xn1);
            results.push(PrecomputedFinalStep {
                hs_output: hs_out_for_xn1,
                t_n_minus_1,
            });

            results // flat_map will flatten these pairs
        });

    final_precomputed_values.par_extend(final_results_producer);
    final_precomputed_values // Contains 2^n items
}

/// Evaluates DPF using fully precomputed final HS step.
pub fn dpf_eval_fast_with_full_final_step(
    b: u8,
    key: &DPFKey,
    _hs_key: &[u8; AES_BLOCK_SIZE], // hs_key might not be needed if aes implies it
    x: u32,
    aes: &Aes128,
    precomputed_values: &[PrecomputedFinalStep],
) -> i64 {
    let n = key.n;
    if n == 0 {
        return 0;
    }
    // For n > 0, precomputed_values should have 2^n elements.
    // assert_eq!(precomputed_values.len(), 1 << n);


    // --- O(1) Lookup ---
    // x is the full input value from 0 to 2^n - 1.
    // The precomputed_values are ordered such that the entry for x
    // is at index x.
    let lookup_index = x as usize;
    if lookup_index >= precomputed_values.len() {
        // This case should ideally not happen if x is within domain 0..2^n-1
        // and precomputation was done correctly.
        // Handle error: out of bounds for precomputed data.
        // For safety, one might return an error or a default value.
        // Depending on DPF properties, an out-of-domain x might be invalid.
        // For now, let's assume x is valid and precomputed_values is correct.
        // If n=0, precomputed_values is empty, this check prevents panic.
        // But n=0 is handled above.
        panic!("Lookup index out of bounds for precomputed values.");
    }

    let precomputed_item = &precomputed_values[lookup_index];

    // This is HS( (s_{n-1} || t_{n-1}) XOR x_n )
    let mut hs_out = precomputed_item.hs_output;
    // This is t_{n-1} (the t-bit from the input to the final HS call)
    let t_n_minus_1_val = precomputed_item.t_n_minus_1;

    // We still need the actual last bit of x (x_n) to select the correct LCW.
    // For n=0, this would be an issue, but n=0 returns early.
    // For n=1, (n-1) is 0. get_bit(x, 0, 1) gives x_0.
    let x_n_val = get_bit(x, (n - 1) as u32, n as u32);

    // Compute final seed: (s_n || t_n) = HS_result ⊕ t_{n-1} * (HCW || LCW^{x_n})
    if t_n_minus_1_val == 1 {
        let hcw = &key.cw_n.0;
        let lcw = if x_n_val == 0 { key.cw_n.1 } else { key.cw_n.2 };

        for j in 0..(AES_BLOCK_SIZE - 1) {
            hs_out[j] ^= hcw[j];
        }
        hs_out[AES_BLOCK_SIZE - 1] ^= lcw;
    }

    // hs_out now holds the final seed (s_n || t_n') before normalization

    // Normalize final seed - ensure only t_n bit remains in last byte
    let t_n_final = hs_out[AES_BLOCK_SIZE - 1] & 1;
    hs_out[AES_BLOCK_SIZE - 1] = t_n_final; // hs_out is now the normalized (s_n || t_n)

    // ConvertG for final output (only using s_n part of hs_out)
    let convert_out = convert_g_final(&hs_out, aes);

    // Calculate y_b = (-1)^b * (ConvertG(s_n) + t_n * CW_{n+1})
    let sign = if b == 0 { 1i64 } else { -1i64 };
    let t_term = if t_n_final == 1 { key.cw_np1 } else { 0 };
    let result = sign.wrapping_mul(convert_out.wrapping_add(t_term));

    result
}





