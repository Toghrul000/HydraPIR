#![allow(non_snake_case)]
use std::time::Instant;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt};
use aes::Aes128;
use aes::cipher::{KeyIvInit, StreamCipher};
use rand::RngCore;
use rayon::prelude::*;
use ctr::Ctr128BE;


type Aes128Ctr = Ctr128BE<Aes128>;

const AES_BLOCK_SIZE: usize = 16;
const AES_BLOCK_BIT_SIZE: usize = AES_BLOCK_SIZE * 8;
const AES_BLOCK_BIT_LOG2: usize = AES_BLOCK_BIT_SIZE.ilog2() as usize;
const AES_BLOCK_BIT_MASK: u32 = (AES_BLOCK_BIT_SIZE - 1) as u32;
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

// Given (s||t) we only use s part
fn hs_final(key: &[u8; AES_BLOCK_SIZE], st: &[u8; AES_BLOCK_SIZE], aes: &Aes128, out: &mut [u8; AES_BLOCK_SIZE]) {
    // Create a copy where we zero out the last bit (t_n)
    let mut s_only = *st;
    // Zero out the entire last byte except for bit 0 (t_n)
    s_only[AES_BLOCK_SIZE - 1] = s_only[AES_BLOCK_SIZE - 1] & 1;

    hs(key, &s_only, aes, out);
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
pub struct BitDPFKey {
    pub n: usize,
    pub seed: [u8; AES_BLOCK_SIZE], // (s_0 || t_0)
    pub cw_levels: Vec<[u8; AES_BLOCK_SIZE]>, // CW_1..CW_{n-1}
    pub cw_n: ([u8; AES_BLOCK_SIZE - 1], u8, u8), // CW_n represented as a tuple: (HCW, LCW^0, LCW^1)
    pub cw_np1: [u8; AES_BLOCK_SIZE],                          // CW_{n+1}
}


pub fn dpf_bit_gen(
    alpha: u32,
    n: usize,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128,
) -> (BitDPFKey, BitDPFKey) {

    // 1) sample Δ with LSB=1 and share
    let delta = sample_delta(); 
    let (s0_initial, s1_initial) = share_delta(&delta); 

    let mut cw_levels = Vec::with_capacity(n - 1);
    let target_stop = AES_BLOCK_BIT_LOG2;

    // Initialize current_s0, s1, for the loop
    let mut current_s0 = s0_initial;
    let mut current_s1 = s1_initial;

    // Buffers reused in the loop
    let mut h0 = [0u8; AES_BLOCK_SIZE];
    let mut h1 = [0u8; AES_BLOCK_SIZE];
    let mut cwi = [0u8; AES_BLOCK_SIZE]; // Reuse buffer for cwi

    let stop = if n <= target_stop {
        0
    } else {
        n - 1 - target_stop
    };
   
    for i in 0..stop {
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
    let last0 = if n <= target_stop { s0_initial } else { current_s0 };
    let last1 = if n <= target_stop { s1_initial } else { current_s1 };
    
    // For n <= target_stop, we need to adjust how we get alpha_n
    let alpha_n = if n <= target_stop {
        get_bit(alpha, 0, n as u32)  // Use first bit when n <= target_stop
    } else {
        get_bit(alpha, (n - 1 - target_stop) as u32, n as u32)
    };
    let alpha_n_bar = 1 - alpha_n; // ᾱ_n
    // println!(" Alpha_n {}", alpha_n);
    // println!("Here");

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

    // final0 => (s_n || t_n)_0
    // final1 => (s_n || t_n)_1

    // Transform final seeds using hs_final
    hs_final(hs_key, &final0, aes, &mut h0);
    hs_final(hs_key, &final1, aes, &mut h1);

    // XOR the transformed seeds to get cw_np1
    let mut cw_np1 = h0;
    xor_bytes(&mut cw_np1, &h1);

    // Set the specific bit in cw_np1 based on alpha
    let byte_pos = ((alpha & AES_BLOCK_BIT_MASK) / 8) as usize;
    let bit_pos = ((alpha & AES_BLOCK_BIT_MASK) % 8) as usize;
    cw_np1[byte_pos] ^= 1 << bit_pos;

    (
        BitDPFKey {
            n,
            seed: s0_initial,
            cw_levels: cw_levels.clone(), // Clone here
            cw_n: (hcw, lcw0, lcw1),
            cw_np1,
        },
        BitDPFKey {
            n,
            seed: s1_initial,
            cw_levels, // Move original vector here
            cw_n: (hcw, lcw0, lcw1),
            cw_np1,
        },
    )
}

pub fn dpf_bit_eval(
    key: &BitDPFKey,
    hs_key: &[u8; AES_BLOCK_SIZE],
    x: u32,
    aes: &Aes128,
) -> u8 {
    // Step 1: Parse k_b components
    let mut current_seed = key.seed; // Start with the initial seed
    let n = key.n;
    let target_stop = AES_BLOCK_BIT_LOG2;

    // Buffer for hs output, reused in the loop
    let mut hs_out = [0u8; AES_BLOCK_SIZE];

    // Calculate stop point similar to dpf_bit_gen
    let stop = if n <= target_stop {
        0
    } else {
        n - 1 - target_stop
    };

    // Step 2: Tree traversal for i ∈ [0, stop)
    for i in 0..stop {
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

    // Step 3: Final level processing
    // For n <= target_stop, we need to adjust how we get x_n
    let x_n = if n <= target_stop {
        get_bit(x, 0, n as u32)  // Use first bit when n <= target_stop
    } else {
        get_bit(x, (n - 1 - target_stop) as u32, n as u32)
    };
    
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
    
    // Transform the final seed using hs_final
    let mut transformed = [0u8; AES_BLOCK_SIZE];
    hs_final(hs_key, &hs_out, aes, &mut transformed);

    // If t_n is 1, XOR with cw_np1
    if t_n == 1 {
        xor_bytes(&mut transformed, &key.cw_np1);
    }

    // Extract and return the specific bit
    let byte_pos = ((x & AES_BLOCK_BIT_MASK) / 8) as usize;
    let bit_pos = ((x & AES_BLOCK_BIT_MASK) % 8) as usize;
    ((transformed[byte_pos] >> bit_pos) & 1) as u8
}


pub fn dpf_bit_eval_full(
    key: &BitDPFKey,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128,
) -> Vec<u8> {
    let n = key.n;
    if n == 0 {
        return vec![];
    }

    let num_cw_levels = key.cw_levels.len(); // Number of bits processed by the main loop
    let num_prefix_paths = 1 << num_cw_levels;

    // This will store the (s_m || t_m) seeds *after* HCW/LCW application,
    // but *before* hs_final. There will be 2^(num_cw_levels + 1) such seeds.
    let mut s_m_t_m_seeds = Vec::with_capacity(num_prefix_paths * 2);

    // --- Phase 1: Expand seeds up to the input of "final level processing" ---
    // `interim_seeds` stores `current_seed` after the `cw_levels` loop for each of the 2^num_cw_levels paths
    let mut interim_seeds = vec![key.seed];
    if num_cw_levels > 0 {
        for i in 0..num_cw_levels {
            let cw_i = key.cw_levels[i];
            let mut next_level_seeds = Vec::with_capacity(interim_seeds.len() * 2);
            for prev_seed_val in &interim_seeds {
                let mut hs_out_loop = [0u8; AES_BLOCK_SIZE];
                let current_t_from_prev = prev_seed_val[AES_BLOCK_SIZE - 1] & 1;
                hs(hs_key, prev_seed_val, aes, &mut hs_out_loop);

                // Path for x_i = 0
                let mut next_seed_0 = hs_out_loop;
                if current_t_from_prev == 1 {
                    xor_bytes(&mut next_seed_0, &cw_i);
                }
                next_level_seeds.push(next_seed_0);

                // Path for x_i = 1
                let mut next_seed_1 = hs_out_loop;
                xor_bytes(&mut next_seed_1, prev_seed_val);
                if current_t_from_prev == 1 {
                    xor_bytes(&mut next_seed_1, &cw_i);
                }
                next_level_seeds.push(next_seed_1);
            }
            interim_seeds = next_level_seeds;
        }
    }
    // `interim_seeds` now has `num_prefix_paths` seeds. Each is `current_seed`
    // before "Step 3: Final level processing" in dpf_bit_eval.

    // --- Phase 2: Apply "final level processing" for each interim seed and for both x_bit_for_lcw choices ---
    for current_seed_from_phase1 in interim_seeds {
        let t_for_final_level_input = current_seed_from_phase1[AES_BLOCK_SIZE - 1] & 1;

        // Case x_bit_for_lcw = 0
        let mut hs_out_final_level_0 = [0u8; AES_BLOCK_SIZE];
        let mut hash_input_0 = current_seed_from_phase1;
        hash_input_0[AES_BLOCK_SIZE - 1] = t_for_final_level_input ^ 0;
        hs(hs_key, &hash_input_0, aes, &mut hs_out_final_level_0);

        if t_for_final_level_input == 1 {
            let hcw = &key.cw_n.0;
            let lcw = key.cw_n.1; // LCW^0
            for j in 0..(AES_BLOCK_SIZE - 1) {
                hs_out_final_level_0[j] ^= hcw[j];
            }
            hs_out_final_level_0[AES_BLOCK_SIZE - 1] ^= lcw;
        }
        s_m_t_m_seeds.push(hs_out_final_level_0);

        // Case x_bit_for_lcw = 1
        let mut hs_out_final_level_1 = [0u8; AES_BLOCK_SIZE];
        let mut hash_input_1 = current_seed_from_phase1;
        hash_input_1[AES_BLOCK_SIZE - 1] = t_for_final_level_input ^ 1;
        hs(hs_key, &hash_input_1, aes, &mut hs_out_final_level_1);

        if t_for_final_level_input == 1 {
            let hcw = &key.cw_n.0;
            let lcw = key.cw_n.2; // LCW^1
            for j in 0..(AES_BLOCK_SIZE - 1) {
                hs_out_final_level_1[j] ^= hcw[j];
            }
            hs_out_final_level_1[AES_BLOCK_SIZE - 1] ^= lcw;
        }
        s_m_t_m_seeds.push(hs_out_final_level_1);
    }
    // `s_m_t_m_seeds` now has `num_prefix_paths * 2` seeds.
    // Each is `(s_m || t_m')` before normalization.

    // --- Phase 3: Normalize, apply hs_final, apply cw_np1, and collect all bits ---
    let total_output_bits = 1 << n;
    let mut output_bit_values = Vec::with_capacity(total_output_bits);

    for mut s_m_t_m_seed_unnormalized in s_m_t_m_seeds {
        // Normalize
        let t_m_final = s_m_t_m_seed_unnormalized[AES_BLOCK_SIZE - 1] & 1;
        s_m_t_m_seed_unnormalized[AES_BLOCK_SIZE - 1] = t_m_final; // Now it's normalized (s_m || t_m)

        let mut transformed_block = [0u8; AES_BLOCK_SIZE];
        hs_final(hs_key, &s_m_t_m_seed_unnormalized, aes, &mut transformed_block);

        if t_m_final == 1 {
            xor_bytes(&mut transformed_block, &key.cw_np1);
        }

        // This block contains AES_BLOCK_BIT_SIZE (e.g., 128) output bits
        for bit_idx_in_block in 0..AES_BLOCK_BIT_SIZE {
            let byte_pos = bit_idx_in_block / 8;
            let bit_pos_in_byte = bit_idx_in_block % 8;
            let bit_val = (transformed_block[byte_pos] >> bit_pos_in_byte) & 1;
            output_bit_values.push(bit_val);
            if output_bit_values.len() == total_output_bits {
                // Should happen if n is small enough that one s_m_t_m_seed_unnormalized
                // doesn't cover the whole domain.
                // For larger n, this loop will run multiple times.
            }
        }
    }
    
    // Ensure we have the correct number of bits. This might be tricky if n is not a multiple of AES_BLOCK_BIT_LOG2
    // The logic above assumes that the number of s_m_t_m_seeds * AES_BLOCK_BIT_SIZE >= total_output_bits.
    // Number of s_m_t_m_seeds = 2^(num_cw_levels + 1).
    // num_cw_levels = n - 1 - AES_BLOCK_BIT_LOG2 (if n > AES_BLOCK_BIT_LOG2)
    // So, number of s_m_t_m_seeds = 2^(n - AES_BLOCK_BIT_LOG2).
    // Total bits from these seeds = 2^(n - AES_BLOCK_BIT_LOG2) * 2^AES_BLOCK_BIT_LOG2 = 2^n. This matches.

    // Convert the Vec<u8> of bits into Vec<u8> of bytes.
    let result_byte_size = (total_output_bits + 7) / 8;
    let mut result_bytes = vec![0u8; result_byte_size];
    for i in 0..total_output_bits {
        if output_bit_values[i] == 1 {
            result_bytes[i / 8] |= 1 << (i % 8);
        }
    }
    result_bytes
}


pub fn dpf_bit_eval_full_optimized(
    key: &BitDPFKey,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128,
) -> Vec<u8> {
    let n = key.n;
    if n == 0 {
        return vec![];
    }

    let num_cw_levels = key.cw_levels.len();
    let total_output_bits = 1 << n;
    let result_byte_size = (total_output_bits + 7) / 8;
    let mut result_bytes = vec![0u8; result_byte_size];

    // Pre-allocate all buffers once
    let mut hs_out_buffer = [0u8; AES_BLOCK_SIZE];
    let mut hash_input_buffer = [0u8; AES_BLOCK_SIZE];
    let mut transformed_block = [0u8; AES_BLOCK_SIZE];
    let mut temp_buffer = [0u8; AES_BLOCK_SIZE];

    // Pre-compute HCW with LCW values to avoid repeated work
    let mut hcw_with_lcw0 = [0u8; AES_BLOCK_SIZE];
    let mut hcw_with_lcw1 = [0u8; AES_BLOCK_SIZE];
    hcw_with_lcw0[..AES_BLOCK_SIZE - 1].copy_from_slice(&key.cw_n.0);
    hcw_with_lcw0[AES_BLOCK_SIZE - 1] = key.cw_n.1;
    hcw_with_lcw1[..AES_BLOCK_SIZE - 1].copy_from_slice(&key.cw_n.0);
    hcw_with_lcw1[AES_BLOCK_SIZE - 1] = key.cw_n.2;

    let mut current_seeds = vec![key.seed];
    let mut next_seeds = Vec::new();

    // Phase 1: Tree expansion 
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

    // Phase 2 & 3: Optimized final processing
    let mut output_bit_offset = 0;

    for current_seed in current_seeds {
        let t_for_final = current_seed[AES_BLOCK_SIZE - 1] & 1;

        // Process both cases in a single loop with branch prediction optimization
        for x_bit in 0u8..2u8 {
            // Prepare hash input (avoid copy_from_slice)
            hash_input_buffer = current_seed;
            hash_input_buffer[AES_BLOCK_SIZE - 1] = t_for_final ^ x_bit;
            
            hs(hs_key, &hash_input_buffer, aes, &mut transformed_block);

            // Branchless correction word application
            if t_for_final == 1 {
                let hcw_to_use = if x_bit == 0 { &hcw_with_lcw0 } else { &hcw_with_lcw1 };
                xor_bytes(&mut transformed_block, hcw_to_use);
            }

            // Final transformation
            let t_m_final = transformed_block[AES_BLOCK_SIZE - 1] & 1;
            transformed_block[AES_BLOCK_SIZE - 1] = t_m_final;
            
            hs_final(hs_key, &transformed_block, aes, &mut temp_buffer);
            
            if t_m_final == 1 {
                xor_bytes(&mut temp_buffer, &key.cw_np1);
            }

            // Optimized bit writing
            write_bits_to_result_optimized(
                &temp_buffer,
                &mut result_bytes,
                output_bit_offset,
                total_output_bits,
            );
            
            output_bit_offset += AES_BLOCK_BIT_SIZE;
            if output_bit_offset >= total_output_bits {
                return result_bytes;
            }
        }
    }

    result_bytes
}

#[inline(always)]
fn write_bits_to_result_optimized(
    source_block: &[u8; AES_BLOCK_SIZE],
    result: &mut [u8],
    bit_offset: usize,
    max_bits: usize,
) {
    let bits_to_write = std::cmp::min(AES_BLOCK_BIT_SIZE, max_bits - bit_offset);
    let byte_offset = bit_offset / 8;
    let bit_shift = bit_offset % 8;

    if bit_shift == 0 {
        // Perfectly aligned case - maximum performance
        let full_bytes = bits_to_write / 8;
        let bytes_available = result.len().saturating_sub(byte_offset);
        let copy_len = std::cmp::min(full_bytes, bytes_available);
        
        if copy_len > 0 {
            result[byte_offset..byte_offset + copy_len]
                .copy_from_slice(&source_block[..copy_len]);
        }
        
        // Handle remaining bits
        let remaining_bits = bits_to_write - (copy_len * 8);
        if remaining_bits > 0 && byte_offset + copy_len < result.len() {
            let mask = (1u8 << remaining_bits) - 1;
            result[byte_offset + copy_len] |= source_block[copy_len] & mask;
        }
    } else {
        // Unaligned case - optimized with chunked processing
        let mut remaining_bits = bits_to_write;
        let mut source_byte_idx = 0;
        let mut target_byte_idx = byte_offset;
        let mut target_bit_offset = bit_shift;

        while remaining_bits > 0 && target_byte_idx < result.len() {
            let bits_in_current_target = 8 - target_bit_offset;
            let bits_to_process = std::cmp::min(remaining_bits, bits_in_current_target);
            
            let source_bits = source_block[source_byte_idx] >> (8 - bits_to_process);
            let mask = ((1u8 << bits_to_process) - 1) << target_bit_offset;
            
            result[target_byte_idx] |= (source_bits << target_bit_offset) & mask;
            
            remaining_bits -= bits_to_process;
            target_bit_offset += bits_to_process;
            
            if target_bit_offset >= 8 {
                target_byte_idx += 1;
                target_bit_offset = 0;
                source_byte_idx += 1;
            }
        }
    }
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
pub fn dmpf_bit_pir_query_gen(
    target_points: &[u32],
    num_buckets: usize,
    bucket_size: usize,
    bucket_bits: u32,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128,
) -> Vec<Vec<BitDPFKey>> {
    // client_keys[server_id][bucket_id] -> DPFKey
    let mut client_keys: Vec<Vec<BitDPFKey>> =
        vec![Vec::with_capacity(num_buckets); 2];

    for server_id in 0..2 {
        for _ in 0..num_buckets {
            // Initialize with dummy values that will be overwritten
            // This ensures proper length so we can index into client_keys[server_id][bucket_idx]
            client_keys[server_id].push(BitDPFKey {
                n: 0,
                seed: [0u8; AES_BLOCK_SIZE],
                cw_levels: Vec::new(),
                cw_n: ([0u8; AES_BLOCK_SIZE - 1], 0, 0),
                cw_np1: [0u8; AES_BLOCK_SIZE],
            });
        }
    }

    //println!("Generating DPF keys per bucket...");
    for bucket_idx in 0..num_buckets {
        let bucket_start_idx = (bucket_idx * bucket_size) as u32;
        let bucket_end_idx = bucket_start_idx + bucket_size as u32;
        let mut current_bucket_point_count = 0;

        // Find points belonging to the current bucket
        for global_idx in target_points {
            if *global_idx >= bucket_start_idx && *global_idx < bucket_end_idx {
                let local_idx = global_idx - bucket_start_idx;
                // println!(
                //     "  Found point {} in bucket {} (local index {})",
                //     global_idx, bucket_idx, local_idx
                // );
                // Generate keys for this specific point
                let (k0, k1) = dpf_bit_gen(
                    local_idx,
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
            let (k0, k1) = dpf_bit_gen(
                0, // Arbitrary index for zero function
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
pub fn dmpf_bit_pir_query_eval<const ENTRY_U64_SIZE: usize>(
    server_id: usize,
    server_keys: &[BitDPFKey], 
    db: &[Entry<ENTRY_U64_SIZE>],
    num_buckets: usize,
    bucket_size: usize,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128,
) -> Vec<[i64; ENTRY_U64_SIZE]> {
    println!("Server {} starting evaluation...", server_id);
    let start = Instant::now();

    let precompute_start = Instant::now();
    let precomputed_seeds_cache: Vec<_> = server_keys.iter()
        .map(|key| dpf_bit_eval_full_optimized(key, hs_key, aes))
        .collect();
    let precompute_duration = precompute_start.elapsed();
    println!("Server {} precomputation took: {:?}", server_id, precompute_duration);

    // Preallocate the results vector
    let mut collected_results = vec![[0i64; ENTRY_U64_SIZE]; num_buckets];

    // Process buckets in parallel with mutable access
    collected_results.par_iter_mut().enumerate().for_each(|(bucket_idx, bucket_result)| {
        let bucket_start_idx = bucket_idx * bucket_size;
        let precomputed_seeds = &precomputed_seeds_cache[bucket_idx];

        // Inner loop over DB entries in the bucket
        for local_idx in 0..bucket_size {
            let global_idx = bucket_start_idx + local_idx;

            if global_idx >= db.len() {
                continue;
            }
            
            let db_item_u64: &Entry<ENTRY_U64_SIZE> = &db[global_idx];

            let byte_idx = local_idx / 8;
            let bit_idx = local_idx % 8;
            let bit_eval = (precomputed_seeds[byte_idx] >> bit_idx) & 1;
            let mask = 0u64.wrapping_sub(bit_eval as u64);

            // Accumulate the result
            for k in 0..ENTRY_U64_SIZE {
                bucket_result[k] ^= (db_item_u64[k] & mask) as i64;
            }
        }
    });

    let duration = start.elapsed();
    println!("Server {} evaluation complete,", server_id);
    println!("Time taken: {:?}", duration);
    println!("In seconds: {:.2}s", duration.as_secs_f64());
    println!("In milliseconds: {}ms", duration.as_millis());

    collected_results
}


pub fn dmpf_bit_pir_query_eval_additive<const ENTRY_U64_SIZE: usize>(
    server_id: usize,
    server_keys: &[BitDPFKey], 
    db: &[[i64; ENTRY_U64_SIZE]],
    num_buckets: usize,
    bucket_size: usize,
    hs_key: &[u8; AES_BLOCK_SIZE],
    aes: &Aes128, // Pass AES by reference
) -> Vec<[i64; ENTRY_U64_SIZE]> {
    println!("Server {} starting evaluation...", server_id);
    let start = Instant::now();

    let precompute_start = Instant::now();
    let precomputed_seeds_cache: Vec<_> = server_keys.iter()
        .map(|key| dpf_bit_eval_full_optimized(key, hs_key, aes))
        .collect();
    let precompute_duration = precompute_start.elapsed();
    println!("Server {} precomputation took: {:?}", server_id, precompute_duration);

    // Preallocate the results vector
    let mut collected_results = vec![[0i64; ENTRY_U64_SIZE]; num_buckets];

    // Process buckets in parallel with mutable access
    collected_results.par_iter_mut().enumerate().for_each(|(bucket_idx, bucket_result)| {
            let bucket_start_idx = bucket_idx * bucket_size;
            let precomputed_seeds = &precomputed_seeds_cache[bucket_idx];

            // Inner loop over DB entries in the bucket
            for local_idx in 0..bucket_size {
                let global_idx = bucket_start_idx + local_idx;

                if global_idx >= db.len() {
                    continue; // Skip if out of DB bounds
                }
                
                let db_item_u64= &db[global_idx];

                // Evaluate the key quickly using precomputed data
                let byte_idx = local_idx / 8;
                let bit_idx = local_idx % 8;
                let bit_eval = (precomputed_seeds[byte_idx] >> bit_idx) & 1;
                let mask = 0u64.wrapping_sub(bit_eval as u64);

                // Accumulate the result
                for k in 0..ENTRY_U64_SIZE {
                    bucket_result[k] ^= db_item_u64[k] & mask as i64;
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
pub fn dmpf_bit_pir_reconstruct_servers<const ENTRY_U64_SIZE: usize>(
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
                component_sum = component_sum ^ all_server_results[server_id][bucket_idx][k];
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


// ================================== PRIVATE UPDATE FUNCTIONS ============================================

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Struct for a DPF key share
pub struct DPFKeyBytes<const ENTRY_U64_SIZE: usize> {
    pub n: usize,
    pub seed: [u8; AES_BLOCK_SIZE], // (s_0 || t_0)
    pub cw_levels: Vec<[u8; AES_BLOCK_SIZE]>, // CW_1..CW_{n-1}
    pub cw_n: ([u8; AES_BLOCK_SIZE - 1], u8, u8), // CW_n represented as a tuple: (HCW, LCW^0, LCW^1)
    pub cw_np1: [i64; ENTRY_U64_SIZE],                          // CW_{n+1} for beta with byte array
}


pub fn dpf_gen_xor_bytes<const ENTRY_U64_SIZE: usize>(
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

    // Calculate CW_{n+1} but for XOR-based sharing instead of additive
    // Compute ConvertG on the final seeds (only using s_n, not t_n)
    let sg0 = convert_g_bytes::<ENTRY_U64_SIZE>(&final0, &aes);
    let sg1 = convert_g_bytes::<ENTRY_U64_SIZE>(&final1, &aes);

    // For XOR-based DPF: CW_{n+1} = beta ⊕ sg0 ⊕ sg1 ⊕ (t_n0 ⊕ t_n1) * correction
    let mut cw_np1 = [0i64; ENTRY_U64_SIZE];
    let t_xor = t_n0 ^ t_n1; // XOR of the t bits
    
    for k in 0..ENTRY_U64_SIZE {
        // For XOR-based sharing: we want f0(α) ⊕ f1(α) = β
        // f0(α) = sg0[k] ⊕ (t_n0 * cw_np1[k])
        // f1(α) = sg1[k] ⊕ (t_n1 * cw_np1[k])
        // f0(α) ⊕ f1(α) = sg0[k] ⊕ sg1[k] ⊕ ((t_n0 ⊕ t_n1) * cw_np1[k])
        // We want this to equal β, so:
        // β = sg0[k] ⊕ sg1[k] ⊕ (t_xor * cw_np1[k])
        // Therefore: cw_np1[k] = (β ⊕ sg0[k] ⊕ sg1[k]) / t_xor (if t_xor != 0)
        
        if t_xor == 1 {
            // When t_xor = 1, we can set cw_np1[k] to make the equation work
            cw_np1[k] = (beta[k] as i64) ^ sg0[k] ^ sg1[k];
        } else {
            // When t_xor = 0, the correction word has no effect
            // We need sg0[k] ⊕ sg1[k] = β[k] for correctness
            // If this doesn't hold, the DPF construction failed
            cw_np1[k] = 0;
        }
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


pub fn dpf_eval_xor_bytes<const ENTRY_U64_SIZE: usize>(
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

    // Calculate y_b using XOR instead of addition
    // For XOR-based DPF: y_b = ConvertG(s_n) ⊕ (t_n * CW_{n+1})
    let mut result = [0i64; ENTRY_U64_SIZE];

    for k in 0..ENTRY_U64_SIZE {
        let t_term = if t_n == 1 { key.cw_np1[k] } else { 0 };
        result[k] = convert_out[k] ^ t_term; // XOR instead of addition
    }

    result
}


pub fn dpf_eval_xor_bytes_full_optimized<const ENTRY_U64_SIZE: usize>(
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

            // Calculate y_b using XOR instead of addition
            if output_index < result.len() {
                for k in 0..ENTRY_U64_SIZE {
                    let t_term = if t_n == 1 { key.cw_np1[k] } else { 0 };
                    result[output_index][k] = convert_out[k] ^ t_term; // XOR instead of addition
                }
                output_index += 1;
            }
        }
    }

    result
}



pub fn dpf_priv_xor_update_gen_buckets<const ENTRY_U64_SIZE: usize>(
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
                let (k0, k1) = dpf_gen_xor_bytes(
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
            let (k0, k1) = dpf_gen_xor_bytes(
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


pub fn dpf_priv_xor_update_additive_buckets<const ENTRY_U64_SIZE: usize>(
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
            // Precompute seeds for the current key
            let precomputed_seeds = dpf_eval_xor_bytes_full_optimized(server_key, hs_key, aes);

            // Inner loop over DB entries in the bucket
            for (local_idx, db_entry) in bucket.iter_mut().enumerate() {
                // Evaluate the key quickly using precomputed data
                let eval_result = precomputed_seeds[local_idx];
                for k in 0..ENTRY_U64_SIZE {
                    db_entry[k] ^= eval_result[k];
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


// ========================================================================================================











