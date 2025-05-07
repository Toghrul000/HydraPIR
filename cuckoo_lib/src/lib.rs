#![allow(non_snake_case)]
use rand::rngs::ThreadRng;
use rand::{Rng, RngCore};
use siphasher::sip::SipHasher24;
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::hash::{Hash, Hasher};


// --- Constants related to the Algorithm (can be adjusted here) ---
const MAX_DISPLACEMENTS: usize = 100;
const MAX_TRACKED_DISPLACEMENTS: usize = 500;
// Default number of hashes if not specified otherwise (could also be generic/configurable)
const DEFAULT_NUM_HASHES: usize = 6;

//Entry<N>
pub type Entry<const N: usize> = [u64; N];


// --- Error Types ---
#[derive(Debug, PartialEq)]
pub enum CuckooError {
    EncodingError(String),
    DecodingError(String),
    InsertionFailed(String),
    RehashFailed(String),
}

impl fmt::Display for CuckooError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CuckooError::EncodingError(msg) => write!(f, "Encoding error: {}", msg),
            CuckooError::DecodingError(msg) => write!(f, "Decoding error: {}", msg),
            CuckooError::InsertionFailed(msg) => write!(f, "Insertion failed: {}", msg),
            CuckooError::RehashFailed(msg) => write!(f, "Rehash failed: {}", msg),
        }
    }
}

// Implement Error trait so it can be potentially boxed or converted
impl Error for CuckooError {}

// --- Private Helper Functions ---

/// Encodes (key: &str, value: &str) into a fixed-size Entry ([u64; N]).
/// Internal function, generic over N.
pub fn encode_entry<const N: usize>(
    key: &str,
    value: &str,
) -> Result<Entry<N>, CuckooError> {
    let ENTRY_SIZE_BYTES: usize = N * 8; // Calculate byte size from N
    if ENTRY_SIZE_BYTES < 4 {
        // Need at least 4 bytes for the two u16 lengths
        return Err(CuckooError::EncodingError(
            "Entry size (N * 8) must be at least 4 bytes.".to_string(),
        ));
    }

    let key_bytes = key.as_bytes();
    let value_bytes = value.as_bytes();
    let key_len = key_bytes.len();
    let value_len = value_bytes.len();

    if key_len > u16::MAX as usize || value_len > u16::MAX as usize {
        return Err(CuckooError::EncodingError(
            "Key or value length exceeds u16::MAX".to_string(),
        ));
    }
    let key_len_u16 = key_len as u16;
    let value_len_u16 = value_len as u16;

    let total_byte_size = 2 + 2 + key_len + value_len;
    if total_byte_size > ENTRY_SIZE_BYTES {
        return Err(CuckooError::EncodingError(format!(
            "Encoded entry byte size ({}) exceeds configured ENTRY_SIZE ({})",
            total_byte_size, ENTRY_SIZE_BYTES
        )));
    }

    let mut byte_buffer = vec![0u8; ENTRY_SIZE_BYTES];
    byte_buffer[0..2].copy_from_slice(&key_len_u16.to_le_bytes());
    byte_buffer[2..4].copy_from_slice(&value_len_u16.to_le_bytes());
    let key_start = 4;
    let key_end = key_start + key_len;
    byte_buffer[key_start..key_end].copy_from_slice(key_bytes);
    let value_start = key_end;
    let value_end = value_start + value_len;
    byte_buffer[value_start..value_end].copy_from_slice(value_bytes);

    let mut entry_u64 = [0u64; N];
    for i in 0..N {
        let byte_chunk_start = i * 8;
        let byte_chunk_end = byte_chunk_start + 8;
        let byte_chunk: [u8; 8] = byte_buffer[byte_chunk_start..byte_chunk_end]
            .try_into()
            .expect("Byte buffer size should be multiple of 8");
        entry_u64[i] = u64::from_le_bytes(byte_chunk);
    }
    Ok(entry_u64)
}

/// Decodes a fixed-size Entry ([u64; N]) back into (key: String, value: String).
/// Internal function, generic over N.
pub fn decode_entry<const N: usize>(
    entry: &Entry<N>,
) -> Result<Option<(String, String)>, CuckooError> {
    let EMPTY_SLOT_N: Entry<N> = [0u64; N]; // Define empty slot locally based on N
    let ENTRY_SIZE_BYTES: usize = N * 8;
     if ENTRY_SIZE_BYTES < 4 {
        return Err(CuckooError::DecodingError(
            "Entry size (N * 8) must be at least 4 bytes.".to_string(),
        ));
    }

    if entry == &EMPTY_SLOT_N {
        return Ok(None);
    }

    let mut byte_buffer = vec![0u8; ENTRY_SIZE_BYTES];
    for i in 0..N {
        let bytes = entry[i].to_le_bytes();
        let byte_chunk_start = i * 8;
        let byte_chunk_end = byte_chunk_start + 8;
        byte_buffer[byte_chunk_start..byte_chunk_end].copy_from_slice(&bytes);
    }

    let key_len_bytes: [u8; 2] = byte_buffer[0..2].try_into().unwrap();
    let key_len = u16::from_le_bytes(key_len_bytes) as usize;
    let value_len_bytes: [u8; 2] = byte_buffer[2..4].try_into().unwrap();
    let value_len = u16::from_le_bytes(value_len_bytes) as usize;

    if key_len == 0 && value_len == 0 {
        // Should have been caught by the entry == &EMPTY_SLOT_N check if truly empty
        println!("Warning: Decoded entry has zero lengths but wasn't EMPTY_SLOT. Treating as empty.");
        return Ok(None);
    }

    let key_start = 4;
    let key_end = key_start + key_len;
    let value_start = key_end;
    let value_end = value_start + value_len;

    if value_end > ENTRY_SIZE_BYTES {
        return Err(CuckooError::DecodingError(format!(
            "Decoded lengths (key={}, value={}) exceed entry bounds ({} > {})",
            key_len, value_len, value_end, ENTRY_SIZE_BYTES
        )));
    }

    let key = String::from_utf8(byte_buffer[key_start..key_end].to_vec())
        .map_err(|e| CuckooError::DecodingError(format!("Failed UTF-8 key decode: {}", e)))?;
    let value = String::from_utf8(byte_buffer[value_start..value_end].to_vec())
        .map_err(|e| CuckooError::DecodingError(format!("Failed UTF-8 value decode: {}", e)))?;

    Ok(Some((key, value)))
}

// --- Cuckoo Hash Table ---

/// A Cuckoo Hash Table storing key-value pairs with fixed-size entries.
///
/// Generic over `N`, the number of `u64` elements per entry.
/// The total byte size per entry is `N * 8`.
pub struct CuckooHashTable<const N: usize> {
    pub table: Vec<Entry<N>>,
    pub table_size: usize, // Must be power of 2
    pub mask: usize,       // table_size - 1
    pub num_hashes: usize,
    pub hash_keys: Vec<[u8; 16]>,
    rng: ThreadRng,
}

impl<const N: usize> CuckooHashTable<N> {
    /// Creates a new CuckooHashTable.
    ///
    /// # Arguments
    /// * `table_size` - The number of slots in the table. Must be a power of 2.
    ///
    /// # Errors
    /// Returns an error string if `table_size` is not a power of 2,
    /// if `N` (entry size in u64) is 0, or if internal checks fail.
    pub fn new(table_size: usize) -> Result<Self, String> {
        if !table_size.is_power_of_two() {
            return Err("Table size must be a power of 2".to_string());
        }
        if N == 0 {
            return Err("Entry size N (number of u64) cannot be zero".to_string());
        }
        // Check minimum byte size for encoding format
        if N * 8 < 4 {
             return Err("Entry byte size (N * 8) must be at least 4".to_string());
        }

        let num_hashes = DEFAULT_NUM_HASHES; // Use default for now
        if num_hashes == 0 {
            return Err("Number of hashes must be greater than 0".to_string());
        }

        let mut rng = rand::rng();
        let hash_keys = (0..num_hashes)
            .map(|_| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                key
            })
            .collect();

        Ok(CuckooHashTable { 
            table: vec![[0u64; N]; table_size], // Initialize with N-sized zero arrays
            table_size,
            mask: table_size - 1,
            num_hashes,
            hash_keys,
            rng,
        })
    }

    /// Calculates the hash of a key using the i-th hash function. (Internal)
    #[inline(always)]
    fn hash(&self, key: &str, hash_index: usize) -> usize {
        // Ensure hash_index is valid, though it should be internally controlled
        let key_bytes = self.hash_keys.get(hash_index).expect("Invalid hash index");
        let mut hasher = SipHasher24::new_with_key(key_bytes);
        key.hash(&mut hasher);
        (hasher.finish() as usize) & self.mask
    }

    /// Calculates all possible indices for a given key. (Internal)
    #[inline(always)]
    pub fn get_indices(&self, key: &str) -> Vec<usize> {
        (0..self.num_hashes).map(|i| self.hash(key, i)).collect()
    }

    pub fn get_target_points(&self, key: &str, beta: u32) -> Vec<(u32, u32)> {
        (0..self.num_hashes)
            .map(|i| (self.hash(key, i) as u32, beta))
            .collect()
    }

    /// Looks up a key in the hash table. Returns the associated String value.
    pub fn lookup(&self, key: &str) -> Result<Option<String>, CuckooError> {
        // Define empty slot locally based on N for comparison
        let EMPTY_SLOT_N: Entry<N> = [0u64; N];

        for i in 0..self.num_hashes {
            let index = self.hash(key, i);
            // Bounds check (should be unnecessary due to mask, but good practice)
            if index >= self.table_size { continue; }

            let entry_data = &self.table[index];

            if entry_data != &EMPTY_SLOT_N {
                 match decode_entry(entry_data)? { // Use generic decode_entry
                    Some((stored_key, stored_value)) => {
                        if stored_key == key {
                            return Ok(Some(stored_value));
                        }
                    }
                    None => continue,
                }
            }
        }
        Ok(None)
    }

    /// Reverts changes made during a failed insertion attempt. (Internal)
    fn revert_changes(&mut self, path: &[(usize, Entry<N>)]) {
        for (index, original_data) in path.iter().rev() {
            if *index < self.table_size { // Bounds check before writing
                self.table[*index] = *original_data;
            } else {
                 // This indicates a serious internal logic error if it happens
                 eprintln!("Error: revert_changes attempted to write out of bounds index {}", index);
            }
        }
    }

    /// Inserts a key-value pair (both Strings) into the hash table. (Simple version)
    pub fn insert(&mut self, key: String, value: String) -> Result<(), CuckooError> {
        let EMPTY_SLOT: Entry<N> = [0u64; N];
        // Encode the String key/value pair into an Entry ([u64; N])
        let mut current_entry_data = encode_entry(&key, &value)?;
        let mut current_key = key; // Keep track of the key being displaced

        let mut displacement_path: Vec<(usize, Entry<N>)> = Vec::new();

        for _attempt in 0..MAX_DISPLACEMENTS {
            // 1. Check all potential slots for the *current* key
            for i in 0..self.num_hashes {
                let index = self.hash(&current_key, i);
                if self.table[index] == EMPTY_SLOT {
                    self.table[index] = current_entry_data;
                    return Ok(());
                }
            }

            // 2. No empty slot found, must displace.
            let evict_hash_index = self.rng.random_range(0..self.num_hashes); // Use random eviction
            let evict_index = self.hash(&current_key, evict_hash_index);

            let displaced_entry_data = self.table[evict_index]; // Copy the [u64; N]
            displacement_path.push((evict_index, displaced_entry_data));
            self.table[evict_index] = current_entry_data; // Place current entry

            // The displaced entry becomes the new entry we need to find a home for
            current_entry_data = displaced_entry_data;

            // Decode the displaced entry to get its key (value is ignored here)
            match decode_entry(&current_entry_data)? {
                    Some((displaced_key, _)) => {
                    current_key = displaced_key; // Update key for next iteration
                    }
                    None => {
                    // This implies we displaced an EMPTY_SLOT, which shouldn't happen
                    // if the initial check didn't find an empty one. Or decode failed.
                    self.revert_changes(&displacement_path);
                    return Err(CuckooError::InsertionFailed(
                        "Displaced an entry that unexpectedly decoded as empty".to_string()
                    ));
                    }
            }
        }

        // 3. Max displacements reached
        self.revert_changes(&displacement_path);
        Err(CuckooError::InsertionFailed(format!(
            "Max displacements ({}) reached, potential cycle detected for key '{}'",
            MAX_DISPLACEMENTS, current_key
        )))
    }


    /// Inserts a key-value pair (both Strings) using hybrid cycle detection.
    pub fn insert_tracked(&mut self, key: String, value: String) -> Result<(), CuckooError> {
        // Define empty slot locally based on N for comparison
        let EMPTY_SLOT_N: Entry<N> = [0u64; N];

        let mut current_entry_data = encode_entry::<N>(&key, &value)?; // Use generic encode
        let mut current_key = key.clone();

        let mut displacement_path: Vec<(usize, [u64; N])> = Vec::new();
        let mut visited: Option<HashSet<(String, usize)>> = None;
        let mut intended_path: Vec<(String, usize)> = Vec::new();

        for displacement_count in 0..MAX_TRACKED_DISPLACEMENTS {
            for i in 0..self.num_hashes {
                let index = self.hash(&current_key, i);
                 if index >= self.table_size { continue; } // Bounds check
                if self.table[index] == EMPTY_SLOT_N {
                    displacement_path.push((index, self.table[index]));
                    self.table[index] = current_entry_data;
                    return Ok(());
                }
            }

            // Determine eviction target
            let evict_hash_index = self.rng.random_range(0..self.num_hashes);
            let evict_index = self.hash(&current_key, evict_hash_index);
             if evict_index >= self.table_size {
                 // Should not happen with correct masking, indicates potential issue
                 self.revert_changes(&displacement_path); // Revert previous steps if any
                 return Err(CuckooError::InsertionFailed(format!(
                    "Internal error: Calculated eviction index {} out of bounds for key '{}'",
                    evict_index, current_key
                 )));
             }

            let target_key_index_pair = (current_key.clone(), evict_index);
            intended_path.push(target_key_index_pair.clone());

            // Cycle Detection Logic
            if displacement_count >= MAX_DISPLACEMENTS {
                if visited.is_none() {
                    let mut initial_visited = HashSet::with_capacity(intended_path.len());
                    for item in &intended_path { initial_visited.insert(item.clone()); }
                    visited = Some(initial_visited);
                }
                if let Some(ref mut visited_set) = visited {
                    if visited_set.contains(&target_key_index_pair) {
                        self.revert_changes(&displacement_path);
                        return Err(CuckooError::InsertionFailed(format!(
                            "Cycle detected for key '{}' at index {}", current_key, evict_index
                        )));
                    }
                    visited_set.insert(target_key_index_pair);
                }
            }

            // Displace
            let displaced_entry_data = self.table[evict_index];
            displacement_path.push((evict_index, displaced_entry_data));
            self.table[evict_index] = current_entry_data;

            // Update current key/entry
            current_entry_data = displaced_entry_data;
            match decode_entry(&current_entry_data)? { // Use generic decode
                 Some((displaced_key, _)) => current_key = displaced_key,
                 None => {
                    self.revert_changes(&displacement_path);
                    return Err(CuckooError::InsertionFailed(
                        "Displaced an entry that unexpectedly decoded as empty".to_string()
                    ));
                 }
            }
        }

        self.revert_changes(&displacement_path);
        Err(CuckooError::InsertionFailed(format!(
            "Max tracked displacements ({}) reached for key '{}'", MAX_TRACKED_DISPLACEMENTS, current_key
        )))
    }

    /// Calculates the current load factor (0.0 to 1.0).
    pub fn load_factor(&self) -> f64 {
        // Define empty slot locally based on N for comparison
        let EMPTY_SLOT_N: Entry<N> = [0u64; N];
        let filled_slots = self
            .table
            .iter()
            .filter(|&&entry| entry != EMPTY_SLOT_N)
            .count();
        if self.table_size == 0 {
            0.0
        } else {
             filled_slots as f64 / self.table_size as f64
        }
    }

    /// Regenerates hash keys and re-inserts all items into the table.
    pub fn rehash(&mut self) -> Result<(), CuckooError> {
        println!(
            "---> Starting rehash process (current load: {:.2}%)...",
            self.load_factor() * 100.0
        );

        let mut new_keys = Vec::with_capacity(self.num_hashes);
        for _ in 0..self.num_hashes {
            let mut key = [0u8; 16];
            self.rng.fill_bytes(&mut key);
            new_keys.push(key);
        }

        // Create a temporary table *of the same generic type*
        let mut temp_cuckoo: CuckooHashTable<N> = CuckooHashTable {
            table: vec![[0u64; N]; self.table_size],
            table_size: self.table_size,
            mask: self.mask,
            num_hashes: self.num_hashes,
            hash_keys: new_keys.clone(),
            rng: rand::rng(),
        };

        let old_table_data = std::mem::take(&mut self.table);
        let mut rehashed_count = 0;
        let mut error_occurred: Option<CuckooError> = None;

        for entry_data in old_table_data.iter() {
            // Define empty slot locally based on N for comparison
            let EMPTY_SLOT_N: Entry<N> = [0u64; N];
            if entry_data != &EMPTY_SLOT_N {
                match decode_entry(entry_data) { // Use generic decode
                    Ok(Some((key, value))) => {
                        // Use insert_tracked on the temp table
                        if let Err(insert_err) = temp_cuckoo.insert_tracked(key.clone(), value) {
                            error_occurred = Some(CuckooError::RehashFailed(format!(
                                "Failed re-insert key '{}': {:?}", key, insert_err
                            )));
                            break;
                        } else {
                            rehashed_count += 1;
                        }
                    }
                    Ok(None) => { /* Skip */ }
                    Err(decode_err) => {
                        error_occurred = Some(CuckooError::RehashFailed(format!(
                            "Failed decode: {:?}", decode_err
                        )));
                        break;
                    }
                }
            }
        }

        if let Some(err) = error_occurred {
            println!("---> Rehash failed. Restoring original table state.");
            self.table = old_table_data; // Restore original table data
            // Keys are implicitly restored as self.hash_keys wasn't updated yet
            Err(err)
        } else {
            println!(
                "---> Rehash successful. {} items re-inserted.", rehashed_count
            );
            self.table = temp_cuckoo.table; // Keep the new table
            self.hash_keys = new_keys; // Update the keys
            Ok(())
        }
    }


    /// Attempts to rehash the table multiple times, increasing the number of hash
    /// functions if necessary, until success or limits are reached.
    ///
    /// # Arguments
    /// * `max_attempts_per_config` - Max times to try rehashing with the current number of hashes.
    ///
    /// # Errors
    /// Returns `CuckooError::RehashFailed` if rehashing fails even after multiple
    /// attempts and potentially increasing the number of hash functions up to
    /// `MAX_ALLOWED_HASHES`.
    pub fn rehash_loop(&mut self, max_attempts_per_config: usize) -> Result<(), CuckooError> {
        println!(
            "--- Starting persistent rehash loop (max {} attempts per config) ---",
            max_attempts_per_config
        );

        loop { // Outer loop for escalating num_hashes
            println!(
                "---> Attempting rehash with {} hash functions...",
                self.num_hashes
            );

            // Inner loop: Try rehashing multiple times with current config
            for attempt in 0..max_attempts_per_config {
                println!(
                    "  Attempt {}/{} with {} hashes...",
                    attempt + 1,
                    max_attempts_per_config,
                    self.num_hashes
                );

                // Call the standard rehash function
                match self.rehash() {
                    Ok(_) => {
                        // Success! self.rehash() already updated the table and keys.
                        println!(
                            "---> Rehash loop successful after {} attempts with {} hashes.",
                            attempt + 1,
                            self.num_hashes
                        );
                        return Ok(()); // Exit the loop and function successfully
                    }
                    Err(e) => {
                        // Log the specific error from this rehash attempt
                        eprintln!("   Rehash attempt failed: {}", e);
                        // self.rehash() should have restored the state, so we can try again.
                        // If the error was fatal (e.g., decode error), it will likely repeat,
                        // but we still allow `max_attempts_per_config`.
                    }
                }
            } // End inner attempt loop

            // If we exit the inner loop, all attempts for the current num_hashes failed.
            println!(
                "---> All {} attempts failed with {} hash functions.",
                max_attempts_per_config, self.num_hashes
            );

            // Check if we can escalate by increasing num_hashes
            // if self.num_hashes >= MAX_ALLOWED_HASHES {
            //     eprintln!(
            //         "---> Reached maximum allowed hash functions ({}) without success.",
            //         MAX_ALLOWED_HASHES
            //     );
            //     // The table state is consistent from the last failed rehash attempt.
            //     return Err(CuckooError::RehashFailed(format!(
            //         "Rehash loop failed after {} attempts with {} hashes (max allowed: {}).",
            //         max_attempts_per_config, self.num_hashes, MAX_ALLOWED_HASHES
            //     )));
            // }

            // Escalate: Increase num_hashes
            // Note: We only increase num_hashes. The next call to self.rehash()
            // inside the loop will handle generating the correct number of new keys.
            self.num_hashes += 1;
            println!(
                "---> Escalating: Increasing number of hash functions to {}.",
                self.num_hashes
            );
            // Continue the outer loop to try rehashing with the new num_hashes

        } // End outer loop
    }



    /// Helper: Performs one attempt to rehash existing items AND insert previously failed items.
    /// Restores state if any part fails.
    pub fn rehash_with_failed(
        &mut self,
        keys_failed_insertion: &Vec<(String, String)>, // Borrow the list
    ) -> Result<(), CuckooError> {
        // --- Phase 1: Rehash existing items (similar to rehash) ---
        println!("    -> Starting single rehash_with_failed attempt...");

        let mut new_keys = Vec::with_capacity(self.num_hashes);
        for _ in 0..self.num_hashes {
            let mut key = [0u8; 16];
            self.rng.fill_bytes(&mut key);
            new_keys.push(key);
        }

        let mut temp_cuckoo: CuckooHashTable<N> = CuckooHashTable {
            table: vec![[0u64; N]; self.table_size],
            table_size: self.table_size,
            mask: self.mask,
            num_hashes: self.num_hashes,
            hash_keys: new_keys.clone(), // Use new keys for temp table
            rng: rand::rng(), // Fresh rng for temp table operations
        };

        let old_table_data = std::mem::take(&mut self.table);
        let mut rehashed_count = 0;
        let mut error_occurred: Option<CuckooError> = None;
        let EMPTY_SLOT_N: Entry<N> = [0u64; N];

        // Try rehashing existing items into temp_cuckoo
        for entry_data in old_table_data.iter() {
            if entry_data != &EMPTY_SLOT_N {
                match decode_entry(entry_data) {
                    Ok(Some((key, value))) => {
                        if let Err(insert_err) = temp_cuckoo.insert_tracked(key.clone(), value) {
                            error_occurred = Some(CuckooError::RehashFailed(format!(
                                "(Phase 1) Failed re-insert key '{}': {:?}", key, insert_err
                            )));
                            break; // Stop this attempt
                        } else {
                            rehashed_count += 1;
                        }
                    }
                    Ok(None) => { /* Skip */ }
                    Err(decode_err) => {
                        error_occurred = Some(CuckooError::RehashFailed(format!(
                            "(Phase 1) Failed decode: {:?}", decode_err
                        )));
                        break; // Stop this attempt
                    }
                }
            }
        }

        // If Phase 1 failed, restore and return error
        if let Some(err) = error_occurred {
            println!("    -> Rehash attempt failed during Phase 1 (rehashing existing). Restoring state.");
            self.table = old_table_data; // Restore original table
            // self.hash_keys remain the old ones
            return Err(err);
        }
        println!("    -> Phase 1 successful ({} existing items placed).", rehashed_count);


        // --- Phase 2: Try inserting the previously failed items ---
        println!("    -> Starting Phase 2: Inserting {} previously failed items...", keys_failed_insertion.len());
        let mut failed_inserted_count = 0;
        for (key, value) in keys_failed_insertion.iter() { // Iterate over borrowed list
             if let Err(insert_err) = temp_cuckoo.insert_tracked(key.clone(), value.clone()) {
                 // If inserting a previously failed item fails *now*, the whole attempt fails
                 error_occurred = Some(CuckooError::RehashFailed(format!(
                     "(Phase 2) Failed inserting previously failed key '{}': {:?}", key, insert_err
                 )));
                 break; // Stop this attempt
             } else {
                 failed_inserted_count += 1;
             }
        }

        // Check result of Phase 2
        if let Some(err) = error_occurred {
            // Phase 2 failed, restore original state and return error
            println!("    -> Rehash attempt failed during Phase 2 (inserting failed items). Restoring state.");
            self.table = old_table_data; // Restore original table
            // self.hash_keys remain the old ones
            Err(err)
        } else {
            // Both phases successful! Commit the changes.
            println!(
                "    -> Phase 2 successful ({} previously failed items placed).",
                failed_inserted_count
            );
            println!("    -> Single rehash_with_failed attempt successful.");
            self.table = temp_cuckoo.table; // Keep the new table
            self.hash_keys = new_keys; // Update the keys
            Ok(())
        }
    }


    /// Attempts to rehash the table and insert previously failed items, looping
    /// and increasing the number of hash functions if necessary, until success
    /// or limits are reached.
    ///
    /// # Arguments
    /// * `keys_failed_insertion` - A list of (key, value) pairs that failed previous insertions.
    /// * `max_attempts_per_config` - Max times to try with the current number of hashes.
    ///
    /// # Returns
    /// * `Ok(())` - If rehashing and inserting all items succeeded.
    /// * `Err((CuckooError, Vec<(String, String)>))` - If the process failed definitively.
    ///   The error indicates the reason, and the Vec contains the items that still
    ///   could not be inserted (the original `keys_failed_insertion` list).
    pub fn rehash_loop_with_failed(
        &mut self,
        mut keys_failed_insertion: Vec<(String, String)>, // Take ownership
        max_attempts_per_config: usize,
    ) -> Result<(), (CuckooError, Vec<(String, String)>)> { // Return tuple on error
        println!(
            "--- Starting persistent rehash loop WITH FAILED items (max {} attempts per config) ---",
            max_attempts_per_config
        );

        if keys_failed_insertion.is_empty() {
            println!("--- No failed items provided, attempting standard rehash loop ---");
            // Fallback to standard rehash_loop logic if no failed items given
             return self.rehash_loop(max_attempts_per_config)
                 .map_err(|e| (e, keys_failed_insertion)); // Still return tuple format
        }

        let initial_num_failed = keys_failed_insertion.len();

        loop { // Outer loop for escalating num_hashes
            println!(
                "---> Attempting rehash_with_failed using {} hash functions...",
                self.num_hashes
            );

            // Inner loop: Try multiple times with current config
            for attempt in 0..max_attempts_per_config {
                println!(
                    "  Attempt {}/{} with {} hashes (targeting {} failed items)...",
                    attempt + 1,
                    max_attempts_per_config,
                    self.num_hashes,
                    initial_num_failed // Use initial count for logging clarity
                );

                // Call the helper function for one full attempt
                match self.rehash_with_failed(&keys_failed_insertion) { // Pass borrow
                    Ok(_) => {
                        // Success! Helper updated the table and keys. Failed items are in.
                        println!(
                            "---> Rehash loop WITH FAILED items successful after {} attempts with {} hashes.",
                            attempt + 1,
                            self.num_hashes
                        );
                        // *** Clear the vector now that items are successfully integrated ***
                        keys_failed_insertion.clear();
                        return Ok(()); // Exit successfully
                    }
                    Err(e) => {
                        // Log the specific error from this attempt
                        eprintln!("   Attempt failed: {}", e);
                    }
                }
            } // End inner attempt loop

            // All attempts for the current num_hashes failed.
            println!(
                "---> All {} attempts failed with {} hash functions.",
                max_attempts_per_config, self.num_hashes
            );

            // // Check if we can escalate
            // if self.num_hashes >= MAX_ALLOWED_HASHES {
            //     eprintln!(
            //         "---> Reached maximum allowed hash functions ({}) without success.",
            //         MAX_ALLOWED_HASHES
            //     );
            //     // Return the last error and the original list of failed items
            //     return Err((
            //         CuckooError::RehashFailed(format!(
            //             "Loop failed after {} attempts with {} hashes (max allowed: {}). Last error: {}",
            //             max_attempts_per_config, self.num_hashes, MAX_ALLOWED_HASHES, last_error
            //         )),
            //         keys_failed_insertion // Return the list
            //     ));
            // }

            // Escalate
            self.num_hashes += 1;
            println!(
                "---> Escalating: Increasing number of hash functions to {}.",
                self.num_hashes
            );
            // Continue outer loop
        } // End outer loop
    }

    /// Resets all entries in the hash table to the empty state.
    pub fn purge_table(&mut self) {
        // Define empty slot locally based on N
        let EMPTY_SLOT_N: Entry<N> = [0u64; N];
        println!("---> Purging table (clearing all entries)...");
        for entry in self.table.iter_mut() {
            *entry = EMPTY_SLOT_N;
        }
        println!(
            "---> Table purged. Load factor: {:.2}%",
            self.load_factor() * 100.0
        );
    }
}

// --- Public Helper Function ---

/// Calculates the required table size (power of 2) and the corresponding
/// exponent `n` (where table_size = 2^n) for given storage and entry size.
///
/// # Arguments
/// * `total_storage_bytes` - The total desired storage capacity in bytes.
/// * `entry_size_bytes` - The size of each entry in bytes.
///
/// # Returns
/// A tuple `(table_size, n)` where:
/// * `table_size`: The smallest power of 2 number of slots >= required entries.
/// * `n`: The exponent such that `table_size == 2^n`.
/// Returns `(0, 0)` if `entry_size_bytes` is 0.
/// Returns `(1, 0)` if `total_storage_bytes` is 0.
pub fn calculate_required_table_size(
    total_storage_bytes: u64,
    entry_size_bytes: usize,
) -> (usize, u32) { // Return type is now a tuple
    if entry_size_bytes == 0 {
        eprintln!("Error: entry_size_bytes cannot be 0.");
        return (0, 0); // Cannot calculate size or n
    }
    // Ensure entry_size_bytes is reasonable (e.g., >= 8 for u64 alignment)
    if entry_size_bytes < 8 || entry_size_bytes % 8 != 0 {
        eprintln!(
            "Warning: calculate_required_table_size_and_n called with \
             entry_size_bytes {} not multiple of 8. Result might be suboptimal.",
            entry_size_bytes
        );
        // Proceed anyway, but the user should align ENTRY_SIZE in main
    }

    // Calculate the minimum number of entries needed (ceiling division)
    let num_entries_required =
        (total_storage_bytes + entry_size_bytes as u64 - 1) / entry_size_bytes as u64;

    // Handle edge case where 0 bytes are requested or result is 0 entries
    if num_entries_required == 0 {
        // The smallest power-of-2 table size is 1 (2^0)
        (1, 0)
    } else {
        // Find the next power of 2 >= num_entries_required
        let table_size = num_entries_required.next_power_of_two() as usize;

        // For a power of 2 (like table_size here), the number of trailing zeros
        // in its binary representation gives the exponent n.
        let n = table_size.trailing_zeros(); // trailing_zeros returns u32

        (table_size, n)
    }
}


pub fn fill_cuckoo_from_csv<const N: usize>(
    cuckoo_table: &mut CuckooHashTable<N>,
    csv_file_path: &str,
    max_rehash_attempts_per_config: usize,
) -> Result<(usize, usize), Box<dyn Error>> { // Return counts on success

    println!("\n--- Performing Insertions from {} ---", csv_file_path);
    let mut successful_insertions = 0;
    let mut failed_insertions_count = 0; // Track count, not just bool
    let mut line_count = 0;
    let mut keys_failed_insertion: Vec<(String, String)> = Vec::new();

    // --- File Reading and Initial Insertions ---
    if !std::path::Path::new(csv_file_path).exists() {
        // Handle missing file - maybe return an error or specific status
        return Err(Box::<dyn Error>::from(format!(
            "CSV file not found at '{}'",
            csv_file_path
        )));
    }

    let file = std::fs::File::open(csv_file_path)?;
    let mut rdr = csv::ReaderBuilder::new().has_headers(true).from_reader(file);

    for result in rdr.records() {
        line_count += 1;
        let record = result?;

        // Use map_err to convert Option error to Box<dyn Error> for ?
        let key = record
            .get(0)
            .ok_or_else(|| Box::<dyn Error>::from("Missing key column in CSV"))?
            .trim() // Trim whitespace from key
            .to_string();
        let value = record
            .get(1)
            .ok_or_else(|| Box::<dyn Error>::from("Missing value column in CSV"))?
            .to_string(); // Keep value as is

        if key.is_empty() {
            println!("Warning: Skipping line {} due to empty key.", line_count + 1);
            continue;
        }

        // Use the library's insert method
        match cuckoo_table.insert_tracked(key.clone(), value.clone()) {
            Ok(_) => {
                successful_insertions += 1;
            }
            Err(e @ CuckooError::InsertionFailed(_)) => {
                if failed_insertions_count < 10 {
                    eprintln!(
                        "Insertion failed for key '{}' (line {}): {}",
                        key,
                        line_count + 1,
                        e
                    );
                } else if failed_insertions_count == 10 {
                    eprintln!("(Further insertion errors suppressed)");
                }
                failed_insertions_count += 1;
                keys_failed_insertion.push((key, value));
            }
            Err(e) => {
                 // Treat other CuckooErrors as potentially serious
                 eprintln!("Unexpected Cuckoo error during insertion for key '{}': {}", key, e);
                 // Option 1: Stop processing
                 return Err(Box::new(e));
                 // Option 2: Treat as failed insertion and continue
                 // failed_insertions_count += 1;
                 // keys_failed_insertion.push((key, value));
            }
        }

        if line_count % 50000 == 0 {
            println!(
                "  Processed {} CSV records ({} successful, {} failed)... Load: {:.2}%",
                line_count,
                successful_insertions,
                failed_insertions_count, // Use the count here
                cuckoo_table.load_factor() * 100.0
            );
        }
    }
    println!("Finished processing {} CSV records.", line_count);

    println!("--- Initial Insertion Summary ---");
    println!("Successful Insertions: {}", successful_insertions);
    println!("Failed Insertions (Initial): {}", failed_insertions_count);
    println!("Load Factor Before Rehash Attempt: {:.2}%", cuckoo_table.load_factor() * 100.0);

    // --- Attempt Rehash Loop WITH FAILED items ---
    let mut final_failed_count = failed_insertions_count; // Initialize with initial failures

    if !keys_failed_insertion.is_empty() {
        println!(
            "\n--- Attempting Rehash Loop WITH FAILED items ({}) ---",
            keys_failed_insertion.len()
        );

        match cuckoo_table.rehash_loop_with_failed(
            keys_failed_insertion, // Pass ownership
            max_rehash_attempts_per_config
        ) {
            Ok(_) => {
                println!("Rehash loop WITH FAILED items completed successfully.");
                final_failed_count = 0; // All items were integrated
            }
            Err((e, still_failed_items)) => {
                eprintln!("Rehash loop WITH FAILED items failed definitively: {}", e);
                println!("Table state restored to before the last failed attempt within the loop.");
                final_failed_count = still_failed_items.len(); // Update count
                if !still_failed_items.is_empty() {
                    eprintln!("{} items could not be inserted even after rehash loop:", final_failed_count);
                    for (key, _) in still_failed_items.iter().take(5) { // Show remaining failed
                        eprintln!("  - {}", key);
                    }
                    if final_failed_count > 5 { eprintln!("  ...") };
                }
                 // Option 1: Return Ok with the non-zero final_failed_count (as implemented now)
                 // Option 2: Return an Err to signal the caller that not everything fit
                 // return Err(Box::new(e));
            }
        }
        println!(
            "Final Load Factor after rehash loop attempt: {:.2}%",
            cuckoo_table.load_factor() * 100.0
        );
        println!("Remaining failed insertions after loop: {}", final_failed_count);

    } else if failed_insertions_count > 0 {
         // This indicates a logic error if the count is > 0 but the list is empty
         eprintln!("Warning: {} insertions reported failed, but the failed items list is empty before rehash.", failed_insertions_count);
         final_failed_count = failed_insertions_count; // Keep the count as reported
    }

    // Return the initial success count and the final failed count
    Ok((successful_insertions, final_failed_count))
}
