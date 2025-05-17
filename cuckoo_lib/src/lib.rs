#![allow(non_snake_case)]
use rand::{Rng, RngCore};
use siphasher::sip::SipHasher24;
use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::hash::{Hash, Hasher};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::sync::Mutex;


// --- Constants related to the Algorithm (can be adjusted here) ---
const MAX_DISPLACEMENTS: usize = 100;
const MAX_TRACKED_DISPLACEMENTS: usize = 500;
// Default number of hashes if not specified otherwise (could also be generic/configurable)
const DEFAULT_NUM_HASHES: usize = 6;
// Default number of distinct bucket choices / local hash functions (k)
const DEFAULT_K_CHOICES: usize = 6;

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
#[derive(Debug)]
pub struct CuckooHashTable<const N: usize> {
    pub table: Vec<Entry<N>>,
    pub table_size: usize, // Must be power of 2
    pub mask: usize,       // table_size - 1
    pub num_hashes: usize,
    pub hash_keys: Vec<[u8; 16]>,
    rng: Mutex<StdRng>,
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

        let mut rng = StdRng::from_os_rng();
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
            rng: Mutex::new(rng),
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
            let evict_hash_index = {
                let mut rng = self.rng.lock().unwrap();
                rng.random_range(0..self.num_hashes)
            };
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
    pub fn insert_tracked(&mut self, key: String, value: String, deterministic_eviction_seed: Option<&[u8; 16]>) -> Result<(), CuckooError> {
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
            let evict_hash_index: usize;
            if let Some(seed) = deterministic_eviction_seed {
                // Deterministic eviction choice
                let mut hasher = SipHasher24::new_with_key(seed);
                current_key.hash(&mut hasher); // Hash current key
                displacement_count.hash(&mut hasher); // Hash displacement count for variance
                evict_hash_index = hasher.finish() as usize % self.num_hashes;
            } else {
                // Random eviction choice using the table's RNG
                evict_hash_index = {
                    let mut rng = self.rng.lock().unwrap();
                    rng.random_range(0..self.num_hashes)
                };
            }
            
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


    /// Inserts a key-value pair (both Strings) using hybrid cycle detection,
    /// and returns a log of changes made to the table upon successful insertion.
    ///
    /// # Returns
    /// * `Ok(Vec<(usize, Entry<N>)>)` - On success, a vector where each tuple is
    ///   `(index_modified, new_value_written_to_index)`.
    /// * `Err(CuckooError)` - If insertion fails.
    pub fn insert_tracked_with_log(
        &mut self,
        key: String,
        value: String,
    ) -> Result<Vec<(usize, Entry<N>)>, CuckooError> {
        let EMPTY_SLOT_N: Entry<N> = [0u64; N];

        let mut current_entry_data = encode_entry::<N>(&key, &value)?;
        let mut current_key = key.clone();

        // For reverting changes if the entire insertion process fails
        let mut displacement_path: Vec<(usize, Entry<N>)> = Vec::new();
        // For logging successful changes
        let mut change_log: Vec<(usize, Entry<N>)> = Vec::new();

        let mut visited: Option<HashSet<(String, usize)>> = None;
        let mut intended_path: Vec<(String, usize)> = Vec::new();

        for displacement_count in 0..MAX_TRACKED_DISPLACEMENTS {
            // --- Phase 1 & 2: Check for empty slot ---
            for i in 0..self.num_hashes {
                let index = self.hash(&current_key, i);
                if index >= self.table_size { continue; } // Bounds check

                if self.table[index] == EMPTY_SLOT_N {
                    // Found an empty slot. This is the final placement for current_entry_data.
                    // displacement_path.push((index, self.table[index])); // self.table[index] is EMPTY_SLOT_N
                    self.table[index] = current_entry_data; // Perform the write
                    change_log.push((index, current_entry_data)); // Log this successful write
                    return Ok(change_log);
                }
            }

            // --- Determine eviction target ---
            let evict_hash_index = {
                let mut rng = self.rng.lock().unwrap();
                rng.random_range(0..self.num_hashes)
            };
            let evict_index = self.hash(&current_key, evict_hash_index);

            if evict_index >= self.table_size {
                self.revert_changes(&displacement_path);
                return Err(CuckooError::InsertionFailed(format!(
                    "Internal error: Calculated eviction index {} out of bounds for key '{}'",
                    evict_index, current_key
                )));
            }

            let target_key_index_pair = (current_key.clone(), evict_index);
            intended_path.push(target_key_index_pair.clone());

            // --- Phase 2: Cycle Detection Logic ---
            if displacement_count >= MAX_DISPLACEMENTS {
                if visited.is_none() {
                    let mut initial_visited = HashSet::with_capacity(intended_path.len());
                    for item in &intended_path { initial_visited.insert(item.clone()); }
                    visited = Some(initial_visited);
                }
                if let Some(ref mut visited_set) = visited {
                    if visited_set.contains(&target_key_index_pair) {
                        self.revert_changes(&displacement_path); // Revert all previous displacements
                        return Err(CuckooError::InsertionFailed(format!(
                            "Cycle detected for key '{}' at index {}", current_key, evict_index
                        )));
                    }
                    visited_set.insert(target_key_index_pair);
                }
            }

            // --- Displace the entry ---
            // current_entry_data is what we are trying to place in this step.
            // It will overwrite the entry at evict_index.
            let displaced_entry_data = self.table[evict_index]; // This is the old value being kicked out

            // For reverting: store the old value that was at evict_index
            displacement_path.push((evict_index, displaced_entry_data));

            // Perform the write: current_entry_data goes into evict_index
            self.table[evict_index] = current_entry_data;

            // For logging: record that current_entry_data was written to evict_index
            change_log.push((evict_index, current_entry_data));

            // The displaced entry becomes the new entry we need to find a home for
            current_entry_data = displaced_entry_data;
            match decode_entry(&current_entry_data)? {
                 Some((displaced_key, _)) => current_key = displaced_key,
                 None => {
                    self.revert_changes(&displacement_path);
                    return Err(CuckooError::InsertionFailed(
                        "Displaced an entry that unexpectedly decoded as empty".to_string()
                    ));
                 }
            }
        } // End displacement loop

        // If loop finishes, MAX_TRACKED_DISPLACEMENTS reached
        self.revert_changes(&displacement_path); // Revert all changes made
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
            let mut rng = self.rng.lock().unwrap();
            rng.fill_bytes(&mut key);
            new_keys.push(key);
        }

        // Create a temporary table *of the same generic type*
        let mut temp_cuckoo: CuckooHashTable<N> = CuckooHashTable {
            table: vec![[0u64; N]; self.table_size],
            table_size: self.table_size,
            mask: self.mask,
            num_hashes: self.num_hashes,
            hash_keys: new_keys.clone(),
            rng: Mutex::new(StdRng::from_os_rng()),
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
                        if let Err(insert_err) = temp_cuckoo.insert_tracked(key.clone(), value, None) {
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
            let mut rng = self.rng.lock().unwrap();
            rng.fill_bytes(&mut key);
            new_keys.push(key);
        }

        let mut temp_cuckoo: CuckooHashTable<N> = CuckooHashTable {
            table: vec![[0u64; N]; self.table_size],
            table_size: self.table_size,
            mask: self.mask,
            num_hashes: self.num_hashes,
            hash_keys: new_keys.clone(), // Use new keys for temp table
            rng: Mutex::new(StdRng::from_os_rng()), // Fresh rng for temp table operations
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
                        if let Err(insert_err) = temp_cuckoo.insert_tracked(key.clone(), value, None) {
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
             if let Err(insert_err) = temp_cuckoo.insert_tracked(key.clone(), value.clone(), None) {
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

// Add these traits to make CuckooHashTable thread-safe
unsafe impl<const N: usize> Send for CuckooHashTable<N> {}
unsafe impl<const N: usize> Sync for CuckooHashTable<N> {}




/// Shuffles a list of usize with a given u64 seed and returns the first k elements.
/// Uses a partial Fisher-Yates shuffle.
fn shuffle_and_take_k_usize(list_len: usize, seed: u64, k: usize) -> Vec<usize> {
    if k == 0 { return Vec::new(); }
    if list_len == 0 { return Vec::new(); }

    let mut rng = StdRng::seed_from_u64(seed);
    let mut all_ids: Vec<usize> = (0..list_len).collect();
    
    let k_clamped = std::cmp::min(k, all_ids.len());
    
    // Partial Fisher-Yates shuffle
    for i in 0..k_clamped {
        let j = rng.random_range(i..all_ids.len());
        all_ids.swap(i, j);
    }
    
    all_ids.truncate(k_clamped);
    all_ids
}


pub fn get_hierarchical_indices(
    bucket_selection_key: &[u8; 16], 
    local_hash_keys: &Vec<[u8; 16]>,
    k_choices: &usize, 
    num_total_buckets: &usize, 
    slots_per_bucket: &usize, 
    key_to_hash: &str) -> Vec<usize> { 

        // Phase 1: Bucket Selection
        let mut bucket_seed_hasher = SipHasher24::new_with_key(bucket_selection_key);
        key_to_hash.hash(&mut bucket_seed_hasher);
        let shuffle_seed = bucket_seed_hasher.finish();

        let selected_bucket_ids = shuffle_and_take_k_usize(
            num_total_buckets.clone(),
            shuffle_seed,
            k_choices.clone(),
        );

        // Phase 2: Local Hashing & Global Index Calculation
        let mut global_indices = Vec::with_capacity(k_choices.clone());
        for (i, bucket_id) in selected_bucket_ids.iter().enumerate() {
            let local_hash_key = local_hash_keys[i]; // Use i-th local hash key
            let mut local_hasher = SipHasher24::new_with_key(&local_hash_key);
            key_to_hash.hash(&mut local_hasher);
            // Local index within the bucket
            let local_index = (local_hasher.finish() as usize) % slots_per_bucket;

            let global_index = bucket_id * slots_per_bucket + local_index;
            global_indices.push(global_index);
        }
        global_indices

}



// Add these traits to make CuckooHashTable thread-safe
unsafe impl<const N: usize> Send for CuckooHashTableBucketed<N> {}
unsafe impl<const N: usize> Sync for CuckooHashTableBucketed<N> {}

// --- Cuckoo Hash Table ---
#[derive(Debug)]
pub struct CuckooHashTableBucketed<const N: usize> {
    pub table: Vec<Entry<N>>,
    pub table_size: usize,      // Total slots: num_total_buckets * slots_per_bucket
    pub mask: usize,            // table_size - 1
    pub k_choices: usize,       // Number of distinct buckets to choose / local hash functions (k)
    pub local_hash_keys: Vec<[u8; 16]>, // Keys for local hashing within buckets
    rng: Mutex<StdRng>,             // For random eviction choice if not deterministic

    // Hierarchical Hashing specific fields
    pub num_total_buckets: usize,
    pub slots_per_bucket: usize,
    pub bucket_selection_key: [u8; 16], // Key for seeding bucket permutation
}

impl<const N: usize> CuckooHashTableBucketed<N> {

    pub fn new(
        num_total_buckets: usize,
        slots_per_bucket: usize,
    ) -> Result<Self, String> {
        if N == 0 { return Err("Entry size N (u64 count) cannot be zero".to_string()); }
        if N * 8 < 4 { return Err("Entry byte size (N * 8) must be at least 4".to_string()); }
        if num_total_buckets == 0 { return Err("Number of total buckets cannot be zero".to_string()); }
        if slots_per_bucket == 0 { return Err("Slots per bucket cannot be zero".to_string()); }

        let table_size = num_total_buckets * slots_per_bucket;
        if !table_size.is_power_of_two() {
            // This constraint is for the global mask. If we want per-bucket masks,
            // then slots_per_bucket should be power of 2. For now, global table_size.
            return Err(format!(
                "Total table size ({} * {} = {}) must be a power of 2.",
                num_total_buckets, slots_per_bucket, table_size
            ));
        }

        let k_choices = DEFAULT_K_CHOICES; // k
        if k_choices == 0 { return Err("Number of choices (k) must be > 0".to_string()); }
        if k_choices > num_total_buckets {
            return Err(format!(
                "Number of choices k ({}) cannot exceed num_total_buckets ({}).",
                k_choices, num_total_buckets
            ));
        }


        let mut rng = StdRng::from_os_rng(); // Correct way to get ThreadRng

        let mut bucket_selection_key = [0u8; 16];
        rng.fill_bytes(&mut bucket_selection_key);

        let local_hash_keys = (0..k_choices)
            .map(|_| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                key
            })
            .collect();

        Ok(CuckooHashTableBucketed {
            table: vec![[0u64; N]; table_size],
            table_size,
            mask: table_size - 1, // Mask for the global table
            k_choices,
            local_hash_keys,
            rng: Mutex::new(rng),
            num_total_buckets,
            slots_per_bucket,
            bucket_selection_key,
        })
    }

    /// Generates k distinct global indices using hierarchical hashing.
    pub fn get_hierarchical_indices(&self, key_to_hash: &str) -> Vec<usize> {
        // Phase 1: Bucket Selection
        let mut bucket_seed_hasher = SipHasher24::new_with_key(&self.bucket_selection_key);
        key_to_hash.hash(&mut bucket_seed_hasher);
        let shuffle_seed = bucket_seed_hasher.finish();

        let selected_bucket_ids = shuffle_and_take_k_usize(
            self.num_total_buckets,
            shuffle_seed,
            self.k_choices,
        );

        // Phase 2: Local Hashing & Global Index Calculation
        let mut global_indices = Vec::with_capacity(self.k_choices);
        for (i, bucket_id) in selected_bucket_ids.iter().enumerate() {
            let local_hash_key = &self.local_hash_keys[i]; // Use i-th local hash key
            let mut local_hasher = SipHasher24::new_with_key(local_hash_key);
            key_to_hash.hash(&mut local_hasher);
            // Local index within the bucket
            let local_index = (local_hasher.finish() as usize) % self.slots_per_bucket;

            let global_index = bucket_id * self.slots_per_bucket + local_index;
            global_indices.push(global_index);
        }
        global_indices
    }



    pub fn lookup(&self, key: &str) -> Result<Option<String>, CuckooError> {
        let EMPTY_SLOT_N: Entry<N> = [0u64; N];
        let potential_indices = self.get_hierarchical_indices(key);

        for &index in &potential_indices {
            if index >= self.table_size { continue; } // Should not happen if logic is correct

            let entry_data = &self.table[index];
            if entry_data != &EMPTY_SLOT_N {
                 match decode_entry(entry_data)? {
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

    fn revert_changes(&mut self, path: &[(usize, Entry<N>)]) {
        for (index, original_data) in path.iter().rev() {
            if *index < self.table_size {
                self.table[*index] = *original_data;
            } else {
                 eprintln!("Error: revert_changes attempted to write out of bounds index {}", index);
            }
        }
    }

    /// Inserts a key-value pair (both Strings) using hybrid cycle detection.
    pub fn insert_tracked(
        &mut self,
        key: String,
        value: String,
        deterministic_eviction_seed: Option<&[u8; 16]>,
    ) -> Result<(), CuckooError> {
        let EMPTY_SLOT_N: Entry<N> = [0u64; N];
        let mut current_entry_data = encode_entry::<N>(&key, &value)?;
        let mut current_key = key.clone();

        let mut displacement_path: Vec<(usize, Entry<N>)> = Vec::new();
        let mut visited: Option<HashSet<(String, usize)>> = None; // Tracks (key, global_index_tried)
        let mut intended_path_for_visited_init: Vec<(String, usize)> = Vec::new(); // For initializing visited

        for displacement_count in 0..MAX_TRACKED_DISPLACEMENTS {
            let potential_indices = self.get_hierarchical_indices(&current_key);

            // Check for empty slot among hierarchical choices
            for &index in &potential_indices {
                if index >= self.table_size { continue; } // Safety check
                if self.table[index] == EMPTY_SLOT_N {
                    // displacement_path.push((index, self.table[index])); // Log empty
                    self.table[index] = current_entry_data;
                    return Ok(());
                }
            }

            // determine eviction target from hierarchical choices
            let choice_idx_to_evict: usize;
            if let Some(seed) = deterministic_eviction_seed {
                // Deterministic eviction choice
                let mut hasher = SipHasher24::new_with_key(seed);
                current_key.hash(&mut hasher); // Hash current key
                displacement_count.hash(&mut hasher); // Hash displacement count for variance
                choice_idx_to_evict = hasher.finish() as usize % potential_indices.len();


            } else {
                choice_idx_to_evict = {
                    let mut rng = self.rng.lock().unwrap();
                    rng.random_range(0..potential_indices.len())
                }
                
            }



            let evict_global_index = potential_indices[choice_idx_to_evict];

            // This check should ideally be redundant if get_hierarchical_indices is correct
            if evict_global_index >= self.table_size {
                 self.revert_changes(&displacement_path);
                 return Err(CuckooError::InsertionFailed(format!(
                    "Internal error: Hierarchical eviction index {} out of bounds for key '{}'",
                    evict_global_index, current_key
                 )));
            }

            let target_key_index_pair = (current_key.clone(), evict_global_index);
            intended_path_for_visited_init.push(target_key_index_pair.clone());

            // Cycle Detection Logic
            if displacement_count >= MAX_DISPLACEMENTS {
                if visited.is_none() {
                    let mut initial_visited = HashSet::with_capacity(intended_path_for_visited_init.len());
                    for item in &intended_path_for_visited_init { initial_visited.insert(item.clone()); }
                    visited = Some(initial_visited);
                }
                if let Some(ref mut visited_set) = visited {
                    if visited_set.contains(&target_key_index_pair) {
                        self.revert_changes(&displacement_path);
                        return Err(CuckooError::InsertionFailed(format!(
                            "Cycle detected for key '{}' at hierarchical index {}", current_key, evict_global_index
                        )));
                    }
                    visited_set.insert(target_key_index_pair);
                }
            }

            // Displace
            let displaced_entry_data = self.table[evict_global_index];
            displacement_path.push((evict_global_index, displaced_entry_data));
            self.table[evict_global_index] = current_entry_data;

            current_entry_data = displaced_entry_data;
            match decode_entry(&current_entry_data)? {
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
        let EMPTY_SLOT_N: Entry<N> = [0u64; N];
        let filled_slots = self.table.iter().filter(|&&entry| entry != EMPTY_SLOT_N).count();
        if self.table_size == 0 { 0.0 } else { filled_slots as f64 / self.table_size as f64 }
    }


    /// Helper: Performs one attempt to rehash existing items AND insert previously failed items
    /// using the current hierarchical configuration. Restores state if any part fails.
    pub fn rehash_with_failed(
        &mut self,
        keys_failed_insertion: &Vec<(String, String)>, // Borrow the list
    ) -> Result<(), CuckooError> {
        println!(
            "    -> Starting single rehash_with_failed attempt (k_choices: {}, buckets: {}, slots/bucket: {})...",
            self.k_choices, self.num_total_buckets, self.slots_per_bucket
        );

        // --- Generate new keys for this attempt ---
        let mut new_bucket_selection_key = [0u8; 16];
        let mut rng = self.rng.lock().unwrap();
        rng.fill_bytes(&mut new_bucket_selection_key);

        let mut new_local_hash_keys = Vec::with_capacity(self.k_choices);
        for _ in 0..self.k_choices {
            let mut key = [0u8; 16];
            rng.fill_bytes(&mut key);
            new_local_hash_keys.push(key);
        }

        // --- Create a temporary table with the new keys and current config ---
        let mut temp_cuckoo: CuckooHashTableBucketed<N> = CuckooHashTableBucketed {
            table: vec![[0u64; N]; self.table_size],
            table_size: self.table_size,
            mask: self.mask,
            k_choices: self.k_choices, // Use current k_choices
            local_hash_keys: new_local_hash_keys.clone(), // Use new local keys
            rng: Mutex::new(StdRng::from_os_rng()), // Fresh rng for temp table operations
            num_total_buckets: self.num_total_buckets,
            slots_per_bucket: self.slots_per_bucket,
            bucket_selection_key: new_bucket_selection_key, // Use new bucket key
        };

        let old_table_data = std::mem::take(&mut self.table);
        // Store old keys in case we need to revert
        let old_bucket_selection_key = self.bucket_selection_key;
        let old_local_hash_keys = self.local_hash_keys.clone();

        let mut rehashed_count = 0;
        let mut error_occurred: Option<CuckooError> = None;
        let EMPTY_SLOT_N: Entry<N> = [0u64; N];

        // --- Phase 1: Rehash existing items into temp_cuckoo ---
        for entry_data in old_table_data.iter() {
            if entry_data != &EMPTY_SLOT_N {
                match decode_entry(entry_data) {
                    Ok(Some((key, value))) => {
                        // insert_tracked now uses hierarchical hashing internally
                        if let Err(insert_err) = temp_cuckoo.insert_tracked(key.clone(), value, None) {
                            error_occurred = Some(CuckooError::RehashFailed(format!(
                                "(Phase 1) Failed re-insert key '{}': {:?}", key, insert_err
                            )));
                            break;
                        } else {
                            rehashed_count += 1;
                        }
                    }
                    Ok(None) => { /* Skip */ }
                    Err(decode_err) => {
                        error_occurred = Some(CuckooError::RehashFailed(format!(
                            "(Phase 1) Failed decode: {:?}", decode_err
                        )));
                        break;
                    }
                }
            }
        }

        if let Some(err) = error_occurred {
            println!("    -> Rehash attempt failed during Phase 1. Restoring state.");
            self.table = old_table_data;
            self.bucket_selection_key = old_bucket_selection_key; // Restore old keys
            self.local_hash_keys = old_local_hash_keys;
            return Err(err);
        }
        println!("    -> Phase 1 successful ({} existing items placed).", rehashed_count);

        // --- Phase 2: Try inserting the previously failed items into temp_cuckoo ---
        println!("    -> Starting Phase 2: Inserting {} previously failed items...", keys_failed_insertion.len());
        let mut failed_inserted_count = 0;
        for (key, value) in keys_failed_insertion.iter() {
             if let Err(insert_err) = temp_cuckoo.insert_tracked(key.clone(), value.clone(), None) {
                 error_occurred = Some(CuckooError::RehashFailed(format!(
                     "(Phase 2) Failed inserting previously failed key '{}': {:?}", key, insert_err
                 )));
                 break;
             } else {
                 failed_inserted_count += 1;
             }
        }

        if let Some(err) = error_occurred {
            println!("    -> Rehash attempt failed during Phase 2. Restoring state.");
            self.table = old_table_data;
            self.bucket_selection_key = old_bucket_selection_key; // Restore old keys
            self.local_hash_keys = old_local_hash_keys;
            Err(err)
        } else {
            println!("    -> Phase 2 successful ({} previously failed items placed).", failed_inserted_count);
            println!("    -> Single rehash_with_failed attempt successful.");
            self.table = temp_cuckoo.table; // Commit new table
            self.bucket_selection_key = new_bucket_selection_key; // Commit new keys
            self.local_hash_keys = new_local_hash_keys;
            Ok(())
        }
    }


    /// Attempts to rehash the table and insert previously failed items, looping
    /// and increasing `k_choices` (number of bucket choices / local hashes)
    /// if necessary, until success or limits are reached.
    pub fn rehash_loop_with_failed(
        &mut self,
        mut keys_failed_insertion: Vec<(String, String)>, // Take ownership
        max_attempts_per_config: usize,
    ) -> Result<(), (CuckooError, Vec<(String, String)>)> {
        println!(
            "--- Starting persistent rehash loop WITH FAILED items (max {} attempts per config) ---",
            max_attempts_per_config
        );

        if keys_failed_insertion.is_empty() {
            println!("--- No failed items provided, attempting standard rehash loop (escalating k_choices) ---");
             return self.rehash_loop(max_attempts_per_config) // rehash_loop now escalates k_choices
                 .map_err(|e| (e, keys_failed_insertion));
        }

        let initial_num_failed = keys_failed_insertion.len();

        loop { // Outer loop for escalating k_choices
            println!(
                "---> Attempting rehash_with_failed using {} k_choices...",
                self.k_choices
            );

            for attempt in 0..max_attempts_per_config {
                println!(
                    "  Attempt {}/{} with {} k_choices (targeting {} failed items)...",
                    attempt + 1,
                    max_attempts_per_config,
                    self.k_choices,
                    initial_num_failed
                );

                match self.rehash_with_failed(&keys_failed_insertion) {
                    Ok(_) => {
                        println!(
                            "---> Rehash loop WITH FAILED items successful after {} attempts with {} k_choices.",
                            attempt + 1,
                            self.k_choices
                        );
                        keys_failed_insertion.clear();
                        return Ok(());
                    }
                    Err(e) => {
                        eprintln!("   Attempt failed: {}", e);
                    }
                }
            }

            println!(
                "---> All {} attempts failed with {} k_choices.",
                max_attempts_per_config, self.k_choices
            );


            // Escalate k_choices
            self.k_choices += 1;
            println!(
                "---> Escalating: Increasing k_choices to {}. Local hash keys regenerated.",
                self.k_choices
            );
        }
    }

    pub fn rehash(&mut self) -> Result<(), CuckooError> {
        println!("--> Starting rehash (current load: {:.2}%)...", self.load_factor() * 100.0);

        let mut new_bucket_selection_key = [0u8; 16];
        let mut rng = self.rng.lock().unwrap();
        rng.fill_bytes(&mut new_bucket_selection_key);

        let mut new_local_hash_keys = Vec::with_capacity(self.k_choices);
        for _ in 0..self.k_choices {
            let mut key = [0u8; 16];
            rng.fill_bytes(&mut key);
            new_local_hash_keys.push(key);
        }

        let mut temp_cuckoo: CuckooHashTableBucketed<N> = CuckooHashTableBucketed {
            table: vec![[0u64; N]; self.table_size],
            table_size: self.table_size,
            mask: self.mask,
            k_choices: self.k_choices,
            local_hash_keys: new_local_hash_keys.clone(), // Use new local keys
            rng: Mutex::new(StdRng::from_os_rng()), // Fresh rng for temp table
            num_total_buckets: self.num_total_buckets,
            slots_per_bucket: self.slots_per_bucket,
            bucket_selection_key: new_bucket_selection_key, // Use new bucket key
        };

        let old_table_data = std::mem::take(&mut self.table);
        let mut rehashed_count = 0;
        let mut error_occurred: Option<CuckooError> = None;
        let EMPTY_SLOT_N: Entry<N> = [0u64; N];

        for entry_data in old_table_data.iter() {
            if entry_data != &EMPTY_SLOT_N {
                match decode_entry(entry_data) {
                    Ok(Some((key, value))) => {
                        // Use insert_tracked on the temp table (without deterministic seed for now)
                        if let Err(insert_err) = temp_cuckoo.insert_tracked(key.clone(), value, None) {
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
            println!("--> Rehash failed. Restoring original table state.");
            self.table = old_table_data;
            // self.bucket_selection_key and self.local_hash_keys remain the old ones
            Err(err)
        } else {
            println!("--> Rehash successful. {} items re-inserted.", rehashed_count);
            self.table = temp_cuckoo.table;
            self.bucket_selection_key = new_bucket_selection_key;
            self.local_hash_keys = new_local_hash_keys;
            Ok(())
        }
    }

    // rehash_loop, rehash_with_failed, rehash_loop_with_failed would need to be
    // updated to correctly handle the new `k_choices` vs `num_hashes` distinction
    // if `k_choices` becomes the thing to escalate. For now, assuming escalation
    // would mean increasing `k_choices` (and thus `local_hash_keys` and bucket choices).
    // This requires careful thought on how `MAX_ALLOWED_HASHES_ESCALATION` relates to `k_choices`.
    // For simplicity, I'll adapt rehash_loop to escalate k_choices.

    pub fn rehash_loop(&mut self, max_attempts_per_config: usize) -> Result<(), CuckooError> {
        println!("--- Starting persistent rehash loop (max {} attempts per config) ---", max_attempts_per_config);
        loop {
            println!("--> Attempting rehash with {} k_choices...", self.k_choices);
            for attempt in 0..max_attempts_per_config {
                println!("  Attempt {}/{} with {} k_choices...", attempt + 1, max_attempts_per_config, self.k_choices);
                match self.rehash() {
                    Ok(_) => {
                        println!("--> Rehash loop successful after {} attempts with {} k_choices.", attempt + 1, self.k_choices);
                        return Ok(());
                    }
                    Err(e) => {
                        eprintln!("   Rehash attempt failed: {}", e);
                    }
                }
            }
            println!("--> All {} attempts failed with {} k_choices.", max_attempts_per_config, self.k_choices);

            self.k_choices += 1;
            println!("--> Escalating: Increasing k_choices to {}.", self.k_choices);
        }
    }

    pub fn purge_table(&mut self) {
        let EMPTY_SLOT_N: Entry<N> = [0u64; N];
        println!("---> Purging table (clearing all entries)...");
        for entry in self.table.iter_mut() { *entry = EMPTY_SLOT_N; }
        println!("---> Table purged. Load factor: {:.2}%", self.load_factor() * 100.0);
    }

}









pub type EntryAdditiveShare<const N: usize> = [i64; N];

// Add these traits to make CuckooHashTable thread-safe
unsafe impl<const N: usize> Send for CuckooHashTableBucketedAdditiveShare<N> {}
unsafe impl<const N: usize> Sync for CuckooHashTableBucketedAdditiveShare<N> {}

// --- Cuckoo Hash Table ---
#[derive(Debug)]
pub struct CuckooHashTableBucketedAdditiveShare<const N: usize> {
    pub table: Vec<EntryAdditiveShare<N>>,
    pub table_size: usize,      // Total slots: num_total_buckets * slots_per_bucket
    pub mask: usize,            // table_size - 1
    pub k_choices: usize,       // Number of distinct buckets to choose / local hash functions (k)
    pub local_hash_keys: Vec<[u8; 16]>, // Keys for local hashing within buckets
    rng: Mutex<StdRng>,             // For random eviction choice if not deterministic

    // Hierarchical Hashing specific fields
    pub num_total_buckets: usize,
    pub slots_per_bucket: usize,
    pub bucket_selection_key: [u8; 16], // Key for seeding bucket permutation
}

impl<const N: usize> CuckooHashTableBucketedAdditiveShare<N> {

    pub fn new(
        num_total_buckets: usize,
        slots_per_bucket: usize,
    ) -> Result<Self, String> {
        if N == 0 { return Err("Entry size N (u64 count) cannot be zero".to_string()); }
        if N * 8 < 4 { return Err("Entry byte size (N * 8) must be at least 4".to_string()); }
        if num_total_buckets == 0 { return Err("Number of total buckets cannot be zero".to_string()); }
        if slots_per_bucket == 0 { return Err("Slots per bucket cannot be zero".to_string()); }

        let table_size = num_total_buckets * slots_per_bucket;
        if !table_size.is_power_of_two() {
            // This constraint is for the global mask. If we want per-bucket masks,
            // then slots_per_bucket should be power of 2. For now, global table_size.
            return Err(format!(
                "Total table size ({} * {} = {}) must be a power of 2.",
                num_total_buckets, slots_per_bucket, table_size
            ));
        }

        let k_choices = DEFAULT_K_CHOICES; // k
        if k_choices == 0 { return Err("Number of choices (k) must be > 0".to_string()); }
        if k_choices > num_total_buckets {
            return Err(format!(
                "Number of choices k ({}) cannot exceed num_total_buckets ({}).",
                k_choices, num_total_buckets
            ));
        }


        let mut rng = StdRng::from_os_rng(); // Correct way to get ThreadRng

        let mut bucket_selection_key = [0u8; 16];
        rng.fill_bytes(&mut bucket_selection_key);

        let local_hash_keys = (0..k_choices)
            .map(|_| {
                let mut key = [0u8; 16];
                rng.fill_bytes(&mut key);
                key
            })
            .collect();

        Ok(CuckooHashTableBucketedAdditiveShare {
            table: vec![[0i64; N]; table_size],
            table_size,
            mask: table_size - 1, // Mask for the global table
            k_choices,
            local_hash_keys,
            rng: Mutex::new(rng),
            num_total_buckets,
            slots_per_bucket,
            bucket_selection_key,
        })
    }

    /// Generates k distinct global indices using hierarchical hashing.
    pub fn get_hierarchical_indices(&self, key_to_hash: &str) -> Vec<usize> {
        // Phase 1: Bucket Selection
        let mut bucket_seed_hasher = SipHasher24::new_with_key(&self.bucket_selection_key);
        key_to_hash.hash(&mut bucket_seed_hasher);
        let shuffle_seed = bucket_seed_hasher.finish();

        let selected_bucket_ids = shuffle_and_take_k_usize(
            self.num_total_buckets,
            shuffle_seed,
            self.k_choices,
        );

        // Phase 2: Local Hashing & Global Index Calculation
        let mut global_indices = Vec::with_capacity(self.k_choices);
        for (i, bucket_id) in selected_bucket_ids.iter().enumerate() {
            let local_hash_key = &self.local_hash_keys[i]; // Use i-th local hash key
            let mut local_hasher = SipHasher24::new_with_key(local_hash_key);
            key_to_hash.hash(&mut local_hasher);
            // Local index within the bucket
            let local_index = (local_hasher.finish() as usize) % self.slots_per_bucket;

            let global_index = bucket_id * self.slots_per_bucket + local_index;
            global_indices.push(global_index);
        }
        global_indices
    }


    fn revert_changes(&mut self, path: &[(usize, EntryAdditiveShare<N>)]) {
        for (index, original_data) in path.iter().rev() {
            if *index < self.table_size {
                self.table[*index] = *original_data;
            } else {
                 eprintln!("Error: revert_changes attempted to write out of bounds index {}", index);
            }
        }
    }

    /// Inserts a key-value pair (both Strings) using hybrid cycle detection.
    pub fn insert_tracked(
        &mut self,
        key: String,
        value: String,
        deterministic_eviction_seed: Option<&[u8; 16]>,
    ) -> Result<(), CuckooError> {
        let EMPTY_SLOT_N: EntryAdditiveShare<N> = [0i64; N];
        let mut current_entry_data = encode_entry::<N>(&key, &value)?.map(|x| x as i64);
        let mut current_key = key.clone();

        let mut displacement_path: Vec<(usize, EntryAdditiveShare<N>)> = Vec::new();
        let mut visited: Option<HashSet<(String, usize)>> = None; // Tracks (key, global_index_tried)
        let mut intended_path_for_visited_init: Vec<(String, usize)> = Vec::new(); // For initializing visited

        for displacement_count in 0..MAX_TRACKED_DISPLACEMENTS {
            let potential_indices = self.get_hierarchical_indices(&current_key);

            // Check for empty slot among hierarchical choices
            for &index in &potential_indices {
                if index >= self.table_size { continue; } // Safety check
                if self.table[index] == EMPTY_SLOT_N {
                    // displacement_path.push((index, self.table[index])); // Log empty
                    self.table[index] = current_entry_data;
                    return Ok(());
                }
            }

            // determine eviction target from hierarchical choices
            let choice_idx_to_evict: usize;
            if let Some(seed) = deterministic_eviction_seed {
                // Deterministic eviction choice
                let mut hasher = SipHasher24::new_with_key(seed);
                current_key.hash(&mut hasher); // Hash current key
                displacement_count.hash(&mut hasher); // Hash displacement count for variance
                choice_idx_to_evict = hasher.finish() as usize % potential_indices.len();


            } else {
                choice_idx_to_evict = {
                    let mut rng = self.rng.lock().unwrap();
                    rng.random_range(0..potential_indices.len())
                }
                
            }



            let evict_global_index = potential_indices[choice_idx_to_evict];

            // This check should ideally be redundant if get_hierarchical_indices is correct
            if evict_global_index >= self.table_size {
                 self.revert_changes(&displacement_path);
                 return Err(CuckooError::InsertionFailed(format!(
                    "Internal error: Hierarchical eviction index {} out of bounds for key '{}'",
                    evict_global_index, current_key
                 )));
            }

            let target_key_index_pair = (current_key.clone(), evict_global_index);
            intended_path_for_visited_init.push(target_key_index_pair.clone());

            // Cycle Detection Logic
            if displacement_count >= MAX_DISPLACEMENTS {
                if visited.is_none() {
                    let mut initial_visited = HashSet::with_capacity(intended_path_for_visited_init.len());
                    for item in &intended_path_for_visited_init { initial_visited.insert(item.clone()); }
                    visited = Some(initial_visited);
                }
                if let Some(ref mut visited_set) = visited {
                    if visited_set.contains(&target_key_index_pair) {
                        self.revert_changes(&displacement_path);
                        return Err(CuckooError::InsertionFailed(format!(
                            "Cycle detected for key '{}' at hierarchical index {}", current_key, evict_global_index
                        )));
                    }
                    visited_set.insert(target_key_index_pair);
                }
            }

            // Displace
            let displaced_entry_data = self.table[evict_global_index];
            displacement_path.push((evict_global_index, displaced_entry_data));
            self.table[evict_global_index] = current_entry_data;

            current_entry_data = displaced_entry_data;
            let u64_current_entry_data = current_entry_data.map(|x| x as u64);
            match decode_entry::<N>(&u64_current_entry_data)? {
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
        let EMPTY_SLOT_N: EntryAdditiveShare<N> = [0i64; N];
        let filled_slots = self.table.iter().filter(|&&entry| entry != EMPTY_SLOT_N).count();
        if self.table_size == 0 { 0.0 } else { filled_slots as f64 / self.table_size as f64 }
    }


    /// Helper: Performs one attempt to rehash existing items AND insert previously failed items
    /// using the current hierarchical configuration. Restores state if any part fails.
    pub fn rehash_with_failed(
        &mut self,
        keys_failed_insertion: &Vec<(String, String)>, // Borrow the list
    ) -> Result<(), CuckooError> {
        println!(
            "    -> Starting single rehash_with_failed attempt (k_choices: {}, buckets: {}, slots/bucket: {})...",
            self.k_choices, self.num_total_buckets, self.slots_per_bucket
        );

        // --- Generate new keys for this attempt ---
        let mut new_bucket_selection_key = [0u8; 16];
        let mut rng = self.rng.lock().unwrap();
        rng.fill_bytes(&mut new_bucket_selection_key);

        let mut new_local_hash_keys = Vec::with_capacity(self.k_choices);
        for _ in 0..self.k_choices {
            let mut key = [0u8; 16];
            rng.fill_bytes(&mut key);
            new_local_hash_keys.push(key);
        }

        // --- Create a temporary table with the new keys and current config ---
        let mut temp_cuckoo: CuckooHashTableBucketedAdditiveShare<N> = CuckooHashTableBucketedAdditiveShare {
            table: vec![[0i64; N]; self.table_size],
            table_size: self.table_size,
            mask: self.mask,
            k_choices: self.k_choices, // Use current k_choices
            local_hash_keys: new_local_hash_keys.clone(), // Use new local keys
            rng: Mutex::new(StdRng::from_os_rng()), // Fresh rng for temp table operations
            num_total_buckets: self.num_total_buckets,
            slots_per_bucket: self.slots_per_bucket,
            bucket_selection_key: new_bucket_selection_key, // Use new bucket key
        };

        let old_table_data = std::mem::take(&mut self.table);
        // Store old keys in case we need to revert
        let old_bucket_selection_key = self.bucket_selection_key;
        let old_local_hash_keys = self.local_hash_keys.clone();

        let mut rehashed_count = 0;
        let mut error_occurred: Option<CuckooError> = None;
        let EMPTY_SLOT_N: EntryAdditiveShare<N> = [0i64; N];

        // --- Phase 1: Rehash existing items into temp_cuckoo ---
        for entry_data in old_table_data.iter() {
            if entry_data != &EMPTY_SLOT_N {
                let u64_entry_data = entry_data.map(|x| x as u64);
                match decode_entry::<N>(&u64_entry_data) {
                    Ok(Some((key, value))) => {
                        // insert_tracked now uses hierarchical hashing internally
                        if let Err(insert_err) = temp_cuckoo.insert_tracked(key.clone(), value, None) {
                            error_occurred = Some(CuckooError::RehashFailed(format!(
                                "(Phase 1) Failed re-insert key '{}': {:?}", key, insert_err
                            )));
                            break;
                        } else {
                            rehashed_count += 1;
                        }
                    }
                    Ok(None) => { /* Skip */ }
                    Err(decode_err) => {
                        error_occurred = Some(CuckooError::RehashFailed(format!(
                            "(Phase 1) Failed decode: {:?}", decode_err
                        )));
                        break;
                    }
                }
            }
        }

        if let Some(err) = error_occurred {
            println!("    -> Rehash attempt failed during Phase 1. Restoring state.");
            self.table = old_table_data;
            self.bucket_selection_key = old_bucket_selection_key; // Restore old keys
            self.local_hash_keys = old_local_hash_keys;
            return Err(err);
        }
        println!("    -> Phase 1 successful ({} existing items placed).", rehashed_count);

        // --- Phase 2: Try inserting the previously failed items into temp_cuckoo ---
        println!("    -> Starting Phase 2: Inserting {} previously failed items...", keys_failed_insertion.len());
        let mut failed_inserted_count = 0;
        for (key, value) in keys_failed_insertion.iter() {
             if let Err(insert_err) = temp_cuckoo.insert_tracked(key.clone(), value.clone(), None) {
                 error_occurred = Some(CuckooError::RehashFailed(format!(
                     "(Phase 2) Failed inserting previously failed key '{}': {:?}", key, insert_err
                 )));
                 break;
             } else {
                 failed_inserted_count += 1;
             }
        }

        if let Some(err) = error_occurred {
            println!("    -> Rehash attempt failed during Phase 2. Restoring state.");
            self.table = old_table_data;
            self.bucket_selection_key = old_bucket_selection_key; // Restore old keys
            self.local_hash_keys = old_local_hash_keys;
            Err(err)
        } else {
            println!("    -> Phase 2 successful ({} previously failed items placed).", failed_inserted_count);
            println!("    -> Single rehash_with_failed attempt successful.");
            self.table = temp_cuckoo.table; // Commit new table
            self.bucket_selection_key = new_bucket_selection_key; // Commit new keys
            self.local_hash_keys = new_local_hash_keys;
            Ok(())
        }
    }


    /// Attempts to rehash the table and insert previously failed items, looping
    /// and increasing `k_choices` (number of bucket choices / local hashes)
    /// if necessary, until success or limits are reached.
    pub fn rehash_loop_with_failed(
        &mut self,
        mut keys_failed_insertion: Vec<(String, String)>, // Take ownership
        max_attempts_per_config: usize,
    ) -> Result<(), (CuckooError, Vec<(String, String)>)> {
        println!(
            "--- Starting persistent rehash loop WITH FAILED items (max {} attempts per config) ---",
            max_attempts_per_config
        );

        if keys_failed_insertion.is_empty() {
            println!("--- No failed items provided, attempting standard rehash loop (escalating k_choices) ---");
             return self.rehash_loop(max_attempts_per_config) // rehash_loop now escalates k_choices
                 .map_err(|e| (e, keys_failed_insertion));
        }

        let initial_num_failed = keys_failed_insertion.len();

        loop { // Outer loop for escalating k_choices
            println!(
                "---> Attempting rehash_with_failed using {} k_choices...",
                self.k_choices
            );

            for attempt in 0..max_attempts_per_config {
                println!(
                    "  Attempt {}/{} with {} k_choices (targeting {} failed items)...",
                    attempt + 1,
                    max_attempts_per_config,
                    self.k_choices,
                    initial_num_failed
                );

                match self.rehash_with_failed(&keys_failed_insertion) {
                    Ok(_) => {
                        println!(
                            "---> Rehash loop WITH FAILED items successful after {} attempts with {} k_choices.",
                            attempt + 1,
                            self.k_choices
                        );
                        keys_failed_insertion.clear();
                        return Ok(());
                    }
                    Err(e) => {
                        eprintln!("   Attempt failed: {}", e);
                    }
                }
            }

            println!(
                "---> All {} attempts failed with {} k_choices.",
                max_attempts_per_config, self.k_choices
            );


            // Escalate k_choices
            self.k_choices += 1;
            println!(
                "---> Escalating: Increasing k_choices to {}. Local hash keys regenerated.",
                self.k_choices
            );
        }
    }

    pub fn rehash(&mut self) -> Result<(), CuckooError> {
        println!("--> Starting rehash (current load: {:.2}%)...", self.load_factor() * 100.0);

        let mut new_bucket_selection_key = [0u8; 16];
        let mut rng = self.rng.lock().unwrap();
        rng.fill_bytes(&mut new_bucket_selection_key);

        let mut new_local_hash_keys = Vec::with_capacity(self.k_choices);
        for _ in 0..self.k_choices {
            let mut key = [0u8; 16];
            rng.fill_bytes(&mut key);
            new_local_hash_keys.push(key);
        }

        let mut temp_cuckoo: CuckooHashTableBucketedAdditiveShare<N> = CuckooHashTableBucketedAdditiveShare {
            table: vec![[0i64; N]; self.table_size],
            table_size: self.table_size,
            mask: self.mask,
            k_choices: self.k_choices,
            local_hash_keys: new_local_hash_keys.clone(), // Use new local keys
            rng: Mutex::new(StdRng::from_os_rng()), // Fresh rng for temp table
            num_total_buckets: self.num_total_buckets,
            slots_per_bucket: self.slots_per_bucket,
            bucket_selection_key: new_bucket_selection_key, // Use new bucket key
        };

        let old_table_data = std::mem::take(&mut self.table);
        let mut rehashed_count = 0;
        let mut error_occurred: Option<CuckooError> = None;
        let EMPTY_SLOT_N: EntryAdditiveShare<N> = [0i64; N];

        for entry_data in old_table_data.iter() {
            if entry_data != &EMPTY_SLOT_N {
                let u64_entry_data = entry_data.map(|x| x as u64);
                match decode_entry::<N>(&u64_entry_data) {
                    Ok(Some((key, value))) => {
                        // Use insert_tracked on the temp table (without deterministic seed for now)
                        if let Err(insert_err) = temp_cuckoo.insert_tracked(key.clone(), value, None) {
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
            println!("--> Rehash failed. Restoring original table state.");
            self.table = old_table_data;
            // self.bucket_selection_key and self.local_hash_keys remain the old ones
            Err(err)
        } else {
            println!("--> Rehash successful. {} items re-inserted.", rehashed_count);
            self.table = temp_cuckoo.table;
            self.bucket_selection_key = new_bucket_selection_key;
            self.local_hash_keys = new_local_hash_keys;
            Ok(())
        }
    }

    // rehash_loop, rehash_with_failed, rehash_loop_with_failed would need to be
    // updated to correctly handle the new `k_choices` vs `num_hashes` distinction
    // if `k_choices` becomes the thing to escalate. For now, assuming escalation
    // would mean increasing `k_choices` (and thus `local_hash_keys` and bucket choices).
    // This requires careful thought on how `MAX_ALLOWED_HASHES_ESCALATION` relates to `k_choices`.
    // For simplicity, I'll adapt rehash_loop to escalate k_choices.

    pub fn rehash_loop(&mut self, max_attempts_per_config: usize) -> Result<(), CuckooError> {
        println!("--- Starting persistent rehash loop (max {} attempts per config) ---", max_attempts_per_config);
        loop {
            println!("--> Attempting rehash with {} k_choices...", self.k_choices);
            for attempt in 0..max_attempts_per_config {
                println!("  Attempt {}/{} with {} k_choices...", attempt + 1, max_attempts_per_config, self.k_choices);
                match self.rehash() {
                    Ok(_) => {
                        println!("--> Rehash loop successful after {} attempts with {} k_choices.", attempt + 1, self.k_choices);
                        return Ok(());
                    }
                    Err(e) => {
                        eprintln!("   Rehash attempt failed: {}", e);
                    }
                }
            }
            println!("--> All {} attempts failed with {} k_choices.", max_attempts_per_config, self.k_choices);

            self.k_choices += 1;
            println!("--> Escalating: Increasing k_choices to {}.", self.k_choices);
        }
    }

    pub fn purge_table(&mut self) {
        let EMPTY_SLOT_N: EntryAdditiveShare<N> = [0i64; N];
        println!("---> Purging table (clearing all entries)...");
        for entry in self.table.iter_mut() { *entry = EMPTY_SLOT_N; }
        println!("---> Table purged. Load factor: {:.2}%", self.load_factor() * 100.0);
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


