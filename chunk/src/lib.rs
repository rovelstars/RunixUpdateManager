//! Content-defined chunking + content-addressed sync for RunixOS image updates.
//!
//! This is the opinion-free transport/dedup engine (the casync/desync job, in
//! native Rust on `fastcdc`). It has no idea about FHS, A/B slots, or boot - it
//! only chunks a blob and reassembles it by fetching the chunks a client is
//! missing, seeded from data it already has (e.g. the current /Core slot).
//!
//! Flow:
//!   build  (release side): chunk an image -> a `ChunkIndex` + a set of unique
//!                          chunks uploaded to a store (R2).
//!   apply  (client, RUM):  fetch the index, reassemble the new image by reusing
//!                          chunks already present in the seed and downloading
//!                          only the missing ones, then verify the result hash.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Content-defined chunking parameters (min / avg / max chunk size in bytes).
/// Variable boundaries mean a small edit only changes nearby chunks, so deltas
/// across versions stay small.
pub const MIN_SIZE: u32 = 16 * 1024;
pub const AVG_SIZE: u32 = 64 * 1024;
pub const MAX_SIZE: u32 = 256 * 1024;

/// sha256 of data as a lowercase hex string.
pub fn hash_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// One chunk in an image, referenced by content hash. Offset is implicit from
/// the running sum of lengths.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ChunkRef {
    pub hash: String,
    pub len: u64,
}

/// The recipe to reconstruct an image: an ordered list of chunk references.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ChunkIndex {
    pub total_len: u64,
    pub chunks: Vec<ChunkRef>,
}

impl ChunkIndex {
    /// Number of distinct chunks (what the store must hold for this image).
    pub fn unique(&self) -> usize {
        let mut set = std::collections::HashSet::new();
        for c in &self.chunks {
            set.insert(&c.hash);
        }
        set.len()
    }
}

/// Split `data` into content-defined chunks. Returns the index plus the unique
/// chunks keyed by hash (identical chunks are deduplicated).
pub fn chunk(data: &[u8]) -> (ChunkIndex, HashMap<String, Vec<u8>>) {
    use fastcdc::v2020::FastCDC;
    let mut chunks = Vec::new();
    let mut store: HashMap<String, Vec<u8>> = HashMap::new();
    for c in FastCDC::new(data, MIN_SIZE, AVG_SIZE, MAX_SIZE) {
        let bytes = &data[c.offset..c.offset + c.length];
        let hash = hash_hex(bytes);
        chunks.push(ChunkRef { hash: hash.clone(), len: c.length as u64 });
        store.entry(hash).or_insert_with(|| bytes.to_vec());
    }
    (ChunkIndex { total_len: data.len() as u64, chunks }, store)
}

/// A source of chunks by hash (a local cache, an HTTP/R2 store, ...).
pub trait Store {
    fn get(&self, hash: &str) -> Result<Vec<u8>, Error>;
}

/// What a reassembly did, for logging/bandwidth accounting.
#[derive(Clone, Copy, Debug, Default)]
pub struct SyncStats {
    pub reused: usize,
    pub fetched: usize,
    pub bytes_fetched: u64,
}

/// Reconstruct the image described by `index`, reusing chunks found in `seed`
/// (the client's existing data) and downloading only the missing ones from
/// `store`. Every fetched chunk is verified against its hash. The caller must
/// still verify the final image against the expected (signed) hash.
pub fn reassemble(
    index: &ChunkIndex,
    store: &dyn Store,
    seed: Option<&[u8]>,
) -> Result<(Vec<u8>, SyncStats), Error> {
    let mut have: HashMap<String, Vec<u8>> = match seed {
        Some(s) => chunk(s).1,
        None => HashMap::new(),
    };
    let mut out = Vec::with_capacity(index.total_len as usize);
    let mut stats = SyncStats::default();

    for r in &index.chunks {
        let bytes = if let Some(b) = have.get(&r.hash) {
            stats.reused += 1;
            b.clone()
        } else {
            let b = store.get(&r.hash)?;
            if hash_hex(&b) != r.hash {
                return Err(Error::HashMismatch(r.hash.clone()));
            }
            stats.fetched += 1;
            stats.bytes_fetched += b.len() as u64;
            have.insert(r.hash.clone(), b.clone());
            b
        };
        if bytes.len() as u64 != r.len {
            return Err(Error::LenMismatch(r.hash.clone()));
        }
        out.extend_from_slice(&bytes);
    }

    if out.len() as u64 != index.total_len {
        return Err(Error::LenMismatch("total".into()));
    }
    Ok((out, stats))
}

/// A store backed by a directory of `<hash>` files. Used both to build a store
/// (release side) and as a local seed/cache.
pub struct LocalStore {
    pub dir: PathBuf,
}

impl LocalStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Write a set of chunks into the store directory.
    pub fn put_all(&self, chunks: &HashMap<String, Vec<u8>>) -> Result<(), Error> {
        std::fs::create_dir_all(&self.dir)?;
        for (hash, bytes) in chunks {
            let path = self.dir.join(hash);
            if !path.exists() {
                std::fs::write(path, bytes)?;
            }
        }
        Ok(())
    }
}

impl Store for LocalStore {
    fn get(&self, hash: &str) -> Result<Vec<u8>, Error> {
        let path: &Path = &self.dir.join(hash);
        std::fs::read(path).map_err(|_| Error::NotFound(hash.to_string()))
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    NotFound(String),
    HashMismatch(String),
    LenMismatch(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::NotFound(h) => write!(f, "chunk not found in store: {h}"),
            Error::HashMismatch(h) => write!(f, "chunk hash mismatch: {h}"),
            Error::LenMismatch(h) => write!(f, "chunk length mismatch: {h}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory store from a chunk map, for tests.
    struct MapStore(HashMap<String, Vec<u8>>);
    impl Store for MapStore {
        fn get(&self, hash: &str) -> Result<Vec<u8>, Error> {
            self.0.get(hash).cloned().ok_or_else(|| Error::NotFound(hash.into()))
        }
    }

    fn pseudo(seed: u64, len: usize) -> Vec<u8> {
        // deterministic pseudo-random bytes (no rng dep)
        let mut x = seed.wrapping_mul(0x9E3779B97F4A7C15);
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn roundtrip() {
        let data = pseudo(1, 2_000_000);
        let (index, chunks) = chunk(&data);
        let (out, stats) = reassemble(&index, &MapStore(chunks), None).unwrap();
        assert_eq!(out, data);
        assert_eq!(stats.reused, 0);
        assert_eq!(stats.fetched, index.unique());
    }

    #[test]
    fn seeded_fetches_only_changed_chunks() {
        // v1, then v2 = v1 with a small middle edit. Reassembling v2 seeded by
        // v1 should download only a few chunks, reuse the rest.
        let mut v1 = pseudo(2, 2_000_000);
        let mut v2 = v1.clone();
        for b in v2[1_000_000..1_000_400].iter_mut() {
            *b = b.wrapping_add(1);
        }
        let _ = &mut v1;
        let (idx2, chunks2) = chunk(&v2);
        let (out, stats) = reassemble(&idx2, &MapStore(chunks2), Some(&v1)).unwrap();
        assert_eq!(out, v2);
        // The vast majority of chunks are unchanged and come from the seed.
        assert!(stats.reused > stats.fetched * 5, "stats: {stats:?}");
        assert!(stats.fetched >= 1);
    }

    #[test]
    fn corrupt_store_chunk_is_caught() {
        let data = pseudo(3, 500_000);
        let (index, mut chunks) = chunk(&data);
        // Corrupt one chunk's bytes in the store (keep its key/hash).
        let key = index.chunks[1].hash.clone();
        chunks.get_mut(&key).unwrap()[0] ^= 0xFF;
        let err = reassemble(&index, &MapStore(chunks), None).unwrap_err();
        assert!(matches!(err, Error::HashMismatch(_)));
    }

    #[test]
    fn local_store_roundtrip() {
        let dir = std::env::temp_dir().join(format!("runix-chunk-test-{}", std::process::id()));
        let data = pseudo(4, 800_000);
        let (index, chunks) = chunk(&data);
        let store = LocalStore::new(&dir);
        store.put_all(&chunks).unwrap();
        let (out, _) = reassemble(&index, &store, None).unwrap();
        assert_eq!(out, data);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
