//! RunixUpdateManager (RUM) - the RunixOS on-device update client.
//!
//! - `check`: report device state, verify the returned manifest against the
//!   RovelStars public key, print the update plan. (Phase 1)
//! - `apply`: reassemble a target image from a content-addressed chunk store,
//!   reusing chunks already in the current slot (seed) and downloading only the
//!   missing ones, then verify the result hash before writing the inactive
//!   slot. (Phase 2)
//!
//! Later phases wire `apply` to a real A/B partition + Rignite staging; for now
//! the "slot" is a file so the whole flow is host-testable.

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand};
use runix_chunk::{ChunkIndex, Store, hash_hex, reassemble};
use runix_update_protocol::{CheckRequest, CheckResponse, Manifest, Version, SCHEMA};
use std::io::Read;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "rum", about = "RunixOS update client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check the update server for a newer system release.
    Check {
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        server: String,
        #[arg(long, default_value = "keys/public.key")]
        key: PathBuf,
        #[arg(long, default_value = "x86_64")]
        arch: String,
        #[arg(long, default_value = "26.2.0")]
        current: String,
        #[arg(long, default_value = "stable")]
        channel: String,
        #[arg(long = "subscribe")]
        subscribed: Vec<String>,
    },
    /// Reassemble a target image from a chunk store into the (inactive) slot,
    /// reusing the current slot as a seed, and verify the result hash.
    Apply {
        /// Chunk index: a file path or an http(s) URL.
        #[arg(long)]
        index: String,
        /// Chunk store base: a directory or an http(s) URL (chunk = <base>/<hash>).
        #[arg(long)]
        store: String,
        /// Existing data to seed from (the current slot). Optional.
        #[arg(long)]
        seed: Option<PathBuf>,
        /// Where to write the reassembled image (the inactive slot).
        #[arg(long)]
        out: PathBuf,
        /// Expected sha256 (hex) of the reassembled image. The image is only
        /// written if it matches. In production this is the signed verity hash.
        #[arg(long)]
        expect: String,
    },
}

// ---- check (Phase 1) ----

fn load_public_key(path: &PathBuf) -> Result<[u8; 32]> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading public key {path:?}"))?;
    let bytes = hex::decode(text.trim()).context("public key is not valid hex")?;
    bytes.try_into().map_err(|_| anyhow!("public key must be 32 bytes"))
}

fn check(
    server: &str,
    key_path: &PathBuf,
    arch: String,
    current: &str,
    channel: String,
    subscribed: Vec<String>,
) -> Result<()> {
    let public = load_public_key(key_path)?;
    let current: Version = current.parse().map_err(|_| anyhow!("bad --current version"))?;
    let req = CheckRequest { schema: SCHEMA, arch, current, channel, subscribed };

    let url = format!("{}/check", server.trim_end_matches('/'));
    let resp: CheckResponse = ureq::post(&url)
        .send_json(&req)
        .with_context(|| format!("POST {url}"))?
        .into_json()
        .context("decoding server response")?;

    match resp {
        CheckResponse::UpToDate => println!("Up to date (system {current})."),
        CheckResponse::Update(signed) => {
            let manifest: Manifest = signed
                .verify(&public)
                .map_err(|e| anyhow!("manifest signature verification failed: {e}"))?;
            print_plan(&current, &signed.key_id, &manifest)?;
        }
    }
    Ok(())
}

fn print_plan(current: &Version, key_id: &str, m: &Manifest) -> Result<()> {
    if m.version <= *current {
        bail!("server offered version {} which is not newer than {current}", m.version);
    }
    println!("Update available: {} -> {}", current, m.version);
    println!("  signed by:   {key_id} (signature verified)");
    println!("  channel:     {} / {}", m.channel, m.arch);
    println!("  image index: {}", m.image_index);
    println!("  verity hash: {}", m.verity_root_hash);
    println!("  size:        {} bytes", m.size);
    println!(
        "\nNext: rum apply --index <{}> --store <store> --seed <current-slot> \\\n      --out <inactive-slot> --expect {}",
        m.image_index, m.verity_root_hash
    );
    Ok(())
}

// ---- apply (Phase 2) ----

/// A chunk store reachable over http(s): chunk bytes live at <base>/<hash>.
struct HttpStore {
    base: String,
}

impl Store for HttpStore {
    fn get(&self, hash: &str) -> Result<Vec<u8>, runix_chunk::Error> {
        let url = format!("{}/{}", self.base.trim_end_matches('/'), hash);
        let resp = ureq::get(&url)
            .call()
            .map_err(|_| runix_chunk::Error::NotFound(hash.to_string()))?;
        let mut buf = Vec::new();
        resp.into_reader().read_to_end(&mut buf)?;
        Ok(buf)
    }
}

fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

fn load_index(spec: &str) -> Result<ChunkIndex> {
    let text = if is_url(spec) {
        ureq::get(spec).call().with_context(|| format!("GET {spec}"))?.into_string()?
    } else {
        std::fs::read_to_string(spec).with_context(|| format!("reading index {spec}"))?
    };
    Ok(serde_json::from_str(&text).context("parsing chunk index")?)
}

fn apply(index: &str, store: &str, seed: Option<PathBuf>, out: PathBuf, expect: &str) -> Result<()> {
    let index = load_index(index)?;
    let store_box: Box<dyn Store> = if is_url(store) {
        Box::new(HttpStore { base: store.to_string() })
    } else {
        Box::new(runix_chunk::LocalStore::new(store))
    };

    let seed_data = match &seed {
        Some(p) => Some(std::fs::read(p).with_context(|| format!("reading seed {p:?}"))?),
        None => None,
    };

    println!(
        "Applying: {} chunks ({} unique), {} bytes, seed: {}",
        index.chunks.len(),
        index.unique(),
        index.total_len,
        seed.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "none".into()),
    );

    let (data, stats) = reassemble(&index, store_box.as_ref(), seed_data.as_deref())
        .map_err(|e| anyhow!("reassembly failed: {e}"))?;

    let got = hash_hex(&data);
    if got != expect {
        bail!("image hash mismatch: got {got}, expected {expect} (refusing to write)");
    }

    std::fs::write(&out, &data).with_context(|| format!("writing {out:?}"))?;
    println!(
        "Verified and wrote {out:?}\n  reused {} chunks, fetched {} ({} bytes) - hash OK",
        stats.reused, stats.fetched, stats.bytes_fetched
    );
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Check { server, key, arch, current, channel, subscribed } => {
            check(&server, &key, arch, &current, channel, subscribed)
        }
        Command::Apply { index, store, seed, out, expect } => {
            apply(&index, &store, seed, out, &expect)
        }
    }
}
