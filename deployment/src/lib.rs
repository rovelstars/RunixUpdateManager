//! RunixOS deployment engine - thin glue over composefs-rs.
//!
//! A *deployment* is one versioned, verity-sealed `/Core`: a composefs image
//! plus the content-addressed objects it references, held in an on-disk
//! repository. The three consumers share this crate:
//!   - RUM        builds/imports deployments + records them in boot-control.
//!   - initramfs  mounts the selected deployment's verity-sealed /Core at boot.
//!   - recovery   reimages by pulling a full deployment over HTTP.
//!
//! It wraps composefs-rs (the `composefs` crate, v0.6.0):
//!   - `composefs::repository::Repository` - content-addressed object store
//!   - `composefs::fs::read_filesystem`    - import a /Core tree into objects
//!   - `FileSystem::commit_image`          - serialize the EROFS image + store it
//!   - `Repository::mount_at`              - mount the verity-sealed image
//!   - `Repository::gc`                    - prune unreferenced objects
//!
//! Boot selection (which deployment) is the separate `runix-bootctl` crate.
//! Pulling missing objects from R2 (composefs-http) is wired in RUM staging.
//!
//! We pin the hash to `Sha256HashValue` (fs-verity SHA-256); the hex of an
//! image's id is the verity root hash the bootloader/initramfs verify.

use anyhow::{Context, Result, bail};
use composefs::fs::read_filesystem;
use composefs::fsverity::{FsVerityHashValue, Sha256HashValue};
use composefs::repository::Repository;
use runix_bootctl::Version;
use std::fs::File;
use std::path::{Path, PathBuf};

/// fs-verity hash flavour for the whole store. SHA-256 matches the kernel
/// fs-verity default and dm-verity sealing of /Core.
type ObjId = Sha256HashValue;

/// A staged deployment of `/Core`.
#[derive(Clone, Debug)]
pub struct Deployment {
    pub version: Version,
    /// fs-verity digest of the composefs image, hex. This is the verity root
    /// hash the bootloader/initramfs verify against.
    pub verity_id: String,
}

/// Result of a garbage-collection pass.
#[derive(Clone, Copy, Debug, Default)]
pub struct GcStats {
    pub objects_removed: u64,
    pub bytes_freed: u64,
}

/// Handle to the on-disk content-addressed repository (objects + images),
/// typically on the data partition (btrfs/f2fs).
pub struct Repo {
    repo: Repository<ObjId>,
    root: PathBuf,
}

impl Repo {
    /// Open (or create) the repository rooted at `root`. Requires fs-verity
    /// support on the backing filesystem (the device path).
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        Self::open_inner(root, false)
    }

    /// Like [`open`](Self::open) but skips fs-verity sealing. For host testing
    /// on filesystems without fs-verity only; never use on device.
    pub fn open_insecure(root: impl Into<PathBuf>) -> Result<Self> {
        Self::open_inner(root, true)
    }

    fn open_inner(root: impl Into<PathBuf>, insecure: bool) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)
            .with_context(|| format!("creating repository dir {}", root.display()))?;
        let root = root
            .canonicalize()
            .with_context(|| format!("resolving repository dir {}", root.display()))?;
        // An absolute path makes openat ignore the base fd, so any valid dirfd
        // works as the anchor.
        let base = File::open("/").context("opening / as base dirfd")?;
        let mut repo = Repository::open_path(&base, &root)
            .with_context(|| format!("opening composefs repository at {}", root.display()))?;
        repo.set_insecure(insecure);
        Ok(Self { repo, root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Build a deployment from a prepared `/Core` source tree: import its files
    /// as content-addressed objects and serialize the composefs (EROFS) image,
    /// returning the deployment + its fs-verity id.
    pub fn build_deployment(&self, core_tree: &Path, version: Version) -> Result<Deployment> {
        let core_tree = core_tree
            .canonicalize()
            .with_context(|| format!("resolving /Core tree {}", core_tree.display()))?;
        let base = File::open("/").context("opening / as base dirfd")?;
        let fs = read_filesystem(&base, &core_tree, Some(&self.repo))
            .with_context(|| format!("reading /Core tree {}", core_tree.display()))?;
        let name = image_name(&version);
        let id = fs
            .commit_image(&self.repo, Some(&name))
            .context("committing composefs image")?;
        Ok(Deployment {
            version,
            verity_id: id.to_hex(),
        })
    }

    /// Fetch a deployment into this repo from a remote, verifying every object
    /// against its fs-verity id. Transport-agnostic: `fetch(hash_hex)` returns
    /// the bytes of the object with that fs-verity id (the caller does the HTTP,
    /// e.g. GET <base>/objects/<hh>/<rest>). Used by RUM staging and recovery;
    /// the initramfs never downloads.
    ///
    /// `expect_verity` is the signed image fs-verity hash from the manifest. The
    /// image object is fetched, re-hashed locally via `write_image`, and refused
    /// unless it matches - so a tampered CDN cannot feed a different image. Each
    /// referenced file object is likewise re-hashed on import (`ensure_object`).
    pub fn pull(
        &self,
        version: Version,
        expect_verity: &str,
        mut fetch: impl FnMut(&str) -> Result<Vec<u8>>,
    ) -> Result<Deployment> {
        let name = image_name(&version);

        // 1. Image object (its id IS the signed verity hash).
        let image = fetch(expect_verity).context("fetching composefs image object")?;
        let id = self
            .repo
            .write_image(Some(&name), &image)
            .context("importing composefs image")?;
        if id.to_hex() != expect_verity {
            bail!(
                "image verity mismatch: got {}, expected {expect_verity} (refusing)",
                id.to_hex()
            );
        }

        // 2. Referenced file objects; fetch + verify any we are missing. Look up
        // by hash (images/<hash>, always created by write_image) rather than the
        // alias name (which lives under images/refs/<name>).
        let refs = self
            .repo
            .objects_for_image(&id.to_hex())
            .context("listing objects referenced by the image")?;
        let (mut fetched, mut present) = (0usize, 0usize);
        for obj in &refs {
            if self.repo.open_object(obj).is_ok() {
                present += 1;
                continue;
            }
            let want = obj.to_hex();
            let data = fetch(&want).with_context(|| format!("fetching object {want}"))?;
            let got = self.repo.ensure_object(&data).context("importing object")?;
            if &got != obj {
                bail!("object verity mismatch: got {}, expected {want} (refusing)", got.to_hex());
            }
            fetched += 1;
        }
        eprintln!("pull {name}: {fetched} fetched, {present} already present, {} total", refs.len());

        Ok(Deployment {
            version,
            verity_id: expect_verity.to_string(),
        })
    }

    /// Mount a deployment's verity-sealed `/Core` at `target`. Used by the
    /// initramfs. The image is identified by its versioned name in the repo.
    pub fn mount(&self, dep: &Deployment, target: &Path) -> Result<()> {
        // open_image() opens images/<key> literally: the by-hash entry is
        // images/<hash>, the alias is images/refs/<name>. Prefer the verity hash
        // (what the manifest/cmdline carry); fall back to the refs/ alias.
        let key = if dep.verity_id.is_empty() {
            format!("refs/{}", image_name(&dep.version))
        } else {
            dep.verity_id.clone()
        };
        self.repo
            .mount_at(&key, target)
            .with_context(|| format!("mounting deployment {} at {}", dep.version, target.display()))
    }

    /// Prune objects no longer reachable from any named image. composefs keeps
    /// every named image as a GC root, so retire an old deployment's image name
    /// first, then call this to reclaim its objects. `keep` names are passed as
    /// extra roots (defensive; named images are already roots).
    pub fn gc(&self, keep: &[Deployment]) -> Result<GcStats> {
        let names: Vec<String> = keep.iter().map(|d| image_name(&d.version)).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let r = self.repo.gc(&refs).context("composefs gc")?;
        Ok(GcStats {
            objects_removed: r.objects_removed,
            bytes_freed: r.objects_bytes,
        })
    }
}

/// Repo image name for a deployment version, e.g. `core-7.0.11`.
fn image_name(v: &Version) -> String {
    format!("core-{v}")
}
