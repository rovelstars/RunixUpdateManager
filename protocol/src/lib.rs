//! Shared types and signing for the RunixOS update protocol.
//!
//! Used by both RUM (the on-device client) and RunixUpdateServer. The server
//! never holds the signing key: manifests are signed offline by the release
//! pipeline, and the server only selects and serves the pre-signed manifest the
//! client should get. RUM verifies the signature against the RovelStars public
//! key baked into the verity-protected system.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Wire-format version, bumped on incompatible protocol changes.
pub const SCHEMA: u32 = 1;

/// A system or package version. Ordering is major, then minor, then patch.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self { major, minor, patch }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl std::str::FromStr for Version {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let mut it = s.split('.');
        let mut next = || it.next().and_then(|p| p.parse::<u32>().ok()).ok_or(Error::BadVersion);
        let v = Version { major: next()?, minor: next()?, patch: next()? };
        if it.next().is_some() {
            return Err(Error::BadVersion);
        }
        Ok(v)
    }
}

/// A vendor / optional package the client should fetch (lives in /Construct,
/// independently signed, never part of the sealed /Core image).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PackageEntry {
    pub name: String,
    pub channel: String,
    pub version: Version,
    /// Reference to the content-addressed chunk index in the store (R2).
    pub index: String,
    /// sha256 of the reassembled package, hex.
    pub sha256: String,
    pub size: u64,
}

/// Describes one target system release. This is the payload that gets signed.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Manifest {
    pub schema: u32,
    pub channel: String,
    pub arch: String,
    /// Target system version this manifest installs.
    pub version: Version,
    /// Oldest installed version this update can be applied from. A client older
    /// than this needs a full image instead of a delta.
    pub min_source: Version,
    /// Reference to the content-addressed chunk index for the /Core image (R2).
    pub image_index: String,
    /// What the reassembled /Core image must hash to (dm-verity root hash, hex).
    pub verity_root_hash: String,
    pub size: u64,
    /// Vendor / optional packages for this device's subscribed channels.
    pub packages: Vec<PackageEntry>,
}

impl Manifest {
    /// Sign this manifest with a 32-byte Ed25519 secret key, producing the
    /// transportable signed envelope. Done offline by the release pipeline.
    pub fn sign(&self, secret: &[u8; 32], key_id: &str) -> Result<SignedManifest, Error> {
        let manifest_json = serde_json::to_string(self)?;
        let sig = sign_bytes(secret, manifest_json.as_bytes());
        Ok(SignedManifest {
            key_id: key_id.to_string(),
            manifest_json,
            signature_b64: B64.encode(sig),
        })
    }
}

/// A manifest plus a detached signature over its exact serialized bytes.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignedManifest {
    /// Identifies which signing key was used (for key rotation).
    pub key_id: String,
    /// The exact JSON bytes that were signed. Kept verbatim so verification is
    /// unambiguous (no canonicalization needed).
    pub manifest_json: String,
    /// Base64 of the 64-byte Ed25519 signature over `manifest_json`.
    pub signature_b64: String,
}

impl SignedManifest {
    /// Verify the signature against the given public key and return the parsed
    /// manifest. This is the only path RUM uses to trust a manifest.
    pub fn verify(&self, public: &[u8; 32]) -> Result<Manifest, Error> {
        let sig_bytes = B64.decode(&self.signature_b64).map_err(|_| Error::BadSignature)?;
        let sig: [u8; 64] = sig_bytes.try_into().map_err(|_| Error::BadSignature)?;
        if !verify_bytes(public, self.manifest_json.as_bytes(), &sig) {
            return Err(Error::BadSignature);
        }
        Ok(serde_json::from_str(&self.manifest_json)?)
    }

    /// Read the manifest WITHOUT verifying. Only for the server's own selection
    /// logic over its trusted release store. Never use on the client.
    pub fn parse_unverified(&self) -> Result<Manifest, Error> {
        Ok(serde_json::from_str(&self.manifest_json)?)
    }
}

/// What the client tells the server about itself.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CheckRequest {
    pub schema: u32,
    pub arch: String,
    pub current: Version,
    /// Base system channel, e.g. "stable".
    pub channel: String,
    /// Subscribed vendor / optional channels.
    pub subscribed: Vec<String>,
}

/// The server's answer.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum CheckResponse {
    UpToDate,
    Update(SignedManifest),
}

// ---- Ed25519 primitives (byte-oriented so callers never touch dalek types) ----

/// Derive the 32-byte public key from a 32-byte secret key.
pub fn public_key(secret: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(secret).verifying_key().to_bytes()
}

/// Sign a message, returning the 64-byte signature.
pub fn sign_bytes(secret: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(secret).sign(msg).to_bytes()
}

/// Verify a 64-byte signature over a message.
pub fn verify_bytes(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    match VerifyingKey::from_bytes(public) {
        Ok(vk) => vk.verify(msg, &Signature::from_bytes(sig)).is_ok(),
        Err(_) => false,
    }
}

#[derive(Debug)]
pub enum Error {
    Json(serde_json::Error),
    BadSignature,
    BadVersion,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Json(e) => write!(f, "json: {e}"),
            Error::BadSignature => write!(f, "bad or missing signature"),
            Error::BadVersion => write!(f, "bad version string"),
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> Manifest {
        Manifest {
            schema: SCHEMA,
            channel: "stable".into(),
            arch: "x86_64".into(),
            version: Version::new(26, 3, 0),
            min_source: Version::new(26, 2, 0),
            image_index: "core/26.3.0.caibx".into(),
            verity_root_hash: "deadbeef".into(),
            size: 1024,
            packages: vec![],
        }
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let secret = [7u8; 32];
        let public = public_key(&secret);
        let signed = sample_manifest().sign(&secret, "dev-1").unwrap();
        let got = signed.verify(&public).unwrap();
        assert_eq!(got.version, Version::new(26, 3, 0));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let signed = sample_manifest().sign(&[7u8; 32], "dev-1").unwrap();
        let other_public = public_key(&[9u8; 32]);
        assert!(matches!(signed.verify(&other_public), Err(Error::BadSignature)));
    }

    #[test]
    fn tampered_manifest_is_rejected() {
        let secret = [7u8; 32];
        let public = public_key(&secret);
        let mut signed = sample_manifest().sign(&secret, "dev-1").unwrap();
        // Flip the version in the signed bytes; signature must no longer match.
        signed.manifest_json = signed.manifest_json.replace("26", "27");
        assert!(matches!(signed.verify(&public), Err(Error::BadSignature)));
    }

    #[test]
    fn version_ordering() {
        assert!(Version::new(26, 3, 0) > Version::new(26, 2, 9));
        assert!(Version::new(27, 0, 0) > Version::new(26, 9, 9));
        assert_eq!("26.3.1".parse::<Version>().unwrap(), Version::new(26, 3, 1));
        assert!("26.3".parse::<Version>().is_err());
    }
}
