//! The signed component manifest. It travels as one envelope file, so a mirror or CDN can
//! never pair a payload with a signature from another release. Nothing in it is trusted until
//! the signature, the lifetime and the rollback floor have all been checked.

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

pub const SCHEMA: &str = "vps-desktop-components-v1";
/// CI signs for 7 days; anything claiming a longer life is malformed.
const MAX_LIFETIME: i64 = 8 * 86_400;
/// A manifest stamped further ahead of the local clock is refused rather than pinned as the floor.
const MAX_CLOCK_SKEW: i64 = 86_400;
const MAX_ENVELOPE_BYTES: usize = 1 << 20;
const MAX_ARTIFACT_BYTES: u64 = 2 << 30;

const COMPONENTS: &[&str] = &["claude-code", "cc-switch", "claude-desktop"];
pub const PLATFORMS: &[&str] = &[
    "darwin-arm64", "darwin-x64", "linux-x64", "linux-arm64",
    "linux-x64-musl", "linux-arm64-musl", "win32-x64", "win32-arm64",
];
const FORMATS: &[&str] = &["msix", "msi", "dmg", "deb", "appimage"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest envelope is malformed")]
    Envelope,
    #[error("manifest signature does not verify")]
    Signature,
    #[error("manifest payload is malformed: {0}")]
    Payload(String),
    #[error("manifest expired")]
    Expired,
    #[error("manifest is stamped in the future")]
    Future,
    #[error("manifest is older than one already seen")]
    Rollback,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    payload: String,
    signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub sequence: i64,
    pub expires: i64,
    pub components: BTreeMap<String, Component>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Component {
    pub version: String,
    pub platforms: BTreeMap<String, Artifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Artifact {
    /// An npm platform package; the binary is the single regular file at `entry`.
    NpmTgz {
        sources: Vec<String>,
        sha512: String,
        size: u64,
        entry: String,
        binary_sha256: String,
        binary_size: u64,
    },
    /// A file handed whole to the system installer.
    File {
        sources: Vec<String>,
        sha256: String,
        size: u64,
        format: String,
    },
}

fn bad(what: &str) -> ManifestError {
    ManifestError::Payload(what.to_string())
}

fn check_sources(sources: &[String]) -> Result<(), ManifestError> {
    let ok = !sources.is_empty()
        && sources.len() <= 8
        && sources.iter().all(|s| {
            s.starts_with("https://") && s.len() <= 2048 && !s.chars().any(|c| c.is_whitespace() || c.is_control())
        });
    if ok { Ok(()) } else { Err(bad("sources")) }
}

fn check_sha256(value: &str) -> Result<(), ManifestError> {
    let ok = value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok { Ok(()) } else { Err(bad("sha256")) }
}

fn check_integrity(value: &str) -> Result<(), ManifestError> {
    match value.strip_prefix("sha512-").map(|b64| STANDARD.decode(b64)) {
        Some(Ok(digest)) if digest.len() == 64 => Ok(()),
        _ => Err(bad("sha512")),
    }
}

fn check_size(size: u64) -> Result<(), ManifestError> {
    if (1..=MAX_ARTIFACT_BYTES).contains(&size) { Ok(()) } else { Err(bad("size")) }
}

/// A relative POSIX path inside the package: no root, no backslash, no `.` or `..` parts.
fn check_entry(entry: &str) -> Result<(), ManifestError> {
    let ok = !entry.is_empty()
        && entry.len() <= 256
        && !entry.starts_with('/')
        && !entry.contains('\\')
        && entry.split('/').all(|part| !part.is_empty() && part != "." && part != "..");
    if ok { Ok(()) } else { Err(bad("entry")) }
}

fn check_version(version: &str) -> Result<(), ManifestError> {
    let ok = !version.is_empty()
        && version.len() <= 64
        && version.chars().all(|c| c.is_ascii_alphanumeric() || ".+-".contains(c));
    if ok { Ok(()) } else { Err(bad("version")) }
}

fn validate(manifest: &Manifest) -> Result<(), ManifestError> {
    if manifest.schema != SCHEMA {
        return Err(bad("schema"));
    }
    if manifest.components.is_empty() {
        return Err(bad("components"));
    }
    for (name, component) in &manifest.components {
        if !COMPONENTS.contains(&name.as_str()) {
            return Err(bad("component"));
        }
        check_version(&component.version)?;
        if component.platforms.is_empty() {
            return Err(bad("platforms"));
        }
        for (platform, artifact) in &component.platforms {
            if !PLATFORMS.contains(&platform.as_str()) {
                return Err(bad("platform"));
            }
            match artifact {
                Artifact::NpmTgz { sources, sha512, size, entry, binary_sha256, binary_size } => {
                    check_sources(sources)?;
                    check_integrity(sha512)?;
                    check_size(*size)?;
                    check_entry(entry)?;
                    check_sha256(binary_sha256)?;
                    check_size(*binary_size)?;
                }
                Artifact::File { sources, sha256, size, format } => {
                    check_sources(sources)?;
                    check_sha256(sha256)?;
                    check_size(*size)?;
                    if !FORMATS.contains(&format.as_str()) {
                        return Err(bad("format"));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Verifies one fetched envelope. `trusted` holds every accepted public key, so the signing key
/// can rotate; `highest_seen` is the persisted floor from earlier manifests.
pub fn verify(envelope: &[u8], trusted: &[[u8; 32]], now: i64, highest_seen: Option<i64>) -> Result<Manifest, ManifestError> {
    if envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(ManifestError::Envelope);
    }
    let envelope: Envelope = serde_json::from_slice(envelope).map_err(|_| ManifestError::Envelope)?;
    let payload = STANDARD.decode(envelope.payload.as_bytes()).map_err(|_| ManifestError::Envelope)?;
    let signature: [u8; 64] = STANDARD
        .decode(envelope.signature.as_bytes())
        .map_err(|_| ManifestError::Envelope)?
        .try_into()
        .map_err(|_| ManifestError::Envelope)?;
    let signature = Signature::from_bytes(&signature);
    let signed = trusted.iter().any(|key| {
        VerifyingKey::from_bytes(key).is_ok_and(|key| key.verify_strict(&payload, &signature).is_ok())
    });
    if !signed {
        return Err(ManifestError::Signature);
    }
    let manifest: Manifest = serde_json::from_slice(&payload).map_err(|e| ManifestError::Payload(e.to_string()))?;
    validate(&manifest)?;
    if manifest.expires <= manifest.sequence || manifest.expires - manifest.sequence > MAX_LIFETIME {
        return Err(bad("lifetime"));
    }
    if manifest.sequence > now + MAX_CLOCK_SKEW {
        return Err(ManifestError::Future);
    }
    if manifest.expires <= now {
        return Err(ManifestError::Expired);
    }
    if highest_seen.is_some_and(|seen| manifest.sequence < seen) {
        return Err(ManifestError::Rollback);
    }
    Ok(manifest)
}

/// Of the copies fetched from every mirror, the valid one with the highest sequence;
/// with none valid, the last refusal.
pub fn newest(results: Vec<Result<Manifest, ManifestError>>) -> Result<Manifest, ManifestError> {
    let mut best: Option<Manifest> = None;
    let mut last = ManifestError::Envelope;
    for result in results {
        match result {
            Ok(manifest) => {
                if best.as_ref().map_or(true, |b| manifest.sequence > b.sequence) {
                    best = Some(manifest);
                }
            }
            Err(error) => last = error,
        }
    }
    best.ok_or(last)
}

/// Why fetched manifests were not accepted.
#[derive(Debug, thiserror::Error)]
pub enum AcceptError {
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("the rollback floor could not be read or saved: {0}")]
    Floor(#[from] io::Error),
}

/// The persisted rollback floor: the highest sequence of any manifest the app accepted. A
/// missing file means none was accepted yet; a malformed one is an error, so a damaged floor
/// never silently allows a rollback.
pub fn read_floor(path: &Path) -> io::Result<Option<i64>> {
    match fs::read_to_string(path) {
        Ok(text) => text
            .trim()
            .parse::<i64>()
            .map(Some)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "manifest floor is malformed")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Raises the floor to `sequence`; it never goes down.
pub fn raise_floor(path: &Path, sequence: i64) -> io::Result<()> {
    if read_floor(path)?.is_some_and(|floor| floor >= sequence) {
        return Ok(());
    }
    crate::owned::write_atomic(path, sequence.to_string().as_bytes())
}

/// Verifies every copy fetched from the mirrors against the persisted floor, keeps the newest
/// valid one and only then raises the floor to it. When no copy verifies, the floor is untouched.
pub fn accept(copies: &[Vec<u8>], trusted: &[[u8; 32]], now: i64, floor: &Path) -> Result<Manifest, AcceptError> {
    let seen = read_floor(floor)?;
    let manifest = newest(copies.iter().map(|copy| verify(copy, trusted, now, seen)).collect())?;
    raise_floor(floor, manifest.sequence)?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{json, Value};

    const NOW: i64 = 1_800_000_000;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn public(key: &SigningKey) -> [u8; 32] {
        key.verifying_key().to_bytes()
    }

    // Signed with the ed25519 library directly, not with anything under test.
    fn envelope(key: &SigningKey, payload: &Value) -> Vec<u8> {
        let bytes = serde_json::to_vec(payload).unwrap();
        let signature = key.sign(&bytes).to_bytes();
        serde_json::to_vec(&json!({"payload": STANDARD.encode(&bytes), "signature": STANDARD.encode(signature)})).unwrap()
    }

    fn sample(sequence: i64) -> Value {
        json!({
            "schema": SCHEMA, "sequence": sequence, "expires": sequence + 7 * 86_400,
            "components": {
                "claude-code": {"version": "2.1.325", "platforms": {"darwin-arm64": {
                    "kind": "npm-tgz", "sources": ["https://registry.npmmirror.com/a.tgz"],
                    "sha512": format!("sha512-{}", STANDARD.encode([1u8; 64])), "size": 10,
                    "entry": "package/claude", "binary_sha256": "a".repeat(64), "binary_size": 9}}},
                "cc-switch": {"version": "4.0.33", "platforms": {"win32-x64": {
                    "kind": "file", "sources": ["https://github.com/a.msi"], "sha256": "b".repeat(64),
                    "size": 5, "format": "msi"}}}
            }
        })
    }

    fn check(payload: &Value) -> Result<Manifest, ManifestError> {
        verify(&envelope(&key(1), payload), &[public(&key(1))], NOW, None)
    }

    fn rename_key(object: &mut Value, from: &str, to: &str) {
        let map = object.as_object_mut().unwrap();
        let value = map.remove(from).unwrap();
        map.insert(to.to_string(), value);
    }

    #[test]
    fn accepts_a_signed_current_manifest() {
        let manifest = check(&sample(NOW - 60)).unwrap();
        assert_eq!(manifest.components["claude-code"].version, "2.1.325");
        assert!(matches!(manifest.components["cc-switch"].platforms["win32-x64"], Artifact::File { .. }));
    }

    #[test]
    fn refuses_another_key_and_accepts_any_trusted_key() {
        let signed = envelope(&key(2), &sample(NOW - 60));
        assert_eq!(verify(&signed, &[public(&key(1))], NOW, None), Err(ManifestError::Signature));
        assert!(verify(&signed, &[public(&key(1)), public(&key(2))], NOW, None).is_ok());
    }

    #[test]
    fn refuses_a_changed_payload() {
        let mut outer: Value = serde_json::from_slice(&envelope(&key(1), &sample(NOW - 60))).unwrap();
        let mut changed = sample(NOW - 60);
        changed["components"]["claude-code"]["version"] = json!("9.9.9");
        outer["payload"] = json!(STANDARD.encode(serde_json::to_vec(&changed).unwrap()));
        let result = verify(&serde_json::to_vec(&outer).unwrap(), &[public(&key(1))], NOW, None);
        assert_eq!(result, Err(ManifestError::Signature));
    }

    #[test]
    fn refuses_expired_and_future_manifests() {
        assert_eq!(check(&sample(NOW - 8 * 86_400)), Err(ManifestError::Expired));
        assert_eq!(check(&sample(NOW + 2 * 86_400)), Err(ManifestError::Future));
    }

    #[test]
    fn refuses_rollback_but_accepts_the_same_sequence() {
        let signed = envelope(&key(1), &sample(NOW - 60));
        assert_eq!(verify(&signed, &[public(&key(1))], NOW, Some(NOW)), Err(ManifestError::Rollback));
        assert!(verify(&signed, &[public(&key(1))], NOW, Some(NOW - 60)).is_ok());
    }

    #[test]
    fn refuses_a_lifetime_longer_than_ci_signs() {
        let mut payload = sample(NOW - 60);
        payload["expires"] = json!(NOW - 60 + 9 * 86_400);
        assert!(matches!(check(&payload), Err(ManifestError::Payload(_))));
    }

    #[test]
    fn refuses_unknown_fields_at_every_level() {
        let mut top = sample(NOW - 60);
        top["extra"] = json!(1);
        assert!(matches!(check(&top), Err(ManifestError::Payload(_))));
        let mut artifact = sample(NOW - 60);
        artifact["components"]["cc-switch"]["platforms"]["win32-x64"]["extra"] = json!(1);
        assert!(matches!(check(&artifact), Err(ManifestError::Payload(_))));
    }

    #[test]
    fn refuses_plain_http_unsafe_entries_and_bad_digests() {
        let cases = [
            ("/components/cc-switch/platforms/win32-x64/sources", json!(["http://github.com/a.msi"])),
            ("/components/cc-switch/platforms/win32-x64/sources", json!([])),
            ("/components/claude-code/platforms/darwin-arm64/entry", json!("../claude")),
            ("/components/claude-code/platforms/darwin-arm64/entry", json!("/package/claude")),
            ("/components/claude-code/platforms/darwin-arm64/entry", json!("package\\claude")),
            ("/components/claude-code/platforms/darwin-arm64/binary_sha256", json!("A".repeat(64))),
            ("/components/claude-code/platforms/darwin-arm64/sha512", json!("sha512-AAAA")),
            ("/components/cc-switch/platforms/win32-x64/size", json!(0)),
            ("/components/cc-switch/platforms/win32-x64/format", json!("exe")),
        ];
        for (pointer, value) in cases {
            let mut payload = sample(NOW - 60);
            *payload.pointer_mut(pointer).unwrap() = value;
            assert!(matches!(check(&payload), Err(ManifestError::Payload(_))), "{pointer}");
        }
    }

    #[test]
    fn refuses_unknown_components_and_platforms() {
        let mut component = sample(NOW - 60);
        rename_key(&mut component["components"], "cc-switch", "other");
        assert!(matches!(check(&component), Err(ManifestError::Payload(_))));
        let mut platform = sample(NOW - 60);
        rename_key(&mut platform["components"]["cc-switch"]["platforms"], "win32-x64", "freebsd-x64");
        assert!(matches!(check(&platform), Err(ManifestError::Payload(_))));
    }

    #[test]
    fn refuses_garbage_envelopes() {
        assert_eq!(verify(b"not json", &[public(&key(1))], NOW, None), Err(ManifestError::Envelope));
        let short = serde_json::to_vec(&json!({"payload": "e30=", "signature": "AAAA"})).unwrap();
        assert_eq!(verify(&short, &[public(&key(1))], NOW, None), Err(ManifestError::Envelope));
    }

    #[test]
    fn newest_prefers_the_highest_valid_sequence() {
        let trusted = [public(&key(1))];
        let results = vec![
            verify(&envelope(&key(1), &sample(NOW - 7200)), &trusted, NOW, None),
            verify(b"x", &trusted, NOW, None),
            verify(&envelope(&key(1), &sample(NOW - 60)), &trusted, NOW, None),
        ];
        assert_eq!(newest(results).unwrap().sequence, NOW - 60);
        assert_eq!(newest(vec![Err(ManifestError::Expired)]), Err(ManifestError::Expired));
    }

    #[test]
    fn accepting_raises_the_floor_and_refuses_an_older_copy_later() {
        let temp = tempfile::tempdir().unwrap();
        let floor = temp.path().join("state/manifest-floor");
        let trusted = [public(&key(1))];
        let newer = envelope(&key(1), &sample(NOW - 60));
        let older = envelope(&key(1), &sample(NOW - 3600));
        assert_eq!(accept(&[newer], &trusted, NOW, &floor).unwrap().sequence, NOW - 60);
        assert_eq!(read_floor(&floor).unwrap(), Some(NOW - 60));
        assert!(matches!(accept(&[older], &trusted, NOW, &floor), Err(AcceptError::Manifest(ManifestError::Rollback))));
        assert_eq!(read_floor(&floor).unwrap(), Some(NOW - 60));
    }

    #[test]
    fn a_refused_copy_never_moves_the_floor() {
        let temp = tempfile::tempdir().unwrap();
        let floor = temp.path().join("manifest-floor");
        let trusted = [public(&key(1))];
        let expired = envelope(&key(1), &sample(NOW - 8 * 86_400));
        let foreign = envelope(&key(2), &sample(NOW - 60));
        let mut tampered: Value = serde_json::from_slice(&envelope(&key(1), &sample(NOW - 60))).unwrap();
        tampered["payload"] = json!(STANDARD.encode(serde_json::to_vec(&sample(NOW)).unwrap()));
        let tampered = serde_json::to_vec(&tampered).unwrap();
        for copy in [expired, foreign, tampered] {
            assert!(accept(&[copy], &trusted, NOW, &floor).is_err());
            assert_eq!(read_floor(&floor).unwrap(), None);
        }
    }

    #[test]
    fn the_newest_valid_copy_sets_the_floor() {
        let temp = tempfile::tempdir().unwrap();
        let floor = temp.path().join("manifest-floor");
        let copies = [envelope(&key(1), &sample(NOW - 7200)), b"garbage".to_vec(), envelope(&key(1), &sample(NOW - 60))];
        assert_eq!(accept(&copies, &[public(&key(1))], NOW, &floor).unwrap().sequence, NOW - 60);
        assert_eq!(read_floor(&floor).unwrap(), Some(NOW - 60));
    }

    #[test]
    fn a_malformed_floor_refuses_everything() {
        let temp = tempfile::tempdir().unwrap();
        let floor = temp.path().join("manifest-floor");
        std::fs::write(&floor, "not a number").unwrap();
        let copy = envelope(&key(1), &sample(NOW - 60));
        assert!(matches!(accept(&[copy], &[public(&key(1))], NOW, &floor), Err(AcceptError::Floor(_))));
        assert_eq!(std::fs::read_to_string(&floor).unwrap(), "not a number");
    }

    #[test]
    fn the_floor_never_goes_down() {
        let temp = tempfile::tempdir().unwrap();
        let floor = temp.path().join("manifest-floor");
        raise_floor(&floor, 200).unwrap();
        raise_floor(&floor, 100).unwrap();
        assert_eq!(read_floor(&floor).unwrap(), Some(200));
        raise_floor(&floor, 300).unwrap();
        assert_eq!(read_floor(&floor).unwrap(), Some(300));
    }
}
