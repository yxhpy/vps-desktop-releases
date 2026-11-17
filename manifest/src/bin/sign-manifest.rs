//! Signs a component-manifest payload for the desktop app:
//! `sign-manifest <payload.json> <envelope.json>`, with the base64 ed25519 seed in
//! `MANIFEST_SIGNING_KEY`. The envelope is checked with the app's own verifier before it is
//! written, so CI can never publish a manifest the app would refuse.
//!
//! `sign-manifest --public` prints only the public key of that seed, as the 64 hex digits
//! `VPS_MANIFEST_KEYS` takes. It reads and writes no file, and never prints the seed.

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use std::env;
use std::fs;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};
use vps_desktop_core::manifest;

const USAGE: &str = "usage: sign-manifest <payload.json> <envelope.json>, or sign-manifest --public";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("sign-manifest: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    match args.as_slice() {
        [_, flag] if flag == "--public" => {
            let public = signing_key()?.verifying_key().to_bytes();
            println!("{}", public.iter().map(|byte| format!("{byte:02x}")).collect::<String>());
            Ok(())
        }
        [_, input, output] if !input.starts_with("--") => sign(&signing_key()?, input, output),
        _ => Err(USAGE.into()),
    }
}

/// The key from `MANIFEST_SIGNING_KEY`. Errors name the variable, never its value.
fn signing_key() -> Result<SigningKey, String> {
    let seed = env::var("MANIFEST_SIGNING_KEY").map_err(|_| "MANIFEST_SIGNING_KEY is not set")?;
    let seed: [u8; 32] = STANDARD
        .decode(seed.trim())
        .map_err(|_| "MANIFEST_SIGNING_KEY is not base64")?
        .try_into()
        .map_err(|_| "MANIFEST_SIGNING_KEY must be a 32-byte seed")?;
    Ok(SigningKey::from_bytes(&seed))
}

fn sign(key: &SigningKey, input: &str, output: &str) -> Result<(), String> {
    let payload = fs::read(input).map_err(|error| format!("{input}: {error}"))?;
    let signature = key.sign(&payload).to_bytes();
    let envelope = serde_json::to_vec(&json!({"payload": STANDARD.encode(&payload), "signature": STANDARD.encode(signature)}))
        .map_err(|error| error.to_string())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|error| error.to_string())?.as_secs() as i64;
    manifest::verify(&envelope, &[key.verifying_key().to_bytes()], now, None)
        .map_err(|error| format!("the app would refuse this manifest: {error}"))?;
    fs::write(output, &envelope).map_err(|error| format!("{output}: {error}"))?;
    Ok(())
}
