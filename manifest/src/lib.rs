//! The desktop app's component-manifest verifier and signer, as the app has them. `manifest.rs`
//! and `bin/sign-manifest.rs` are byte-for-byte copies of the app's own (desktop/core in the
//! app's repository); this crate is named `vps_desktop_core` so they build unchanged. The
//! signer checks every envelope with the app's verifier before writing it, so this repository
//! can never publish a manifest the app would refuse.

pub mod manifest;
mod owned;
