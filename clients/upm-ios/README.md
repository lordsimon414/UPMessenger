# UPM iOS client scaffold (Phase 5)

This is the native platform boundary for the future iOS client. The intended production split is:
SwiftUI/native lifecycle and APNs handling on the outside, shared Rust protocol/crypto core on the inside,
and Keychain for long-lived private material.

No App Store/build configuration is claimed yet; protocol behavior must remain identical to the Rust core.
