# UPM Android client scaffold (Phase 4)

This directory contains the Phase 4 platform boundary only. It is not yet a distributable APK.
The production design uses the shared `upm-core` protocol/crypto layer through a JNI/UniFFI-style
bridge, while Android UI/background delivery owns lifecycle, notifications, and Android Keystore access.

The current Kotlin boundary mirrors the versioned server API so the native UI work can begin without
inventing a second wire protocol.
