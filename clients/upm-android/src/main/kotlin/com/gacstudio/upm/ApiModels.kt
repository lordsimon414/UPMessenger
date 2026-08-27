package com.gacstudio.upm

data class RegisterResponse(val userId: String, val upmId: String, val deviceId: String)
data class DirectoryEntry(val upmId: String, val username: String, val deviceId: String, val identityPublicKey: String)
data class DeviceKeyBundle(
    val deviceId: String,
    val identityPublicKey: String,
    val identityExchangePublic: String,
    val signedPrekeyPublic: String,
    val signedPrekeySignature: String,
)

data class PullEnvelope(
    val messageId: String,
    val senderDeviceId: String,
    val ciphertextBase64: String,
    val createdAt: Long,
    val expiresAt: Long,
    val protocolVersion: Int,
)
