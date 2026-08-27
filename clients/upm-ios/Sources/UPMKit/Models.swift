import Foundation

public struct UPMDirectoryEntry: Codable, Sendable {
    public let upmId: String
    public let username: String
    public let deviceId: String
    public let identityPublicKey: String
}

public struct UPMDeviceKeyBundle: Codable, Sendable {
    public let deviceId: String
    public let identityPublicKey: String
    public let identityExchangePublic: String
    public let signedPrekeyPublic: String
    public let signedPrekeySignature: String
}

public struct UPMPullEnvelope: Codable, Sendable {
    public let messageId: String
    public let senderDeviceId: String
    public let ciphertextBase64: String
    public let createdAt: Int64
    public let expiresAt: Int64
    public let protocolVersion: UInt16
}
