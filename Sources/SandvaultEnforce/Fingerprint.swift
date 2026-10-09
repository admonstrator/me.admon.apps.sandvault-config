import Crypto
import Foundation

/// Lowercase hex SHA-256, used for integrity records and drift detection.
public enum Fingerprint {
    public static func sha256(_ data: Data) -> String {
        let digits = Array("0123456789abcdef".utf8)
        var hex: [UInt8] = []
        hex.reserveCapacity(64)
        for byte in SHA256.hash(data: data) {
            hex.append(digits[Int(byte >> 4)])
            hex.append(digits[Int(byte & 0x0F)])
        }
        return String(decoding: hex, as: UTF8.self)
    }

    public static func sha256(_ text: String) -> String {
        sha256(Data(text.utf8))
    }
}
