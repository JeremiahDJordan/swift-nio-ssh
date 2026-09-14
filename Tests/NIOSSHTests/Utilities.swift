//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import NIOConcurrencyHelpers
import NIOCore
import XCTest

@testable import NIOSSH

func assertNoThrowWithValue<T>(
    _ body: @autoclosure () throws -> T,
    defaultValue: T? = nil,
    message: String? = nil,
    file: StaticString = #filePath,
    line: UInt = #line
) throws -> T {
    do {
        return try body()
    } catch {
        XCTFail("\(message.map { $0 + ": " } ?? "")unexpected error \(error) thrown", file: file, line: line)
        if let defaultValue = defaultValue {
            return defaultValue
        } else {
            throw error
        }
    }
}

// This algorithm is not secure, used only for testing purposes
struct InsecureEncryptionAlgorithm {
    static func encrypt(key: ByteBuffer, plaintext: ByteBuffer) -> ByteBuffer {
        var ciphertext = ByteBuffer()
        var plaintext = plaintext
        var key = key
        guard let k0 = key.readInteger(as: UInt32.self),
            let k1 = key.readInteger(as: UInt32.self),
            let k2 = key.readInteger(as: UInt32.self),
            let k3 = key.readInteger(as: UInt32.self)
        else {
            preconditionFailure("check key size")
        }

        while var block = plaintext.readSlice(length: 16) {
            guard var v0 = block.readInteger(as: UInt32.self),
                var v1 = block.readInteger(as: UInt32.self),
                var v2 = block.readInteger(as: UInt32.self),
                var v3 = block.readInteger(as: UInt32.self)
            else {
                preconditionFailure("check block size")
            }

            v0 = v0 ^ k0
            v1 = v1 ^ k1
            v2 = v2 ^ k2
            v3 = v3 ^ k3

            ciphertext.writeInteger(v0)
            ciphertext.writeInteger(v1)
            ciphertext.writeInteger(v2)
            ciphertext.writeInteger(v3)
        }
        return ciphertext
    }

    static func decrypt(key: ByteBuffer, ciphertext: ByteBuffer) -> ByteBuffer {
        var plaintext = ByteBuffer()
        var ciphertext = ciphertext
        var key = key
        guard let k0 = key.readInteger(as: UInt32.self),
            let k1 = key.readInteger(as: UInt32.self),
            let k2 = key.readInteger(as: UInt32.self),
            let k3 = key.readInteger(as: UInt32.self)
        else {
            preconditionFailure("check key size")
        }

        while var block = ciphertext.readSlice(length: 16) {
            guard var v0 = block.readInteger(as: UInt32.self),
                var v1 = block.readInteger(as: UInt32.self),
                var v2 = block.readInteger(as: UInt32.self),
                var v3 = block.readInteger(as: UInt32.self)
            else {
                preconditionFailure("check block size")
            }

            v0 = v0 ^ k0
            v1 = v1 ^ k1
            v2 = v2 ^ k2
            v3 = v3 ^ k3

            plaintext.writeInteger(v0)
            plaintext.writeInteger(v1)
            plaintext.writeInteger(v2)
            plaintext.writeInteger(v3)
        }

        return plaintext
    }
}

@available(iOS 13.2, macOS 10.15, watchOS 6.1, tvOS 13.2, *)
class TestTransportProtection: NIOSSHTransportProtection {
    enum TestError: Error {
        case doubleDecode
    }

    static var cipherBlockSize: Int {
        16
    }

    var macBytes: Int {
        32
    }

    var lengthEncrypted: Bool {
        true
    }

    class var cipherName: String {
        "insecure-tiny-encription-cipher"
    }

    class var macName: String? {
        nil
    }

    /// Whether the MAC covers the packet's sequence number, as every real
    /// encrypt-then-MAC scheme's does (`AESCTRETMTransportProtection` MACs
    /// `seq ‖ length ‖ ciphertext`). The base scheme does not, like AES-GCM, whose
    /// nonce it keeps itself; `SequenceNumberBoundTransportProtection` does, which is
    /// what makes an end-to-end test notice a sequence-number desync between the two
    /// ends — the failure mode strict key exchange's NEWKEYS resets can introduce.
    class var bindsSequenceNumber: Bool {
        false
    }

    private func macInput(_ plaintext: ByteBufferView, sequenceNumber: UInt32) -> [UInt8] {
        guard Self.bindsSequenceNumber else {
            return Array(plaintext)
        }
        return withUnsafeBytes(of: sequenceNumber.bigEndian) { Array($0) } + Array(plaintext)
    }

    class var keySizes: ExpectedKeySizes {
        .init(ivSize: 12, encryptionKeySize: 16, macKeySize: 16)
    }

    private var outboundEncryptionKey: ByteBuffer
    private var inboundEncryptionKey: ByteBuffer
    private var outboundMACKey: SymmetricKey
    private var inboundMACKey: SymmetricKey

    private var lastFirstBlock: ByteBufferView?

    required init(initialKeys: NIOSSHSessionKeys) {
        precondition(initialKeys.outboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8)
        precondition(initialKeys.inboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8)
        self.outboundEncryptionKey = initialKeys.outboundEncryptionKey.withUnsafeBytes {
            ByteBuffer(bytes: $0)
        }
        self.inboundEncryptionKey = initialKeys.inboundEncryptionKey.withUnsafeBytes {
            ByteBuffer(bytes: $0)
        }
        self.outboundMACKey = initialKeys.outboundMACKey
        self.inboundMACKey = initialKeys.inboundMACKey
    }

    func updateKeys(_ newKeys: NIOSSHSessionKeys) throws {
        precondition(newKeys.outboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8)
        precondition(newKeys.inboundEncryptionKey.bitCount == Self.keySizes.encryptionKeySize * 8)
        self.outboundEncryptionKey = newKeys.outboundEncryptionKey.withUnsafeBytes {
            ByteBuffer(bytes: $0)
        }
        self.inboundEncryptionKey = newKeys.inboundEncryptionKey.withUnsafeBytes {
            ByteBuffer(bytes: $0)
        }
        self.outboundMACKey = newKeys.outboundMACKey
        self.inboundMACKey = newKeys.inboundMACKey
    }

    func decryptFirstBlock(_ source: inout ByteBuffer) throws {
        let index = source.readerIndex

        guard let ciphertextView = source.viewBytes(at: index, length: Self.cipherBlockSize),
            ciphertextView.count > 0, ciphertextView.count % Self.cipherBlockSize == 0
        else {
            // The only way this fails is if the payload doesn't match this encryption scheme.
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        if self.lastFirstBlock == ciphertextView {
            throw TestError.doubleDecode
        }

        self.lastFirstBlock = ciphertextView

        let plaintext = InsecureEncryptionAlgorithm.decrypt(
            key: self.inboundEncryptionKey,
            ciphertext: ByteBuffer(bytes: ciphertextView)
        )

        source.setBytes(plaintext.readableBytesView, at: index)
    }

    func decryptAndVerifyRemainingPacket(_ source: inout ByteBuffer, sequenceNumber: UInt32) throws -> ByteBuffer {
        defer {
            self.lastFirstBlock = nil
        }

        guard var plaintext = source.readSlice(length: Self.cipherBlockSize) else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        // First block is expected to be decoded by decodeFirstBlock
        if source.readableBytes > self.macBytes {
            guard let ciphertext = source.readSlice(length: source.readableBytes - 32),
                ciphertext.readableBytes > 0, ciphertext.readableBytes % Self.cipherBlockSize == 0
            else {
                // The only way this fails is if the payload doesn't match this encryption scheme.
                throw NIOSSHError.invalidEncryptedPacketLength
            }

            var tail = InsecureEncryptionAlgorithm.decrypt(key: self.inboundEncryptionKey, ciphertext: ciphertext)
            plaintext.writeBuffer(&tail)
        }

        guard let tagView = source.readSlice(length: 32)?.readableBytesView else {
            throw NIOSSHError.invalidEncryptedPacketLength
        }

        guard
            HMAC<SHA256>.isValidAuthenticationCode(
                tagView,
                authenticating: self.macInput(plaintext.readableBytesView, sequenceNumber: sequenceNumber),
                using: self.inboundMACKey
            )
        else {
            // Thrown, not `preconditionFailure`: a sequence-number desync is a thing a
            // test needs to be able to observe as a failure rather than a crash.
            throw NIOSSHError.protocolViolation(protocolName: "transport", violation: "authentication failure")
        }

        // First 4 bytes are length
        plaintext.moveReaderIndex(forwardBy: 4)
        let paddingLength = plaintext.readInteger(as: UInt8.self)!
        return plaintext.readSlice(length: plaintext.readableBytes - Int(paddingLength))!
    }

    func encryptPacket(_ destination: inout ByteBuffer, sequenceNumber: UInt32) throws {
        let packetLengthIndex = destination.readerIndex
        let encryptedBufferSize = destination.readableBytes

        let plaintextView = destination.viewBytes(at: packetLengthIndex, length: encryptedBufferSize)!
        let ciphertext = InsecureEncryptionAlgorithm.encrypt(
            key: self.outboundEncryptionKey,
            plaintext: ByteBuffer(bytes: plaintextView)
        )
        assert(ciphertext.readableBytes == encryptedBufferSize)

        var hmac = HMAC<SHA256>.init(key: self.outboundMACKey)
        hmac.update(data: self.macInput(plaintextView, sequenceNumber: sequenceNumber))

        // We now want to overwrite the portion of the bytebuffer that contains the plaintext with the ciphertext, and then append the tag.
        destination.setBytes(ciphertext.readableBytesView, at: packetLengthIndex)
        let tagLength = destination.writeBytes(hmac.finalize())
        precondition(tagLength == self.macBytes, "Unexpected short tag")
    }
}

/// `TestTransportProtection` with the sequence number bound into the MAC, the way
/// every encrypt-then-MAC scheme binds it. Used to run whole connections so that the
/// two strict-KEX sequence-number resets (serializer and parser, each end) have to
/// stay in step for anything to decrypt at all: the fork's other schemes ignore the
/// parameter (AES-GCM carries its own nonce), so without this no end-to-end test in
/// the suite can see a desync.
@available(iOS 13.2, macOS 10.15, watchOS 6.1, tvOS 13.2, *)
final class SequenceNumberBoundTransportProtection: TestTransportProtection {
    override class var cipherName: String {
        "insecure-sequence-number-bound-cipher"
    }

    override class var bindsSequenceNumber: Bool {
        true
    }

    /// Every sequence number this scheme has encrypted with, oldest first, across
    /// both peers of an in-process test. Two peers that *both* fail to reset at
    /// NEWKEYS stay in step with each other, so nothing decrypts wrongly and no
    /// end-to-end assertion can see it — the numbers themselves are the only
    /// observable, which is what makes this the way to pin the resets a rekey
    /// under strict key exchange performs.
    static let encryptedSequenceNumbers = NIOLockedValueBox<[UInt32]>([])

    override func encryptPacket(_ destination: inout ByteBuffer, sequenceNumber: UInt32) throws {
        Self.encryptedSequenceNumbers.withLockedValue { $0.append(sequenceNumber) }
        try super.encryptPacket(&destination, sequenceNumber: sequenceNumber)
    }
}
