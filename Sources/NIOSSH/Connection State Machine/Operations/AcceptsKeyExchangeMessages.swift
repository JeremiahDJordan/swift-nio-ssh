//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// A connection state that is driving a key exchange, whether it is currently sending
/// or receiving.
protocol HasKeyExchangeStateMachine {
    var keyExchangeStateMachine: SSHKeyExchangeStateMachine { get set }
}

extension HasKeyExchangeStateMachine {
    /// Whether a message that is not part of the key exchange may be processed right now.
    /// Under strict key exchange nothing but the key exchange messages themselves is
    /// tolerated during the initial key exchange (OpenSSH PROTOCOL, "strict KEX"), because
    /// anything tolerated there can be injected or deleted by an attacker to shift the
    /// packet sequence numbers the transcript is bound to (Terrapin, CVE-2023-48795).
    var toleratesNonKeyExchangeMessages: Bool {
        !self.keyExchangeStateMachine.strictKeyExchange
    }
}

protocol AcceptsKeyExchangeMessages: HasKeyExchangeStateMachine {
    var parser: SSHPacketParser { get set }
}

extension AcceptsKeyExchangeMessages {
    mutating func receiveKeyExchangeMessage(
        _ message: SSHMessage.KeyExchangeMessage
    ) throws -> SSHConnectionStateMachine.StateMachineInboundProcessResult {
        // The sequence number of the packet we have just parsed: `nextPacket()` has
        // already counted it. Strict key exchange requires the peer's first KEXINIT
        // to *be* packet zero (OpenSSH PROTOCOL, "strict KEX", clause (a)), which is
        // the half of the rule that catches anything injected before it.
        let sequenceNumber = self.parser.sequenceNumber &- 1
        let message = try self.keyExchangeStateMachine.handle(
            keyExchange: message,
            sequenceNumber: sequenceNumber
        )

        if let message = message {
            return .emitMessage(message)
        } else {
            return .noMessage
        }
    }

    mutating func receiveKeyExchangeInitMessage(
        _ message: SSHMessage.KeyExchangeECDHInitMessage
    ) throws -> SSHConnectionStateMachine.StateMachineInboundProcessResult {
        let message = try self.keyExchangeStateMachine.handle(keyExchangeInit: message)

        if let message = message {
            return .emitMessage(message)
        } else {
            return .noMessage
        }
    }

    mutating func receiveKeyExchangeReplyMessage(
        _ message: SSHMessage.KeyExchangeECDHReplyMessage
    ) throws -> SSHConnectionStateMachine.StateMachineInboundProcessResult {
        let message = try self.keyExchangeStateMachine.handle(keyExchangeReply: message)
        return .possibleFutureMessage(message)
    }

    mutating func receiveNewKeysMessage() throws {
        // Received a new keys message. Apply the encryption keys to the parser.
        let result = try self.keyExchangeStateMachine.handleNewKeys()
        self.parser.addEncryption(
            result,
            resetSequenceNumber: self.keyExchangeStateMachine.strictKeyExchange
        )
    }
}
