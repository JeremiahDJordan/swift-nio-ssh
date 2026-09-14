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

extension SSHConnectionStateMachine {
    /// The state of a state machine that hasn't done any work yet.
    struct IdleState {
        /// The role of the connection
        let role: SSHConnectionRole

        /// The packet serializer used by this state machine.
        internal var serializer: SSHPacketSerializer

        internal var protectionSchemes: [NIOSSHTransportProtection.Type]

        /// Whether this role implements strict key exchange at all. Always true in
        /// production; see `SSHKeyExchangeStateMachine`.
        internal let implementsStrictKeyExchange: Bool

        init(
            role: SSHConnectionRole,
            protectionSchemes: [NIOSSHTransportProtection.Type],
            implementsStrictKeyExchange: Bool = true
        ) {
            self.role = role
            self.serializer = SSHPacketSerializer()
            self.protectionSchemes = protectionSchemes
            self.implementsStrictKeyExchange = implementsStrictKeyExchange
        }
    }
}
