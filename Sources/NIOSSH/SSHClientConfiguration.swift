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

import NIOCore

/// Configuration for an SSH client.
public struct SSHClientConfiguration {
    /// The user authentication delegate to be used with this client.
    public var userAuthDelegate: NIOSSHClientUserAuthenticationDelegate

    /// The server authentication delegate to be used with this client.
    public var serverAuthDelegate: NIOSSHClientServerAuthenticationDelegate

    /// The global request delegate to be used with this client.
    public var globalRequestDelegate: GlobalRequestDelegate

    /// Supported data encryption algorithms
    public var transportProtectionSchemes: [NIOSSHTransportProtection.Type]

    /// The maximum size, in bytes, of a channel data payload this peer is willing to receive (the
    /// "maximum packet size" of an SSH channel, RFC 4254 §5.1). It is advertised to the remote peer
    /// when opening channels and bounds inbound encrypted packets. Defaults to `1 << 17` (128 KiB).
    ///
    /// The per-channel receive window we advertise is a fixed multiple of this value (64x), so raising
    /// this value raises the window proportionally. The window is stored as an `Int32`, meaning
    /// values above ~33 MiB (`Int32.max / 64`) saturate the window.
    ///
    /// - Precondition: Must be at least 32768 bytes, the uncompressed payload size
    ///   RFC 4253 §6.1 requires every implementation to support.
    /// - Precondition: The packet size must leave 1024 bytes for headers and framing.
    public var maximumPacketSize: Int = Constants.defaultMaximumChannelPacketSize {
        didSet {
            precondition(
                self.maximumPacketSize >= Constants.minimumChannelPacketSize,
                "maximumPacketSize must be at least \(Constants.minimumChannelPacketSize) bytes (RFC 4253 §6.1)"
            )
            precondition(
                self.maximumPacketSize <= Constants.maximumChannelPacketSize,
                "maximumPacketSize must leave room for SSH framing and padding (RFC 4253 §6)."
            )
        }
    }

    /// Client keepalive: `keepalive@openssh.com` probes after a quiet interval, and a limit on
    /// unanswered ones (OpenSSH's `ServerAliveInterval` and `ServerAliveCountMax`). `nil`, the
    /// default, sends none. ``NIOSSHHandler/sendKeepAlive(promise:)`` sends one on demand
    /// whether or not this is set.
    public var keepAlive: SSHKeepAliveConfiguration? = nil

    public init(
        userAuthDelegate: NIOSSHClientUserAuthenticationDelegate,
        serverAuthDelegate: NIOSSHClientServerAuthenticationDelegate,
        globalRequestDelegate: GlobalRequestDelegate? = nil
    ) {
        self.init(
            userAuthDelegate: userAuthDelegate,
            serverAuthDelegate: serverAuthDelegate,
            globalRequestDelegate: globalRequestDelegate,
            transportProtectionSchemes: Constants.bundledTransportProtectionSchemes
        )
    }

    public init(
        userAuthDelegate: NIOSSHClientUserAuthenticationDelegate,
        serverAuthDelegate: NIOSSHClientServerAuthenticationDelegate,
        globalRequestDelegate: GlobalRequestDelegate? = nil,
        transportProtectionSchemes: [NIOSSHTransportProtection.Type]
    ) {
        self.userAuthDelegate = userAuthDelegate
        self.serverAuthDelegate = serverAuthDelegate
        self.globalRequestDelegate = globalRequestDelegate ?? DefaultGlobalRequestDelegate()
        self.transportProtectionSchemes = transportProtectionSchemes
    }
}

/// Client keepalive settings, as OpenSSH's `ServerAliveInterval` and `ServerAliveCountMax`.
///
/// Once user authentication has succeeded, each `interval` in which nothing arrived from the
/// server sends a `keepalive@openssh.com` global request asking for a reply. Any reply (servers
/// answer this unknown request with `SSH_MSG_REQUEST_FAILURE`) proves the server alive and resets
/// the count. When `maximumUnansweredProbes` probes are unanswered at the next quiet interval, the
/// handler fires ``NIOSSHError/ErrorType/keepAliveTimeout`` and closes the connection: a dead peer
/// is noticed after about `interval × (maximumUnansweredProbes + 1)` of silence.
public struct SSHKeepAliveConfiguration: Hashable, Sendable {
    /// The quiet time before a probe is sent, and between probes. Must be positive.
    public var interval: TimeAmount

    /// The number of unanswered probes tolerated; the next quiet interval closes the connection.
    /// Must be at least 1.
    public var maximumUnansweredProbes: Int

    public init(interval: TimeAmount, maximumUnansweredProbes: Int = 3) {
        precondition(interval > .zero, "keepalive interval must be positive")
        precondition(maximumUnansweredProbes >= 1, "keepalive must tolerate at least one unanswered probe")
        self.interval = interval
        self.maximumUnansweredProbes = maximumUnansweredProbes
    }
}

// The various delegates aren't required to be Sendable, so the config isn't sendable.
@available(*, unavailable)
extension SSHClientConfiguration: Sendable {}
