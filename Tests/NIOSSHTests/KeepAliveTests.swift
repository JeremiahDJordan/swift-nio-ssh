//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import NIOCore
import NIOEmbedded
import XCTest

@testable import NIOSSH

/// Records the errors that reach the end of a pipeline.
private final class ErrorRecorder: ChannelInboundHandler {
    typealias InboundIn = Any
    var errors: [Error] = []

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        self.errors.append(error)
    }
}

/// Records whether the channel was still open when an error arrived. (`NIOSSHHandler` does
/// not forward `channelInactive`, so that cannot be observed past it.)
private final class ErrorBeforeInactive: ChannelInboundHandler {
    typealias InboundIn = Any
    var events: [String] = []

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        self.events.append(context.channel.isActive ? "error while open" : "error after close")
        context.fireErrorCaught(error)
    }
}

/// Holds the password prompt until the test releases it (a person typing slowly).
private final class SlowPasswordDelegate: NIOSSHClientUserAuthenticationDelegate {
    var pending: EventLoopPromise<NIOSSHUserAuthenticationOffer?>?

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        self.pending = nextChallengePromise
    }

    func release() {
        self.pending?.succeed(.init(username: "foo", serviceName: "", offer: .password(.init(password: "bar"))))
        self.pending = nil
    }
}

/// Accepts the first host key at once and holds every later check (rekeys) until released, as
/// an asynchronous known-hosts lookup does.
private final class HeldRekeyValidation: NIOSSHClientServerAuthenticationDelegate {
    var count = 0
    var held: EventLoopPromise<Void>?

    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        self.count += 1
        if self.count == 1 {
            validationCompletePromise.succeed(())
        } else {
            self.held = validationCompletePromise
        }
    }
}

/// Client keepalive (`SSHClientConfiguration.keepAlive`, `NIOSSHHandler.sendKeepAlive`): OpenSSH's
/// `ServerAliveInterval`/`ServerAliveCountMax` with `keepalive@openssh.com` global requests.
final class KeepAliveTests: XCTestCase {
    private var channel: BackToBackEmbeddedChannel!
    private var clientErrors: ErrorRecorder!
    private let interval = TimeAmount.seconds(15)

    override func setUp() {
        self.channel = BackToBackEmbeddedChannel()
        self.clientErrors = ErrorRecorder()
    }

    override func tearDown() {
        try? self.channel.finish()
        self.channel = nil
    }

    private func connect(keepAlive: SSHKeepAliveConfiguration?) throws {
        var harness = TestHarness()
        harness.clientKeepAlive = keepAlive
        try self.channel.configureWithHarness(harness)
        try self.channel.client.pipeline.syncOperations.addHandler(self.clientErrors)
        try self.channel.activate()
        try self.channel.interactInMemory()
        XCTAssertNotNil(self.channel.clientSSHHandler)
    }

    /// Whatever the client has written since the last delivery, taken off the wire (not delivered).
    private func clientOutbound() throws -> [IOData] {
        var data: [IOData] = []
        while let next = try self.channel.client.readOutbound(as: IOData.self) {
            data.append(next)
        }
        return data
    }

    private func deliverToServer(_ data: [IOData]) throws {
        for datum in data {
            try self.channel.server.writeInbound(datum)
        }
        try self.channel.interactInMemory()
    }

    func testNoProbesWithoutConfiguration() throws {
        try self.connect(keepAlive: nil)
        for _ in 0..<10 {
            self.channel.advanceTime(by: self.interval)
            XCTAssertEqual(try self.clientOutbound().count, 0)
        }
        XCTAssertTrue(self.channel.client.isActive)
    }

    /// A quiet connection is probed each interval; the server's answer (a REQUEST_FAILURE, as
    /// every server gives an unknown request) keeps it open indefinitely.
    func testQuietConnectionIsProbedAndAnsweredProbesKeepItOpen() throws {
        try self.connect(keepAlive: .init(interval: self.interval, maximumUnansweredProbes: 2))
        XCTAssertEqual(try self.clientOutbound().count, 0)

        for _ in 0..<10 {
            self.channel.advanceTime(by: self.interval - .seconds(1))
            XCTAssertEqual(try self.clientOutbound().count, 0, "no probe before the interval")
            self.channel.advanceTime(by: .seconds(1))
            let probe = try self.clientOutbound()
            XCTAssertEqual(probe.count, 1, "one probe per quiet interval")
            try self.deliverToServer(probe)
        }
        XCTAssertTrue(self.channel.client.isActive)
        XCTAssertTrue(self.clientErrors.errors.isEmpty, "\(self.clientErrors.errors)")
    }

    /// With the limit of unanswered probes reached, the next quiet interval fails the connection:
    /// `maximumUnansweredProbes` probes go out, and the one after that is a close.
    func testUnansweredProbesCloseTheConnection() throws {
        try self.connect(keepAlive: .init(interval: self.interval, maximumUnansweredProbes: 3))

        for probe in 1...3 {
            self.channel.advanceTime(by: self.interval)
            XCTAssertEqual(try self.clientOutbound().count, 1, "probe \(probe)")  // dropped on the floor
            XCTAssertTrue(self.channel.client.isActive)
            XCTAssertTrue(self.clientErrors.errors.isEmpty)
        }

        self.channel.advanceTime(by: self.interval)
        XCTAssertFalse(self.channel.client.isActive)
        XCTAssertEqual(self.clientErrors.errors.count, 1)
        XCTAssertEqual((self.clientErrors.errors.first as? NIOSSHError)?.type, .keepAliveTimeout)
    }

    /// One answer clears all unanswered probes before it.
    func testAnAnswerResetsTheCount() throws {
        try self.connect(keepAlive: .init(interval: self.interval, maximumUnansweredProbes: 2))

        // Two probes go unanswered...
        self.channel.advanceTime(by: self.interval)
        let first = try self.clientOutbound()
        self.channel.advanceTime(by: self.interval)
        let second = try self.clientOutbound()
        // ...then both arrive and are answered just before the limit bites.
        try self.deliverToServer(first + second)

        for _ in 0..<2 {
            self.channel.advanceTime(by: self.interval)
            XCTAssertEqual(try self.clientOutbound().count, 1)
        }
        XCTAssertTrue(self.channel.client.isActive)
        self.channel.advanceTime(by: self.interval)
        XCTAssertFalse(self.channel.client.isActive)
    }

    /// Like OpenSSH, a probe is only sent after an interval in which nothing arrived.
    func testTrafficFromTheServerDefersProbes() throws {
        try self.connect(keepAlive: .init(interval: self.interval, maximumUnansweredProbes: 1))
        _ = try self.channel.createNewChannel()
        try self.channel.interactInMemory()
        let serverChild = try XCTUnwrap(self.channel.activeServerChannels.first)

        for _ in 0..<5 {
            self.channel.advanceTime(by: self.interval - .seconds(1))
            try serverChild.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(ByteBuffer(string: "x"))))
                .wait()
            try self.channel.interactInMemory()
            self.channel.advanceTime(by: .seconds(1))
            XCTAssertEqual(try self.clientOutbound().count, 0, "traffic arrived during the interval")
        }

        self.channel.advanceTime(by: self.interval)
        XCTAssertEqual(try self.clientOutbound().count, 1, "a quiet interval is probed")
        XCTAssertTrue(self.channel.client.isActive)
    }

    func testSendKeepAliveSucceedsOnTheServersAnswer() throws {
        try self.connect(keepAlive: nil)
        let handler = try XCTUnwrap(self.channel.clientSSHHandler)

        let answered = self.channel.client.eventLoop.makePromise(of: Void.self)
        handler.sendKeepAlive(promise: answered)
        var outcome: Result<Void, Error>?
        answered.futureResult.assumeIsolated().whenComplete { outcome = $0 }
        self.channel.run()
        XCTAssertNil(outcome, "no answer yet")

        try self.channel.interactInMemory()
        guard case .some(.success) = outcome else {
            return XCTFail("expected the answer, got \(String(describing: outcome))")
        }
    }

    func testSendKeepAliveFailsWhenTheConnectionCloses() throws {
        try self.connect(keepAlive: nil)
        let handler = try XCTUnwrap(self.channel.clientSSHHandler)

        let answered = self.channel.client.eventLoop.makePromise(of: Void.self)
        handler.sendKeepAlive(promise: answered)
        var outcome: Result<Void, Error>?
        answered.futureResult.assumeIsolated().whenComplete { outcome = $0 }
        self.channel.run()
        _ = try self.clientOutbound()

        try self.channel.client.close().wait()
        self.channel.run()
        guard case .some(.failure) = outcome else {
            return XCTFail("expected a failure, got \(String(describing: outcome))")
        }
    }

    // MARK: Review of 264a023

    /// The timer starts only after user authentication: a person taking minutes at a password
    /// or keyboard-interactive prompt is not timed out.
    func testSlowUserAuthenticationIsNotTimedOut() throws {
        let auth = SlowPasswordDelegate()
        var harness = TestHarness()
        harness.clientAuthDelegate = auth
        harness.clientKeepAlive = .init(interval: self.interval, maximumUnansweredProbes: 1)
        try self.channel.configureWithHarness(harness)
        try self.channel.client.pipeline.syncOperations.addHandler(self.clientErrors)
        try self.channel.activate()
        try self.channel.interactInMemory()
        XCTAssertNotNil(auth.pending, "authentication waits for the user")

        for _ in 0..<10 {
            self.channel.advanceTime(by: self.interval)
        }
        XCTAssertTrue(self.channel.client.isActive)
        XCTAssertTrue(self.clientErrors.errors.isEmpty, "\(self.clientErrors.errors)")

        auth.release()
        try self.channel.interactInMemory()
        self.channel.advanceTime(by: self.interval)
        XCTAssertEqual(try self.clientOutbound().count, 1, "the first probe one interval after authentication")
    }

    /// The wait restarts at the last packet received, not at the check that noticed it.
    func testTheProbeComesOneIntervalAfterTheLastPacket() throws {
        try self.connect(keepAlive: .init(interval: self.interval, maximumUnansweredProbes: 1))
        _ = try self.channel.createNewChannel()
        try self.channel.interactInMemory()
        let serverChild = try XCTUnwrap(self.channel.activeServerChannels.first)

        // Something arrives 1 s before the check; the probe is due one interval after it.
        self.channel.advanceTime(by: self.interval - .seconds(1))
        try serverChild.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(ByteBuffer(string: "x"))))
            .wait()
        try self.channel.interactInMemory()
        self.channel.advanceTime(by: self.interval - .seconds(1))
        XCTAssertEqual(try self.clientOutbound().count, 0)
        self.channel.advanceTime(by: .seconds(1))
        XCTAssertEqual(try self.clientOutbound().count, 1)
    }

    /// The timeout reaches the pipeline before the channel goes inactive, so an application can
    /// tell why it closed; afterwards the timer is gone.
    func testTheTimeoutErrorPrecedesTheCloseAndNothingFollows() throws {
        let order = ErrorBeforeInactive()
        try self.connect(keepAlive: .init(interval: self.interval, maximumUnansweredProbes: 1))
        try self.channel.client.pipeline.syncOperations.addHandler(order, position: .before(self.clientErrors))

        self.channel.advanceTime(by: self.interval)
        _ = try self.clientOutbound()
        self.channel.advanceTime(by: self.interval)
        XCTAssertEqual(order.events, ["error while open"])
        XCTAssertFalse(self.channel.client.isActive)

        for _ in 0..<5 {
            self.channel.advanceTime(by: self.interval)
        }
        XCTAssertEqual(order.events, ["error while open"])
        XCTAssertEqual(self.clientErrors.errors.count, 1)
    }

    /// A probe asked for during a rekey waits until the connection is active again. When the
    /// client's host key check for the rekey completes asynchronously, that moment is the client's
    /// NEWKEYS going out, and the probe must go with it, not wait for the server's next packet.
    func testAProbeQueuedDuringARekeyIsSentWhenTheRekeyCompletes() throws {
        let validation = HeldRekeyValidation()
        var harness = TestHarness()
        harness.clientServerAuthDelegate = validation
        try self.channel.configureWithHarness(harness)
        try self.channel.activate()
        try self.channel.interactInMemory()

        try self.channel.serverSSHHandler!._rekey()
        try self.channel.interactInMemory()
        let held = try XCTUnwrap(validation.held, "the rekey's host key check is pending")

        var outcome: Result<Void, Error>?
        let answered = self.channel.client.eventLoop.makePromise(of: Void.self)
        answered.futureResult.assumeIsolated().whenComplete { outcome = $0 }
        self.channel.clientSSHHandler!.sendKeepAlive(promise: answered)
        try self.channel.interactInMemory()
        XCTAssertNil(outcome)

        held.succeed(())
        self.channel.run()
        try self.channel.interactInMemory()
        guard case .some(.success) = outcome else {
            return XCTFail("the probe waited past the rekey: \(String(describing: outcome))")
        }
    }

    func testSendKeepAliveFailsWithoutAPipeline() throws {
        try self.connect(keepAlive: nil)
        // A handler that is not in a pipeline (never added, or already removed).
        let handler = NIOSSHHandler(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            ),
            allocator: ByteBufferAllocator(),
            inboundChildChannelInitializer: nil
        )

        var outcome: Result<Void, Error>?
        let answered = self.channel.client.eventLoop.makePromise(of: Void.self)
        answered.futureResult.assumeIsolated().whenComplete { outcome = $0 }
        handler.sendKeepAlive(promise: answered)
        guard case .some(.failure) = outcome else {
            return XCTFail("expected a failure, got \(String(describing: outcome))")
        }
    }
}
