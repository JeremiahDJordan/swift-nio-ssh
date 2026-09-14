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

import Crypto
import NIOConcurrencyHelpers
import NIOCore
import NIOEmbedded
import XCTest

@testable import NIOSSH

final class ExplodingAuthDelegate: NIOSSHClientUserAuthenticationDelegate {
    enum Error: Swift.Error {
        case kaboom
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        XCTFail("Next Authentication Type must not be called")
        nextChallengePromise.fail(Error.kaboom)
    }
}

final class AcceptAllHostKeysDelegate: NIOSSHClientServerAuthenticationDelegate {
    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        validationCompletePromise.succeed(())
    }
}

final class SSHConnectionStateMachineTests: XCTestCase {
    private func assertSuccessfulConnection(
        client: inout SSHConnectionStateMachine,
        server: inout SSHConnectionStateMachine,
        allocator: ByteBufferAllocator,
        loop: EmbeddedEventLoop
    ) throws {
        let clientMessage: SSHMultiMessage? = client.start()
        let serverMessage: SSHMultiMessage? = server.start()

        try self.run(
            clientMessage: clientMessage,
            client: &client,
            serverMessage: serverMessage,
            server: &server,
            allocator: allocator,
            loop: loop
        )
    }

    private func run(
        clientMessage: SSHMultiMessage?,
        client: inout SSHConnectionStateMachine,
        serverMessage: SSHMultiMessage?,
        server: inout SSHConnectionStateMachine,
        allocator: ByteBufferAllocator,
        loop: EmbeddedEventLoop,
        dripFeed: Bool = false
    ) throws {
        let clientMessage = NIOLoopBoundBox(clientMessage, eventLoop: loop)
        let serverMessage = NIOLoopBoundBox(serverMessage, eventLoop: loop)
        var clientBuffer = allocator.buffer(capacity: 1024)
        var serverBuffer = allocator.buffer(capacity: 1024)
        let waitingForClientMessage = NIOLoopBoundBox(false, eventLoop: loop)
        let waitingForServerMessage = NIOLoopBoundBox(false, eventLoop: loop)

        while clientMessage.value != nil || serverMessage.value != nil {
            if let clientMessage = clientMessage.value {
                for message in clientMessage {
                    XCTAssertNoThrow(
                        try client.processOutboundMessage(
                            message,
                            buffer: &clientBuffer,
                            allocator: allocator,
                            loop: loop
                        )
                    )
                }
            }

            if let serverMessage = serverMessage.value {
                for message in serverMessage {
                    XCTAssertNoThrow(
                        try server.processOutboundMessage(
                            message,
                            buffer: &serverBuffer,
                            allocator: allocator,
                            loop: loop
                        )
                    )
                }
            }

            if clientBuffer.readableBytes > 0 {
                if dripFeed {
                    while var next = clientBuffer.readSlice(length: 1) {
                        server.bufferInboundData(&next)
                        if clientBuffer.readableBytes > 0 {
                            switch try assertNoThrowWithValue(
                                server.processInboundMessage(allocator: allocator, loop: loop)
                            ) {
                            case .some(.emitMessage(let message)):
                                serverMessage.value.append(message)
                            case .none:
                                ()
                            case .some(.noMessage):
                                ()
                            case .some(.possibleFutureMessage(let futureMessage)):
                                waitingForServerMessage.value = true

                                futureMessage.whenComplete { result in
                                    waitingForServerMessage.value = false

                                    switch result {
                                    case .failure(let err):
                                        XCTFail("Unexpected error in delayed message production: \(err)")
                                    case .success(let message):
                                        if let message = message {
                                            serverMessage.value.append(message)
                                        }
                                    }
                                }
                            case .some(.forwardToMultiplexer), .some(.globalRequest), .some(.globalRequestResponse),
                                .some(.disconnect):
                                fatalError("Currently unsupported")
                            case .some(.event):
                                ()
                            }
                        }
                    }
                } else {
                    server.bufferInboundData(&clientBuffer)
                }
                clientBuffer.clear()
            }

            if serverBuffer.readableBytes > 0 {
                if dripFeed {
                    while var next = serverBuffer.readSlice(length: 1) {
                        client.bufferInboundData(&next)
                        if serverBuffer.readableBytes > 0 {
                            switch try assertNoThrowWithValue(
                                client.processInboundMessage(allocator: allocator, loop: loop)
                            ) {
                            case .some(.emitMessage(let message)):
                                clientMessage.value.append(message)
                            case .none:
                                ()
                            case .some(.noMessage):
                                ()
                            case .some(.possibleFutureMessage(let futureMessage)):
                                waitingForClientMessage.value = true

                                futureMessage.whenComplete { result in
                                    waitingForClientMessage.value = false

                                    switch result {
                                    case .failure(let err):
                                        XCTFail("Unexpected error in delayed message production: \(err)")
                                    case .success(let message):
                                        if let message = message {
                                            clientMessage.value.append(message)
                                        }
                                    }
                                }
                            case .some(.forwardToMultiplexer), .some(.globalRequest), .some(.globalRequestResponse),
                                .some(.disconnect), .some(.event):
                                fatalError("Currently unsupported")
                            }
                        }
                    }
                } else {
                    client.bufferInboundData(&serverBuffer)
                }
                serverBuffer.clear()
            }

            clientMessage.value = nil
            serverMessage.value = nil

            clientLoop: while true {
                switch try assertNoThrowWithValue(client.processInboundMessage(allocator: allocator, loop: loop)) {
                case .some(.emitMessage(let message)):
                    clientMessage.value.append(message)
                case .none:
                    break clientLoop
                case .some(.noMessage):
                    ()
                case .some(.possibleFutureMessage(let futureMessage)):
                    waitingForClientMessage.value = true

                    futureMessage.whenComplete { result in
                        waitingForClientMessage.value = false

                        switch result {
                        case .failure(let err):
                            XCTFail("Unexpected error in delayed message production: \(err)")
                        case .success(let message):
                            if let message = message {
                                clientMessage.value.append(message)
                            }
                        }
                    }
                case .some(.forwardToMultiplexer), .some(.globalRequest), .some(.globalRequestResponse),
                    .some(.disconnect):
                    fatalError("Currently unsupported")
                case .some(.event):
                    ()
                }
            }

            serverLoop: while true {
                switch try assertNoThrowWithValue(server.processInboundMessage(allocator: allocator, loop: loop)) {
                case .some(.emitMessage(let message)):
                    serverMessage.value.append(message)
                case .none:
                    break serverLoop
                case .some(.noMessage):
                    ()
                case .some(.possibleFutureMessage(let futureMessage)):
                    precondition(
                        !waitingForServerMessage.value,
                        "Unexpected emit message while another message is being processed"
                    )
                    waitingForServerMessage.value = true

                    futureMessage.whenComplete { result in
                        waitingForServerMessage.value = false

                        switch result {
                        case .failure(let err):
                            XCTFail("Unexpected error in delayed message production: \(err)")
                        case .success(let message):
                            if let message = message {
                                serverMessage.value.append(message)
                            }
                        }
                    }
                case .some(.forwardToMultiplexer), .some(.globalRequest), .some(.globalRequestResponse),
                    .some(.disconnect), .some(.event):
                    fatalError("Currently unsupported")
                }
            }

            // Bottom of the loop, run the event loop to fire any futures we might need.
            loop.run()
        }

        XCTAssertFalse(waitingForClientMessage.value, "Loop exited while waiting for a client message")
        XCTAssertFalse(waitingForServerMessage.value, "Loop exited while waiting for a server message")
    }

    private func assertForwardsToMultiplexer(
        _ message: SSHMessage,
        sender: inout SSHConnectionStateMachine,
        receiver: inout SSHConnectionStateMachine,
        allocator: ByteBufferAllocator,
        loop: EmbeddedEventLoop
    ) throws {
        var tempBuffer = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(
            try sender.processOutboundMessage(message, buffer: &tempBuffer, allocator: allocator, loop: loop)
        )
        XCTAssert(tempBuffer.readableBytes > 0)

        receiver.bufferInboundData(&tempBuffer)
        let result = try assertNoThrowWithValue(receiver.processInboundMessage(allocator: allocator, loop: loop))

        switch result {
        case .some(.forwardToMultiplexer(let forwardedMessage)):
            XCTAssertEqual(forwardedMessage, message)
        case .some(.emitMessage), .some(.possibleFutureMessage), .some(.noMessage), .some(.globalRequest),
            .some(.globalRequestResponse), .some(.disconnect), .some(.event), .none:
            XCTFail("Unexpected result: \(String(describing: result))")
        }
    }

    private func assertSendingIsProtocolError(
        _ message: SSHMessage,
        sender: inout SSHConnectionStateMachine,
        allocator: ByteBufferAllocator,
        loop: EmbeddedEventLoop
    ) throws {
        var tempBuffer = allocator.buffer(capacity: 1024)
        XCTAssertThrowsError(
            try sender.processOutboundMessage(message, buffer: &tempBuffer, allocator: allocator, loop: loop)
        ) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
        XCTAssertEqual(tempBuffer.readableBytes, 0)
    }

    private func assertDisconnects(
        _ message: SSHMessage,
        sender: inout SSHConnectionStateMachine,
        receiver: inout SSHConnectionStateMachine,
        allocator: ByteBufferAllocator,
        loop: EmbeddedEventLoop
    ) throws {
        var tempBuffer = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(
            try sender.processOutboundMessage(message, buffer: &tempBuffer, allocator: allocator, loop: loop)
        )
        XCTAssert(tempBuffer.readableBytes > 0)

        receiver.bufferInboundData(&tempBuffer)
        let result = try assertNoThrowWithValue(receiver.processInboundMessage(allocator: allocator, loop: loop))

        switch result {
        case .some(.disconnect):
            // Good
            break
        case .some(.forwardToMultiplexer), .some(.emitMessage), .some(.possibleFutureMessage), .some(.noMessage),
            .some(.globalRequest), .some(.globalRequestResponse), .some(.event), .none:
            XCTFail("Unexpected result: \(String(describing: result))")
        }
    }

    private func assertTriggersGlobalRequest(
        _ message: SSHMessage,
        sender: inout SSHConnectionStateMachine,
        receiver: inout SSHConnectionStateMachine,
        allocator: ByteBufferAllocator,
        loop: EmbeddedEventLoop
    ) throws {
        var tempBuffer = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(
            try sender.processOutboundMessage(message, buffer: &tempBuffer, allocator: allocator, loop: loop)
        )
        XCTAssert(tempBuffer.readableBytes > 0)

        receiver.bufferInboundData(&tempBuffer)
        let result = try assertNoThrowWithValue(receiver.processInboundMessage(allocator: allocator, loop: loop))

        switch result {
        case .some(.globalRequest(let receivedMessage)):
            // Good
            XCTAssertEqual(.globalRequest(receivedMessage), message)
        case .some(.forwardToMultiplexer), .some(.emitMessage), .some(.possibleFutureMessage), .some(.noMessage),
            .some(.globalRequestResponse), .some(.disconnect), .some(.event), .none:
            XCTFail("Unexpected result: \(String(describing: result))")
        }
    }

    private func assertTriggersGlobalRequestResponse(
        _ message: SSHMessage,
        sender: inout SSHConnectionStateMachine,
        receiver: inout SSHConnectionStateMachine,
        allocator: ByteBufferAllocator,
        loop: EmbeddedEventLoop
    ) throws -> SSHConnectionStateMachine.StateMachineInboundProcessResult.GlobalRequestResponse? {
        var tempBuffer = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(
            try sender.processOutboundMessage(message, buffer: &tempBuffer, allocator: allocator, loop: loop)
        )
        XCTAssert(tempBuffer.readableBytes > 0)

        receiver.bufferInboundData(&tempBuffer)
        let result = try assertNoThrowWithValue(receiver.processInboundMessage(allocator: allocator, loop: loop))

        switch result {
        case .some(.globalRequestResponse(let response)):
            // Good
            return response
        case .some(.forwardToMultiplexer), .some(.emitMessage), .some(.possibleFutureMessage), .some(.noMessage),
            .some(.globalRequest), .some(.disconnect), .some(.event), .none:
            XCTFail("Unexpected result: \(String(describing: result))")
            return nil
        }
    }

    func assertTriggersNothing(
        _ message: SSHMessage,
        sender: inout SSHConnectionStateMachine,
        receiver: inout SSHConnectionStateMachine,
        allocator: ByteBufferAllocator,
        loop: EmbeddedEventLoop
    ) throws {
        var tempBuffer = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(
            try sender.processOutboundMessage(message, buffer: &tempBuffer, allocator: allocator, loop: loop)
        )
        XCTAssert(tempBuffer.readableBytes > 0)

        receiver.bufferInboundData(&tempBuffer)
        let result = try assertNoThrowWithValue(receiver.processInboundMessage(allocator: allocator, loop: loop))

        switch result {
        case .some(.noMessage):
            // Good
            break
        case .some(.forwardToMultiplexer), .some(.emitMessage), .some(.possibleFutureMessage), .some(.globalRequest),
            .some(.globalRequestResponse), .some(.disconnect), .some(.event), .none:
            XCTFail("Unexpected result: \(String(describing: result))")
        }
    }

    private func assertUnimplementedCausesError(
        sequenceNumber: UInt32,
        sender: inout SSHConnectionStateMachine,
        receiver: inout SSHConnectionStateMachine,
        allocator: ByteBufferAllocator,
        loop: EmbeddedEventLoop
    ) throws {
        var tempBuffer = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(
            try sender.processOutboundMessage(
                .unimplemented(.init(sequenceNumber: sequenceNumber)),
                buffer: &tempBuffer,
                allocator: allocator,
                loop: loop
            )
        )
        XCTAssert(tempBuffer.readableBytes > 0)

        receiver.bufferInboundData(&tempBuffer)
        XCTAssertThrowsError(try receiver.processInboundMessage(allocator: allocator, loop: loop)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .remotePeerDoesNotSupportMessage)
        }
    }

    func testBasicConnectionDance() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            )
        )
        var server = SSHConnectionStateMachine(
            role: .server(
                .init(
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1)
                )
            )
        )

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)

        XCTAssertTrue(client.isActive)
        XCTAssertTrue(server.isActive)
    }

    // Messages that are usable once child channels are allowed.
    let channelMessages: [SSHMessage] = [
        .channelOpen(.init(type: .session, senderChannel: 0, initialWindowSize: 0, maximumPacketSize: 12)),
        .channelOpenConfirmation(
            .init(recipientChannel: 0, senderChannel: 0, initialWindowSize: 0, maximumPacketSize: 12)
        ),
        .channelOpenFailure(.init(recipientChannel: 0, reasonCode: 0, description: "foo", language: "bar")),
        .channelEOF(.init(recipientChannel: 0)),
        .channelClose(.init(recipientChannel: 0)),
        .channelWindowAdjust(.init(recipientChannel: 0, bytesToAdd: 1)),
        .channelData(.init(recipientChannel: 0, data: ByteBufferAllocator().buffer(capacity: 0))),
        .channelExtendedData(
            .init(recipientChannel: 0, dataTypeCode: .stderr, data: ByteBufferAllocator().buffer(capacity: 0))
        ),
        .channelRequest(.init(recipientChannel: 0, type: .exec("uname"), wantReply: false)),
        .channelSuccess(.init(recipientChannel: 0)),
        .channelFailure(.init(recipientChannel: 0)),
    ]

    func testReceivingChannelMessagesGetForwardedOnceConnectionMade() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            )
        )
        var server = SSHConnectionStateMachine(
            role: .server(
                .init(
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1)
                )
            )
        )
        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)

        for message in self.channelMessages {
            XCTAssertNoThrow(
                try self.assertForwardsToMultiplexer(
                    message,
                    sender: &client,
                    receiver: &server,
                    allocator: allocator,
                    loop: loop
                )
            )
        }
    }

    func testDisconnectMessageCausesImmediateConnectionClose() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            )
        )
        var server = SSHConnectionStateMachine(
            role: .server(
                .init(
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1)
                )
            )
        )

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)

        XCTAssertFalse(client.disconnected)
        XCTAssertFalse(server.disconnected)

        // Have the client send and the server receive a disconnection message.
        try self.assertDisconnects(
            .disconnect(.init(reason: 0, description: "", tag: "")),
            sender: &client,
            receiver: &server,
            allocator: allocator,
            loop: loop
        )

        XCTAssertTrue(client.disconnected)
        XCTAssertTrue(server.disconnected)

        // Further messages are not sent.
        for message in self.channelMessages {
            XCTAssertNoThrow(
                try self.assertSendingIsProtocolError(message, sender: &client, allocator: allocator, loop: loop)
            )
        }
    }

    func testDisconnectedReturnsNil() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            )
        )
        var server = SSHConnectionStateMachine(
            role: .server(
                .init(
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1)
                )
            )
        )

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)
        try self.assertDisconnects(
            .disconnect(.init(reason: 0, description: "", tag: "")),
            sender: &client,
            receiver: &server,
            allocator: allocator,
            loop: loop
        )

        // Ok, in disconnected state. At this time, any attempt to process the connection should return nil.
        var junkBuffer = allocator.buffer(capacity: 1024)
        junkBuffer.writeBytes(0...255)
        server.bufferInboundData(&junkBuffer)

        XCTAssertNoThrow(try XCTAssertNil(server.processInboundMessage(allocator: allocator, loop: loop)))
    }

    func testGlobalRequestCanBeSent() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            )
        )
        var server = SSHConnectionStateMachine(
            role: .server(
                .init(
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1)
                )
            )
        )

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)

        var message = SSHMessage.GlobalRequestMessage(wantReply: true, type: .tcpipForward("foo", 66))
        try self.assertTriggersGlobalRequest(
            .globalRequest(message),
            sender: &client,
            receiver: &server,
            allocator: allocator,
            loop: loop
        )

        message = SSHMessage.GlobalRequestMessage(wantReply: false, type: .cancelTcpipForward("foo", 66))
        try self.assertTriggersGlobalRequest(
            .globalRequest(message),
            sender: &client,
            receiver: &server,
            allocator: allocator,
            loop: loop
        )
    }

    func testGlobalRequestResponsesTriggerResponse() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            )
        )
        var server = SSHConnectionStateMachine(
            role: .server(
                .init(
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1)
                )
            )
        )

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)

        // Deliver a request success message.
        var response = try self.assertTriggersGlobalRequestResponse(
            .requestSuccess(.init(.tcpForwarding(.init(boundPort: 6)), allocator: allocator)),
            sender: &server,
            receiver: &client,
            allocator: allocator,
            loop: loop
        )
        guard case .some(.success(let firstResponse)) = response,
            GlobalRequest.TCPForwardingResponse(firstResponse).boundPort == 6
        else {
            XCTFail("Unexpected response: \(String(describing: response))")
            return
        }

        // Now without a port.
        response = try self.assertTriggersGlobalRequestResponse(
            .requestSuccess(.init(.tcpForwarding(.init(boundPort: nil)), allocator: allocator)),
            sender: &server,
            receiver: &client,
            allocator: allocator,
            loop: loop
        )
        guard case .some(.success(let secondResponse)) = response,
            GlobalRequest.TCPForwardingResponse(secondResponse).boundPort == nil
        else {
            XCTFail("Unexpected response: \(String(describing: response))")
            return
        }

        // Now a failure.
        response = try self.assertTriggersGlobalRequestResponse(
            .requestFailure,
            sender: &server,
            receiver: &client,
            allocator: allocator,
            loop: loop
        )
        guard case .some(.failure) = response else {
            XCTFail("Unexpected response: \(String(describing: response))")
            return
        }
    }

    func testIgnoreDebugAndIgnoreMessages() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            )
        )
        var server = SSHConnectionStateMachine(
            role: .server(
                .init(
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1)
                )
            )
        )

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)

        try self.assertTriggersNothing(
            .ignore(.init(data: allocator.buffer(capacity: 1024))),
            sender: &client,
            receiver: &server,
            allocator: allocator,
            loop: loop
        )
        try self.assertTriggersNothing(
            .debug(.init(alwaysDisplay: true, message: "foo", language: "bar")),
            sender: &client,
            receiver: &server,
            allocator: allocator,
            loop: loop
        )
    }

    /// Strict key exchange (CVE-2023-48795, "Terrapin"): once both peers propose the
    /// marker, nothing but the key exchange messages themselves may appear between
    /// KEXINIT and NEWKEYS. SSH_MSG_IGNORE is the packet the attack injects to shift the
    /// sequence numbers, and unknown message types reach the same case (this fork maps
    /// them to SSH_MSG_IGNORE, see docs/FORK.md #224), so both are refused here.
    func testStrictKeyExchangeRefusesIgnoreDuringKeyExchange() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            )
        )
        var server = SSHConnectionStateMachine(
            role: .server(
                .init(
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1)
                )
            )
        )

        // Version exchange, then each side emits its KEXINIT: both are now mid-key-exchange
        // and, because both roles propose their strict-KEX marker, both are in strict mode.
        var clientBuffer = allocator.buffer(capacity: 1024)
        var serverBuffer = allocator.buffer(capacity: 1024)
        for message in client.start()! {
            try client.processOutboundMessage(message, buffer: &clientBuffer, allocator: allocator, loop: loop)
        }
        for message in server.start()! {
            try server.processOutboundMessage(message, buffer: &serverBuffer, allocator: allocator, loop: loop)
        }
        client.bufferInboundData(&serverBuffer)
        server.bufferInboundData(&clientBuffer)

        // Each side reads the peer's version and emits its own KEXINIT.
        var clientKexInitBytes = allocator.buffer(capacity: 1024)
        guard case .some(.emitMessage(let clientKexInit)) = try client.processInboundMessage(allocator: allocator, loop: loop)
        else { return XCTFail("client did not emit its KEXINIT") }
        for message in clientKexInit {
            try client.processOutboundMessage(message, buffer: &clientKexInitBytes, allocator: allocator, loop: loop)
        }

        var serverKexInitBytes = allocator.buffer(capacity: 1024)
        guard case .some(.emitMessage(let serverKexInit)) = try server.processInboundMessage(allocator: allocator, loop: loop)
        else { return XCTFail("server did not emit its KEXINIT") }
        for message in serverKexInit {
            try server.processOutboundMessage(message, buffer: &serverKexInitBytes, allocator: allocator, loop: loop)
        }

        // Deliver both KEXINITs: the strict-KEX markers are now negotiated on both sides.
        client.bufferInboundData(&serverKexInitBytes)
        server.bufferInboundData(&clientKexInitBytes)
        XCTAssertNotNil(try client.processInboundMessage(allocator: allocator, loop: loop))
        XCTAssertNotNil(try server.processInboundMessage(allocator: allocator, loop: loop))

        // The server now sends SSH_MSG_IGNORE mid-key-exchange. The client must refuse it.
        var injected = allocator.buffer(capacity: 32)
        try server.processOutboundMessage(
            .ignore(.init(data: allocator.buffer(capacity: 0))),
            buffer: &injected,
            allocator: allocator,
            loop: loop
        )
        XCTAssertGreaterThan(injected.readableBytes, 0)
        client.bufferInboundData(&injected)
        XCTAssertThrowsError(try client.processInboundMessage(allocator: allocator, loop: loop)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
            XCTAssertTrue(
                "\(error)".contains("strict key exchange"),
                "the violation must name strict key exchange: \(error)"
            )
        }
    }

    /// A `SSH_MSG_DEBUG` is attacker-chosen text sent before authentication, and the
    /// violation string reaches the application's user-facing error. Name the message
    /// type, never its contents.
    func testStrictKeyExchangeViolationDoesNotQuoteThePeersText() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            )
        )
        var server = SSHConnectionStateMachine(
            role: .server(
                .init(
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1)
                )
            )
        )
        try self.exchangeVersionsAndKexInits(
            client: &client,
            server: &server,
            allocator: allocator,
            loop: loop
        )

        let secret = "CANARY-e6b1f0-\u{1b}[2J\nTrusted"
        var injected = allocator.buffer(capacity: 128)
        try server.processOutboundMessage(
            .debug(.init(alwaysDisplay: true, message: secret, language: "en")),
            buffer: &injected,
            allocator: allocator,
            loop: loop
        )
        client.bufferInboundData(&injected)
        XCTAssertThrowsError(try client.processInboundMessage(allocator: allocator, loop: loop)) { error in
            let rendered = "\(error)"
            XCTAssertTrue(rendered.contains("strict key exchange"), rendered)
            XCTAssertTrue(rendered.contains("SSH_MSG_DEBUG"), rendered)
            XCTAssertFalse(rendered.contains("CANARY"), "the peer's text must not reach the error: \(rendered)")
        }
    }

    /// OpenSSH PROTOCOL, "strict KEX", clause (a): with the mode negotiated the
    /// KEXINIT must be the connection's first packet. Anything ahead of it has already
    /// been counted by the parser, which is the sequence-number shift the mitigation
    /// exists to remove.
    func testStrictKeyExchangeRequiresKexInitToBeTheFirstPacket() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            )
        )
        var server = SSHConnectionStateMachine(
            role: .server(
                .init(
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1)
                )
            )
        )

        var clientBuffer = allocator.buffer(capacity: 1024)
        var serverBuffer = allocator.buffer(capacity: 1024)
        for message in client.start()! {
            try client.processOutboundMessage(message, buffer: &clientBuffer, allocator: allocator, loop: loop)
        }
        for message in server.start()! {
            try server.processOutboundMessage(message, buffer: &serverBuffer, allocator: allocator, loop: loop)
        }
        client.bufferInboundData(&serverBuffer)
        server.bufferInboundData(&clientBuffer)

        var clientKexInitBytes = allocator.buffer(capacity: 1024)
        guard case .some(.emitMessage(let clientKexInit)) = try client.processInboundMessage(allocator: allocator, loop: loop)
        else { return XCTFail("client did not emit its KEXINIT") }
        for message in clientKexInit {
            try client.processOutboundMessage(message, buffer: &clientKexInitBytes, allocator: allocator, loop: loop)
        }
        server.bufferInboundData(&clientKexInitBytes)
        guard case .some(.emitMessage(let serverKexInit)) = try server.processInboundMessage(allocator: allocator, loop: loop)
        else { return XCTFail("server did not emit its KEXINIT") }

        // The server slips an SSH_MSG_IGNORE in ahead of its KEXINIT. The mode is not
        // on yet when that packet is parsed, so it is tolerated — but it consumed
        // sequence number zero, and the KEXINIT behind it must therefore be refused.
        var serverBytes = allocator.buffer(capacity: 1024)
        try server.processOutboundMessage(
            .ignore(.init(data: allocator.buffer(capacity: 0))),
            buffer: &serverBytes,
            allocator: allocator,
            loop: loop
        )
        for message in serverKexInit {
            try server.processOutboundMessage(message, buffer: &serverBytes, allocator: allocator, loop: loop)
        }
        client.bufferInboundData(&serverBytes)

        guard case .some(.noMessage) = try client.processInboundMessage(allocator: allocator, loop: loop) else {
            return XCTFail("the SSH_MSG_IGNORE ahead of the KEXINIT should be tolerated: the mode is not on yet")
        }
        XCTAssertThrowsError(try client.processInboundMessage(allocator: allocator, loop: loop)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
            XCTAssertTrue(
                "\(error)".contains("KEXINIT was not the first packet"),
                "unexpected violation: \(error)"
            )
        }
    }

    /// The proof that the two strict-KEX sequence-number resets stay in step.
    ///
    /// The bundled schemes cannot show it: AES-GCM keeps its own nonce and ignores the
    /// `sequenceNumber` parameter, so a client whose receive counter never reset would
    /// still decrypt everything. `SequenceNumberBoundTransportProtection` binds the
    /// number into the MAC, the way every encrypt-then-MAC scheme does (which is what
    /// makes a desync fatal against a modern CTR+ETM server), so a whole connection
    /// driven over it — key exchange, NEWKEYS on both sides, user auth, then traffic in
    /// both directions — only completes if all four resets agree.
    func testSequenceNumbersStayInStepUnderStrictKeyExchange() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        let schemes: [NIOSSHTransportProtection.Type] = [SequenceNumberBoundTransportProtection.self]
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            ),
            protectionSchemes: schemes
        )
        var server = SSHConnectionStateMachine(
            role: .server(
                .init(
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1)
                )
            ),
            protectionSchemes: schemes
        )
        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)
        try self.assertDataFlowsBothWays(client: &client, server: &server, allocator: allocator, loop: loop)
    }

    /// …and at *every* NEWKEYS, not only the first. OpenSSH resets the sequence
    /// numbers on each rekey under strict key exchange, so
    /// `SentKexInitWhenActiveState` / `ReceivedKexInitWhenActiveState` inherit
    /// `previous.parser.strictKeyExchange`; nothing else in this suite rekeys with
    /// the mode engaged, and over a scheme that binds the sequence number into the
    /// MAC, dropping that inheritance is a MAC failure on the first packet after
    /// the new keys.
    func testSequenceNumbersStayInStepAcrossARekeyUnderStrictKeyExchange() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        let schemes: [NIOSSHTransportProtection.Type] = [SequenceNumberBoundTransportProtection.self]
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            ),
            protectionSchemes: schemes
        )
        var server = SSHConnectionStateMachine(
            role: .server(
                .init(
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1)
                )
            ),
            protectionSchemes: schemes
        )
        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)
        try self.assertDataFlowsBothWays(client: &client, server: &server, allocator: allocator, loop: loop)

        // The client asks to rekey; pump both sides to quiescence.

        var buffer = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(try client.beginRekeying(buffer: &buffer, allocator: allocator, loop: loop))
        server.bufferInboundData(&buffer)
        guard case .some(.emitMessage(let response)) =
            try server.processInboundMessage(allocator: allocator, loop: loop)
        else { return XCTFail("the server did not answer the rekey") }
        try self.run(
            clientMessage: nil,
            client: &client,
            serverMessage: response,
            server: &server,
            allocator: allocator,
            loop: loop
        )

        // Both sides are on the second set of keys now, and both reset at the second
        // NEWKEYS: the first packet each sends afterwards is sequence number 0.
        // Two peers that both *fail* to reset stay in step with each other, so the
        // numbers themselves are the only observable — nothing decrypts wrongly.
        SequenceNumberBoundTransportProtection.encryptedSequenceNumbers.withLockedValue { $0 = [] }
        try self.assertDataFlowsBothWays(client: &client, server: &server, allocator: allocator, loop: loop)
        let afterRekey = SequenceNumberBoundTransportProtection.encryptedSequenceNumbers.withLockedValue { $0 }
        XCTAssertEqual(
            Array(afterRekey.prefix(2)),
            [0, 0],
            "the sequence numbers did not reset at the rekey's NEWKEYS: \(afterRekey.prefix(4))"
        )
    }

    /// The path every peer without the mitigation takes — Dropbear, libssh, an
    /// appliance. Both roles propose the marker, so nothing else in this suite reaches
    /// it: no sequence-number reset at NEWKEYS, and the connection has to work anyway.
    func testConnectionWithAPeerThatDoesNotImplementStrictKeyExchange() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        let schemes: [NIOSSHTransportProtection.Type] = [SequenceNumberBoundTransportProtection.self]
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            ),
            protectionSchemes: schemes
        )
        var server = SSHConnectionStateMachine(
            role: .server(
                .init(
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1)
                )
            ),
            protectionSchemes: schemes,
            implementsStrictKeyExchange: false
        )
        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)
        try self.assertDataFlowsBothWays(client: &client, server: &server, allocator: allocator, loop: loop)
    }

    /// …and the same peer's `SSH_MSG_IGNORE` during key exchange must still be
    /// tolerated: the message discipline is only in force when the mode is negotiated,
    /// and RFC 4253 allows the message otherwise.
    func testAMarkerlessPeerMayStillSendIgnoreDuringKeyExchange() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            )
        )
        var server = SSHConnectionStateMachine(
            role: .server(
                .init(
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1)
                )
            ),
            implementsStrictKeyExchange: false
        )
        try self.exchangeVersionsAndKexInits(
            client: &client,
            server: &server,
            allocator: allocator,
            loop: loop
        )

        var injected = allocator.buffer(capacity: 32)
        try server.processOutboundMessage(
            .ignore(.init(data: allocator.buffer(capacity: 0))),
            buffer: &injected,
            allocator: allocator,
            loop: loop
        )
        client.bufferInboundData(&injected)
        guard case .some(.noMessage) = try client.processInboundMessage(allocator: allocator, loop: loop) else {
            return XCTFail("a peer without strict key exchange may send SSH_MSG_IGNORE during key exchange")
        }
    }

    /// Version exchange plus both KEXINITs, leaving each side mid-key-exchange.
    private func exchangeVersionsAndKexInits(
        client: inout SSHConnectionStateMachine,
        server: inout SSHConnectionStateMachine,
        allocator: ByteBufferAllocator,
        loop: EmbeddedEventLoop
    ) throws {
        var clientBuffer = allocator.buffer(capacity: 1024)
        var serverBuffer = allocator.buffer(capacity: 1024)
        for message in client.start()! {
            try client.processOutboundMessage(message, buffer: &clientBuffer, allocator: allocator, loop: loop)
        }
        for message in server.start()! {
            try server.processOutboundMessage(message, buffer: &serverBuffer, allocator: allocator, loop: loop)
        }
        client.bufferInboundData(&serverBuffer)
        server.bufferInboundData(&clientBuffer)

        var clientKexInitBytes = allocator.buffer(capacity: 1024)
        guard case .some(.emitMessage(let clientKexInit)) = try client.processInboundMessage(allocator: allocator, loop: loop)
        else { return XCTFail("client did not emit its KEXINIT") }
        for message in clientKexInit {
            try client.processOutboundMessage(message, buffer: &clientKexInitBytes, allocator: allocator, loop: loop)
        }

        var serverKexInitBytes = allocator.buffer(capacity: 1024)
        guard case .some(.emitMessage(let serverKexInit)) = try server.processInboundMessage(allocator: allocator, loop: loop)
        else { return XCTFail("server did not emit its KEXINIT") }
        for message in serverKexInit {
            try server.processOutboundMessage(message, buffer: &serverKexInitBytes, allocator: allocator, loop: loop)
        }

        client.bufferInboundData(&serverKexInitBytes)
        server.bufferInboundData(&clientKexInitBytes)
        XCTAssertNotNil(try client.processInboundMessage(allocator: allocator, loop: loop))
        XCTAssertNotNil(try server.processInboundMessage(allocator: allocator, loop: loop))
    }

    /// One encrypted `SSH_MSG_CHANNEL_DATA` each way over an established connection.
    private func assertDataFlowsBothWays(
        client: inout SSHConnectionStateMachine,
        server: inout SSHConnectionStateMachine,
        allocator: ByteBufferAllocator,
        loop: EmbeddedEventLoop
    ) throws {
        func send(
            _ message: SSHMessage,
            from sender: inout SSHConnectionStateMachine,
            to receiver: inout SSHConnectionStateMachine
        ) throws {
            var buffer = allocator.buffer(capacity: 1024)
            try sender.processOutboundMessage(message, buffer: &buffer, allocator: allocator, loop: loop)
            receiver.bufferInboundData(&buffer)
            guard case .some(.forwardToMultiplexer(let received)) =
                try receiver.processInboundMessage(allocator: allocator, loop: loop)
            else { return XCTFail("message did not arrive") }
            XCTAssertEqual(received, message)
        }

        // Several in each direction: a desync that only bites after the first packet
        // (a counter that resumes from the wrong base) has to show up too.
        for i in 0..<4 {
            let toServer = SSHMessage.channelData(
                .init(recipientChannel: 1, data: ByteBuffer(repeating: UInt8(i), count: 5))
            )
            try send(toServer, from: &client, to: &server)
            let toClient = SSHMessage.channelData(
                .init(recipientChannel: 2, data: ByteBuffer(repeating: UInt8(i + 64), count: 7))
            )
            try send(toClient, from: &server, to: &client)
        }
    }

    func testUnimplementedGivesARichError() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            )
        )
        var server = SSHConnectionStateMachine(
            role: .server(
                .init(
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1)
                )
            )
        )

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)
        try self.assertUnimplementedCausesError(
            sequenceNumber: 0,
            sender: &client,
            receiver: &server,
            allocator: allocator,
            loop: loop
        )
    }

    func testWeTolerateMessagesAfterSendingKexInit() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            )
        )
        var server = SSHConnectionStateMachine(
            role: .server(
                .init(
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1)
                )
            )
        )

        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)

        // Ok, the server is going to try to rekey.
        var buffer = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(try server.beginRekeying(buffer: &buffer, allocator: allocator, loop: loop))

        // We're not passing this to the client though. Now we'll send all the channel messages through: the server should tolerate them
        // all.
        for message in self.channelMessages {
            XCTAssertNoThrow(
                try self.assertForwardsToMultiplexer(
                    message,
                    sender: &client,
                    receiver: &server,
                    allocator: allocator,
                    loop: loop
                )
            )
        }
    }

    func testWeTolerateMultipleStarts() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            )
        )

        let message = client.start()
        guard case message = Optional.some(SSHMultiMessage(SSHMessage.version(Constants.version))) else {
            XCTFail("Unexpected message")
            return
        }

        var buffer = allocator.buffer(capacity: 42)
        XCTAssertNoThrow(
            try client.processOutboundMessage(
                SSHMessage.version(Constants.version),
                buffer: &buffer,
                allocator: allocator,
                loop: loop
            )
        )

        XCTAssertNil(client.start())
    }

    func testClientToleratesLinesBeforeVersion() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            )
        )

        let message = client.start()
        guard case message = Optional.some(SSHMultiMessage(SSHMessage.version(Constants.version))) else {
            XCTFail("Unexpected message")
            return
        }

        var buffer = allocator.buffer(capacity: 42)
        XCTAssertNoThrow(
            try client.processOutboundMessage(
                SSHMessage.version(Constants.version),
                buffer: &buffer,
                allocator: allocator,
                loop: loop
            )
        )

        var version = ByteBuffer(string: "xxxx\nyyy\nSSH-2.0-OpenSSH_8.1\r\n")
        client.bufferInboundData(&version)

        XCTAssertNoThrow(try client.processInboundMessage(allocator: allocator, loop: loop))
    }

    func testServerRejectsLinesBeforeVersion() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var server = SSHConnectionStateMachine(
            role: .server(
                .init(
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 1)
                )
            )
        )

        let message = server.start()
        guard case message = Optional.some(SSHMultiMessage(SSHMessage.version(Constants.version))) else {
            XCTFail("Unexpected message")
            return
        }

        var buffer = allocator.buffer(capacity: 42)
        XCTAssertNoThrow(
            try server.processOutboundMessage(
                SSHMessage.version(Constants.version),
                buffer: &buffer,
                allocator: allocator,
                loop: loop
            )
        )

        var version = ByteBuffer(string: "xxxx\nyyy\nSSH-2.0-OpenSSH_8.1\r\n")
        server.bufferInboundData(&version)

        XCTAssertThrowsError(try server.processInboundMessage(allocator: allocator, loop: loop)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testClintVersionNotFound() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            )
        )

        let message = client.start()
        guard case message = Optional.some(SSHMultiMessage(SSHMessage.version(Constants.version))) else {
            XCTFail("Unexpected message")
            return
        }

        var buffer = allocator.buffer(capacity: 42)
        XCTAssertNoThrow(
            try client.processOutboundMessage(
                SSHMessage.version(Constants.version),
                buffer: &buffer,
                allocator: allocator,
                loop: loop
            )
        )

        var version = ByteBuffer(string: "SSH-\r\n")
        client.bufferInboundData(&version)

        XCTAssertThrowsError(try client.processInboundMessage(allocator: allocator, loop: loop)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
        }
    }

    func testVersionNotSupported() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            )
        )

        let message = client.start()
        guard case message = Optional.some(SSHMultiMessage(SSHMessage.version(Constants.version))) else {
            XCTFail("Unexpected message")
            return
        }

        var buffer = allocator.buffer(capacity: 42)
        XCTAssertNoThrow(
            try client.processOutboundMessage(
                SSHMessage.version(Constants.version),
                buffer: &buffer,
                allocator: allocator,
                loop: loop
            )
        )

        var version = ByteBuffer(string: "SSH-1.0-OpenSSH_8.1\r\n")
        client.bufferInboundData(&version)

        XCTAssertThrowsError(try client.processInboundMessage(allocator: allocator, loop: loop)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .unsupportedVersion)
        }
    }

    @available(iOS 13.2, macOS 10.15, watchOS 6.1, tvOS 13.2, *)
    func testFirstBlockDecodedOnce() throws {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()
        let schemes: [NIOSSHTransportProtection.Type] = [TestTransportProtection.self]
        var client = SSHConnectionStateMachine(
            role: .client(
                .init(userAuthDelegate: InfinitePasswordDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            ),
            protectionSchemes: schemes
        )
        var server = SSHConnectionStateMachine(
            role: .server(
                .init(
                    hostKeys: [NIOSSHPrivateKey(ed25519Key: .init())],
                    userAuthDelegate: DenyThenAcceptDelegate(messagesToDeny: 0)
                )
            ),
            protectionSchemes: schemes
        )
        try assertSuccessfulConnection(client: &client, server: &server, allocator: allocator, loop: loop)

        let message = SSHMessage.channelData(.init(recipientChannel: 1, data: ByteBuffer(repeating: 17, count: 5)))

        var tempBuffer = allocator.buffer(capacity: 1024)
        XCTAssertNoThrow(
            try client.processOutboundMessage(message, buffer: &tempBuffer, allocator: allocator, loop: loop)
        )
        XCTAssert(tempBuffer.readableBytes > 0)

        while var next = tempBuffer.readSlice(length: 1) {
            server.bufferInboundData(&next)
            if tempBuffer.readableBytes > 0 {
                XCTAssertNil(try server.processInboundMessage(allocator: allocator, loop: loop))
            }
        }

        var result = try server.processInboundMessage(allocator: allocator, loop: loop)
        switch result {
        case .some(.forwardToMultiplexer(let forwardedMessage)):
            XCTAssertEqual(forwardedMessage, message)
        case .some(.emitMessage), .some(.possibleFutureMessage), .some(.noMessage), .some(.globalRequest),
            .some(.globalRequestResponse), .some(.disconnect), .some(.event), .none:
            XCTFail("Unexpected result: \(String(describing: result))")
        }

        tempBuffer.clear()
        XCTAssertNoThrow(try client.beginRekeying(buffer: &tempBuffer, allocator: allocator, loop: loop))

        while var next = tempBuffer.readSlice(length: 1) {
            server.bufferInboundData(&next)
            if tempBuffer.readableBytes > 0 {
                XCTAssertNil(try server.processInboundMessage(allocator: allocator, loop: loop))
            }
        }

        result = try server.processInboundMessage(allocator: allocator, loop: loop)
        switch result {
        case .some(.emitMessage(let message)):
            XCTAssertNoThrow(
                try self.run(
                    clientMessage: nil,
                    client: &client,
                    serverMessage: message,
                    server: &server,
                    allocator: allocator,
                    loop: loop,
                    dripFeed: true
                )
            )
        case .some(.forwardToMultiplexer), .some(.possibleFutureMessage), .some(.noMessage), .some(.globalRequest),
            .some(.globalRequestResponse), .some(.disconnect), .some(.event), .none:
            XCTFail("Unexpected result: \(String(describing: result))")
        }
    }
}

extension Optional where Wrapped == SSHMultiMessage {
    mutating func append(_ message: SSHMultiMessage) {
        if let original = self {
            precondition(original.count == 1)
            precondition(message.count == 1)
            self = .some(SSHMultiMessage(original.first!, message.first!))
        } else {
            self = .some(message)
        }
    }
}
