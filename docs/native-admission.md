# Experimental native Warden admission

The WDA2 host owns one fixed UDP endpoint and validates a confidential token from
STUN USERNAME plus MESSAGE-INTEGRITY before reserving replay/session state or
calling native peer creation. There is no offer/control input to the endpoint.
The signalling-side token carries the client ICE password, SHA-256 fingerprint,
SCTP parameters, identity hash and network ID. Host/profile audience and client
ufrag are authenticated. A minimal remote SDP is reconstructed only after
validation. Full ICE learns the incoming peer-reflexive tuple; ICE-lite is not
required by the demonstrated native path.

The conventional NetherNet server and RakNet implementation are unchanged. This
branch adds `NativeAdmissionServerChannel` and a bounded child transport. The
provider SPI is the shared WS2 boundary. `NativeProviderTransport` implements
background key installation, profile publication, drain/close and bounded events.
It rejects per-join control commands; registration is supplied by WS2. This is **not**
stock-client admission or gameplay evidence.

## Reproduce

Linux x86_64, JDK 8/17/21, OpenSSL development headers/CLI, CMake, C++ compiler,
Git and Gradle wrapper access are required. The Gradle daemon uses JDK 21.

```sh
./scripts/bootstrap-native-admission.sh
./gradlew :transport-nethernet:test :warden-signalling:test :warden-signalling:nativeAdmissionTest
```

The bootstrap script builds the exact owned JNI SHA in `gradle.properties`,
including its pinned owned libdatachannel/libjuice submodules. It preserves
existing JNI classifier packaging under the distinct `dev.ziax.warden` group.
The development classifier links Linux system OpenSSL; it is not a portable
release artifact. An existing clean checkout can be selected with
`WARDEN_NATIVE_BINDING_CHECKOUT`. Build output goes under ignored `build/`.

Canonical fixture copies record the Warden source revision and SHA-256 hashes in
`warden-signalling/src/test/resources/warden/provenance.json`. Tests decode the
TypeScript-generated encrypted token and independently verify the RFC5769 raw
STUN fixture. Fixture keys are public test material.

## Demonstrated checks

- Real JNI/Netty echo across ReliableDataChannel (20,013-byte segmented message)
  and UnreliableDataChannel (7-byte message); nonzero ByteBuf reader index.
- No per-join control input or prestaged client state; zero initial host peers.
- Tampered, expired, wrong-host, wrong-client-ufrag and bad-STUN-integrity packets
  produce zero native creation attempts, agents, promoted tuples and reservations.
- One lazy peer, first-request STUN response without a client retry, conflicting-tuple replay rejection,
  closed replay tombstones, concurrent duplicate reservation and cleanup.
- Fixed high UDP port 49190, duplicate listener refusal and socket reuse after
  close. Existing RakNet responds to unconnected pings on UDP 49191 while the
  native session is active. This is coexistence evidence, not RakNet gameplay.
- Bounded fragment assembly and partial cleanup; bounded unflushed Netty writes,
  refused oversized unreliable writes, failed promises and exact buffer release.

The primitive JNI probe additionally establishes 167-, 178- and 256-character
ufrags and rejects a wrong token-bound fingerprint at DTLS. See the owned JNI
repository's `native-test/README.md` for that distinct gate.

## Limits and lifecycle

Defaults: 1,024 live reservations, 1,024 pending creations, 8,192 total replay
claims, 15-second handshake deadline, 8 background key epochs. No live/tombstone
eviction to admit new traffic: capacity exhaustion refuses admission. Creation
failure is terminal until token expiry. A periodic sweep retires closed claims.
Same-tuple consent and retransmissions keep working after token expiry; another
tuple never acquires a used token. A fresh profile incarnation on restart is a
required provider contract implemented by `NativeProviderTransport`. Its published
candidate uses the explicit bound interface, fixed port and pre-provisioned PEM
identity. Wildcard binds are refused until an advertised-address contract exists.

Java receive queue: 128 frames of at most 10,000 bytes. Reliable assembly: at most
262,144 bytes. Java outbound hard bound: 1 MiB including pending write overhead;
native send buffer: at most 512 KiB per data channel, checked before a whole
application message is submitted. Backpressure keeps Netty ownership until send
or rejects the write. Overflow closes the child; callback data is copied before
native storage expires. A bounded periodic pump performs native creation and
Netty delivery, never the raw mux callback.

The first authenticated STUN request is retained with its reservation (at most
2048 bytes per pending admission). After peer configuration it is transferred
once to the native mux replay queue, which holds at most 1,024 requests. The mux
thread re-runs the admission guard and ordinary ICE processing, preserving the
original source tuple and transaction ID. Expiry before creation, cancellation,
creation failure and close release the retained packet; listener removal clears
native queued packets. No client retry is needed to obtain the first response.
The native single-datagram regression sends exactly one nominated Binding request
and requires a matching success response from the bound endpoint. Its printed
latency is a local measurement, not stock-client or gameplay evidence. Mux
processed-packet and gate retransmission counters include the internal replay.
Each queue has a maximum 2 MiB of packet payload at these defaults, plus metadata
and temporary handoff copies. Pending-limit rejections emit an aggregate warning
on the owner event loop at most once every five seconds, containing the count at
rejection, configured limit, and rejected requests since the last warning. Raw
ingress never calls a logger or logs client/token material.

Reliable traffic is ordered/reliable; unreliable traffic is unordered with zero
retransmissions. Unreliable application messages must fit a single 9,999-byte
payload: countdown-only framing cannot identify interleaved/lost fragments on an
unordered stream. Outbound oversize and received nonzero fragment headers are
refused. Stock-client compatibility of this explicit restriction remains to be
measured; it must not be represented as proven gameplay support.

Only validated token identity metadata is placed in `AdmissionPrincipal.KEY` on
the accepted child. DTLS must verify the corresponding token-bound fingerprint.
This does not itself prove an authenticated Minecraft game join. Events are
bounded to 256 entries with an explicit dropped-event counter. No token, ICE
password, SDP, private key or player credentials are logged.

## Demonstrated native cleanup constraint and remedy

[Initial CI run](https://github.com/teamziax/NetworkCompatible/actions/runs/33828480051)
failed the immediate zero-agent assertion on endpoint reuse. The old native delete
API schedules transport teardown and can return while its ICE agent still exists.
The pinned dependency now includes `test/admission/teardown.cpp`, which stalls the
teardown worker to reproduce that behavior deterministically. The new bounded
per-peer completion API reports timeout while the agent remains, then succeeds
only after the queued transport teardown releases it. The original zero-agent
assertion remains unchanged.

Native children use `closeAndAwait` from their Netty owner thread before completing
close/freeing native capacity. Callback-thread calls are rejected. A five-second
teardown timeout is a terminal endpoint failure, never permission to admit more
peers while teardown is unresolved. Endpoint termination propagates close errors.
The old asynchronous close API remains available for existing direct consumers.

The cleanup remedy passes [CI run 33829800445](https://github.com/teamziax/NetworkCompatible/actions/runs/33829800445).
The provider boundary test also verifies zero peer creation from background
profile/key setup, key rotation, rejection of join-admission control, and a fresh
incarnation when the same UDP endpoint restarts.

`NativeAdmissionWriteTest.nettyClosureCannotHideNativeTeardownFailure` reproduces
a second cleanup pitfall: Netty's `closeFuture` succeeds even when `doClose`
throws. Capacity now follows a separate native termination result. Failed teardown
retains the native capacity count, drains admission and fails the endpoint; it
cannot turn into apparent successful cleanup through Netty's close notification.

Worker CI run 33830909678 additionally retained an ICE agent through a transport
reference outside the teardown task. The native pinned regression now holds that
reference explicitly. Completion follows actual destruction of all transports,
not just release of the teardown task references, with zero-agent reuse retained.
