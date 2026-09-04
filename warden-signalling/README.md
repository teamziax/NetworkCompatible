# Provider registration and Warden client

Java 21 module beside `transport-nethernet`. No native dependency or Warden account
API is required by the client. The same `ProviderClient` registers with Warden or
the independent HTTP stub using discovery at the configured URL.

## Build and reproduce

```sh
./gradlew :warden-signalling:test :warden-signalling:jar
./gradlew :warden-signalling:providerStub
# In the Warden checkout, with its local Worker running:
node scripts/provider-java-bench.mjs --network /absolute/path/to/NetworkCompatible
```

The last command proves anonymous PoW/possession, Warden claim/activation, two
key-bound EU fleet attachments, status aggregation/fixed override, drain and
persistent restart. It uses disposable private directories, a fake transport and
loopback only. It does not prove native admission or gameplay. The standalone
stub deliberately uses `/example/*` operations and neutral service/instance IDs.

The JSON schema and known-answer/control fixtures under `src/*/resources` come
from `teamziax/warden-signalling` registration v0. Their byte equality is checked
by the cross-repository workflow. Intentional fixture private keys are labelled
conformance-only. Production credentials must never use them.

## Embedding

1. Construct `ProviderStateStore` on a server-owned directory. It creates POSIX
   0700/0600 state with an exclusive process lock, fsync and atomic replacement.
2. Fleet automation calls `ProviderIdentity.initialize(store, origin)` before
   enrollment, exports **only its public JWK**, then obtains a one-use grant from
   a controller delegated to the target service, region and pool. Pass the grant
   via a private file/configuration secret. Anonymous startup omits it.
3. Supply `ProviderTransport`, a complete `ServerStatus` supplier, independent
   operational `Health` supplier and redacted diagnostic sink to `ProviderClient`.
4. `start()` discovers, registers/recovers, fences a new activation generation,
   persists and installs ticket keys, publishes the actual profile and starts
   heartbeat/control. Follow any returned pending action once for a new service.
   Existing-fleet attachments and persistent restarts require no human claim.
5. Update all seven fields with `setServerStatus` or the supplier. Invoke
   `requestStatusRefresh()` on changes; bursts coalesce to the advertised cadence.
   Failed suppliers omit the snapshot so old status expires honestly.
6. `rotateMachineKey()` and `rotateTicketKey()` are independent. `drain()` stops
   new assignment while the transport may finish sessions. Await `stop()` when
   an orderly shutdown completion is needed; `close()` starts it asynchronously.

HTTP/signing/state work uses one dedicated executor per provider instance, never a
Netty event loop or one poller per player. Redirects are disabled; operation URLs
must remain on the configured HTTPS origin (explicit loopback HTTP is permitted).
Bodies, pages, retries, heartbeat rate and event queues are bounded. A revoked or
fenced client fails closed rather than creating another service automatically.

## Native interface

`org.cloudburstmc.netty.warden.ProviderTransport` is the agreed WS2/WS3 boundary.
`hostProfile()` returns the existing full JSON profile, including any optional
`statelessAdmission` incarnation supplied by native code. Native code owns real
bound candidates, DTLS fingerprints and token validation. This module defines no
WDA2 encoding and requires no per-join command for stateless admission.

`installTicketKeys` accepts `(keyId, secret, notBefore, retireAfter)` snapshots;
completion promises that the snapshot is usable. Active epochs have an unbounded
retirement time until acknowledgement of a replacement returns an absolute
bounded deadline. Old issued tickets never gain extra lifetime. Native code must
apply timestamps and erase retired material.

Control commands are validated before native handoff. `PENDING` holds the page;
`APPLIED`/`REJECTED` must mean durable or replay-safe terminal handling, **not** a
volatile queued admission. Only redacted ticket/decision markers persist for
pending admissions. A replacement process records `ticket.failed` and discards
those old admissions before acknowledging. SDP/passwords never enter that journal.
Unknown/invalid commands hold the cursor; later valid lifecycle commands still run in page order. Ticket
lifecycle events and separate `game_joined` events use existing wire formats.

This slice supplies a fake transport. WS3 supplies `dev.kastle.warden.admission`
and the actual native implementation. Initial verified platform is Linux x86_64,
Java 21; private-state permission handling currently requires POSIX support.

## Lineage and artifacts

Owned fork: `teamziax/NetworkCompatible`, parent `rtm516/NetworkCompatible`, common
base `feature/http-signaling` at `8d1c989ee6fb5eb7a28a9130573d30634f39cba4`.
The existing `ziaxzulu/Network` Cloudburst lineage is a separate repository.
WS2 uses `codex/registration-provider`; WS3 uses `codex/native-admission`.
`codex/warden-integration` records the shared base until reviewed integration.

CI archives `0.1.0-registration-<full commit SHA>` module artifacts with test
reports. No Maven publication, upstream merge or production deployment occurs.
Geyser's composite build resolves both modules from this checkout; use its pinned
`registration-network.properties` commit when assembling the reviewed artifacts.
