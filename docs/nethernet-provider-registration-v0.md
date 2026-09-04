# NetherNet provider registration v0

Status: experimental. Protocol: `nethernet-provider-registration-v0`.
Machine signature: `provider-es384-v0`.

This is an open, provider-neutral registration protocol for NetherNet signalling
services. It defines how a fresh server creates a signalling service or joins an
existing one, how anonymous proof of work and provider-issued credentials are
negotiated, and how machine identity is bound to placement. It does not
standardise provider accounts, billing, token issuance, DNS, or the selected
post-registration admission profile.

The machine-readable schema is
[`warden-signalling/src/main/resources/provider-registration-v0.schema.json`](../warden-signalling/src/main/resources/provider-registration-v0.schema.json).
The independent-provider tests and shared known-answer fixture in this module are
the portable conformance boundary. Warden is one implementation, not a dependency.

## Deployment model

Registration combines one mode with one advertised authorization scheme:

| Use case | Mode | Authorization | Result |
| --- | --- | --- | --- |
| Standalone server, no credential | `new-service` | `anonymous-proof-of-work` | New public service and machine identity |
| Existing provider customer | `new-service` | `bearer-token` | Account-owned service with no PoW |
| Autoscaled proxy replica | `attach-instance` | `bearer-token` | Machine in an existing service/pool with no PoW |
| One-machine controller handoff | `attach-instance` | `bootstrap-grant` | Attachment using a short-lived key-bound grant |
| Server host's own infrastructure | Either | Any advertised scheme | Registration stays at the configured host origin |

Provider policy decides what a token represents. It may map to an account that
can create services, or to a fixed service, region, pool, and tag set. That mapping
is deliberately outside the protocol.

## Discovery and trust

The client requests `GET /.well-known/nethernet-provider` on an
operator-configured HTTPS origin. Loopback HTTP may be enabled for development.
The response declares provider/control origins, protocols, signatures, modes,
profiles, operations, authorization, policy, and limits. For example:

```json
{
  "authorization": {
    "header": "Authorization",
    "schemes": [
      { "scheme": "anonymous-proof-of-work", "modes": ["new-service"] },
      { "scheme": "bearer-token", "modes": ["new-service", "attach-instance"] },
      { "scheme": "bootstrap-grant", "modes": ["attach-instance"] }
    ]
  }
}
```

Provider and control origins must equal the configured canonical origin. Every
credential-bearing operation must use exactly that origin. Clients disable
redirects and reject unsupported protocols, signatures, modes, profiles, schemes,
or required capabilities before sending credentials.

Bearer credentials use `Authorization: Bearer <token>` and are sent only to the
discovered challenge operation. They must never appear in request JSON, challenge
responses, proof payloads, durable machine state, or logs.

## Challenge request

First create and durably store a fresh P-384 machine key. A fleet request is:

```json
{
  "protocol": "nethernet-provider-registration-v0",
  "mode": "attach-instance",
  "profile": "provider-supported-profile-v1",
  "publicKeyJwk": { "kty": "EC", "crv": "P-384", "x": "...", "y": "..." },
  "label": "proxy-7",
  "authorization": { "scheme": "bearer-token" },
  "placement": {
    "region": "EU",
    "pool": "proxy",
    "tags": { "location": "london", "role": "game-proxy" }
  }
}
```

`new-service` cannot name a service or instance. `attach-instance` requires an
explicit placement and provider-resolved authority for the existing service. A
`bootstrap-grant` request also carries `bootstrapGrant` in JSON; the grant should
be short-lived and bound to the machine public-key thumbprint.

For first-v0 compatibility, omitting `authorization` implies `bootstrap-grant`
when `bootstrapGrant` is present, otherwise `anonymous-proof-of-work`. New clients
should send the selection explicitly.

Placement contains `region`, `pool`, and at most 16 provider-defined tags. Tag
keys match `[A-Za-z0-9_.-]{1,32}`. Values are trimmed, non-empty strings of at most
64 characters. Tags are sorted by key for canonicalization. Providers authorize
the exact placement; labels do not grant authority.

## Proof of work and possession

The provider stores and returns a challenge containing the machine thumbprint,
provider audience, expiry, immutable context, context digest, PoW algorithm and
difficulty. Credential-backed schemes normally use difficulty zero. An authorized
challenge includes the selected scheme and an opaque reference, never the token.

Public JWKs are EC P-384 with canonical 48-byte unpadded base64url `x` and `y`.
A private `d` member is forbidden. The RFC 7638 SHA-256 thumbprint hashes UTF-8
JSON with exactly `crv`, `kty`, `x`, and `y` in that order.

Canonical arrays use UTF-8 JSON with no whitespace or Unicode normalization,
integer epoch milliseconds, and empty strings for absent context strings. The base
context digest hashes:

```text
[mode, profile, label, grantId, serviceId, region, pool, registrationId]
```

When tags are non-empty, append `tagsDigest`: unpadded base64url SHA-256 of the
JSON array of sorted `[key,value]` pairs. Omitting this suffix for empty tags
preserves the original v0 bytes.

The completion proof and ES384 signature cover:

```text
[protocol, "complete", audience, challengeId, nonce, thumbprint,
 contextDigest, expiresAt, proofNonce, idempotencyKey]
```

ES384 signatures are 96-byte P1363 `r || s`, unpadded base64url; DER is rejected.
PoW counts leading zero bits of SHA-256 over the same proof bytes. Completion sends
`protocol`, `challengeId`, `proofNonce`, `idempotencyKey`, and `signature`.

The provider revalidates token or grant authority at atomic completion. A token
revoked after challenge creation fails closed. Challenge/grant consumption and all
created resources commit together. Completion is single-use and must not replay
one-time secrets.

## Result and lifecycle

Completion returns provider, registration, service, instance, and key IDs; the
profile; public address; immutable placement; lease timing; and readiness. It may
return one-time ticket material needed by the profile. Anonymous creation may
return an optional provider-account claim action. Token-owned creation should not
require a second claim.

Persist the private key before requesting a challenge, the challenge before
completion, and returned IDs/key material before activation. On restart, use the
discovered recovery operation and prove possession of the same key. Do not register
a new machine merely because a process restarted.

Providers expose signed activation, readiness, heartbeat, drain, recovery, and
credential rotation operations for the advertised profile. Graceful termination
drains first; a crash leaves rotation when its lease expires. These lifecycle
operations use the machine credential, never the registration token.

The current Java client implements the Warden-compatible signed operational shape
after the neutral registration exchange. A provider may advertise another profile
only when the client also implements it.

## Operator recipes

For Kubernetes fleets, inject one provider token from a Secret, select
`attach-instance` plus `bearer-token`, and set a fixed region, pool, and tag set.
Give each logical replica its own persistent state directory. A StatefulSet keeps
ordinal identity/storage across restart. Scaling up creates independently keyed
instances without PoW; scaling down drains. UDP candidate reachability remains a
separate deployment task.

For a Minecraft host, set the provider URL/profile, mount a per-customer token as
a secret file, select `new-service`, and persist the state directory. Customer
servers then register with the host instead of Warden. If the host advertises
anonymous PoW, omit the token and select `anonymous-proof-of-work`.

## Conformance resources

- Schema: `warden-signalling/src/main/resources/provider-registration-v0.schema.json`
- Fixture: `warden-signalling/src/test/resources/provider-registration-v0.fixtures.json`
- Independent provider: `IndependentProviderStub`
- Client suite: `ProviderClientTest`

The fixture covers P-384 thumbprints, tags, context digests, completion proof
bytes, P1363 signatures, body digests, and exact encoded paths. The independent
stub has no Warden account, database, hostname, or server code and demonstrates
that registration interoperability is not tied to Warden.
