package org.cloudburstmc.netty.warden;

import com.google.gson.*;
import com.sun.net.httpserver.*;
import java.net.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;

/** Standalone conformance provider: no Warden code, accounts, hostname rules or database. */
public final class IndependentProviderStub implements AutoCloseable {
    final HttpServer server;
    final String origin;
    final Map<String, JsonObject> challenges = new HashMap<>(), keys = new HashMap<>();
    JsonObject registration; volatile JsonObject lastHeartbeat;
    volatile int failHeartbeats;
    volatile long checkInMillis;
    volatile int controlPolls;
    final java.util.List<JsonObject> events = new java.util.concurrent.CopyOnWriteArrayList<>();
    long generation, sequence;
    volatile int registrations, heartbeats, acknowledgements;
    volatile boolean optionalClaim;
    volatile int claimActions;
    boolean draining;
    volatile JsonArray commands = new JsonArray();
    public IndependentProviderStub() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0); origin = "http://127.0.0.1:" + server.getAddress().getPort();
        server.createContext("/", this::handle); server.start();
    }
    private synchronized void handle(HttpExchange e) throws IOException {
        int status = 200; JsonObject response;
        try { response = dispatch(e); } catch (Failure f) { status = f.status; response = new JsonObject(); response.addProperty("code", f.getMessage()); }
        catch (Exception f) { status = 400; response = new JsonObject(); response.addProperty("code", "invalid_request"); }
        byte[] bytes = response.toString().getBytes(StandardCharsets.UTF_8); e.getResponseHeaders().add("content-type", "application/json"); e.sendResponseHeaders(status, bytes.length); try (OutputStream out = e.getResponseBody()) { out.write(bytes); }
    }
    private JsonObject dispatch(HttpExchange e) throws Exception {
        String path = e.getRequestURI().getPath(), raw = new String(e.getRequestBody().readNBytes(65537), StandardCharsets.UTF_8);
        if (raw.length() > 65536) throw new Failure(400, "payload_limit");
        JsonObject body = raw.isEmpty() ? new JsonObject() : JsonParser.parseString(raw).getAsJsonObject();
        if (path.equals("/.well-known/nethernet-provider")) {
            JsonObject d = new JsonObject(); d.addProperty("provider", origin); d.addProperty("controlOrigin", origin);
            d.add("protocols", strings(ProviderCrypto.PROTOCOL)); d.add("signatures", strings(ProviderCrypto.SIGNATURE)); d.add("modes", strings("new-service", "attach-instance")); d.add("profiles", strings("example-profile-v0"));
            JsonObject operations = new JsonObject(); for (String op : List.of("challenges", "complete", "recover", "activate", "heartbeat", "host-profile", "readiness", "control", "control/ack", "drain", "rotate", "retire", "ticket-keys", "ticket-keys/ack", "ticket-events", "events")) operations.addProperty(op, origin + "/example/" + op);
            if (optionalClaim) operations.addProperty("claim-action", origin + "/example/claim-action");
            d.add("operations", operations); JsonObject limits = new JsonObject(); limits.addProperty("heartbeatIntervalMs", 1000); if (checkInMillis > 0) limits.addProperty("checkInVersion", 1); limits.addProperty("maxControlPage", 100); limits.addProperty("leaseMs", 30000); limits.addProperty("maxBodyBytes", 65536); limits.addProperty("clockSkewMs", 60000); d.add("limits", limits);
            JsonObject policy = new JsonObject(); policy.addProperty("newServiceClaim", "none"); policy.addProperty("anonymousPow", true); policy.addProperty("attachmentPow", false); d.add("policy", policy); return d;
        }
        if (path.equals("/example/challenges") || path.equals("/example/recover")) {
            boolean recovery = path.endsWith("recover");
            if (recovery && (registration == null || !registration.get("registrationId").equals(body.get("registrationId")))) throw new Failure(403, "recovery_unavailable");
            JsonObject key = recovery ? keys.get(registration.get("keyId").getAsString()) : body.getAsJsonObject("publicKeyJwk");
            if (!recovery && !body.get("mode").getAsString().equals("new-service")) throw new Failure(403, "bootstrap_grant_required");
            JsonObject c = new JsonObject(); c.addProperty("protocol", ProviderCrypto.PROTOCOL); c.addProperty("signature", ProviderCrypto.SIGNATURE); c.addProperty("challengeId", UUID.randomUUID().toString()); c.addProperty("audience", origin); c.addProperty("nonce", UUID.randomUUID().toString()); c.addProperty("thumbprint", ProviderCrypto.thumbprint(key)); c.addProperty("expiresAt", System.currentTimeMillis() + 60000); c.addProperty("serverTime", System.currentTimeMillis());
            JsonObject context = new JsonObject(); for (String f : List.of("label", "grantId", "serviceId", "region", "pool", "registrationId")) context.addProperty(f, ""); context.addProperty("mode", recovery ? "recover" : "new-service"); context.addProperty("profile", "example-profile-v0"); c.add("context", context); c.addProperty("contextDigest", ProviderCrypto.contextDigest(context)); JsonObject pow = new JsonObject(); pow.addProperty("algorithm", "sha256-leading-zero-bits-v0"); pow.addProperty("difficulty", recovery ? 0 : 2); c.add("pow", pow);
            challenges.put(c.get("challengeId").getAsString(), c.deepCopy()); keys.put(c.get("challengeId").getAsString(), key); return c;
        }
        if (path.equals("/example/complete")) {
            String id = body.get("challengeId").getAsString(); JsonObject c = challenges.get(id);
            if (c == null) throw new Failure(409, "challenge_consumed");
            String proof = ProviderCrypto.proof(c, body.get("proofNonce").getAsString(), body.get("idempotencyKey").getAsString());
            if (!ProviderCrypto.verify(keys.get(id), body.get("signature").getAsString(), proof) || !ProviderCrypto.meetsDifficulty(ProviderCrypto.digest(proof), c.getAsJsonObject("pow").get("difficulty").getAsInt())) throw new Failure(401, "proof_invalid");
            challenges.remove(id);
            if (c.getAsJsonObject("context").get("mode").getAsString().equals("recover")) { JsonObject r = registration.deepCopy(); r.remove("ticketKey"); r.addProperty("leaseGeneration", generation); return r; }
            if (registration != null) throw new Failure(409, "already_registered"); registrations++;
            registration = new JsonObject(); registration.addProperty("protocol", ProviderCrypto.PROTOCOL); registration.addProperty("provider", origin); registration.addProperty("registrationId", id); registration.addProperty("instanceId", "example-machine-1"); registration.addProperty("serviceId", "example-service-1"); registration.addProperty("keyId", "example-key-1"); registration.addProperty("publicAddress", "https://play.example.invalid"); registration.addProperty("profile", "example-profile-v0"); registration.addProperty("leaseGeneration", 0); registration.addProperty("leaseDeadline", 0); registration.addProperty("heartbeatIntervalMs", 1000); JsonObject ready = new JsonObject(); ready.addProperty("routable", false); ready.add("reasons", new JsonArray()); registration.add("readiness", ready); JsonObject place = new JsonObject(); place.addProperty("region", ""); place.addProperty("pool", ""); registration.add("placement", place); registration.add("ticketKey", ticket()); keys.put("example-key-1", keys.get(id)); return registration.deepCopy();
        }
        if (path.equals("/example/heartbeat") && failHeartbeats-- > 0) throw new Failure(503, "fixture_transient");
        authenticate(e, raw);
        JsonObject ok = new JsonObject(); ok.addProperty("accepted", true);
        switch (path) {
            case "/example/activate" -> { generation++; sequence = 0; draining = false; ok.addProperty("leaseGeneration", generation); ok.addProperty("leaseDeadline", System.currentTimeMillis() + 30000); }
            case "/example/host-profile" -> ok.addProperty("revision", "example-profile-revision");
            case "/example/heartbeat" -> { if (draining) throw new Failure(403, "draining"); lastHeartbeat = body; heartbeats++;
                if (checkInMillis > 0 && body.has("checkInVersion")) {
                    long now = System.currentTimeMillis(); JsonObject schedule = new JsonObject();
                    schedule.addProperty("version", 1); schedule.addProperty("afterMillis", checkInMillis);
                    schedule.addProperty("nextCheckInAt", now + checkInMillis); schedule.addProperty("leaseExpiresAt", now + checkInMillis + 30000);
                    schedule.addProperty("minUpdateIntervalMillis", 1000); schedule.addProperty("controlPollAfterMillis", checkInMillis);
                    ok.add("checkIn", schedule); ok.addProperty("receivedAt", java.time.Instant.ofEpochMilli(now).toString());
                } }
            case "/example/control" -> { controlPolls++; ok.add("commands", commands.deepCopy()); ok.addProperty("cursor", "example-cursor"); ok.addProperty("serverTime", java.time.Instant.now().toString()); }
            case "/example/control/ack" -> { acknowledgements++; commands = new JsonArray(); }
            case "/example/readiness" -> { ok.addProperty("routable", heartbeats > 0 && !draining); if (optionalClaim) ok.addProperty("claimAvailable", true); }
            case "/example/claim-action" -> {
                if (!optionalClaim) throw new Failure(422, "unknown_operation");
                claimActions++; JsonObject action = new JsonObject(); action.addProperty("url", origin + "/optional-claim/" + claimActions);
                action.addProperty("expiresAt", System.currentTimeMillis() + 60000); action.addProperty("text", "Optional ownership claim"); ok.add("pendingAction", action);
            }
            case "/example/drain" -> draining = true;
            case "/example/ticket-keys" -> ok.add("ticketKey", ticket());
            case "/example/ticket-keys/ack" -> { }
            case "/example/ticket-events", "/example/events" -> { for (JsonElement event : body.getAsJsonArray("events")) events.add(event.getAsJsonObject()); }
            case "/example/rotate" -> {
                String old = e.getRequestHeaders().getFirst("warden-agent-key-id"), intent = e.getRequestHeaders().getFirst("idempotency-key"); JsonObject key = body.getAsJsonObject("publicKeyJwk");
                if (!ProviderCrypto.verify(key, body.get("proof").getAsString(), ProviderCrypto.array(ProviderCrypto.PROTOCOL, "rotate", origin, "example-machine-1", old, ProviderCrypto.thumbprint(key), generation, intent))) throw new Failure(401, "replacement_proof_invalid");
                String id = "example-key-" + UUID.randomUUID(); keys.put(id, key); registration.addProperty("keyId", id); ok.addProperty("keyId", id);
            }
            case "/example/retire" -> keys.remove(body.get("keyId").getAsString());
            default -> throw new Failure(422, "unknown_operation");
        }
        return ok;
    }
    private void authenticate(HttpExchange e, String raw) throws Failure {
        try {
            Headers h = e.getRequestHeaders(); String key = h.getFirst("warden-agent-key-id"), instance = h.getFirst("warden-agent-id"); long timestamp = Long.parseLong(h.getFirst("warden-agent-timestamp")), gen = Long.parseLong(h.getFirst("x-warden-generation")), seq = Long.parseLong(h.getFirst("x-warden-sequence"));
            if (!ProviderCrypto.SIGNATURE.equals(h.getFirst("warden-agent-signature-version")) || !"example-machine-1".equals(instance) || Math.abs(System.currentTimeMillis() - timestamp) > 60000 || gen != generation || seq <= sequence) throw new Failure(401, "auth_invalid");
            if (!ProviderCrypto.verify(keys.get(key), h.getFirst("warden-agent-signature"), ProviderCrypto.request(origin, e.getRequestMethod(), e.getRequestURI().toASCIIString(), timestamp, instance, key, h.getFirst("idempotency-key"), gen, seq, raw))) throw new Failure(401, "signature_invalid"); sequence = seq;
        } catch (RuntimeException f) { throw new Failure(401, "auth_invalid"); }
    }
    private static JsonArray strings(String... strings) { JsonArray a = new JsonArray(); for (String s : strings) a.add(s); return a; }
    private static JsonObject ticket() { JsonObject key = new JsonObject(); key.addProperty("keyId", "T001"); key.addProperty("secret", "independent-stub-only-secret"); return key; }
    private static final class Failure extends Exception { final int status; Failure(int status, String message) { super(message); this.status = status; } }
    @Override public void close() { server.stop(0); }
    public static void main(String[] args) throws Exception { var stub = new IndependentProviderStub(); System.out.println(stub.origin); Runtime.getRuntime().addShutdownHook(new Thread(stub::close)); new CountDownLatch(1).await(); }
}
