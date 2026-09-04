package org.cloudburstmc.netty.warden;

import com.google.gson.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.net.URI;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

class ProviderClientTest {
    @Test void usesProviderNeutralBearerAuthorizationWithoutPowOrPersistingTheToken(@TempDir Path path) throws Exception {
        try (IndependentProviderStub stub = new IndependentProviderStub()) {
            var config = new ProviderClient.Configuration(URI.create(stub.origin), "example-profile-v0", "Hosted customer",
                ProviderClient.NEW_SERVICE, ProviderClient.BEARER_TOKEN, "independent-provider-token", null, "EU", "customers", Map.of("plan", "premium"));
            ProviderClient client = new ProviderClient(config, new ProviderStateStore(path), new FakeTransport(), () -> null,
                () -> new ProviderClient.Health(true, 10, 0, "nethernet", "fixture"), message -> {});
            try {
                JsonObject registration = client.start().get(20, TimeUnit.SECONDS);
                assertEquals("example-machine-1", registration.get("instanceId").getAsString());
                assertEquals("Bearer independent-provider-token", stub.challengeAuthorization);
                assertEquals(0, stub.challengeDifficulty);
                assertFalse(java.nio.file.Files.readString(path.resolve("provider-state.json")).contains("independent-provider-token"));
                assertFalse(config.toString().contains("independent-provider-token"));
            } finally { client.stop().toCompletableFuture().get(10, TimeUnit.SECONDS); }
        }
    }

    @Test void refreshesAnExpiredOptionalClaimWithoutBlockingReadiness(@TempDir Path path) throws Exception {
        try (IndependentProviderStub stub = new IndependentProviderStub()) {
            stub.optionalClaim = true;
            var config = new ProviderClient.Configuration(URI.create(stub.origin), "example-profile-v0", "Example", null, null, null);
            java.util.function.Supplier<ProviderClient> create = () -> {
                try { return new ProviderClient(config, new ProviderStateStore(path), new FakeTransport(), () -> null,
                    () -> new ProviderClient.Health(true, 10, 0, "nethernet", "fixture"), message -> {}); }
                catch (java.io.IOException e) { throw new java.io.UncheckedIOException(e); }
            };
            ProviderClient first = create.get();
            try {
                assertTrue(first.start().get(20, TimeUnit.SECONDS).has("pendingAction"));
                assertTrue(first.readiness().get(10, TimeUnit.SECONDS).get("routable").getAsBoolean());
            } finally { first.stop().toCompletableFuture().get(10, TimeUnit.SECONDS); }
            try (ProviderStateStore store = new ProviderStateStore(path)) {
                JsonObject state = store.read(); state.getAsJsonObject("registration").getAsJsonObject("pendingAction").addProperty("expiresAt", 0); store.write(state);
            }
            ProviderClient resumed = create.get();
            try {
                JsonObject registration = resumed.start().get(20, TimeUnit.SECONDS);
                assertEquals("example-machine-1", registration.get("instanceId").getAsString());
                assertTrue(registration.getAsJsonObject("pendingAction").get("url").getAsString().endsWith("/2"));
                assertEquals(1, stub.registrations); assertEquals(2, stub.claimActions);
                assertTrue(resumed.readiness().get(10, TimeUnit.SECONDS).get("routable").getAsBoolean());
            } finally { resumed.stop().toCompletableFuture().get(10, TimeUnit.SECONDS); }
        }
    }
    @Test void followsProviderScheduleWithoutIdlePollingAndWakesForPlayers(@TempDir Path path) throws Exception {
        try (IndependentProviderStub stub = new IndependentProviderStub()) {
            stub.checkInMillis = 900000;
            AtomicInteger players = new AtomicInteger(0); FakeTransport transport = new FakeTransport(); transport.stateless = true;
            ProviderClient client = new ProviderClient(new ProviderClient.Configuration(URI.create(stub.origin), "example-profile-v0", "Scheduled", null, null, null),
                new ProviderStateStore(path), transport, () -> new ServerStatus("Scheduled", 1234, "fixture", "world", players.get(), 40, 0),
                () -> new ProviderClient.Health(true, 40, players.get() / 40.0, "nethernet", "fixture"), message -> {});
            try {
                client.start().get(20, TimeUnit.SECONDS);
                eventually(() -> stub.controlPolls == 1);
                Thread.sleep(2200);
                assertEquals(1, stub.heartbeats); assertEquals(1, stub.controlPolls);
                for (int i = 0; i < 100; i++) client.requestStatusRefresh();
                Thread.sleep(1200); assertEquals(1, stub.heartbeats, "Unchanged local refreshes must not send requests");
                stub.checkInMillis = 1000; players.set(1); client.requestStatusRefresh();
                eventually(() -> stub.lastHeartbeat.getAsJsonObject("serverStatus").get("players").getAsInt() == 1);
                int busyBefore = stub.heartbeats;
                eventually(() -> stub.heartbeats > busyBefore && stub.controlPolls > 1);
                stub.checkInMillis = 3600000; players.set(0); client.requestStatusRefresh();
                eventually(() -> stub.lastHeartbeat.getAsJsonObject("serverStatus").get("players").getAsInt() == 0);
                Thread.sleep(2200); int before = stub.heartbeats; int polls = stub.controlPolls;
                Thread.sleep(2200); assertEquals(before, stub.heartbeats); assertEquals(polls, stub.controlPolls);
            } finally { client.stop().toCompletableFuture().get(10, TimeUnit.SECONDS); }
            assertTrue(stub.draining, "Orderly shutdown still reports drain while the timer is asleep");
            int beforeRestart = stub.heartbeats;
            FakeTransport replacement = new FakeTransport(); replacement.stateless = true;
            stub.checkInMillis = 900000;
            ProviderClient resumed = new ProviderClient(new ProviderClient.Configuration(URI.create(stub.origin), "example-profile-v0", "Scheduled", null, null, null),
                new ProviderStateStore(path), replacement, () -> new ServerStatus("Restarted", 1234, "fixture", "world", 0, 40, 0),
                () -> new ProviderClient.Health(true, 40, 0, "nethernet", "fixture"), message -> {});
            try {
                resumed.start().get(20, TimeUnit.SECONDS);
                assertEquals(2, stub.generation);
                assertEquals(beforeRestart + 1, stub.heartbeats, "Startup must publish immediately despite the previous one-hour schedule");
                assertEquals("Restarted", stub.lastHeartbeat.getAsJsonObject("serverStatus").get("name").getAsString());
            } finally { resumed.stop().toCompletableFuture().get(10, TimeUnit.SECONDS); }

        }
    }
    static final class FakeTransport implements ProviderTransport {
        final CompletableFuture<Void> closed = new CompletableFuture<>();
        volatile int installed, applied, admissions, drains;
        boolean stateless;
        volatile ApplyResult result = ApplyResult.APPLIED;
        public CompletionStage<JsonObject> hostProfile() { JsonObject p = new JsonObject(); p.addProperty("credentialKeyId", "T001"); p.addProperty("dtlsFingerprint", "fixture-native-profile"); if (stateless) p.add("statelessAdmission", new JsonObject()); return CompletableFuture.completedFuture(p); }
        public CompletionStage<Void> installTicketKeys(List<TicketKey> keys) { installed = keys.size(); return CompletableFuture.completedFuture(null); }
        public CompletionStage<ApplyResult> applyControl(JsonObject c) {
            applied++; String kind = c.get("kind").getAsString();
            if (kind.equals("join-admission")) admissions++;
            if (kind.equals("drain")) drains++;
            return CompletableFuture.completedFuture(kind.equals("join-admission") ? result : ApplyResult.APPLIED);
        }
        public List<JsonObject> pollEvents() { return List.of(); }
        public CompletionStage<Void> drain() { return CompletableFuture.completedFuture(null); }
        public CompletionStage<Void> close() { closed.complete(null); return closed; }
    }
    @Test void portableRegistrationRefreshRotationAndRestart(@TempDir Path path) throws Exception {
        try (IndependentProviderStub stub = new IndependentProviderStub()) {
            AtomicInteger players = new AtomicInteger(2); FakeTransport host = new FakeTransport();
            var config = new ProviderClient.Configuration(URI.create(stub.origin), "example-profile-v0", "Example", null, null, null);
            ProviderClient client = new ProviderClient(config, new ProviderStateStore(path), host, () -> new ServerStatus("Example", 1234, "preview-fixture", "", players.get(), 40, 0), () -> new ProviderClient.Health(true, 100, 0.1, "nethernet", "fixture"), message -> {});
            JsonObject registration = client.start().get(20, TimeUnit.SECONDS);
            assertEquals("example-machine-1", registration.get("instanceId").getAsString()); assertEquals(1, stub.registrations); assertEquals(1, host.installed);
            assertEquals(100, stub.lastHeartbeat.get("capacity").getAsInt()); assertEquals(40, stub.lastHeartbeat.getAsJsonObject("serverStatus").get("maxPlayers").getAsInt());
            players.set(7); Thread.sleep(2200); assertEquals(7, stub.lastHeartbeat.getAsJsonObject("serverStatus").get("players").getAsInt());
            client.setServerStatus(new ServerStatus("Renamed", 1234, "preview-fixture", "World", 8, 30, 2)); Thread.sleep(2200); assertEquals("Renamed", stub.lastHeartbeat.getAsJsonObject("serverStatus").get("name").getAsString());
            assertTrue(client.readiness().get(10, TimeUnit.SECONDS).get("routable").getAsBoolean());
            client.rotateMachineKey().get(10, TimeUnit.SECONDS); client.drain().get(10, TimeUnit.SECONDS); assertTrue(stub.draining);
            client.stop().toCompletableFuture().get(10, TimeUnit.SECONDS);
            FakeTransport restarted = new FakeTransport(); ProviderClient resumed = new ProviderClient(config, new ProviderStateStore(path), restarted, () -> new ServerStatus("Restarted", 1234, "preview-fixture", "", 1, 50, 1), () -> new ProviderClient.Health(true, 100, 0, "nethernet", "fixture"), message -> {});
            try { assertEquals("example-machine-1", resumed.start().get(20, TimeUnit.SECONDS).get("instanceId").getAsString()); assertEquals(1, stub.registrations); assertEquals(2, stub.generation); } finally { resumed.stop().toCompletableFuture().get(10, TimeUnit.SECONDS); }
        }
    }
    private static void eventually(java.util.function.BooleanSupplier condition) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8);
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(40);
        assertTrue(condition.getAsBoolean(), "Timed out waiting for provider lifecycle");
    }
    @Test void failedRefreshRetriesCoalescingAndPendingAdmissionRecovery(@TempDir Path path) throws Exception {
        try (IndependentProviderStub stub = new IndependentProviderStub()) {
            AtomicInteger players = new AtomicInteger(2); FakeTransport host = new FakeTransport();
            var config = new ProviderClient.Configuration(URI.create(stub.origin), "example-profile-v0", "Example", null, null, null);
            var health = (java.util.function.Supplier<ProviderClient.Health>) () -> new ProviderClient.Health(true, 100, 0.1, "nethernet", "fixture");
            ProviderClient client = new ProviderClient(config, new ProviderStateStore(path), host, () -> {
                if (players.get() < 0) throw new IllegalStateException("query unavailable");
                return new ServerStatus("Example", 1234, "fixture", "", players.get(), 40, 0);
            }, health, message -> {});
            client.start().get(20, TimeUnit.SECONDS);
            players.set(-1); eventually(() -> !stub.lastHeartbeat.has("serverStatus"));
            int before = stub.heartbeats; players.set(5); stub.failHeartbeats = 1;
            for (int i = 0; i < 500; i++) client.requestStatusRefresh();
            eventually(() -> stub.lastHeartbeat.has("serverStatus") && stub.lastHeartbeat.getAsJsonObject("serverStatus").get("players").getAsInt() == 5);
            assertTrue(stub.heartbeats - before <= 2, "Burst must coalesce within heartbeat cadence");
            JsonObject fixture;
            try (var reader = new java.io.InputStreamReader(getClass().getResourceAsStream("/agent-control-consumer.fixtures.json"), java.nio.charset.StandardCharsets.UTF_8)) {
                fixture = JsonParser.parseReader(reader).getAsJsonObject().getAsJsonArray("fixtures").get(0).getAsJsonObject().getAsJsonObject("controlResponse").getAsJsonArray("commands").get(1).getAsJsonObject();
            }
            fixture.addProperty("gameServerId", "example-machine-1"); fixture.addProperty("signalServerId", "example-service-1");
            fixture.getAsJsonObject("ticketClaims").addProperty("gameServerId", "example-machine-1"); fixture.getAsJsonObject("ticketClaims").addProperty("signalServerId", "example-service-1"); fixture.getAsJsonObject("ticketClaims").addProperty("expiresAt", System.currentTimeMillis() + 30000);
            host.result = ProviderTransport.ApplyResult.PENDING; JsonArray commands = new JsonArray(); commands.add(fixture);
            JsonObject unknown = new JsonObject(); unknown.addProperty("kind", "future-command"); commands.add(unknown);
            JsonObject drain = new JsonObject(); drain.addProperty("kind", "drain"); commands.add(drain); stub.commands = commands;
            eventually(() -> host.admissions > 0 && host.drains > 0); assertEquals(0, stub.acknowledgements);
            // The provider operator removes the unknown command; pending admission still holds ack.
            JsonArray known = new JsonArray(); known.add(fixture); known.add(drain); stub.commands = known;
            client.stop().toCompletableFuture().get(10, TimeUnit.SECONDS);
            FakeTransport replacement = new FakeTransport(); ProviderClient resumed = new ProviderClient(config, new ProviderStateStore(path), replacement, () -> null, health, message -> {});
            try {
                resumed.start().get(20, TimeUnit.SECONDS);
                eventually(() -> stub.acknowledgements == 1 && !stub.events.isEmpty());
                assertEquals(0, replacement.admissions, "Volatile admission from the prior incarnation must fail, not resurrect");
                assertEquals("ticket.failed", stub.events.getFirst().get("stage").getAsString());
                assertFalse(java.nio.file.Files.readString(path.resolve("provider-state.json")).contains("client-password-valid"));
            } finally { resumed.stop().toCompletableFuture().get(10, TimeUnit.SECONDS); }
        }
    }

    @Test void localPersistenceFailureStopsPublicationAndClosesTransport(@TempDir Path path) throws Exception {
        try (IndependentProviderStub stub = new IndependentProviderStub()) {
            FakeTransport host = new FakeTransport();
            var client = new ProviderClient(new ProviderClient.Configuration(URI.create(stub.origin), "example-profile-v0", "Example", null, null, null), new ProviderStateStore(path), host, () -> null, () -> new ProviderClient.Health(true, 10, 0, "nethernet", "fixture"), message -> {});
            client.start().get(20, TimeUnit.SECONDS);
            java.nio.file.Files.move(path.resolve("provider-state.json"), path.resolve("saved-state.json"));
            java.nio.file.Files.createDirectory(path.resolve("provider-state.json"));
            assertThrows(ExecutionException.class, () -> client.readiness().get(10, TimeUnit.SECONDS));
            client.stop().toCompletableFuture().get(10, TimeUnit.SECONDS);
            assertTrue(host.closed.isDone());
        }
    }

}
