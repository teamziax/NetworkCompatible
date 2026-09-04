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
    static final class FakeTransport implements ProviderTransport {
        final CompletableFuture<Void> closed = new CompletableFuture<>();
        volatile int installed, applied;
        volatile ApplyResult result = ApplyResult.APPLIED;
        public CompletionStage<JsonObject> hostProfile() { JsonObject p = new JsonObject(); p.addProperty("credentialKeyId", "T001"); p.addProperty("dtlsFingerprint", "fixture-native-profile"); return CompletableFuture.completedFuture(p); }
        public CompletionStage<Void> installTicketKeys(List<TicketKey> keys) { installed = keys.size(); return CompletableFuture.completedFuture(null); }
        public CompletionStage<ApplyResult> applyControl(JsonObject c) { applied++; return CompletableFuture.completedFuture(result); }
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
            host.result = ProviderTransport.ApplyResult.PENDING; JsonArray commands = new JsonArray(); commands.add(fixture); stub.commands = commands;
            eventually(() -> host.applied > 0); assertEquals(0, stub.acknowledgements);
            client.stop().toCompletableFuture().get(10, TimeUnit.SECONDS);
            FakeTransport replacement = new FakeTransport(); ProviderClient resumed = new ProviderClient(config, new ProviderStateStore(path), replacement, () -> null, health, message -> {});
            try {
                resumed.start().get(20, TimeUnit.SECONDS);
                eventually(() -> stub.acknowledgements == 1 && !stub.events.isEmpty());
                assertEquals(0, replacement.applied, "Volatile admission from the prior incarnation must fail, not resurrect");
                assertEquals("ticket.failed", stub.events.getFirst().get("stage").getAsString());
                assertFalse(java.nio.file.Files.readString(path.resolve("provider-state.json")).contains("client-password-valid"));
            } finally { resumed.stop().toCompletableFuture().get(10, TimeUnit.SECONDS); }
        }
    }

}
