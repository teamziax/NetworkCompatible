package org.cloudburstmc.netty.warden;

import com.google.gson.*;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ControlFixtureTest {
    @Test void sharedTypeScriptControlFixtures() throws Exception {
        try (var reader = new InputStreamReader(getClass().getResourceAsStream("/agent-control-consumer.fixtures.json"), StandardCharsets.UTF_8)) {
            var fixtures = JsonParser.parseReader(reader).getAsJsonObject().getAsJsonArray("fixtures");
            for (JsonElement entry : fixtures) {
                JsonObject fixture = entry.getAsJsonObject(), page = fixture.getAsJsonObject("controlResponse");
                long now = Instant.parse(page.get("serverTime").getAsString()).toEpochMilli();
                boolean valid = true;
                for (JsonElement item : page.getAsJsonArray("commands")) {
                    JsonObject command = item.getAsJsonObject(); long validationTime = now;
                    if (command.get("kind").getAsString().equals("join-admission") && command.has("ticketClaims")) {
                        long expires = command.getAsJsonObject("ticketClaims").get("expiresAt").getAsLong();
                        // Expired but otherwise valid records are discarded only after durable failure recording.
                        if (expires <= now) validationTime = expires - 1;
                    }
                    valid &= ControlValidator.valid(command, "gs_fixture_lon", "sig_fixture", validationTime);
                }
                assertEquals(fixture.getAsJsonObject("expected").getAsJsonObject("ack").get("allowed").getAsBoolean(), valid, fixture.get("name").getAsString());
            }
        }
    }
}
