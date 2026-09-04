package org.cloudburstmc.netty.warden;

import com.google.gson.*;
import java.util.*;

/** Validates the existing control wire envelope before handing sensitive data to the transport. */
public final class ControlValidator {
    private ControlValidator() {}
    public static boolean valid(JsonObject c, String instance, String service, long now) {
        try {
            return switch (c.get("kind").getAsString()) {
                case "noop", "drain", "suspend", "revoke" -> true;
                case "rotate-credential" -> c.has("credentialKeyId") && !c.get("credentialKeyId").getAsString().isEmpty();
                case "reconfigure" -> c.has("resourceId") && service.equals(c.get("signalServerId").getAsString()) && Set.of("game-server", "routing-policy", "signal-server").contains(c.get("resource").getAsString());
                case "join-admission" -> admission(c, instance, service, now);
                default -> false;
            };
        } catch (RuntimeException e) { return false; }
    }
    private static boolean admission(JsonObject c, String instance, String service, long now) {
        JsonObject claims = c.getAsJsonObject("ticketClaims");
        for (String field : List.of("gameServerId", "signalServerId", "networkId")) if (!c.get(field).equals(claims.get(field))) return false;
        if (!instance.equals(c.get("gameServerId").getAsString()) || !service.equals(c.get("signalServerId").getAsString()) || claims.get("expiresAt").getAsLong() <= now) return false;
        String ufrag = c.getAsJsonObject("clientIce").get("ufrag").getAsString();
        if (claims.has("clientIceUfrag") && !ufrag.equals(claims.get("clientIceUfrag").getAsString())) return false;
        String sdp = c.getAsJsonObject("clientOffer").get("sdp").getAsString();
        if (sdp.length() > 49152 || c.getAsJsonObject("answerIce").get("ufrag").getAsString().isEmpty() || c.getAsJsonObject("answerIce").get("pwd").getAsString().isEmpty()) return false;
        List<String> fingerprints = new ArrayList<>(); boolean hasPwd = false, hasUfrag = false;
        for (String line : sdp.split("\\r?\\n")) {
            if (line.startsWith("a=identity:")) return false;
            if (line.startsWith("a=ice-pwd:")) hasPwd |= line.length() > 10;
            if (line.startsWith("a=ice-ufrag:")) hasUfrag |= line.substring(12).equals(ufrag);
            if (line.startsWith("a=fingerprint:")) fingerprints.add(line.substring(14).trim());
        }
        Collections.sort(fingerprints);
        if (!hasPwd || !hasUfrag || fingerprints.isEmpty() || !hash(String.join("\n", fingerprints)).equals(claims.get("offerFingerprintHash").getAsString())) return false;
        if (claims.has("playerIdentityHash")) {
            if (!c.has("player")) return false;
            JsonObject player = c.getAsJsonObject("player");
            String canonical = String.join("\n", "warden-answer-ticket-player-v1", player.get("identitySource").getAsString(), player.has("playerKey") ? player.get("playerKey").getAsString().trim() : "", player.has("xuid") ? player.get("xuid").getAsString().trim() : "");
            if (!hash(canonical).equals(claims.get("playerIdentityHash").getAsString())) return false;
        }
        return true;
    }
    private static String hash(String value) {
        byte[] bytes = Arrays.copyOf(ProviderCrypto.digest(value), 16); String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; StringBuilder out = new StringBuilder(); int buffer = 0, bits = 0;
        for (byte b : bytes) { buffer = (buffer << 8) | (b & 255); bits += 8; while (bits >= 5) { bits -= 5; out.append(alphabet.charAt((buffer >> bits) & 31)); } }
        if (bits > 0) out.append(alphabet.charAt((buffer << (5 - bits)) & 31)); return out.toString();
    }
}
