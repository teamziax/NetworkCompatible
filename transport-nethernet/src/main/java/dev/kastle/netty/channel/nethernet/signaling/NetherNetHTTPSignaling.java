package dev.kastle.netty.channel.nethernet.signaling;

import com.google.gson.Gson;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import dev.kastle.netty.util.nethernet.Identity;
import dev.kastle.netty.util.nethernet.IdentityUtils;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtContext;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

public class NetherNetHTTPSignaling implements NetherNetServerSignaling {

    private final InternalLogger log = InternalLoggerFactory.getInstance(getClass());

    private HttpsServer server;
    private SSLContext ssl;

    private NetherNetServerSignaling.NewConnectionHandler newConnectionHandler;
    private Map<String, String> sdpAnswers = new HashMap<>();

    public NetherNetHTTPSignaling(File keystore) {
        this(keystore, "");
    }

    public NetherNetHTTPSignaling(File keystore, String password) {
        try {
            char[] passwordChars = password.toCharArray();

            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream("keystore.p12")) {
                ks.load(fis, passwordChars);
            }

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, passwordChars);

            ssl = SSLContext.getInstance("TLS");
            ssl.init(kmf.getKeyManagers(), null, null);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    @Override
    public void bind(SocketAddress localAddress) throws ConnectException {
        if (!(localAddress instanceof InetSocketAddress)) throw new IllegalArgumentException("Unsupported address type");
        try {
            server = HttpsServer.create((InetSocketAddress) localAddress, 0);
            server.setHttpsConfigurator(new HttpsConfigurator(ssl));
            server.createContext("/v1/join", this::handleJoin);
            server.setExecutor(null); // creates a default executor
            server.start();
        } catch (Exception e) {
            throw new ConnectException("Failed to bind to address: " + localAddress + ". Error: " + e.getMessage());
        }
    }

    private void handleJoin(HttpExchange exchange) throws IOException {
        log.debug("Received join request: " + exchange.getRequestMethod() + " " + exchange.getRequestURI());

        if (exchange.getRequestURI().getPath().equals("/v1/join")) {
            if (exchange.getRequestMethod().equals("GET")) {
                exchange.sendResponseHeaders(200, 0);
            } else {
                exchange.sendResponseHeaders(405, 0);
            }

            exchange.close();
            return;
        }

        if (!exchange.getRequestMethod().equals("POST")) {
            exchange.sendResponseHeaders(405, 0);
            exchange.close();
            return;
        }

        String networkId = exchange.getRequestURI().getPath().substring("/v1/join/".length());

        // Reject empty, or anything with a further path segment
        if (networkId.isEmpty() || networkId.indexOf('/') >= 0)
        {
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
            return;
        }

        String sdpOffer = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

        log.trace("Received sdp offer: " + sdpOffer);

        try {
            JwtClaims claims = IdentityUtils.validateSdp(sdpOffer);

            // TODO Some form of callback if people want to do filtering of xuid etc at this point?
            log.debug("Identity is valid: " + claims.getClaimValueAsString("xname") + " (" + claims.getClaimValueAsString("xid") + ")");
        } catch (Exception e) {
            log.error("Identity validation failed", e);
            exchange.sendResponseHeaders(401, -1);
            exchange.close();
            return;
        }

        newConnectionHandler.onConnect(Long.parseLong(networkId), networkId, sdpOffer);

        // Wait for sdpAnswers to contain the answer for this networkId
        // TODO Timeout
        while (!sdpAnswers.containsKey(networkId)) {
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                exchange.sendResponseHeaders(500, 0);
                exchange.close();
                return;
            }
        }

        String sdpAnswer = sdpAnswers.get(networkId);
        log.trace("Received SDP answer: " + sdpAnswer);

        log.debug("Sending SDP answer");

        exchange.getResponseHeaders().add("Content-Type", "application/sdp");
        exchange.sendResponseHeaders(200, sdpAnswer.length());
        exchange.getResponseBody().write(sdpAnswer.getBytes());
        exchange.close();
    }

    @Override
    public void setNewConnectionHandler(NewConnectionHandler handler) {
        this.newConnectionHandler = handler;
    }

    @Override
    public void setAdvertisementData(PongData pongData) {
        // No-op for Web Signaling.
    }

    @Override
    public void sendFullSdp(String targetNetworkId, String sdp) {
        log.debug("Sending sdp to " + targetNetworkId + ": " + sdp);
        sdpAnswers.put(targetNetworkId, sdp);
    }

    @Override
    public void setSignalHandler(long connectionId, SignalHandler handler) {
        // No-op for Web Signaling.
    }

    @Override
    public void removeSignalHandler(long connectionId) {
        // No-op for Web Signaling.
    }

    @Override
    public String getLocalNetworkId() {
        return "";
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
