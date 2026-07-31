package dev.kastle.netty.channel.nethernet.signaling;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import dev.kastle.netty.util.nethernet.IdentityUtils;
import dev.kastle.netty.util.logs.LoggingHttpFilter;
import dev.kastle.netty.util.nethernet.ServerIdentity;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;
import org.jose4j.jwt.JwtClaims;

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
import java.util.Random;

/**
 * This class implements a signaling server using HTTP(S) for the NetherNet protocol.
 * <p>
 * Follows <a href="https://github.com/Mojang/bedrock-protocol-docs/blob/7330880ab78ef001cad0b9cdfedb3aa3eaa6d4af/NetherNetOnboardingGuide.md">...</a>
 */
public class NetherNetHTTPSignaling implements NetherNetServerSignaling {

    private final InternalLogger log = InternalLoggerFactory.getInstance(getClass());

    private HttpServer server;
    private SSLContext ssl;
    private ServerIdentity serverIdentity;

    private NetherNetServerSignaling.NewConnectionHandler newConnectionHandler;
    private Map<String, String> sdpAnswers = new HashMap<>();

    private Random random;

    public NetherNetHTTPSignaling(File identityKeystore, String identityPassword) {
        this(identityKeystore, identityPassword, null, "");
    }

    public NetherNetHTTPSignaling(File identityKeystore, File httpsKeystore) {
        this(identityKeystore, "", httpsKeystore, "");
    }

    /**
     * Creates an HTTPS signalling server, backed by one keystore for the TLS
     * listener and another for the server identity used to sign SDP answers.
     * <p>
     * Both must be PKCS12 files. The identity key must be EC P-384, and its certificate
     * CN is surfaced as the identity domain, so set it to something recognisable.
     * Generate one with:
     * <pre>{@code
     * keytool -genkeypair -alias identity -keyalg EC -groupname secp384r1 \
     *         -storetype PKCS12 -keystore identity.p12 -storepass changeit \
     *         -dname "CN=Your Server" -validity 3650
     * }</pre>
     *
     * @param identityKeystore PKCS12 keystore holding the EC P-384 identity key
     * @param identityPassword Password for {@code identityKeystore}, or "" if unprotected
     * @param httpsKeystore PKCS12 keystore holding the TLS certificate and key
     * @param httpsPassword Password for {@code httpsKeystore}, or "" if unprotected
     */
    public NetherNetHTTPSignaling(File identityKeystore, String identityPassword, File httpsKeystore, String httpsPassword) {
        this.random = new Random();

        try {
            if (httpsKeystore != null) {
                char[] passwordChars = httpsPassword.toCharArray();

                KeyStore ks = KeyStore.getInstance("PKCS12");
                try (FileInputStream fis = new FileInputStream(httpsKeystore)) {
                    ks.load(fis, passwordChars);
                }

                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(ks, passwordChars);

                ssl = SSLContext.getInstance("TLS");
                ssl.init(kmf.getKeyManagers(), null, null);
            }
        } catch (Exception ex) {
            log.error("Error loading https keystore: " + ex.getMessage(), ex);
        }

        try {
            this.serverIdentity = ServerIdentity.fromKeystore(identityKeystore, identityPassword);
        } catch (Exception ex) {
            log.error("Error loading identity keystore: " + ex.getMessage(), ex);
        }
    }

    @Override
    public void bind(SocketAddress localAddress) throws ConnectException {
        if (!(localAddress instanceof InetSocketAddress)) throw new IllegalArgumentException("Unsupported address type");
        try {
            if (ssl != null) {
                server = HttpsServer.create((InetSocketAddress) localAddress, 0);
                ((HttpsServer) server).setHttpsConfigurator(new HttpsConfigurator(ssl));
            } else {
                // TODO Find a way of making the client accept non-TLS connections
                // The spec says this is possible
                server = HttpServer.create((InetSocketAddress) localAddress, 0);
            }

            server.createContext("/v1/join", this::handleJoin).getFilters().add(new LoggingHttpFilter(log));
            server.setExecutor(null); // creates a default executor
            server.start();
        } catch (Exception e) {
            throw new ConnectException("Failed to bind to address: " + localAddress + ". Error: " + e.getMessage());
        }
    }

    private void handleJoin(HttpExchange exchange) throws IOException {
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
        if (networkId.isEmpty() || networkId.indexOf('/') >= 0) {
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

        // We cant use the network ID as the connection ID as they can be out of the bounds of a long
        newConnectionHandler.onConnect(random.nextLong(), networkId, sdpOffer);

        // Wait for sdpAnswers to contain the answer for this networkId
        // TODO Timeout
        while (!sdpAnswers.containsKey(networkId)) {
            try {
                Thread.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Thread interrupted while waiting for SDP answer", e);
                exchange.sendResponseHeaders(500, 0);
                exchange.close();
                return;
            }
        }

        String sdpAnswer = sdpAnswers.get(networkId);
        log.trace("Received SDP answer: " + sdpAnswer);

        // Sign the answer with the server identity
        String signedAnswer;
        try {
            signedAnswer = serverIdentity.augmentAnswer(sdpAnswer);
            log.trace("Signed SDP answer: " + signedAnswer);
        } catch (Exception e) {
            log.error("Failed to attach server identity to answer", e);
            exchange.sendResponseHeaders(500, -1);
            exchange.close();
            return;
        }

        log.debug("Sending SDP answer");

        byte[] body = signedAnswer.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/sdp");
        exchange.sendResponseHeaders(200, body.length);
        exchange.getResponseBody().write(body);
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
