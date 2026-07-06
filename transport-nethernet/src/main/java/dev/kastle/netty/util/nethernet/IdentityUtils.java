package dev.kastle.netty.util.nethernet;

import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.jose4j.lang.JoseException;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Collectors;

public class IdentityUtils {
    private static final InternalLogger log = InternalLoggerFactory.getInstance(IdentityUtils.class);

    private static final JwtConsumer JWT_CONSUMER = new JwtConsumerBuilder()
        .setVerificationKeyResolver(new HttpsJwksVerificationKeyResolver(new HttpsJwks("https://authorization.franchise.minecraft-services.net/.well-known/keys")))
        .setRequireExpirationTime()
        .setRequireSubject()
        .setExpectedAudience(true, "api://auth-minecraft-services/multiplayer")
        .setExpectedIssuer("https://authorization.franchise.minecraft-services.net/")
        .build();

    public static JwtContext validateIdentity(Identity identity) throws InvalidJwtException {
        return JWT_CONSUMER.process(identity.assertion().token()); // TODO Take into account the idp in the identity
    }

    public static JwtClaims validateSdp(String sdpOffer) throws JoseException, InvalidJwtException {
        // Extract the identity
        Identity identity = Identity.fromSdpOffer(sdpOffer);
        if (identity == null) {
            throw new JoseException("Invalid SDP offer: missing identity");
        }
        log.debug("Received identity: " + identity);

        JwtContext jwtContext = IdentityUtils.validateIdentity(identity);
        JwtClaims claims = jwtContext.getJwtClaims();

        // Reconstruct the detached payload from the SDP fingerprint lines
        String fingerprints = getCanonicalFingerprintJson(sdpOffer);
        if (fingerprints.length() == 18) { // Check if it is just the empty array {"fingerprint":[]}
            throw new JoseException("Invalid SDP offer: no fingerprints");
        }

        // Validate the detached fingerprints JWS against the cpk from the token
        String detachedJws = identity.assertion().fingerprints();
        try {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(detachedJws);

            // Derive the key type from the JWS header
            String alg = jws.getAlgorithmHeaderValue();
            String keyType = keyAlgorithmFor(alg);

            // cpk is base64, decode it and parse as a public key
            byte[] der = Base64.getDecoder().decode(claims.getClaimValueAsString("cpk"));
            PublicKey cpkKey = KeyFactory.getInstance(keyType).generatePublic(new X509EncodedKeySpec(der));

            // Set the JWS properties so we can verify
            jws.setKey(cpkKey);
            jws.setPayload(fingerprints);
            jws.setAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.PERMIT, alg));

            if (!jws.verifySignature()) {
                throw new JoseException("Fingerprint signature mismatch");
            }
        } catch (GeneralSecurityException e) {
            throw new JoseException("Fingerprint JWS validation failed", e);
        }

        return claims;
    }

    private static String keyAlgorithmFor(String jwsAlg) throws JoseException {
        return switch (jwsAlg) { // No idea if this is complete or even all needed, just guessed at common ones
            case AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256,
                 AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384,
                 AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512 -> "EC";

            case AlgorithmIdentifiers.RSA_USING_SHA256,
                 AlgorithmIdentifiers.RSA_USING_SHA384,
                 AlgorithmIdentifiers.RSA_USING_SHA512,
                 AlgorithmIdentifiers.RSA_PSS_USING_SHA256,
                 AlgorithmIdentifiers.RSA_PSS_USING_SHA384,
                 AlgorithmIdentifiers.RSA_PSS_USING_SHA512 -> "RSA";

            case AlgorithmIdentifiers.EDDSA -> "EdDSA";

            default -> throw new JoseException("Unsupported fingerprint alg: " + jwsAlg);
        };
    }

    private static String getCanonicalFingerprintJson(String sdpOffer) {
        String prefix = "a=fingerprint:";
        return Arrays.stream(sdpOffer.split("\n"))
            .filter(line -> line.startsWith(prefix))
            .map(line -> line.substring(prefix.length()).trim())
            .map(line -> {
                String[] parts = line.split(" ");
                if (parts.length != 2) {
                    throw new IllegalArgumentException("Invalid fingerprint line: " + line);
                }
                return "{\"algorithm\":\"" + parts[0] + "\",\"digest\":\"" + parts[1] + "\"}";
            })
            .collect(Collectors.joining(",", "{\"fingerprint\":[", "]}"));
    }
}
