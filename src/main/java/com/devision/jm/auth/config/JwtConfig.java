package com.devision.jm.auth.config;

import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * JWT Configuration
 *
 * Centralized JWT configuration for token generation and validation.
 *
 * Implements:
 * - JWS signing key for token integrity (2.1.2)
 * - JWE encryption key for token confidentiality (2.2.1)
 */
@Slf4j
@Configuration
@Getter
public class JwtConfig {

    // Secret for signing (JWS) - used for token integrity
    @Value("${jwt.secret:YourSuperSecretKeyForJWTSigningMustBeAtLeast256BitsLong123456789}")
    private String secret;

    // Secret for encryption (JWE) - used for token confidentiality (2.2.1)
    // If not provided, derives from signing secret
    @Value("${jwt.encryption-secret:}")
    private String encryptionSecret;

    @Value("${jwt.access-token.expiration:3600000}")  // 1 hour
    private long accessTokenExpiration;

    @Value("${jwt.refresh-token.expiration:604800000}")  // 7 days
    private long refreshTokenExpiration;

    @Value("${jwt.issuer:devision-jm-auth}")
    private String issuer;

    /**
     * Get the signing key for JWS (token signing)
     * Used for verifying token integrity
     */
    public SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Get the encryption key for JWE (token encryption) - Requirement 2.2.1
     * Used for encrypting token payload so it cannot be read by unauthorized parties
     *
     * @return 256-bit AES key for A256GCM encryption
     */
    public SecretKey getEncryptionKey() {
        String keySource = (encryptionSecret != null && !encryptionSecret.isEmpty())
                ? encryptionSecret
                : secret + "_encryption";  // Derive from signing secret if not provided

        try {
            // Generate a 256-bit key using SHA-256 hash
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = digest.digest(keySource.getBytes(StandardCharsets.UTF_8));
            return new SecretKeySpec(keyBytes, "AES");
        } catch (NoSuchAlgorithmException e) {
            log.error("Failed to generate encryption key: {}", e.getMessage());
            throw new RuntimeException("Failed to generate encryption key", e);
        }
    }

    /**
     * Get access token expiration in seconds
     */
    public long getAccessTokenExpirationSeconds() {
        return accessTokenExpiration / 1000;
    }

    /**
     * Get refresh token expiration in seconds
     */
    public long getRefreshTokenExpirationSeconds() {
        return refreshTokenExpiration / 1000;
    }
}
