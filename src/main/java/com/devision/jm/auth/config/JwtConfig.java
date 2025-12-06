package com.devision.jm.auth.config;

import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

/**
 * JWT Configuration
 *
 * Centralized JWT configuration for token generation and validation.
 */
@Configuration
@Getter
public class JwtConfig {

    @Value("${jwt.secret:YourSuperSecretKeyForJWTSigningMustBeAtLeast256BitsLong123456789}")
    private String secret;

    @Value("${jwt.access-token.expiration:3600000}")  // 1 hour
    private long accessTokenExpiration;

    @Value("${jwt.refresh-token.expiration:604800000}")  // 7 days
    private long refreshTokenExpiration;

    @Value("${jwt.issuer:devision-jm-auth}")
    private String issuer;

    /**
     * Get the signing key derived from secret
     */
    public SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
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
