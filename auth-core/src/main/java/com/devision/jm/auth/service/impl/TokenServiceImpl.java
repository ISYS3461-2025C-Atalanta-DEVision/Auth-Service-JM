package com.devision.jm.auth.service.impl;

import com.devision.jm.auth.api.internal.dto.TokenInternalDto;
import com.devision.jm.auth.api.internal.interfaces.TokenService;
import com.devision.jm.auth.config.JweConfig;
import com.devision.jm.auth.exception.InvalidTokenException;
import com.devision.jm.auth.exception.TokenExpiredException;
import com.devision.jm.auth.model.entity.RefreshToken;
import com.devision.jm.auth.model.entity.User;
import com.devision.jm.auth.repository.RefreshTokenRepository;
import com.devision.jm.auth.repository.UserRepository;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Token Service Implementation
 *
 * Handles JWE (JSON Web Encryption) token generation, validation, and revocation.
 *
 * Implements:
 * - JWE token generation with encrypted payload (2.2.1)
 * - Token refresh mechanism (2.3.3)
 * - Token revocation via Redis (2.3.2)
 * - Token invalidation on logout (2.2.3)
 *
 * JWE ensures the token payload is encrypted and cannot be read by unauthorized parties.
 * Uses A256GCM (AES-256-GCM) for content encryption and dir (direct) key agreement.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private static final String REVOKED_TOKEN_PREFIX = "revoked:";

    private final JweConfig jweConfig;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final RedisTemplate<String, String> redisTemplate;

    /**
     * Generate JWE access token and refresh token (2.2.1)
     * The access token payload is encrypted and cannot be read by unauthorized parties.
     */
    @Override
    public TokenInternalDto generateTokens(String userId, String email, String role,
                                           String ipAddress, String deviceInfo) {
        LocalDateTime now = LocalDateTime.now();

        // Generate encrypted JWE access token (2.2.1)
        Date accessTokenExpiry = new Date(System.currentTimeMillis() + jweConfig.getAccessTokenExpiration());
        String accessToken = generateJweToken(userId, email, role, accessTokenExpiry);

        // Generate refresh token (random UUID, stored in database)
        String refreshTokenValue = UUID.randomUUID().toString();
        LocalDateTime refreshTokenExpiry = now.plusSeconds(jweConfig.getRefreshTokenExpirationSeconds());

        // Get user entity for refresh token
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new InvalidTokenException("User not found"));

        // Save refresh token to database
        RefreshToken refreshToken = RefreshToken.builder()
                .token(refreshTokenValue)
                .user(user)
                .userId(userId)
                .expiresAt(refreshTokenExpiry)
                .ipAddress(ipAddress)
                .deviceInfo(deviceInfo)
                .build();
        refreshTokenRepository.save(refreshToken);

        log.debug("Generated JWE tokens for user: {}", email);

        return TokenInternalDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshTokenValue)
                .accessTokenExpiry(LocalDateTime.now().plusSeconds(jweConfig.getAccessTokenExpirationSeconds()))
                .refreshTokenExpiry(refreshTokenExpiry)
                .userId(userId)
                .userEmail(email)
                .role(role)
                .build();
    }

    /**
     * Generate JWE (encrypted) token - Requirement 2.2.1
     * Uses direct encryption with AES-256-GCM
     */
    private String generateJweToken(String userId, String email, String role, Date expiry) {
        try {
            // Build JWE claims (payload)
            JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                    .subject(email)
                    .claim("userId", userId)
                    .claim("email", email)
                    .claim("role", role)
                    .issuer(jweConfig.getIssuer())
                    .issueTime(new Date())
                    .expirationTime(expiry)
                    .jwtID(UUID.randomUUID().toString())  // Unique token ID for revocation
                    .build();

            // Create JWE header with direct encryption using A256GCM
            JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A256GCM)
                    .contentType("JWT")
                    .build();

            // Create encrypted JWE
            EncryptedJWT encryptedJWT = new EncryptedJWT(header, claimsSet);

            // Encrypt with AES-256 key
            DirectEncrypter encrypter = new DirectEncrypter(jweConfig.getEncryptionKey());
            encryptedJWT.encrypt(encrypter);

            // Serialize to compact form
            return encryptedJWT.serialize();

        } catch (JOSEException e) {
            log.error("Failed to generate JWE token: {}", e.getMessage());
            throw new RuntimeException("Failed to generate token", e);
        }
    }

    /**
     * Validate JWE access token (2.2.1)
     * Decrypts the token and verifies expiration
     */
    @Override
    public boolean validateAccessToken(String token) {
        try {
            JWTClaimsSet claims = decryptAndValidateToken(token);

            // Check if token is expired
            if (claims.getExpirationTime().before(new Date())) {
                log.debug("Token expired");
                return false;
            }

            // Check Redis for revocation (2.3.2)
            return !isAccessTokenRevoked(token);

        } catch (Exception e) {
            log.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Decrypt JWE token and extract claims
     */
    private JWTClaimsSet decryptAndValidateToken(String token) throws ParseException, JOSEException {
        // Parse the JWE token
        EncryptedJWT encryptedJWT = EncryptedJWT.parse(token);

        // Decrypt with AES-256 key
        DirectDecrypter decrypter = new DirectDecrypter(jweConfig.getEncryptionKey());
        encryptedJWT.decrypt(decrypter);

        // Get claims
        return encryptedJWT.getJWTClaimsSet();
    }

    @Override
    public Optional<String> extractUserId(String token) {
        try {
            JWTClaimsSet claims = decryptAndValidateToken(token);
            return Optional.ofNullable(claims.getStringClaim("userId"));
        } catch (Exception e) {
            log.debug("Failed to extract userId: {}", e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public Optional<String> extractEmail(String token) {
        try {
            JWTClaimsSet claims = decryptAndValidateToken(token);
            return Optional.ofNullable(claims.getStringClaim("email"));
        } catch (Exception e) {
            log.debug("Failed to extract email: {}", e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public Optional<String> extractRole(String token) {
        try {
            JWTClaimsSet claims = decryptAndValidateToken(token);
            return Optional.ofNullable(claims.getStringClaim("role"));
        } catch (Exception e) {
            log.debug("Failed to extract role: {}", e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public Optional<TokenInternalDto> refreshTokens(String refreshTokenValue) {
        // Find refresh token in database
        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenValue)
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

        // Check if token is valid
        if (!refreshToken.isValid()) {
            if (refreshToken.isExpired()) {
                throw new TokenExpiredException("Refresh");
            }
            throw new InvalidTokenException("Refresh token has been revoked");
        }

        User user = refreshToken.getUser();

        // Revoke the old refresh token (token rotation for security)
        refreshToken.revoke();
        refreshTokenRepository.save(refreshToken);

        // Generate new tokens
        TokenInternalDto newTokens = generateTokens(
                user.getId(),
                user.getEmail(),
                user.getRole().name(),
                refreshToken.getIpAddress(),
                refreshToken.getDeviceInfo()
        );

        // Link old token to new token (for audit trail)
        refreshToken.setReplacedByToken(newTokens.getRefreshToken());
        refreshTokenRepository.save(refreshToken);

        log.debug("Refreshed tokens for user: {}", user.getEmail());

        return Optional.of(newTokens);
    }

    /**
     * Revoke access token by adding to Redis blacklist (2.2.3, 2.3.2)
     */
    @Override
    public void revokeAccessToken(String accessToken) {
        try {
            // Decrypt to get expiration time
            JWTClaimsSet claims = decryptAndValidateToken(accessToken);
            Date expiration = claims.getExpirationTime();

            // Calculate TTL (time until token expires)
            long ttlMillis = expiration.getTime() - System.currentTimeMillis();
            if (ttlMillis > 0) {
                // Store in Redis with TTL matching token expiration
                String key = REVOKED_TOKEN_PREFIX + accessToken;
                redisTemplate.opsForValue().set(key, "revoked", ttlMillis, TimeUnit.MILLISECONDS);
                log.debug("JWE access token revoked and stored in Redis");
            }
        } catch (Exception e) {
            // Token may already be expired or invalid
            log.debug("Could not revoke access token (may be expired): {}", e.getMessage());
        }
    }

    @Override
    public void revokeRefreshToken(String refreshToken) {
        refreshTokenRepository.findByToken(refreshToken).ifPresent(token -> {
            token.revoke();
            refreshTokenRepository.save(token);
        });
        log.debug("Refresh token revoked");
    }

    @Override
    public void revokeAllUserTokens(String userId) {
        List<RefreshToken> tokens = refreshTokenRepository.findAllByUserId(userId);
        tokens.forEach(token -> {
            token.revoke();
            refreshTokenRepository.save(token);
        });
        log.debug("All tokens revoked for user: {}", userId);
    }

    /**
     * Check if access token is revoked in Redis (2.3.2)
     */
    @Override
    public boolean isAccessTokenRevoked(String token) {
        try {
            String key = REVOKED_TOKEN_PREFIX + token;
            return Boolean.TRUE.equals(redisTemplate.hasKey(key));
        } catch (Exception e) {
            // Fail-open for availability (log and allow)
            // In high-security scenarios, you might want to fail-closed
            log.error("Redis unavailable for token revocation check: {}", e.getMessage());
            return false;
        }
    }
}
