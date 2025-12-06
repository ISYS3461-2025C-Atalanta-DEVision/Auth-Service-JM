package com.devision.jm.auth.service.impl;

import com.devision.jm.auth.api.internal.dto.TokenInternalDto;
import com.devision.jm.auth.api.internal.interfaces.TokenService;
import com.devision.jm.auth.config.JwtConfig;
import com.devision.jm.auth.exception.InvalidTokenException;
import com.devision.jm.auth.exception.TokenExpiredException;
import com.devision.jm.auth.model.entity.RefreshToken;
import com.devision.jm.auth.model.entity.User;
import com.devision.jm.auth.repository.RefreshTokenRepository;
import com.devision.jm.auth.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * Token Service Implementation
 *
 * Handles JWT token generation, validation, and revocation.
 *
 * Implements:
 * - JWS token generation (2.1.2)
 * - Token refresh mechanism (2.3.3)
 * - Token revocation via Redis (2.3.2)
 * - Token invalidation on logout (2.2.3)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenServiceImpl implements TokenService {

    private static final String REVOKED_TOKEN_PREFIX = "revoked:";

    private final JwtConfig jwtConfig;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final RedisTemplate<String, String> redisTemplate;

    @Override
    @Transactional
    public TokenInternalDto generateTokens(UUID userId, String email, String role,
                                           String ipAddress, String deviceInfo) {
        LocalDateTime now = LocalDateTime.now();

        // Generate access token
        Date accessTokenExpiry = new Date(System.currentTimeMillis() + jwtConfig.getAccessTokenExpiration());
        String accessToken = Jwts.builder()
                .subject(email)
                .claim("userId", userId.toString())
                .claim("email", email)
                .claim("role", role)
                .issuer(jwtConfig.getIssuer())
                .issuedAt(new Date())
                .expiration(accessTokenExpiry)
                .signWith(jwtConfig.getSigningKey())
                .compact();

        // Generate refresh token
        String refreshTokenValue = UUID.randomUUID().toString();
        LocalDateTime refreshTokenExpiry = now.plusSeconds(jwtConfig.getRefreshTokenExpirationSeconds());

        // Get user entity for refresh token
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new InvalidTokenException("User not found"));

        // Save refresh token to database
        RefreshToken refreshToken = RefreshToken.builder()
                .token(refreshTokenValue)
                .user(user)
                .expiresAt(refreshTokenExpiry)
                .ipAddress(ipAddress)
                .deviceInfo(deviceInfo)
                .build();
        refreshTokenRepository.save(refreshToken);

        log.debug("Generated tokens for user: {}", email);

        return TokenInternalDto.builder()
                .accessToken(accessToken)
                .refreshToken(refreshTokenValue)
                .accessTokenExpiry(LocalDateTime.now().plusSeconds(jwtConfig.getAccessTokenExpirationSeconds()))
                .refreshTokenExpiry(refreshTokenExpiry)
                .userId(userId)
                .userEmail(email)
                .role(role)
                .build();
    }

    @Override
    public boolean validateAccessToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith(jwtConfig.getSigningKey())
                    .build()
                    .parseSignedClaims(token);

            // Also check Redis for revocation
            return !isAccessTokenRevoked(token);
        } catch (ExpiredJwtException e) {
            log.debug("Token expired: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    @Override
    public Optional<UUID> extractUserId(String token) {
        try {
            Claims claims = extractClaims(token);
            String userIdStr = claims.get("userId", String.class);
            return Optional.of(UUID.fromString(userIdStr));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    @Override
    public Optional<String> extractEmail(String token) {
        try {
            Claims claims = extractClaims(token);
            return Optional.ofNullable(claims.get("email", String.class));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    @Override
    public Optional<String> extractRole(String token) {
        try {
            Claims claims = extractClaims(token);
            return Optional.ofNullable(claims.get("role", String.class));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    @Override
    @Transactional
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

    @Override
    public void revokeAccessToken(String accessToken) {
        try {
            // Get token expiration
            Claims claims = extractClaims(accessToken);
            Date expiration = claims.getExpiration();

            // Calculate TTL (time until token expires)
            long ttlMillis = expiration.getTime() - System.currentTimeMillis();
            if (ttlMillis > 0) {
                // Store in Redis with TTL matching token expiration
                String key = REVOKED_TOKEN_PREFIX + accessToken;
                redisTemplate.opsForValue().set(key, "revoked", ttlMillis, TimeUnit.MILLISECONDS);
                log.debug("Access token revoked and stored in Redis");
            }
        } catch (ExpiredJwtException e) {
            // Token already expired, no need to revoke
            log.debug("Token already expired, no revocation needed");
        } catch (Exception e) {
            log.error("Failed to revoke access token: {}", e.getMessage());
        }
    }

    @Override
    @Transactional
    public void revokeRefreshToken(String refreshToken) {
        refreshTokenRepository.revokeByToken(refreshToken, LocalDateTime.now());
        log.debug("Refresh token revoked");
    }

    @Override
    @Transactional
    public void revokeAllUserTokens(UUID userId) {
        refreshTokenRepository.revokeAllTokensByUser(userId, LocalDateTime.now());
        log.debug("All tokens revoked for user: {}", userId);
    }

    @Override
    public boolean isAccessTokenRevoked(String token) {
        try {
            String key = REVOKED_TOKEN_PREFIX + token;
            return Boolean.TRUE.equals(redisTemplate.hasKey(key));
        } catch (Exception e) {
            log.error("Failed to check token revocation: {}", e.getMessage());
            return false;  // Fail open if Redis is unavailable
        }
    }

    private Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(jwtConfig.getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
