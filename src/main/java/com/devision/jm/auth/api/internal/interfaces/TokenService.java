package com.devision.jm.auth.api.internal.interfaces;

import com.devision.jm.auth.api.internal.dto.TokenInternalDto;

import java.util.Optional;

/**
 * Token Service Interface (Internal)
 *
 * Internal API for JWE token operations.
 * Handles token generation, validation, and revocation.
 */
public interface TokenService {

    /**
     * Generate access and refresh tokens for user
     *
     * @param userId User ID (MongoDB ObjectId as String)
     * @param email User email
     * @param role User role
     * @param ipAddress Client IP
     * @param deviceInfo Device information
     * @return Token details
     */
    TokenInternalDto generateTokens(String userId, String email, String role, String ipAddress, String deviceInfo);

    /**
     * Validate access token
     *
     * @param token Access token
     * @return True if valid
     */
    boolean validateAccessToken(String token);

    /**
     * Extract user ID from token
     *
     * @param token Access token
     * @return User ID as String
     */
    Optional<String> extractUserId(String token);

    /**
     * Extract user email from token
     *
     * @param token Access token
     * @return User email
     */
    Optional<String> extractEmail(String token);

    /**
     * Extract user role from token
     *
     * @param token Access token
     * @return User role
     */
    Optional<String> extractRole(String token);

    /**
     * Refresh tokens using refresh token
     *
     * @param refreshToken Refresh token
     * @return New tokens
     */
    Optional<TokenInternalDto> refreshTokens(String refreshToken);

    /**
     * Revoke access token
     *
     * @param accessToken Token to revoke
     */
    void revokeAccessToken(String accessToken);

    /**
     * Revoke refresh token
     *
     * @param refreshToken Token to revoke
     */
    void revokeRefreshToken(String refreshToken);

    /**
     * Revoke all tokens for user
     *
     * @param userId User ID (MongoDB ObjectId as String)
     */
    void revokeAllUserTokens(String userId);

    /**
     * Check if access token is revoked
     *
     * @param token Access token
     * @return True if revoked
     */
    boolean isAccessTokenRevoked(String token);
}
