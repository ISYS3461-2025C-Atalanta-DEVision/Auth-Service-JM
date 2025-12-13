package com.devision.jm.auth.repository;

import com.devision.jm.auth.model.entity.RefreshToken;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Refresh Token Repository (MongoDB)
 *
 * Data access layer for RefreshToken document.
 * Supports token refresh mechanism (2.3.3).
 */
@Repository
public interface RefreshTokenRepository extends MongoRepository<RefreshToken, String> {

    /**
     * Find refresh token by token string
     */
    Optional<RefreshToken> findByToken(String token);

    /**
     * Find all valid (non-revoked, non-expired) tokens for a user
     */
    @Query("{ 'user_id': ?0, 'revoked': false, 'expires_at': { $gt: ?1 } }")
    List<RefreshToken> findValidTokensByUserId(String userId, LocalDateTime now);

    /**
     * Find all tokens for a user (for logout all devices)
     */
    List<RefreshToken> findByUserId(String userId);

    /**
     * Delete expired tokens (cleanup job)
     */
    @Query(value = "{ 'expires_at': { $lt: ?0 } }", delete = true)
    long deleteExpiredTokens(LocalDateTime now);

    /**
     * Check if token exists and is valid
     */
    @Query(value = "{ 'token': ?0, 'revoked': false, 'expires_at': { $gt: ?1 } }", exists = true)
    boolean existsValidToken(String token, LocalDateTime now);

    /**
     * Revoke all tokens for a user by user ID
     */
    @Query("{ 'user_id': ?0 }")
    List<RefreshToken> findAllByUserId(String userId);
}
