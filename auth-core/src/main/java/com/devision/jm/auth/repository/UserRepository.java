package com.devision.jm.auth.repository;

import com.devision.jm.auth.model.entity.User;
import com.devision.jm.auth.model.enums.AccountStatus;
import com.devision.jm.auth.model.enums.AuthProvider;
import com.devision.jm.auth.model.enums.Role;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * User Repository (MongoDB)
 *
 * Data access layer for User document.
 * Implements Repository Layer (A.1.2) - queries are defined here.
 */
@Repository
public interface UserRepository extends MongoRepository<User, String> {

    // ==================== Find Operations ====================

    /**
     * Find user by email (case-insensitive)
     * Used for: Login, Registration validation (1.1.2)
     */
    @Query("{ 'email': { $regex: ?0, $options: 'i' } }")
    Optional<User> findByEmailIgnoreCase(String email);

    /**
     * Check if email exists (1.1.2)
     */
    @Query(value = "{ 'email': { $regex: ?0, $options: 'i' } }", exists = true)
    boolean existsByEmailIgnoreCase(String email);

    /**
     * Find user by activation token (1.1.3)
     */
    Optional<User> findByActivationToken(String activationToken);

    /**
     * Find users by SSO provider and provider ID (1.3.1)
     */
    Optional<User> findByAuthProviderAndProviderId(AuthProvider authProvider, String providerId);

    /**
     * Find users by role
     */
    List<User> findByRole(Role role);

    /**
     * Find users by status
     */
    List<User> findByStatus(AccountStatus status);

    /**
     * Search users by email (Admin feature)
     * Note: Company name search moved to Profile Service
     */
    @Query("{ 'email': { $regex: ?0, $options: 'i' } }")
    List<User> searchByEmail(String searchTerm);

    // ==================== Security Operations ====================

    /**
     * Find users with expired locks that need to be unlocked
     */
    @Query("{ 'locked_until': { $ne: null, $lt: ?0 } }")
    List<User> findUsersWithExpiredLocks(LocalDateTime now);
}
