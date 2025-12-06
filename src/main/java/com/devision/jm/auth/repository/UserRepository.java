package com.devision.jm.auth.repository;

import com.devision.jm.auth.model.entity.User;
import com.devision.jm.auth.model.enums.AccountStatus;
import com.devision.jm.auth.model.enums.AuthProvider;
import com.devision.jm.auth.model.enums.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * User Repository
 *
 * Data access layer for User entity.
 * Implements Repository Layer (A.1.2) - queries are defined here.
 */
@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    // ==================== Find Operations ====================

    /**
     * Find user by email (case-insensitive)
     * Used for: Login, Registration validation (1.1.2)
     */
    Optional<User> findByEmailIgnoreCase(String email);

    /**
     * Check if email exists (1.1.2)
     */
    boolean existsByEmailIgnoreCase(String email);

    /**
     * Find user by activation token (1.1.3)
     */
    Optional<User> findByActivationToken(String activationToken);

    /**
     * Find user by password reset token
     */
    Optional<User> findByPasswordResetToken(String passwordResetToken);

    /**
     * Find users by SSO provider and provider ID (1.3.1)
     */
    Optional<User> findByAuthProviderAndProviderId(AuthProvider authProvider, String providerId);

    /**
     * Find users by role
     */
    List<User> findByRole(Role role);

    /**
     * Find users by country (for sharding support - 1.3.3)
     */
    List<User> findByCountry(String country);

    /**
     * Find users by status
     */
    List<User> findByStatus(AccountStatus status);

    // ==================== Admin Operations (6.1.2, 6.2.1) ====================

    /**
     * Search users by email or company name (Admin feature 6.2.1)
     */
    @Query("SELECT u FROM User u WHERE " +
            "LOWER(u.email) LIKE LOWER(CONCAT('%', :searchTerm, '%')) OR " +
            "LOWER(u.companyName) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    List<User> searchByEmailOrCompanyName(@Param("searchTerm") String searchTerm);

    // ==================== Security Operations ====================

    /**
     * Find users with expired locks that need to be unlocked
     */
    @Query("SELECT u FROM User u WHERE u.lockedUntil IS NOT NULL AND u.lockedUntil < :now")
    List<User> findUsersWithExpiredLocks(@Param("now") LocalDateTime now);

    /**
     * Update account status (Admin deactivation - 6.1.2)
     */
    @Modifying
    @Query("UPDATE User u SET u.status = :status, u.updatedAt = :now WHERE u.id = :userId")
    int updateAccountStatus(@Param("userId") UUID userId,
                           @Param("status") AccountStatus status,
                           @Param("now") LocalDateTime now);

    /**
     * Reset failed login attempts
     */
    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = 0, u.lockedUntil = NULL WHERE u.id = :userId")
    int resetFailedLoginAttempts(@Param("userId") UUID userId);

    /**
     * Lock user account (2.2.2 brute-force protection)
     */
    @Modifying
    @Query("UPDATE User u SET u.lockedUntil = :lockedUntil WHERE u.id = :userId")
    int lockUserAccount(@Param("userId") UUID userId, @Param("lockedUntil") LocalDateTime lockedUntil);

    // ==================== Token Operations ====================

    /**
     * Clear activation token after successful activation
     */
    @Modifying
    @Query("UPDATE User u SET u.activationToken = NULL, u.activationTokenExpiry = NULL, " +
            "u.status = :status WHERE u.id = :userId")
    int clearActivationToken(@Param("userId") UUID userId, @Param("status") AccountStatus status);

    /**
     * Clear password reset token after successful reset
     */
    @Modifying
    @Query("UPDATE User u SET u.passwordResetToken = NULL, u.passwordResetTokenExpiry = NULL, " +
            "u.lastPasswordChange = :now WHERE u.id = :userId")
    int clearPasswordResetToken(@Param("userId") UUID userId, @Param("now") LocalDateTime now);
}
