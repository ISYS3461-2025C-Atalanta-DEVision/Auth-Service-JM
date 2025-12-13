package com.devision.jm.auth.api.internal.interfaces;

import com.devision.jm.auth.api.internal.dto.UserInternalDto;
import com.devision.jm.auth.model.enums.AccountStatus;

import java.util.Optional;
import java.util.UUID;

/**
 * User Management Service Interface (Internal)
 *
 * Internal API for user management operations.
 * NOT accessible by other modules (A.2.3 - Internal APIs).
 */
public interface UserManagementService {

    /**
     * Find user by ID
     */
    Optional<UserInternalDto> findById(UUID id);

    /**
     * Find user by email
     */
    Optional<UserInternalDto> findByEmail(String email);

    /**
     * Create new user
     */
    UserInternalDto createUser(UserInternalDto userDto);

    /**
     * Update user
     */
    UserInternalDto updateUser(UserInternalDto userDto);

    /**
     * Update account status
     */
    void updateAccountStatus(UUID userId, AccountStatus status);

    /**
     * Check if email exists
     */
    boolean emailExists(String email);

    /**
     * Generate activation token
     */
    String generateActivationToken(UUID userId);

    /**
     * Generate password reset token
     */
    String generatePasswordResetToken(UUID userId);

    /**
     * Verify activation token
     */
    boolean verifyActivationToken(String token);

    /**
     * Verify password reset token
     */
    boolean verifyPasswordResetToken(String token);

    /**
     * Update password
     */
    void updatePassword(UUID userId, String newPasswordHash);
}
